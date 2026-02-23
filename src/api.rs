use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::audit_store::{AuditRecord, AuditStore};
use crate::profile::{profile_from_env, RuleProfile};
use crate::telemetry::{Metrics, MetricsSnapshot};
use crate::{evaluate_with_config, Decision, FinalDecision, TransactionIntent};

const DEFAULT_AUDIT_PATH: &str = "logs/audit_records.jsonl";
const DEFAULT_RETENTION: usize = 5_000;

#[derive(Clone)]
pub struct AppState {
    pub profile: RuleProfile,
    pub audit_store: AuditStore,
    pub metrics: Arc<Metrics>,
    pub audit_enabled: bool,
}

impl AppState {
    pub fn from_env() -> Self {
        let path =
            std::env::var("NEXO_AUDIT_PATH").unwrap_or_else(|_| DEFAULT_AUDIT_PATH.to_string());
        let retention = std::env::var("NEXO_AUDIT_RETENTION")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_RETENTION);
        Self {
            profile: profile_from_env(),
            audit_store: AuditStore::new(path, retention),
            metrics: Metrics::new_shared(),
            audit_enabled: true,
        }
    }

    pub fn for_tests(path: PathBuf) -> Self {
        Self {
            profile: profile_from_env(),
            audit_store: AuditStore::new(path, 500),
            metrics: Metrics::new_shared(),
            audit_enabled: true,
        }
    }

    pub fn for_bench() -> Self {
        Self {
            profile: profile_from_env(),
            audit_store: AuditStore::new(std::env::temp_dir().join("nexo_bench_unused.jsonl"), 1),
            metrics: Metrics::new_shared(),
            audit_enabled: false,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    pub user_id: String,
    pub amount_cents: u64,
    pub is_pep: bool,
    pub has_active_kyc: bool,
    pub timestamp_utc_ms: u64,
    pub risk_bps: u16,
    pub ui_hash_valid: bool,
    pub request_id: Option<String>,
    pub calc_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    pub request_id: String,
    pub calc_version: Option<String>,
    pub profile_name: String,
    pub profile_version: String,
    pub final_decision: FinalDecision,
    pub trace: Vec<Decision>,
    pub audit_hash: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub request_id: String,
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub timestamp_utc_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AuditRecentResponse {
    pub records: Vec<AuditRecord>,
}

pub fn app() -> Router {
    app_with_state(AppState::from_env())
}

pub fn app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/evaluate", post(evaluate_handler))
        .route("/healthz", get(health_handler))
        .route("/readyz", get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .route("/audit/recent", get(audit_recent_handler))
        .with_state(state)
}

async fn evaluate_handler(
    State(state): State<AppState>,
    Json(req): Json<EvaluateRequest>,
) -> impl IntoResponse {
    let start = Instant::now();
    let request_id = req.request_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    if req.user_id.trim().is_empty() {
        state
            .metrics
            .observe_error(start.elapsed().as_nanos() as u64);
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                request_id,
                error: "user_id must not be empty".to_string(),
            }),
        )
            .into_response();
    }

    let server_time_ms = now_utc_ms();
    let tx = match TransactionIntent::new(
        &req.user_id,
        req.amount_cents,
        req.is_pep,
        req.has_active_kyc,
        req.timestamp_utc_ms,
        server_time_ms,
        req.risk_bps,
        req.ui_hash_valid,
    ) {
        Ok(tx) => tx,
        Err(err) => {
            let elapsed = start.elapsed().as_nanos() as u64;
            state.metrics.observe_error(elapsed);
            warn!(request_id = %request_id, error = %err, "evaluate rejected request");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    request_id,
                    error: err.to_string(),
                }),
            )
                .into_response();
        }
    };

    let (final_decision, trace, audit_hash) =
        evaluate_with_config(&tx, state.profile.engine_config());

    let record = AuditRecord {
        request_id: request_id.clone(),
        calc_version: req.calc_version.clone(),
        profile_name: state.profile.name.to_string(),
        profile_version: state.profile.version.to_string(),
        timestamp_utc_ms: now_utc_ms(),
        user_id: req.user_id.clone(),
        amount_cents: req.amount_cents,
        risk_bps: req.risk_bps,
        final_decision,
        trace: serde_json::to_value(&trace).unwrap_or_else(|_| serde_json::json!([])),
        audit_hash: audit_hash.clone(),
    };

    if state.audit_enabled {
        if let Err(err) = state.audit_store.append(&record) {
            let elapsed = start.elapsed().as_nanos() as u64;
            state.metrics.observe_error(elapsed);
            warn!(request_id = %request_id, error = %err, "failed to persist audit record");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    request_id,
                    error: "failed to persist audit record".to_string(),
                }),
            )
                .into_response();
        }
    }

    let elapsed = start.elapsed().as_nanos() as u64;
    state.metrics.observe_success(final_decision, elapsed);
    info!(
        request_id = %request_id,
        decision = ?final_decision,
        profile = state.profile.name,
        latency_ns = elapsed,
        "evaluate request completed"
    );

    let response = EvaluateResponse {
        request_id,
        calc_version: req.calc_version,
        profile_name: state.profile.name.to_string(),
        profile_version: state.profile.version.to_string(),
        final_decision,
        trace,
        audit_hash,
    };
    (StatusCode::OK, Json(response)).into_response()
}

async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            timestamp_utc_ms: now_utc_ms(),
        }),
    )
}

async fn ready_handler(State(state): State<AppState>) -> impl IntoResponse {
    if !state.audit_enabled {
        return (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ready",
                timestamp_utc_ms: now_utc_ms(),
            }),
        )
            .into_response();
    }
    match state.audit_store.ready() {
        Ok(()) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ready",
                timestamp_utc_ms: now_utc_ms(),
            }),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "not_ready",
                timestamp_utc_ms: now_utc_ms(),
            }),
        )
            .into_response(),
    }
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let snapshot: MetricsSnapshot = state.metrics.snapshot();
    (StatusCode::OK, Json(snapshot))
}

async fn audit_recent_handler(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    match state.audit_store.recent(limit) {
        Ok(records) => (StatusCode::OK, Json(AuditRecentResponse { records })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                request_id: Uuid::new_v4().to_string(),
                error: "failed to load audit records".to_string(),
            }),
        )
            .into_response(),
    }
}

fn now_utc_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::util::ServiceExt;

    use super::*;

    fn test_state() -> AppState {
        let path = std::env::temp_dir().join(format!("nexo_api_test_{}.jsonl", Uuid::new_v4()));
        AppState::for_tests(path)
    }

    #[tokio::test]
    async fn evaluate_contract_returns_expected_fields() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id": "contract_user",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true,
            "request_id": "req-contract-1",
            "calc_version": "plca_v1"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(req_body.to_string()))
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json body");

        assert_eq!(json["request_id"], "req-contract-1");
        assert_eq!(json["calc_version"], "plca_v1");
        assert!(json["profile_name"].is_string());
        assert!(json["profile_version"].is_string());
        assert_eq!(json["final_decision"], "Approved");
        assert!(json["trace"].is_array());
        assert!(json["audit_hash"].is_string());
    }

    #[tokio::test]
    async fn evaluate_rejects_replay_timestamp() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id": "bad_time",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now.saturating_sub(600_000),
            "risk_bps": 1_000,
            "ui_hash_valid": true
        });

        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(req_body.to_string()))
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json body");
        assert!(json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("replay"));
    }

    #[tokio::test]
    async fn evaluate_rejects_empty_user_id() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id": "   ",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true
        });

        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(req_body.to_string()))
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
