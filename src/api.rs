use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::audit_store::{AuditRecord, AuditStore};
use crate::profile::{profile_from_env, RuleProfile};
use crate::telemetry::{Metrics, MetricsSnapshot};
use crate::{evaluate_with_config, Decision, FinalDecision, TransactionIntent};

const DEFAULT_AUDIT_PATH: &str = "logs/audit_records.jsonl";
const DEFAULT_RETENTION: usize = 5_000;
const AUTH_WINDOW_MS: u64 = 60_000;
const REPLAY_TTL_MS: u64 = 120_000;
const HEADER_SIGNATURE: &str = "x-signature";
const HEADER_REQUEST_ID: &str = "x-request-id";
const HEADER_TIMESTAMP: &str = "x-timestamp";
const HEADER_KEY_ID: &str = "x-key-id";

pub const BENCH_HMAC_SECRET: &str = "bench_hmac_secret";
pub const BENCH_KEY_ID: &str = "active";

#[derive(Clone)]
pub struct AppState {
    pub profile: RuleProfile,
    pub audit_store: AuditStore,
    pub metrics: Arc<Metrics>,
    pub audit_enabled: bool,
    pub auth: AuthSecrets,
    pub replay_cache: Arc<DashMap<String, u64>>,
    pub last_replay_cleanup_ms: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct AuthSecrets {
    pub active: AuthKey,
    pub previous: Option<AuthKey>,
}

#[derive(Clone)]
pub struct AuthKey {
    pub id: String,
    key: [u8; 32],
}

impl AppState {
    pub fn from_env() -> Self {
        let path =
            std::env::var("NEXO_AUDIT_PATH").unwrap_or_else(|_| DEFAULT_AUDIT_PATH.to_string());
        let retention = std::env::var("NEXO_AUDIT_RETENTION")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_RETENTION);

        let active_secret = std::env::var("NEXO_HMAC_SECRET")
            .expect("NEXO_HMAC_SECRET is required. Refusing to start without HMAC secret.");
        let active_id =
            std::env::var("NEXO_HMAC_KEY_ID").unwrap_or_else(|_| BENCH_KEY_ID.to_string());
        let previous_secret = std::env::var("NEXO_HMAC_SECRET_PREV").ok();
        let previous_id =
            std::env::var("NEXO_HMAC_KEY_ID_PREV").unwrap_or_else(|_| "previous".to_string());

        Self {
            profile: profile_from_env(),
            audit_store: AuditStore::new(path, retention),
            metrics: Metrics::new_shared(),
            audit_enabled: true,
            auth: AuthSecrets {
                active: AuthKey::new(active_id, &active_secret),
                previous: previous_secret.map(|secret| AuthKey::new(previous_id, &secret)),
            },
            replay_cache: Arc::new(DashMap::new()),
            last_replay_cleanup_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn for_tests(path: PathBuf) -> Self {
        Self {
            profile: profile_from_env(),
            audit_store: AuditStore::new(path, 500),
            metrics: Metrics::new_shared(),
            audit_enabled: true,
            auth: AuthSecrets {
                active: AuthKey::new("active".to_string(), "test_active_secret"),
                previous: Some(AuthKey::new("previous".to_string(), "test_previous_secret")),
            },
            replay_cache: Arc::new(DashMap::new()),
            last_replay_cleanup_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn for_bench() -> Self {
        Self {
            profile: profile_from_env(),
            audit_store: AuditStore::new(std::env::temp_dir().join("nexo_bench_unused.jsonl"), 1),
            metrics: Metrics::new_shared(),
            audit_enabled: false,
            auth: AuthSecrets {
                active: AuthKey::new(BENCH_KEY_ID.to_string(), BENCH_HMAC_SECRET),
                previous: None,
            },
            replay_cache: Arc::new(DashMap::new()),
            last_replay_cleanup_ms: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl AuthKey {
    fn new(id: String, secret: &str) -> Self {
        Self {
            id,
            key: derive_hmac_key(secret),
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
    pub auth_key_id: String,
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

#[derive(Debug)]
enum AuthError {
    Unauthorized(&'static str),
    RequestTimeout(&'static str),
    Conflict(&'static str),
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
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let start = Instant::now();

    let (header_request_id, header_timestamp, key_used_id) =
        match validate_security_headers(&state, &headers, &body) {
            Ok(v) => v,
            Err(err) => {
                let elapsed = start.elapsed().as_nanos() as u64;
                state.metrics.observe_error(elapsed);
                let request_id = extract_header(&headers, HEADER_REQUEST_ID)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                return auth_error_response(request_id, err);
            }
        };

    let req: EvaluateRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(_) => {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    request_id: header_request_id,
                    error: "invalid JSON payload".to_string(),
                }),
            )
                .into_response();
        }
    };

    if req.user_id.trim().is_empty() {
        state
            .metrics
            .observe_error(start.elapsed().as_nanos() as u64);
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                request_id: header_request_id,
                error: "user_id must not be empty".to_string(),
            }),
        )
            .into_response();
    }

    if let Some(body_request_id) = req.request_id.as_deref() {
        if body_request_id != header_request_id {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    request_id: header_request_id,
                    error: "request_id in body must match X-Request-Id".to_string(),
                }),
            )
                .into_response();
        }
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
            warn!(request_id = %header_request_id, error = %err, "evaluate rejected request");
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    request_id: header_request_id,
                    error: err.to_string(),
                }),
            )
                .into_response();
        }
    };

    let (final_decision, trace, audit_hash) =
        evaluate_with_config(&tx, state.profile.engine_config());

    let record = AuditRecord {
        request_id: header_request_id.clone(),
        calc_version: req.calc_version.clone(),
        profile_name: state.profile.name.to_string(),
        profile_version: state.profile.version.to_string(),
        timestamp_utc_ms: header_timestamp,
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
            warn!(request_id = %header_request_id, error = %err, "failed to persist audit record");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    request_id: header_request_id,
                    error: "failed to persist audit record".to_string(),
                }),
            )
                .into_response();
        }
    }

    let elapsed = start.elapsed().as_nanos() as u64;
    state.metrics.observe_success(final_decision, elapsed);
    info!(
        request_id = %header_request_id,
        decision = ?final_decision,
        profile = state.profile.name,
        key_id = %key_used_id,
        latency_ns = elapsed,
        "evaluate request completed"
    );

    let response = EvaluateResponse {
        request_id: header_request_id,
        calc_version: req.calc_version,
        profile_name: state.profile.name.to_string(),
        profile_version: state.profile.version.to_string(),
        auth_key_id: key_used_id,
        final_decision,
        trace,
        audit_hash,
    };
    (StatusCode::OK, Json(response)).into_response()
}

fn validate_security_headers(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(String, u64, String), AuthError> {
    let signature = extract_header(headers, HEADER_SIGNATURE)
        .ok_or(AuthError::Unauthorized("missing X-Signature header"))?;
    let request_id = extract_header(headers, HEADER_REQUEST_ID)
        .ok_or(AuthError::Unauthorized("missing X-Request-Id header"))?
        .to_string();
    let timestamp_ms = extract_header(headers, HEADER_TIMESTAMP)
        .ok_or(AuthError::Unauthorized("missing X-Timestamp header"))?
        .parse::<u64>()
        .map_err(|_| AuthError::Unauthorized("invalid X-Timestamp header"))?;
    let key_id = extract_header(headers, HEADER_KEY_ID)
        .ok_or(AuthError::Unauthorized("missing X-Key-Id header"))?;

    let now = now_utc_ms();
    if now.abs_diff(timestamp_ms) > AUTH_WINDOW_MS {
        return Err(AuthError::RequestTimeout(
            "timestamp outside 60s security window",
        ));
    }

    maybe_purge_replay_cache(state, now);
    if state.replay_cache.contains_key(&request_id) {
        return Err(AuthError::Conflict(
            "replay detected: X-Request-Id already used",
        ));
    }

    let signing_bytes = signing_message(key_id, &request_id, timestamp_ms, body);
    let expected_active = mac_hex(&state.auth.active.key, &signing_bytes);
    if timing_safe_eq(expected_active.as_bytes(), signature.as_bytes()) {
        state.replay_cache.insert(request_id.clone(), now);
        return Ok((request_id, timestamp_ms, state.auth.active.id.clone()));
    }

    if let Some(previous) = &state.auth.previous {
        let expected_previous = mac_hex(&previous.key, &signing_bytes);
        if timing_safe_eq(expected_previous.as_bytes(), signature.as_bytes()) {
            state.replay_cache.insert(request_id.clone(), now);
            return Ok((request_id, timestamp_ms, previous.id.clone()));
        }
    }

    Err(AuthError::Unauthorized("invalid request signature"))
}

fn maybe_purge_replay_cache(state: &AppState, now_ms: u64) {
    let last = state.last_replay_cleanup_ms.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < REPLAY_TTL_MS / 2 {
        return;
    }
    state
        .last_replay_cleanup_ms
        .store(now_ms, Ordering::Relaxed);
    state
        .replay_cache
        .retain(|_, seen_ms| now_ms.saturating_sub(*seen_ms) <= REPLAY_TTL_MS);
}

fn auth_error_response(request_id: String, err: AuthError) -> axum::response::Response {
    let (status, message) = match err {
        AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
        AuthError::RequestTimeout(msg) => (StatusCode::REQUEST_TIMEOUT, msg),
        AuthError::Conflict(msg) => (StatusCode::CONFLICT, msg),
    };
    (
        status,
        Json(ErrorResponse {
            request_id,
            error: message.to_string(),
        }),
    )
        .into_response()
}

fn extract_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

pub fn compute_signature(
    secret: &str,
    key_id: &str,
    request_id: &str,
    timestamp_ms: u64,
    body: &[u8],
) -> String {
    let key = derive_hmac_key(secret);
    let msg = signing_message(key_id, request_id, timestamp_ms, body);
    mac_hex(&key, &msg)
}

pub fn benchmark_security_check(
    state: &AppState,
    body: &[u8],
    request_id: &str,
    timestamp_ms: u64,
) -> bool {
    let signature = compute_signature(
        BENCH_HMAC_SECRET,
        BENCH_KEY_ID,
        request_id,
        timestamp_ms,
        body,
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        HEADER_SIGNATURE,
        signature.parse().expect("signature header"),
    );
    headers.insert(
        HEADER_REQUEST_ID,
        request_id.parse().expect("request id header"),
    );
    headers.insert(
        HEADER_TIMESTAMP,
        timestamp_ms.to_string().parse().expect("timestamp header"),
    );
    headers.insert(HEADER_KEY_ID, BENCH_KEY_ID.parse().expect("key id header"));
    validate_security_headers(state, &headers, body).is_ok()
}

fn derive_hmac_key(secret: &str) -> [u8; 32] {
    *blake3::hash(secret.as_bytes()).as_bytes()
}

fn signing_message(key_id: &str, request_id: &str, timestamp_ms: u64, body: &[u8]) -> Vec<u8> {
    fn push_part(buf: &mut Vec<u8>, part: &[u8]) {
        buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
        buf.extend_from_slice(part);
    }
    let mut out = Vec::with_capacity(body.len() + 96);
    push_part(&mut out, key_id.as_bytes());
    push_part(&mut out, request_id.as_bytes());
    push_part(&mut out, timestamp_ms.to_string().as_bytes());
    push_part(&mut out, body);
    out
}

fn mac_hex(key: &[u8; 32], msg: &[u8]) -> String {
    let mut data = Vec::with_capacity(key.len() + msg.len());
    data.extend_from_slice(key);
    data.extend_from_slice(msg);
    blake3::hash(&data).to_hex().to_string()
}

fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
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

pub fn now_utc_ms() -> u64 {
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

    fn signed_request(
        payload: serde_json::Value,
        secret: &str,
        key_id: &str,
        request_id: &str,
        timestamp_ms: u64,
    ) -> Request<Body> {
        let body = payload.to_string();
        let signature =
            compute_signature(secret, key_id, request_id, timestamp_ms, body.as_bytes());
        Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .header("x-signature", signature)
            .header("x-request-id", request_id)
            .header("x-timestamp", timestamp_ms.to_string())
            .header("x-key-id", key_id)
            .body(Body::from(body))
            .expect("request")
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
        let req = signed_request(
            req_body,
            "test_active_secret",
            "active",
            "req-contract-1",
            now,
        );

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
        assert_eq!(json["auth_key_id"], "active");
        assert!(json["profile_name"].is_string());
        assert!(json["profile_version"].is_string());
        assert_eq!(json["final_decision"], "Approved");
        assert!(json["trace"].is_array());
        assert!(json["audit_hash"].is_string());
    }

    #[tokio::test]
    async fn request_without_signature_returns_401() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id": "user_a",
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
            .header("x-request-id", "req-no-sig")
            .header("x-timestamp", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(req_body.to_string()))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn request_with_wrong_signature_returns_401() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id": "user_b",
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
            .header("x-signature", "deadbeef")
            .header("x-request-id", "req-wrong-sig")
            .header("x-timestamp", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(req_body.to_string()))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn request_with_expired_timestamp_returns_408() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let expired = now.saturating_sub(180_000);
        let req_body = serde_json::json!({
            "user_id": "user_c",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true
        });
        let req = signed_request(
            req_body,
            "test_active_secret",
            "active",
            "req-expired",
            expired,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn request_id_reused_returns_409() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_id = "req-replay";
        let req_body = serde_json::json!({
            "user_id": "user_d",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true
        });
        let first = signed_request(
            req_body.clone(),
            "test_active_secret",
            "active",
            req_id,
            now,
        );
        let second = signed_request(req_body, "test_active_secret", "active", req_id, now);

        let resp1 = app.clone().oneshot(first).await.expect("response1");
        assert_eq!(resp1.status(), StatusCode::OK);

        let resp2 = app.oneshot(second).await.expect("response2");
        assert_eq!(resp2.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn previous_key_valid_returns_200() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id": "user_prev",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true
        });
        let req = signed_request(
            req_body,
            "test_previous_secret",
            "previous",
            "req-prev-1",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["auth_key_id"], "previous");
    }
}
