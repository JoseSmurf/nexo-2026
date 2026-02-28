use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
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
const DEFAULT_AUTH_WINDOW_MS: u64 = 60_000;
const DEFAULT_REPLAY_TTL_MS: u64 = 120_000;
const DEFAULT_REPLAY_MAX_KEYS: usize = 100_000;
const DEFAULT_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
const DEFAULT_RATE_LIMIT_IP: u32 = 600;
const DEFAULT_RATE_LIMIT_USER: u32 = 300;
const MAX_REQUEST_BODY_BYTES: usize = 1_048_576;
const MAX_REQUEST_ID_LEN: usize = 64;
const MAX_KEY_ID_LEN: usize = 64;
const MAX_USER_ID_LEN: usize = 128;

const HEADER_SIGNATURE: &str = "x-signature";
const HEADER_REQUEST_ID: &str = "x-request-id";
const HEADER_TIMESTAMP: &str = "x-timestamp";
const HEADER_KEY_ID: &str = "x-key-id";
const HEADER_RESPONSE_SIGNATURE: &str = "x-response-signature";
const HEADER_RESPONSE_KEY_ID: &str = "x-response-key-id";
const HEADER_FORWARDED_FOR: &str = "x-forwarded-for";
const HEADER_REAL_IP: &str = "x-real-ip";
const HEADER_CONTENT_TYPE: &str = "content-type";
const HEADER_CACHE_CONTROL: &str = "cache-control";
const HEADER_X_CONTENT_TYPE_OPTIONS: &str = "x-content-type-options";

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
    pub replay_ttl_ms: u64,
    pub replay_max_keys: usize,
    pub auth_window_ms: u64,
    pub rate_limiter: Arc<RateLimiter>,
    pub key_usage: Arc<DashMap<String, u64>>,
}

#[derive(Clone)]
pub struct AuthSecrets {
    pub active: AuthKey,
    pub previous: Option<AuthKey>,
}

#[derive(Clone)]
pub struct AuthKey {
    pub id: String,
    secret: Vec<u8>,
}

#[derive(Clone)]
pub struct RateLimiter {
    ip_windows: Arc<DashMap<String, WindowCounter>>,
    user_windows: Arc<DashMap<String, WindowCounter>>,
    window_ms: u64,
    limit_per_ip: u32,
    limit_per_user: u32,
    hits: Arc<AtomicU64>,
}

#[derive(Clone, Copy)]
struct WindowCounter {
    window_start_ms: u64,
    count: u32,
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
    pub hash_algo: String,
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

#[derive(Debug, Serialize)]
pub struct SecurityStatusResponse {
    pub auth_window_ms: u64,
    pub replay_ttl_ms: u64,
    pub replay_cache_size: usize,
    pub replay_max_keys: usize,
    pub key_active_id: String,
    pub key_previous_id: Option<String>,
    pub key_usage_total: HashMap<String, u64>,
    pub rate_limit_window_ms: u64,
    pub rate_limit_ip: u32,
    pub rate_limit_user: u32,
    pub rate_limit_hits: u64,
    pub unauthorized_total: u64,
    pub request_timeout_total: u64,
    pub conflict_total: u64,
    pub too_many_requests_total: u64,
    pub p95_latency_ns: f64,
    pub p99_latency_ns: f64,
    pub rotation_mode: String,
}

#[derive(Debug)]
enum AuthError {
    Unauthorized(&'static str),
    RequestTimeout(&'static str),
    Conflict(&'static str),
}

impl AppState {
    pub fn from_env() -> Self {
        let path =
            std::env::var("NEXO_AUDIT_PATH").unwrap_or_else(|_| DEFAULT_AUDIT_PATH.to_string());
        let retention = std::env::var("NEXO_AUDIT_RETENTION")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_RETENTION);
        let active_secret = load_required_secret("NEXO_HMAC_SECRET");
        let active_id = load_key_id("NEXO_HMAC_KEY_ID", BENCH_KEY_ID);
        assert!(
            !active_id.trim().is_empty(),
            "NEXO_HMAC_KEY_ID must not be empty."
        );
        let previous_secret = load_optional_secret("NEXO_HMAC_SECRET_PREV");
        let previous_id = load_key_id("NEXO_HMAC_KEY_ID_PREV", "previous");
        if previous_secret.is_some() {
            assert!(
                !previous_id.trim().is_empty(),
                "NEXO_HMAC_KEY_ID_PREV must not be empty when NEXO_HMAC_SECRET_PREV is set."
            );
            assert!(
                previous_id != active_id,
                "NEXO_HMAC_KEY_ID_PREV must be different from NEXO_HMAC_KEY_ID."
            );
        }
        let auth_window_ms = std::env::var("NEXO_AUTH_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_AUTH_WINDOW_MS);
        let replay_ttl_ms = std::env::var("NEXO_REPLAY_TTL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_REPLAY_TTL_MS);
        let replay_max_keys = std::env::var("NEXO_REPLAY_MAX_KEYS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_REPLAY_MAX_KEYS);
        let rate_limit_window_ms = std::env::var("NEXO_RATE_LIMIT_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_WINDOW_MS);
        let rate_limit_ip = std::env::var("NEXO_RATE_LIMIT_IP")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_IP);
        let rate_limit_user = std::env::var("NEXO_RATE_LIMIT_USER")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_USER);

        Self {
            profile: profile_from_env(),
            audit_store: AuditStore::new(path, retention),
            metrics: Metrics::new_shared(),
            audit_enabled: true,
            auth: AuthSecrets {
                active: AuthKey::new(active_id, active_secret),
                previous: previous_secret.map(|s| AuthKey::new(previous_id, s)),
            },
            replay_cache: Arc::new(DashMap::new()),
            last_replay_cleanup_ms: Arc::new(AtomicU64::new(0)),
            replay_ttl_ms,
            replay_max_keys,
            auth_window_ms,
            rate_limiter: Arc::new(RateLimiter::new(
                rate_limit_window_ms,
                rate_limit_ip,
                rate_limit_user,
            )),
            key_usage: Arc::new(DashMap::new()),
        }
    }

    pub fn for_tests(path: PathBuf) -> Self {
        Self {
            profile: profile_from_env(),
            audit_store: AuditStore::new(path, 500),
            metrics: Metrics::new_shared(),
            audit_enabled: true,
            auth: AuthSecrets {
                active: AuthKey::new("active".to_string(), "test_active_secret".to_string()),
                previous: Some(AuthKey::new(
                    "previous".to_string(),
                    "test_previous_secret".to_string(),
                )),
            },
            replay_cache: Arc::new(DashMap::new()),
            last_replay_cleanup_ms: Arc::new(AtomicU64::new(0)),
            replay_ttl_ms: DEFAULT_REPLAY_TTL_MS,
            replay_max_keys: DEFAULT_REPLAY_MAX_KEYS,
            auth_window_ms: DEFAULT_AUTH_WINDOW_MS,
            rate_limiter: Arc::new(RateLimiter::new(
                DEFAULT_RATE_LIMIT_WINDOW_MS,
                10_000,
                10_000,
            )),
            key_usage: Arc::new(DashMap::new()),
        }
    }

    pub fn for_bench() -> Self {
        Self {
            profile: profile_from_env(),
            audit_store: AuditStore::new(std::env::temp_dir().join("nexo_bench_unused.jsonl"), 1),
            metrics: Metrics::new_shared(),
            audit_enabled: false,
            auth: AuthSecrets {
                active: AuthKey::new(BENCH_KEY_ID.to_string(), BENCH_HMAC_SECRET.to_string()),
                previous: None,
            },
            replay_cache: Arc::new(DashMap::new()),
            last_replay_cleanup_ms: Arc::new(AtomicU64::new(0)),
            replay_ttl_ms: DEFAULT_REPLAY_TTL_MS,
            replay_max_keys: DEFAULT_REPLAY_MAX_KEYS,
            auth_window_ms: DEFAULT_AUTH_WINDOW_MS,
            rate_limiter: Arc::new(RateLimiter::new(
                DEFAULT_RATE_LIMIT_WINDOW_MS,
                u32::MAX,
                u32::MAX,
            )),
            key_usage: Arc::new(DashMap::new()),
        }
    }
}

fn load_key_id(env_key: &str, default: &str) -> String {
    let file_key = format!("{env_key}_FILE");
    if let Ok(path) = std::env::var(&file_key) {
        let value = read_secret_file(&path, &file_key);
        assert!(
            is_valid_key_id(&value),
            "{env_key} loaded from {file_key} is invalid."
        );
        return value;
    }
    std::env::var(env_key).unwrap_or_else(|_| default.to_string())
}

fn load_required_secret(env_key: &str) -> String {
    load_optional_secret(env_key).unwrap_or_else(|| {
        panic!("{env_key} or {env_key}_FILE is required. Refusing to start without HMAC secret.")
    })
}

fn load_optional_secret(env_key: &str) -> Option<String> {
    let file_key = format!("{env_key}_FILE");
    if let Ok(path) = std::env::var(&file_key) {
        let value = read_secret_file(&path, &file_key);
        assert!(
            !value.trim().is_empty(),
            "{env_key} loaded from {file_key} is empty."
        );
        return Some(value);
    }

    std::env::var(env_key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_secret_file(path: &str, file_key: &str) -> String {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {file_key} at '{path}': {err}"));
    content.trim_end_matches(['\r', '\n']).trim().to_string()
}

impl AuthKey {
    fn new(id: String, secret: String) -> Self {
        Self {
            id,
            secret: secret.into_bytes(),
        }
    }
}

impl RateLimiter {
    fn new(window_ms: u64, limit_per_ip: u32, limit_per_user: u32) -> Self {
        Self {
            ip_windows: Arc::new(DashMap::new()),
            user_windows: Arc::new(DashMap::new()),
            window_ms,
            limit_per_ip,
            limit_per_user,
            hits: Arc::new(AtomicU64::new(0)),
        }
    }

    fn allow(&self, ip_key: &str, user_key: &str, now_ms: u64) -> bool {
        let ip_ok = Self::allow_key(
            &self.ip_windows,
            ip_key,
            self.limit_per_ip,
            self.window_ms,
            now_ms,
        );
        let user_ok = Self::allow_key(
            &self.user_windows,
            user_key,
            self.limit_per_user,
            self.window_ms,
            now_ms,
        );
        let allowed = ip_ok && user_ok;
        if !allowed {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        allowed
    }

    fn allow_key(
        map: &DashMap<String, WindowCounter>,
        key: &str,
        limit: u32,
        window_ms: u64,
        now_ms: u64,
    ) -> bool {
        let mut entry = map.entry(key.to_string()).or_insert(WindowCounter {
            window_start_ms: now_ms,
            count: 0,
        });
        if now_ms.saturating_sub(entry.window_start_ms) >= window_ms {
            entry.window_start_ms = now_ms;
            entry.count = 0;
        }
        if entry.count >= limit {
            return false;
        }
        entry.count += 1;
        true
    }

    fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
}

pub fn app() -> Router {
    app_with_state(AppState::from_env())
}

pub fn app_with_state(state: AppState) -> Router {
    let evaluate_route = post(evaluate_handler).route_layer(middleware::from_fn_with_state(
        state.clone(),
        rate_limit_middleware,
    ));
    Router::new()
        .route("/evaluate", evaluate_route)
        .route("/healthz", get(health_handler))
        .route("/readyz", get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .route("/audit/recent", get(audit_recent_handler))
        .route("/security/status", get(security_status_handler))
        .with_state(state)
}

async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let body_bytes = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            let request_id = extract_header(&parts.headers, HEADER_REQUEST_ID)
                .map(ToString::to_string)
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            return error_response(
                StatusCode::BAD_REQUEST,
                &state,
                &request_id,
                "request body too large",
            );
        }
    };

    let now = now_utc_ms();
    let ip = extract_client_ip(&parts.headers);
    let user_id = extract_user_id_from_body(&body_bytes).unwrap_or_else(|| "unknown".to_string());

    if !is_json_content_type(&parts.headers) {
        let request_id = extract_header(&parts.headers, HEADER_REQUEST_ID)
            .map(ToString::to_string)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &state,
            &request_id,
            "content-type must be application/json",
        );
    }

    if !state.rate_limiter.allow(&ip, &user_id, now) {
        let request_id = extract_header(&parts.headers, HEADER_REQUEST_ID)
            .map(ToString::to_string)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            &state,
            &request_id,
            "rate limit exceeded",
        );
    }

    let request = Request::from_parts(parts, Body::from(body_bytes));
    next.run(request).await
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
                state
                    .metrics
                    .observe_error(start.elapsed().as_nanos() as u64);
                let request_id = extract_header(&headers, HEADER_REQUEST_ID)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                return auth_error_response(&state, request_id, err);
            }
        };

    let req: EvaluateRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(_) => {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            return error_response(
                StatusCode::BAD_REQUEST,
                &state,
                &header_request_id,
                "invalid JSON payload",
            );
        }
    };

    if req.user_id.trim().is_empty() {
        state
            .metrics
            .observe_error(start.elapsed().as_nanos() as u64);
        return error_response(
            StatusCode::BAD_REQUEST,
            &state,
            &header_request_id,
            "user_id must not be empty",
        );
    }
    if req.user_id.chars().count() > MAX_USER_ID_LEN {
        state
            .metrics
            .observe_error(start.elapsed().as_nanos() as u64);
        return error_response(
            StatusCode::BAD_REQUEST,
            &state,
            &header_request_id,
            "user_id too long",
        );
    }

    if let Some(body_request_id) = req.request_id.as_deref() {
        if !is_uuid_v4(body_request_id) {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            return error_response(
                StatusCode::BAD_REQUEST,
                &state,
                &header_request_id,
                "request_id in body must be UUID v4",
            );
        }
        if body_request_id != header_request_id {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            return error_response(
                StatusCode::BAD_REQUEST,
                &state,
                &header_request_id,
                "request_id in body must match X-Request-Id",
            );
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
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            warn!(request_id = %header_request_id, error = %err, "evaluate rejected request");
            return error_response(StatusCode::BAD_REQUEST, &state, &header_request_id, err);
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
        hash_algo: "blake3".to_string(),
    };

    if state.audit_enabled {
        if let Err(err) = state.audit_store.append(&record) {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            warn!(request_id = %header_request_id, error = %err, "failed to persist audit record");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &state,
                &header_request_id,
                "failed to persist audit record",
            );
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
        request_id: header_request_id.clone(),
        calc_version: req.calc_version,
        profile_name: state.profile.name.to_string(),
        profile_version: state.profile.version.to_string(),
        auth_key_id: key_used_id,
        final_decision,
        trace,
        audit_hash,
        hash_algo: "blake3".to_string(),
    };
    signed_json_response(StatusCode::OK, &state, &header_request_id, &response)
}

fn validate_security_headers(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(String, u64, String), AuthError> {
    let signature_hex = extract_header(headers, HEADER_SIGNATURE)
        .ok_or(AuthError::Unauthorized("missing X-Signature header"))?;
    let signature = decode_hex_32(signature_hex)
        .ok_or(AuthError::Unauthorized("invalid X-Signature format"))?;
    let request_id = extract_header(headers, HEADER_REQUEST_ID)
        .ok_or(AuthError::Unauthorized("missing X-Request-Id header"))?
        .to_string();
    if request_id.len() > MAX_REQUEST_ID_LEN || !is_uuid_v4(&request_id) {
        return Err(AuthError::Unauthorized(
            "invalid X-Request-Id header (expected UUID v4)",
        ));
    }
    let timestamp_ms = extract_header(headers, HEADER_TIMESTAMP)
        .ok_or(AuthError::Unauthorized("missing X-Timestamp header"))?
        .parse::<u64>()
        .map_err(|_| AuthError::Unauthorized("invalid X-Timestamp header"))?;
    if timestamp_ms == 0 {
        return Err(AuthError::Unauthorized("invalid X-Timestamp header"));
    }
    let key_id = extract_header(headers, HEADER_KEY_ID)
        .ok_or(AuthError::Unauthorized("missing X-Key-Id header"))?;
    if key_id.len() > MAX_KEY_ID_LEN || !is_valid_key_id(key_id) {
        return Err(AuthError::Unauthorized("invalid X-Key-Id header"));
    }

    let now = now_utc_ms();
    if now.abs_diff(timestamp_ms) > state.auth_window_ms {
        return Err(AuthError::RequestTimeout(
            "timestamp outside configured security window",
        ));
    }

    let allowed_key = if key_id == state.auth.active.id {
        Some(&state.auth.active)
    } else {
        state
            .auth
            .previous
            .as_ref()
            .filter(|prev| key_id == prev.id)
    };
    let key = allowed_key.ok_or(AuthError::Unauthorized("unknown or inactive X-Key-Id"))?;

    maybe_purge_replay_cache(state, now);
    enforce_replay_capacity(state);
    if state.replay_cache.contains_key(&request_id) {
        return Err(AuthError::Conflict(
            "replay detected: X-Request-Id already used",
        ));
    }

    let signing_bytes = signing_message(key_id, &request_id, timestamp_ms, body);
    let expected = hmac_blake3(&key.secret, &signing_bytes);
    if !timing_safe_eq_32(&signature, &expected) {
        return Err(AuthError::Unauthorized("invalid request signature"));
    }

    state.replay_cache.insert(request_id.clone(), now);
    state
        .key_usage
        .entry(key.id.clone())
        .and_modify(|v| *v += 1)
        .or_insert(1);
    Ok((request_id, timestamp_ms, key.id.clone()))
}

fn maybe_purge_replay_cache(state: &AppState, now_ms: u64) {
    let last = state.last_replay_cleanup_ms.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < state.replay_ttl_ms / 2 {
        return;
    }
    state
        .last_replay_cleanup_ms
        .store(now_ms, Ordering::Relaxed);
    state
        .replay_cache
        .retain(|_, seen_ms| now_ms.saturating_sub(*seen_ms) <= state.replay_ttl_ms);
}

fn enforce_replay_capacity(state: &AppState) {
    if state.replay_cache.len() <= state.replay_max_keys {
        return;
    }
    let mut entries: Vec<(String, u64)> = state
        .replay_cache
        .iter()
        .map(|e| (e.key().clone(), *e.value()))
        .collect();
    entries.sort_by_key(|(_, ts)| *ts);
    let to_remove = entries.len().saturating_sub(state.replay_max_keys);
    for (key, _) in entries.into_iter().take(to_remove) {
        state.replay_cache.remove(&key);
    }
}

fn auth_error_response(state: &AppState, request_id: String, err: AuthError) -> Response {
    let (status, message) = match err {
        AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
        AuthError::RequestTimeout(msg) => (StatusCode::REQUEST_TIMEOUT, msg),
        AuthError::Conflict(msg) => (StatusCode::CONFLICT, msg),
    };
    error_response(status, state, &request_id, message)
}

fn error_response(status: StatusCode, state: &AppState, request_id: &str, msg: &str) -> Response {
    state.metrics.observe_http_status(status.as_u16());
    let payload = ErrorResponse {
        request_id: request_id.to_string(),
        error: msg.to_string(),
    };
    signed_json_response(status, state, request_id, &payload)
}

fn signed_json_response<T: Serialize>(
    status: StatusCode,
    state: &AppState,
    request_id: &str,
    payload: &T,
) -> Response {
    let body =
        serde_json::to_vec(payload).unwrap_or_else(|_| b"{\"error\":\"serialization\"}".to_vec());
    let sig = bytes_to_hex(&hmac_blake3(
        &state.auth.active.secret,
        &response_signing_message(request_id, &body),
    ));
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        HeaderName::from_static(HEADER_CONTENT_TYPE),
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        HeaderName::from_static(HEADER_CACHE_CONTROL),
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        HeaderName::from_static(HEADER_X_CONTENT_TYPE_OPTIONS),
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(v) = HeaderValue::from_str(&sig) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(HEADER_RESPONSE_SIGNATURE), v);
    }
    if let Ok(v) = HeaderValue::from_str(&state.auth.active.id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(HEADER_RESPONSE_KEY_ID), v);
    }
    response
}

fn extract_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
}

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(v) = extract_header(headers, HEADER_FORWARDED_FOR) {
        if let Some(first) = v.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    if let Some(v) = extract_header(headers, HEADER_REAL_IP) {
        if !v.is_empty() {
            return v.to_string();
        }
    }
    "unknown".to_string()
}

fn extract_user_id_from_body(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("user_id")?.as_str().map(ToString::to_string)
}

fn is_uuid_v4(value: &str) -> bool {
    Uuid::parse_str(value)
        .map(|uuid| uuid.get_version_num() == 4)
        .unwrap_or(false)
}

fn is_valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let Some(raw) = extract_header(headers, HEADER_CONTENT_TYPE) else {
        return false;
    };
    let mime = raw
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    mime == "application/json"
}

pub fn compute_signature(
    secret: &str,
    key_id: &str,
    request_id: &str,
    timestamp_ms: u64,
    body: &[u8],
) -> String {
    let msg = signing_message(key_id, request_id, timestamp_ms, body);
    bytes_to_hex(&hmac_blake3(secret.as_bytes(), &msg))
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

fn response_signing_message(request_id: &str, body: &[u8]) -> Vec<u8> {
    fn push_part(buf: &mut Vec<u8>, part: &[u8]) {
        buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
        buf.extend_from_slice(part);
    }
    let mut out = Vec::with_capacity(body.len() + 48);
    push_part(&mut out, request_id.as_bytes());
    push_part(&mut out, body);
    out
}

fn hmac_blake3(secret: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if secret.len() > BLOCK {
        let digest = blake3::hash(secret);
        key_block[..32].copy_from_slice(digest.as_bytes());
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = blake3::hash(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(inner_hash.as_bytes());
    *blake3::hash(&outer).as_bytes()
}

fn timing_safe_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
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

async fn security_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut usage = HashMap::new();
    for entry in state.key_usage.iter() {
        usage.insert(entry.key().clone(), *entry.value());
    }
    let metrics = state.metrics.snapshot();
    let rotation_mode = if state.auth.previous.is_some() {
        "active_plus_previous"
    } else {
        "active_only"
    };
    (
        StatusCode::OK,
        Json(SecurityStatusResponse {
            auth_window_ms: state.auth_window_ms,
            replay_ttl_ms: state.replay_ttl_ms,
            replay_cache_size: state.replay_cache.len(),
            replay_max_keys: state.replay_max_keys,
            key_active_id: state.auth.active.id.clone(),
            key_previous_id: state.auth.previous.as_ref().map(|k| k.id.clone()),
            key_usage_total: usage,
            rate_limit_window_ms: state.rate_limiter.window_ms,
            rate_limit_ip: state.rate_limiter.limit_per_ip,
            rate_limit_user: state.rate_limiter.limit_per_user,
            rate_limit_hits: state.rate_limiter.hits(),
            unauthorized_total: metrics.unauthorized_total,
            request_timeout_total: metrics.request_timeout_total,
            conflict_total: metrics.conflict_total,
            too_many_requests_total: metrics.too_many_requests_total,
            p95_latency_ns: metrics.p95_latency_ns,
            p99_latency_ns: metrics.p99_latency_ns,
            rotation_mode: rotation_mode.to_string(),
        }),
    )
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
            "request_id": "564a7218-13e5-46c9-84f6-bf4c53ff533f",
            "calc_version": "plca_v1"
        });
        let req = signed_request(
            req_body,
            "test_active_secret",
            "active",
            "564a7218-13e5-46c9-84f6-bf4c53ff533f",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(HEADER_RESPONSE_SIGNATURE));
        assert!(resp.headers().contains_key(HEADER_RESPONSE_KEY_ID));
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["request_id"], "564a7218-13e5-46c9-84f6-bf4c53ff533f");
        assert_eq!(json["auth_key_id"], "active");
    }

    #[tokio::test]
    async fn request_without_signature_returns_401() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .header("x-request-id", "req-no-sig")
            .header("x-timestamp", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(
                serde_json::json!({
                    "user_id":"u",
                    "amount_cents":50_000,
                    "is_pep":false,
                    "has_active_kyc":true,
                    "timestamp_utc_ms":now,
                    "risk_bps":1000,
                    "ui_hash_valid":true
                })
                .to_string(),
            ))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn request_with_wrong_signature_returns_401() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .header("x-signature", "deadbeef")
            .header("x-request-id", "req-wrong")
            .header("x-timestamp", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(
                serde_json::json!({
                    "user_id":"u",
                    "amount_cents":50_000,
                    "is_pep":false,
                    "has_active_kyc":true,
                    "timestamp_utc_ms":now,
                    "risk_bps":1000,
                    "ui_hash_valid":true
                })
                .to_string(),
            ))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn request_with_expired_timestamp_returns_408() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"u",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(
            req_body,
            "test_active_secret",
            "active",
            "eff9d36f-f47e-484d-884e-172ceaf7056b",
            now.saturating_sub(180_000),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn request_id_reused_returns_409() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"u",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req1 = signed_request(
            req_body.clone(),
            "test_active_secret",
            "active",
            "2f68f4d8-c2f4-402f-bb72-76b24f3de390",
            now,
        );
        let req2 = signed_request(
            req_body,
            "test_active_secret",
            "active",
            "2f68f4d8-c2f4-402f-bb72-76b24f3de390",
            now,
        );
        assert_eq!(
            app.clone().oneshot(req1).await.expect("r1").status(),
            StatusCode::OK
        );
        assert_eq!(
            app.oneshot(req2).await.expect("r2").status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn previous_key_valid_returns_200() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"u_prev",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(
            req_body,
            "test_previous_secret",
            "previous",
            "695bcb2a-8c59-4894-a4ef-a6a41847f3cc",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn payload_adulterated_returns_401() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let body_original = serde_json::json!({
            "user_id":"u1",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let body_tampered = serde_json::json!({
            "user_id":"u1",
            "amount_cents":999_999,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let signature = compute_signature(
            "test_active_secret",
            "active",
            "5c316bd5-a0c2-4e6d-aed8-ed706734af08",
            now,
            body_original.to_string().as_bytes(),
        );
        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .header("x-signature", signature)
            .header("x-request-id", "5c316bd5-a0c2-4e6d-aed8-ed706734af08")
            .header("x-timestamp", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(body_tampered.to_string()))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn strict_key_id_rejects_unknown_key() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"u",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(
            req_body,
            "test_active_secret",
            "unknown",
            "1816f9cf-62f5-4c3f-b205-cdba315c52d4",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_header_request_id_returns_401() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"u",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(req_body, "test_active_secret", "active", "not-a-uuid", now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_header_key_id_returns_401() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"u",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(
            req_body,
            "test_active_secret",
            "active;DROP",
            "7f6565ca-a7d1-4512-b118-cf7a410ca4f3",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_json_content_type_returns_415() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"u_non_json",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let body = req_body.to_string();
        let request_id = "d37e2ed0-08de-4f32-a174-e6f721ce8ace";
        let signature = compute_signature(
            "test_active_secret",
            "active",
            request_id,
            now,
            body.as_bytes(),
        );
        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "text/plain")
            .header("x-signature", signature)
            .header("x-request-id", request_id)
            .header("x-timestamp", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(body))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn body_request_id_must_be_uuid_v4() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"u_body_req_id",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true,
            "request_id":"abc123"
        });
        let req = signed_request(
            req_body,
            "test_active_secret",
            "active",
            "42980a6c-9b20-4f39-93a9-7ed0ace98e93",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
