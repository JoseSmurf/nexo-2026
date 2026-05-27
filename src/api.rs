use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{error::Error, fmt};

use aws_config::BehaviorVersion;
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use dashmap::DashMap;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use self::admin::{audit_recent_handler, metrics_handler, security_status_handler};
#[cfg(test)]
use self::audit::select_audit_hash_algo;
use self::auth::validate_security_headers;
use self::errors::{AuthError, ChatSendError};
use self::evaluate::{evaluate_handler, rate_limit_middleware};
use self::replay::validate_persistent_replay_requirement;
use self::state::{build_state_response, StateChatMessage};
use crate::audit_store::{AuditRecord, AuditStore};
#[cfg(feature = "network")]
use crate::message::CanonicalMessage;
#[cfg(feature = "network")]
use crate::offline_store::OfflineStore;
use crate::profile::{profile_from_env, RuleProfile};
use crate::telemetry::Metrics;
#[cfg(test)]
use crate::{audit_hash_with_algo, evaluate_with_config, AuditHashAlgo, TransactionIntent};
use crate::{Decision, FinalDecision};

mod admin;
mod audit;
mod auth;
mod errors;
mod evaluate;
mod rate_limit;
mod replay;
mod state;

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
const DEFAULT_SECRET_PROVIDER: &str = "none";
const DEFAULT_VAULT_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_AZURE_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_AZURE_API_VERSION: &str = "7.4";
const DEFAULT_GCP_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_AWS_RUNTIME_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_SHA3_SHADOW_ENABLED: bool = false;
const DEFAULT_ADMIN_API_ENABLED: bool = false;
const DEFAULT_REDIS_OP_TIMEOUT_MS: u64 = 100;
const DEFAULT_HIGH_THRESHOLD_CENTS: u64 = 5_000_000;
const DEFAULT_SHAKE_BITS: u16 = 512;
const DEFAULT_STATE_CHAT_LIMIT: usize = 5;
const ADAPTIVE_RISK_BPS_THRESHOLD: u16 = 8_000;
const MAX_CHAT_MESSAGE_BYTES: usize = 32;
const MAX_CHAT_REQUEST_BODY_BYTES: usize = 4 * 1024;

const HEADER_SIGNATURE: &str = "x-signature";
const HEADER_REQUEST_ID: &str = "x-request-id";
const HEADER_TIMESTAMP: &str = "x-timestamp";
const HEADER_NONCE: &str = "x-nonce";
const HEADER_KEY_ID: &str = "x-key-id";
const HEADER_RESPONSE_SIGNATURE: &str = "x-response-signature";
const HEADER_RESPONSE_KEY_ID: &str = "x-response-key-id";
const HEADER_FORWARDED_FOR: &str = "x-forwarded-for";
const HEADER_REAL_IP: &str = "x-real-ip";
const HEADER_CONTENT_TYPE: &str = "content-type";
const HEADER_CACHE_CONTROL: &str = "cache-control";
const HEADER_X_CONTENT_TYPE_OPTIONS: &str = "x-content-type-options";
const HEADER_CLIENT_CERT_VERIFIED: &str = "x-client-cert-verified";
const HEADER_CLIENT_ID: &str = "x-client-id";
const HEADER_CLIENT_SIGNATURE: &str = "x-client-signature";
const HEADER_EDGE_AUTH: &str = "x-edge-auth";
const HEADER_AUTHORIZATION: &str = "authorization";
const HEADER_NEXO_REASON: &str = "x-nexo-reason";
const API_STATE_EXPOSURE_DISABLED_REASON: &str =
    "API state exposure is disabled in this configuration";

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
    // Proxy identity headers are spoofable unless the deployment strictly enforces a trusted proxy boundary.
    // Default is fail-safe: do not trust X-Forwarded-For / X-Real-IP unless explicitly enabled.
    pub trust_proxy_headers: bool,
    pub key_usage: Arc<DashMap<String, u64>>,
    pub mtls: Option<MtlsConfig>,
    pub client_sig: Option<ClientSignatureConfig>,
    pub edge_guard: Option<EdgeGuardConfig>,
    pub redis_guard: Option<RedisGuardConfig>,
    pub redis_op_timeout_ms: u64,
    pub security_level: SecurityLevel,
    pub high_threshold_cents: u64,
    pub shake_bits: u16,
    pub sha3_shadow_enabled: bool,
    pub admin_api_enabled: bool,
    pub admin_api_token: Option<String>,
    pub expose_api_state: bool,
    pub p2p_db_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Normal,
    Elevated,
    Incident,
}

impl SecurityLevel {
    fn from_env() -> Self {
        let value = std::env::var("NEXO_SECURITY_LEVEL")
            .unwrap_or_else(|_| "NORMAL".to_string())
            .trim()
            .to_ascii_uppercase();
        match value.as_str() {
            "NORMAL" => SecurityLevel::Normal,
            "ELEVATED" => SecurityLevel::Elevated,
            "INCIDENT" => SecurityLevel::Incident,
            _ => panic!("NEXO_SECURITY_LEVEL must be NORMAL, ELEVATED or INCIDENT"),
        }
    }
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

#[derive(Clone)]
pub struct EdgeGuardConfig {
    pub header: String,
    secret: String,
}

#[derive(Clone)]
pub struct RedisGuardConfig {
    pub client: redis::Client,
    pub key_prefix: String,
}

#[derive(Clone)]
pub struct MtlsConfig {
    pub verified_header: String,
    pub verified_value: String,
    pub client_id_header: String,
    pub allowed_client_ids: Option<HashSet<String>>,
}

#[derive(Clone)]
pub struct ClientSignatureConfig {
    pub client_id_header: String,
    pub signature_header: String,
    pub public_keys: HashMap<String, VerifyingKey>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha3_shadow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadow_hash_algo: Option<String>,
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
    pub mtls_mode: String,
    pub client_signature_mode: String,
    pub edge_guard_mode: String,
    pub distributed_guard_mode: String,
}

#[derive(Debug, Deserialize)]
pub struct ChatSendRequest {
    pub origin: Option<String>,
    pub channel: Option<String>,
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct ChatSendResponse {
    pub status: String,
    pub message: StateChatMessage,
    pub send_mode: String,
}

#[derive(Debug, Clone, Copy)]
struct ChatSendCapability {
    available: bool,
    mode: &'static str,
    reason: &'static str,
    error_message: &'static str,
}

#[derive(Debug, Clone, Default)]
struct SecretBundle {
    active_secret: Option<String>,
    previous_secret: Option<String>,
    active_key_id: Option<String>,
    previous_key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfigError {
    pub code: &'static str,
    pub message: String,
    pub checklist: [&'static str; 3],
}

impl ApiConfigError {
    fn unsupported_secret_provider(provider: &str) -> Self {
        Self {
            code: "NEXO_SECRET_PROVIDER_UNSUPPORTED",
            message: format!("unsupported NEXO_SECRET_PROVIDER '{provider}'"),
            checklist: [
                "Set NEXO_SECRET_PROVIDER to one of: none, vault, azure, gcp, aws.",
                "Remove typos from NEXO_SECRET_PROVIDER.",
                "Unset NEXO_SECRET_PROVIDER to use the default (none).",
            ],
        }
    }
}

impl fmt::Display for ApiConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} | checklist=[1] {} [2] {} [3] {}",
            self.code, self.message, self.checklist[0], self.checklist[1], self.checklist[2]
        )
    }
}

impl Error for ApiConfigError {}

impl AppState {
    pub fn from_env() -> Self {
        let path =
            std::env::var("NEXO_AUDIT_PATH").unwrap_or_else(|_| DEFAULT_AUDIT_PATH.to_string());
        let retention = std::env::var("NEXO_AUDIT_RETENTION")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_RETENTION);
        let bundle = load_secret_bundle_from_env().unwrap_or_else(|err| panic!("{err}"));
        let active_secret = load_required_secret(
            "NEXO_HMAC_SECRET",
            bundle.as_ref().and_then(|b| b.active_secret.as_deref()),
        );
        let active_id = load_key_id(
            "NEXO_HMAC_KEY_ID",
            BENCH_KEY_ID,
            bundle.as_ref().and_then(|b| b.active_key_id.as_deref()),
        );
        assert!(
            !active_id.trim().is_empty(),
            "NEXO_HMAC_KEY_ID must not be empty."
        );
        let previous_secret = load_optional_secret(
            "NEXO_HMAC_SECRET_PREV",
            bundle.as_ref().and_then(|b| b.previous_secret.as_deref()),
        );
        let previous_id = load_key_id(
            "NEXO_HMAC_KEY_ID_PREV",
            "previous",
            bundle.as_ref().and_then(|b| b.previous_key_id.as_deref()),
        );
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
        let auth_window_ms = std::env::var("NEXO_TIMESTAMP_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .or_else(|| {
                std::env::var("NEXO_AUTH_WINDOW_MS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .unwrap_or(DEFAULT_AUTH_WINDOW_MS);
        let replay_ttl_ms = std::env::var("NEXO_REPLAY_TTL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_REPLAY_TTL_MS);
        let replay_max_keys = std::env::var("NEXO_REPLAY_MAX_KEYS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_REPLAY_MAX_KEYS);
        let require_audit_preflight = env_bool("NEXO_REQUIRE_AUDIT_PREFLIGHT", false);
        let require_persistent_replay = env_bool("NEXO_REQUIRE_PERSISTENT_REPLAY", false);
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
        let trust_proxy_headers = env_bool("NEXO_TRUST_PROXY_HEADERS", false);
        let mtls = load_mtls_config_from_env();
        let client_sig = load_client_signature_config_from_env();
        let edge_guard = load_edge_guard_config_from_env();
        let redis_guard = load_redis_guard_from_env();
        validate_persistent_replay_requirement(require_persistent_replay, redis_guard.is_some())
            .unwrap_or_else(|msg| panic!("{msg}"));
        let redis_op_timeout_ms = std::env::var("NEXO_REDIS_OP_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_REDIS_OP_TIMEOUT_MS);
        let security_level = SecurityLevel::from_env();
        let high_threshold_cents = std::env::var("NEXO_AUDIT_HIGH_THRESHOLD_CENTS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_HIGH_THRESHOLD_CENTS);
        let shake_bits = load_shake_bits(DEFAULT_SHAKE_BITS);
        let sha3_shadow_enabled = env_bool("NEXO_SHA3_SHADOW_ENABLED", DEFAULT_SHA3_SHADOW_ENABLED);
        let admin_api_enabled = env_bool("NEXO_ADMIN_API_ENABLED", DEFAULT_ADMIN_API_ENABLED);
        let admin_api_token = if admin_api_enabled {
            let token = std::env::var("NEXO_ADMIN_API_TOKEN")
                .expect("NEXO_ADMIN_API_TOKEN is required when NEXO_ADMIN_API_ENABLED=true")
                .trim()
                .to_string();
            assert!(
                !token.is_empty(),
                "NEXO_ADMIN_API_TOKEN must not be empty when NEXO_ADMIN_API_ENABLED=true"
            );
            Some(token)
        } else {
            None
        };
        let expose_api_state = env_bool("NEXO_EXPOSE_API_STATE", false);
        let p2p_db_path = std::env::var("NEXO_P2P_DB_PATH")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let audit_store = AuditStore::new(path.clone(), retention);
        apply_audit_preflight_requirement(&audit_store, require_audit_preflight).unwrap_or_else(
            |err| {
                panic!(
                    "NEXO_REQUIRE_AUDIT_PREFLIGHT preflight failed for {}: {err}",
                    path
                )
            },
        );

        Self {
            profile: profile_from_env().unwrap_or_else(|err| panic!("{err}")),
            audit_store,
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
            trust_proxy_headers,
            key_usage: Arc::new(DashMap::new()),
            mtls,
            client_sig,
            edge_guard,
            redis_guard,
            redis_op_timeout_ms,
            security_level,
            high_threshold_cents,
            shake_bits,
            sha3_shadow_enabled,
            admin_api_enabled,
            admin_api_token,
            expose_api_state,
            p2p_db_path,
        }
    }

    pub fn for_tests(path: PathBuf) -> Self {
        Self {
            profile: profile_from_env().unwrap_or_else(|err| panic!("{err}")),
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
            trust_proxy_headers: false,
            key_usage: Arc::new(DashMap::new()),
            mtls: None,
            client_sig: None,
            edge_guard: None,
            redis_guard: None,
            redis_op_timeout_ms: DEFAULT_REDIS_OP_TIMEOUT_MS,
            security_level: SecurityLevel::Normal,
            high_threshold_cents: DEFAULT_HIGH_THRESHOLD_CENTS,
            shake_bits: DEFAULT_SHAKE_BITS,
            sha3_shadow_enabled: false,
            admin_api_enabled: false,
            admin_api_token: None,
            expose_api_state: false,
            p2p_db_path: None,
        }
    }

    pub fn for_bench() -> Self {
        Self {
            profile: profile_from_env().unwrap_or_else(|err| panic!("{err}")),
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
            trust_proxy_headers: false,
            key_usage: Arc::new(DashMap::new()),
            mtls: None,
            client_sig: None,
            edge_guard: None,
            redis_guard: None,
            redis_op_timeout_ms: DEFAULT_REDIS_OP_TIMEOUT_MS,
            security_level: SecurityLevel::Normal,
            high_threshold_cents: DEFAULT_HIGH_THRESHOLD_CENTS,
            shake_bits: DEFAULT_SHAKE_BITS,
            sha3_shadow_enabled: false,
            admin_api_enabled: false,
            admin_api_token: None,
            expose_api_state: false,
            p2p_db_path: None,
        }
    }
}

fn load_shake_bits(default_bits: u16) -> u16 {
    let raw = std::env::var("NEXO_AUDIT_SHAKE_BITS").unwrap_or_else(|_| default_bits.to_string());
    let parsed = raw
        .trim()
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("NEXO_AUDIT_SHAKE_BITS must be one of: 256, 384, 512"));
    assert!(
        matches!(parsed, 256 | 384 | 512),
        "NEXO_AUDIT_SHAKE_BITS must be one of: 256, 384, 512"
    );
    parsed
}

fn load_secret_bundle_from_env() -> Result<Option<SecretBundle>, ApiConfigError> {
    let provider = std::env::var("NEXO_SECRET_PROVIDER")
        .unwrap_or_else(|_| DEFAULT_SECRET_PROVIDER.to_string())
        .to_ascii_lowercase();

    match provider.as_str() {
        "" | "none" => Ok(None),
        "vault" => Ok(Some(load_vault_bundle_from_env())),
        "azure" => Ok(Some(load_azure_bundle_from_env())),
        "gcp" => Ok(Some(load_gcp_bundle_from_env())),
        "aws" => Ok(Some(load_aws_bundle_from_env())),
        other => Err(ApiConfigError::unsupported_secret_provider(other)),
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| {
            let value = v.trim().to_ascii_lowercase();
            value == "1" || value == "true" || value == "yes"
        })
        .unwrap_or(default)
}

fn apply_audit_preflight_requirement(
    audit_store: &AuditStore,
    require_audit_preflight: bool,
) -> io::Result<()> {
    if !require_audit_preflight {
        return Ok(());
    }
    audit_store.verify_existing_artifact_preflight()
}

fn load_mtls_config_from_env() -> Option<MtlsConfig> {
    if !env_bool("NEXO_MTLS_REQUIRED", false) {
        return None;
    }
    let verified_header = std::env::var("NEXO_MTLS_VERIFIED_HEADER")
        .unwrap_or_else(|_| HEADER_CLIENT_CERT_VERIFIED.to_string())
        .to_ascii_lowercase();
    let verified_value = std::env::var("NEXO_MTLS_VERIFIED_VALUE")
        .unwrap_or_else(|_| "true".to_string())
        .trim()
        .to_ascii_lowercase();
    let client_id_header = std::env::var("NEXO_MTLS_CLIENT_ID_HEADER")
        .unwrap_or_else(|_| HEADER_CLIENT_ID.to_string())
        .to_ascii_lowercase();
    let allowed_client_ids = std::env::var("NEXO_MTLS_ALLOWED_CLIENT_IDS")
        .ok()
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect::<HashSet<String>>()
        })
        .filter(|set| !set.is_empty());
    Some(MtlsConfig {
        verified_header,
        verified_value,
        client_id_header,
        allowed_client_ids,
    })
}

fn load_client_signature_config_from_env() -> Option<ClientSignatureConfig> {
    if !env_bool("NEXO_CLIENT_SIG_REQUIRED", false) {
        return None;
    }
    let pubkeys_json = std::env::var("NEXO_CLIENT_PUBKEYS_JSON")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("NEXO_CLIENT_PUBKEYS_FILE")
                .ok()
                .map(|path| read_secret_file(&path, "NEXO_CLIENT_PUBKEYS_FILE"))
        })
        .unwrap_or_else(|| {
            panic!(
                "NEXO_CLIENT_PUBKEYS_JSON or NEXO_CLIENT_PUBKEYS_FILE is required when NEXO_CLIENT_SIG_REQUIRED=true"
            )
        });
    let map: HashMap<String, String> =
        serde_json::from_str(&pubkeys_json).expect("NEXO_CLIENT_PUBKEYS JSON must be an object");
    let mut public_keys = HashMap::new();
    for (client_id, key_b64) in map {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64.trim())
            .unwrap_or_else(|_| panic!("invalid base64 public key for client '{client_id}'"));
        let key_bytes: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("public key for client '{client_id}' must be 32 bytes"));
        let key = VerifyingKey::from_bytes(&key_bytes)
            .unwrap_or_else(|_| panic!("invalid Ed25519 key bytes for client '{client_id}'"));
        public_keys.insert(client_id, key);
    }
    assert!(
        !public_keys.is_empty(),
        "NEXO_CLIENT_PUBKEYS must contain at least one client key."
    );
    Some(ClientSignatureConfig {
        client_id_header: std::env::var("NEXO_CLIENT_ID_HEADER")
            .unwrap_or_else(|_| HEADER_CLIENT_ID.to_string())
            .to_ascii_lowercase(),
        signature_header: std::env::var("NEXO_CLIENT_SIGNATURE_HEADER")
            .unwrap_or_else(|_| HEADER_CLIENT_SIGNATURE.to_string())
            .to_ascii_lowercase(),
        public_keys,
    })
}

fn load_edge_guard_config_from_env() -> Option<EdgeGuardConfig> {
    if !env_bool("NEXO_EDGE_REQUIRED", false) {
        return None;
    }
    let header = std::env::var("NEXO_EDGE_HEADER")
        .unwrap_or_else(|_| HEADER_EDGE_AUTH.to_string())
        .to_ascii_lowercase();
    let secret = load_required_secret("NEXO_EDGE_SHARED_SECRET", None);
    Some(EdgeGuardConfig { header, secret })
}

fn load_redis_guard_from_env() -> Option<RedisGuardConfig> {
    let url = std::env::var("NEXO_REDIS_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())?;
    let key_prefix = std::env::var("NEXO_REDIS_PREFIX")
        .unwrap_or_else(|_| "nexo".to_string())
        .trim()
        .to_string();
    let client = redis::Client::open(url).expect("NEXO_REDIS_URL is invalid");
    Some(RedisGuardConfig { client, key_prefix })
}

fn load_vault_bundle_from_env() -> SecretBundle {
    let addr = std::env::var("NEXO_VAULT_ADDR")
        .expect("NEXO_VAULT_ADDR is required when NEXO_SECRET_PROVIDER=vault");
    let token = std::env::var("NEXO_VAULT_TOKEN")
        .expect("NEXO_VAULT_TOKEN is required when NEXO_SECRET_PROVIDER=vault");
    let mount = std::env::var("NEXO_VAULT_MOUNT").unwrap_or_else(|_| "secret".to_string());
    let path = std::env::var("NEXO_VAULT_PATH")
        .expect("NEXO_VAULT_PATH is required when NEXO_SECRET_PROVIDER=vault");
    let timeout_ms = std::env::var("NEXO_VAULT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_VAULT_TIMEOUT_MS);
    let field_active_secret =
        std::env::var("NEXO_VAULT_FIELD_ACTIVE_SECRET").unwrap_or_else(|_| "hmac_secret".into());
    let field_prev_secret =
        std::env::var("NEXO_VAULT_FIELD_PREV_SECRET").unwrap_or_else(|_| "hmac_secret_prev".into());
    let field_active_key_id =
        std::env::var("NEXO_VAULT_FIELD_ACTIVE_KEY_ID").unwrap_or_else(|_| "hmac_key_id".into());
    let field_prev_key_id =
        std::env::var("NEXO_VAULT_FIELD_PREV_KEY_ID").unwrap_or_else(|_| "hmac_key_id_prev".into());

    let url = format!(
        "{}/v1/{}/data/{}",
        addr.trim_end_matches('/'),
        mount.trim_matches('/'),
        path.trim_matches('/')
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .expect("failed to build vault HTTP client");

    let response = client
        .get(url)
        .header("X-Vault-Token", token)
        .send()
        .expect("failed to fetch secrets from Vault");
    assert!(
        response.status().is_success(),
        "vault returned HTTP {} while fetching secrets",
        response.status()
    );
    let payload: serde_json::Value = response
        .json()
        .expect("failed to parse Vault JSON response");
    parse_vault_bundle(
        &payload,
        &field_active_secret,
        &field_prev_secret,
        &field_active_key_id,
        &field_prev_key_id,
    )
    .expect("invalid Vault payload for security secrets")
}

fn load_azure_bundle_from_env() -> SecretBundle {
    let vault_url = std::env::var("NEXO_AZURE_VAULT_URL")
        .expect("NEXO_AZURE_VAULT_URL is required when NEXO_SECRET_PROVIDER=azure");
    let timeout_ms = std::env::var("NEXO_AZURE_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_AZURE_TIMEOUT_MS);
    let api_version = std::env::var("NEXO_AZURE_API_VERSION")
        .unwrap_or_else(|_| DEFAULT_AZURE_API_VERSION.to_string());

    let name_active_secret = std::env::var("NEXO_AZURE_SECRET_ACTIVE")
        .unwrap_or_else(|_| "nexo-hmac-secret-active".into());
    let name_prev_secret =
        std::env::var("NEXO_AZURE_SECRET_PREV").unwrap_or_else(|_| "nexo-hmac-secret-prev".into());
    let name_active_key_id = std::env::var("NEXO_AZURE_SECRET_KEY_ID_ACTIVE")
        .unwrap_or_else(|_| "nexo-hmac-key-id-active".into());
    let name_prev_key_id = std::env::var("NEXO_AZURE_SECRET_KEY_ID_PREV")
        .unwrap_or_else(|_| "nexo-hmac-key-id-prev".into());

    let token = load_azure_access_token(timeout_ms);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .expect("failed to build azure key vault HTTP client");

    let active_secret = fetch_azure_secret_value(
        &client,
        &vault_url,
        &name_active_secret,
        &api_version,
        &token,
    );
    let previous_secret =
        fetch_azure_secret_optional(&client, &vault_url, &name_prev_secret, &api_version, &token);
    let active_key_id = fetch_azure_secret_optional(
        &client,
        &vault_url,
        &name_active_key_id,
        &api_version,
        &token,
    );
    let previous_key_id =
        fetch_azure_secret_optional(&client, &vault_url, &name_prev_key_id, &api_version, &token);

    SecretBundle {
        active_secret: Some(active_secret),
        previous_secret,
        active_key_id,
        previous_key_id,
    }
}

fn load_azure_access_token(timeout_ms: u64) -> String {
    if let Ok(path) = std::env::var("NEXO_AZURE_ACCESS_TOKEN_FILE") {
        let token = read_secret_file(&path, "NEXO_AZURE_ACCESS_TOKEN_FILE");
        assert!(
            !token.trim().is_empty(),
            "NEXO_AZURE_ACCESS_TOKEN_FILE contains empty token."
        );
        return token;
    }
    if let Ok(token) = std::env::var("NEXO_AZURE_ACCESS_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return token;
        }
    }

    let use_mi = std::env::var("NEXO_AZURE_USE_MANAGED_IDENTITY")
        .ok()
        .map(|v| {
            let val = v.to_ascii_lowercase();
            val == "1" || val == "true" || val == "yes"
        })
        .unwrap_or(false);
    assert!(
        use_mi,
        "NEXO_AZURE_ACCESS_TOKEN (or *_FILE) is required unless NEXO_AZURE_USE_MANAGED_IDENTITY=true"
    );

    let mut query = vec![
        ("api-version", "2018-02-01".to_string()),
        ("resource", "https://vault.azure.net".to_string()),
    ];
    if let Ok(client_id) = std::env::var("NEXO_AZURE_MANAGED_IDENTITY_CLIENT_ID") {
        let id = client_id.trim().to_string();
        if !id.is_empty() {
            query.push(("client_id", id));
        }
    }
    let endpoint = std::env::var("NEXO_AZURE_IMDS_ENDPOINT")
        .unwrap_or_else(|_| "http://169.254.169.254/metadata/identity/oauth2/token".to_string());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .expect("failed to build azure IMDS HTTP client");
    let response = client
        .get(endpoint)
        .query(&query)
        .header("Metadata", "true")
        .send()
        .expect("failed to fetch managed identity token from IMDS");
    assert!(
        response.status().is_success(),
        "azure IMDS returned HTTP {} while fetching token",
        response.status()
    );
    let payload: serde_json::Value = response
        .json()
        .expect("failed to parse azure IMDS token JSON");
    parse_azure_access_token_response(&payload).expect("missing access_token in azure IMDS payload")
}

fn parse_azure_access_token_response(payload: &serde_json::Value) -> Option<String> {
    payload
        .as_object()?
        .get("access_token")?
        .as_str()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn build_azure_secret_url(vault_url: &str, secret_name: &str, api_version: &str) -> reqwest::Url {
    let mut url = reqwest::Url::parse(&format!(
        "{}/secrets/{}",
        vault_url.trim_end_matches('/'),
        secret_name.trim_matches('/')
    ))
    .expect("invalid NEXO_AZURE_VAULT_URL or secret name");
    url.query_pairs_mut()
        .append_pair("api-version", api_version)
        .finish();
    url
}

fn parse_azure_secret_value(payload: &serde_json::Value) -> Option<String> {
    payload
        .as_object()?
        .get("value")?
        .as_str()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn fetch_azure_secret_value(
    client: &reqwest::blocking::Client,
    vault_url: &str,
    secret_name: &str,
    api_version: &str,
    token: &str,
) -> String {
    fetch_azure_secret_optional(client, vault_url, secret_name, api_version, token).unwrap_or_else(
        || panic!("required secret '{secret_name}' not found or empty in Azure Key Vault"),
    )
}

fn fetch_azure_secret_optional(
    client: &reqwest::blocking::Client,
    vault_url: &str,
    secret_name: &str,
    api_version: &str,
    token: &str,
) -> Option<String> {
    let url = build_azure_secret_url(vault_url, secret_name, api_version);
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .expect("failed to fetch secret from Azure Key Vault");

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return None;
    }
    assert!(
        response.status().is_success(),
        "azure key vault returned HTTP {} for secret '{}'",
        response.status(),
        secret_name
    );
    let payload: serde_json::Value = response
        .json()
        .expect("failed to parse Azure Key Vault secret JSON");
    parse_azure_secret_value(&payload)
}

fn load_gcp_bundle_from_env() -> SecretBundle {
    let project_id = std::env::var("NEXO_GCP_PROJECT_ID")
        .expect("NEXO_GCP_PROJECT_ID is required when NEXO_SECRET_PROVIDER=gcp");
    let timeout_ms = std::env::var("NEXO_GCP_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_GCP_TIMEOUT_MS);
    let active_name = std::env::var("NEXO_GCP_SECRET_ACTIVE")
        .unwrap_or_else(|_| "nexo-hmac-secret-active".into());
    let prev_name =
        std::env::var("NEXO_GCP_SECRET_PREV").unwrap_or_else(|_| "nexo-hmac-secret-prev".into());
    let active_key_id_name = std::env::var("NEXO_GCP_SECRET_KEY_ID_ACTIVE")
        .unwrap_or_else(|_| "nexo-hmac-key-id-active".into());
    let prev_key_id_name = std::env::var("NEXO_GCP_SECRET_KEY_ID_PREV")
        .unwrap_or_else(|_| "nexo-hmac-key-id-prev".into());

    let token = load_gcp_access_token(timeout_ms);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .expect("failed to build GCP secret manager HTTP client");

    let active_secret = fetch_gcp_secret_value(&client, &project_id, &active_name, &token);
    let previous_secret = fetch_gcp_secret_optional(&client, &project_id, &prev_name, &token);
    let active_key_id =
        fetch_gcp_secret_optional(&client, &project_id, &active_key_id_name, &token);
    let previous_key_id =
        fetch_gcp_secret_optional(&client, &project_id, &prev_key_id_name, &token);

    SecretBundle {
        active_secret: Some(active_secret),
        previous_secret,
        active_key_id,
        previous_key_id,
    }
}

fn load_aws_bundle_from_env() -> SecretBundle {
    let region = std::env::var("NEXO_AWS_REGION")
        .expect("NEXO_AWS_REGION is required when NEXO_SECRET_PROVIDER=aws");
    let secret_id = std::env::var("NEXO_AWS_SECRET_ID")
        .expect("NEXO_AWS_SECRET_ID is required when NEXO_SECRET_PROVIDER=aws");
    let field_active_secret =
        std::env::var("NEXO_AWS_FIELD_ACTIVE_SECRET").unwrap_or_else(|_| "hmac_secret".into());
    let field_prev_secret =
        std::env::var("NEXO_AWS_FIELD_PREV_SECRET").unwrap_or_else(|_| "hmac_secret_prev".into());
    let field_active_key_id =
        std::env::var("NEXO_AWS_FIELD_ACTIVE_KEY_ID").unwrap_or_else(|_| "hmac_key_id".into());
    let field_prev_key_id =
        std::env::var("NEXO_AWS_FIELD_PREV_KEY_ID").unwrap_or_else(|_| "hmac_key_id_prev".into());
    let timeout_ms = std::env::var("NEXO_AWS_RUNTIME_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_AWS_RUNTIME_TIMEOUT_MS);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create Tokio runtime for AWS secrets");

    let payload = runtime.block_on(async move {
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .load()
            .await;
        let client = aws_sdk_secretsmanager::Client::new(&config);
        let fut = client.get_secret_value().secret_id(secret_id).send();
        tokio::time::timeout(Duration::from_millis(timeout_ms), fut)
            .await
            .expect("timeout while fetching AWS secret bundle")
            .expect("failed to fetch AWS secret bundle")
    });

    let raw_secret = payload
        .secret_string()
        .expect("AWS secret bundle must be a JSON string");
    let json_payload: serde_json::Value =
        serde_json::from_str(raw_secret).expect("AWS secret bundle JSON is invalid");
    parse_generic_secret_bundle(
        &json_payload,
        &field_active_secret,
        &field_prev_secret,
        &field_active_key_id,
        &field_prev_key_id,
    )
    .expect("invalid AWS secret bundle fields")
}

fn load_gcp_access_token(timeout_ms: u64) -> String {
    if let Ok(path) = std::env::var("NEXO_GCP_ACCESS_TOKEN_FILE") {
        let token = read_secret_file(&path, "NEXO_GCP_ACCESS_TOKEN_FILE");
        assert!(
            !token.trim().is_empty(),
            "NEXO_GCP_ACCESS_TOKEN_FILE contains empty token."
        );
        return token;
    }
    if let Ok(token) = std::env::var("NEXO_GCP_ACCESS_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return token;
        }
    }

    let use_metadata = std::env::var("NEXO_GCP_USE_METADATA_TOKEN")
        .ok()
        .map(|v| {
            let val = v.to_ascii_lowercase();
            val == "1" || val == "true" || val == "yes"
        })
        .unwrap_or(false);
    assert!(
        use_metadata,
        "NEXO_GCP_ACCESS_TOKEN (or *_FILE) is required unless NEXO_GCP_USE_METADATA_TOKEN=true"
    );

    let endpoint = std::env::var("NEXO_GCP_METADATA_TOKEN_URL").unwrap_or_else(|_| {
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
            .to_string()
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .expect("failed to build GCP metadata HTTP client");
    let response = client
        .get(endpoint)
        .header("Metadata-Flavor", "Google")
        .send()
        .expect("failed to fetch GCP metadata token");
    assert!(
        response.status().is_success(),
        "gcp metadata returned HTTP {} while fetching token",
        response.status()
    );
    let payload: serde_json::Value = response
        .json()
        .expect("failed to parse GCP metadata token JSON");
    parse_gcp_access_token_response(&payload).expect("missing access_token in GCP metadata payload")
}

fn parse_gcp_access_token_response(payload: &serde_json::Value) -> Option<String> {
    payload
        .as_object()?
        .get("access_token")?
        .as_str()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn build_gcp_secret_access_url(project_id: &str, secret_name: &str) -> reqwest::Url {
    reqwest::Url::parse(&format!(
        "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/latest:access",
        project_id.trim_matches('/'),
        secret_name.trim_matches('/')
    ))
    .expect("invalid GCP project or secret name")
}

fn parse_gcp_secret_access_payload(payload: &serde_json::Value) -> Option<String> {
    let b64 = payload
        .as_object()?
        .get("payload")?
        .as_object()?
        .get("data")?
        .as_str()?;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    String::from_utf8(raw)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn fetch_gcp_secret_value(
    client: &reqwest::blocking::Client,
    project_id: &str,
    secret_name: &str,
    token: &str,
) -> String {
    fetch_gcp_secret_optional(client, project_id, secret_name, token).unwrap_or_else(|| {
        panic!("required secret '{secret_name}' not found or empty in GCP Secret Manager")
    })
}

fn fetch_gcp_secret_optional(
    client: &reqwest::blocking::Client,
    project_id: &str,
    secret_name: &str,
    token: &str,
) -> Option<String> {
    let url = build_gcp_secret_access_url(project_id, secret_name);
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .expect("failed to fetch secret from GCP Secret Manager");
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return None;
    }
    assert!(
        response.status().is_success(),
        "gcp secret manager returned HTTP {} for secret '{}'",
        response.status(),
        secret_name
    );
    let payload: serde_json::Value = response
        .json()
        .expect("failed to parse GCP secret access JSON");
    parse_gcp_secret_access_payload(&payload)
}

fn parse_vault_bundle(
    payload: &serde_json::Value,
    field_active_secret: &str,
    field_prev_secret: &str,
    field_active_key_id: &str,
    field_prev_key_id: &str,
) -> Result<SecretBundle, &'static str> {
    let top = payload
        .as_object()
        .ok_or("vault payload is not an object")?;
    let data_node = top.get("data").ok_or("vault payload missing data field")?;
    let map_v2 = data_node
        .get("data")
        .and_then(|v| v.as_object())
        .cloned()
        .or_else(|| data_node.as_object().cloned())
        .ok_or("vault payload data field is not an object")?;

    Ok(SecretBundle {
        active_secret: map_v2
            .get(field_active_secret)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        previous_secret: map_v2
            .get(field_prev_secret)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        active_key_id: map_v2
            .get(field_active_key_id)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        previous_key_id: map_v2
            .get(field_prev_key_id)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    })
}

fn parse_generic_secret_bundle(
    payload: &serde_json::Value,
    field_active_secret: &str,
    field_prev_secret: &str,
    field_active_key_id: &str,
    field_prev_key_id: &str,
) -> Result<SecretBundle, &'static str> {
    let map = payload
        .as_object()
        .ok_or("secret bundle payload is not an object")?;
    Ok(SecretBundle {
        active_secret: map
            .get(field_active_secret)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        previous_secret: map
            .get(field_prev_secret)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        active_key_id: map
            .get(field_active_key_id)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        previous_key_id: map
            .get(field_prev_key_id)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    })
}

fn pick_secret_source(
    from_bundle: Option<&str>,
    from_file: Option<String>,
    from_env: Option<String>,
) -> Option<String> {
    from_bundle
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(from_file)
        .or(from_env)
}

fn load_key_id(env_key: &str, default: &str, from_bundle: Option<&str>) -> String {
    let file_key = format!("{env_key}_FILE");
    let from_file = std::env::var(&file_key)
        .ok()
        .map(|path| read_secret_file(&path, &file_key));
    let from_env = std::env::var(env_key).ok();
    let selected =
        pick_secret_source(from_bundle, from_file, from_env).unwrap_or_else(|| default.to_string());
    assert!(is_valid_key_id(&selected), "{env_key} has invalid format.");
    selected
}

fn load_required_secret(env_key: &str, from_bundle: Option<&str>) -> String {
    load_optional_secret(env_key, from_bundle).unwrap_or_else(|| {
        panic!("{env_key} or {env_key}_FILE is required. Refusing to start without HMAC secret.")
    })
}

fn load_optional_secret(env_key: &str, from_bundle: Option<&str>) -> Option<String> {
    let file_key = format!("{env_key}_FILE");
    let from_file = std::env::var(&file_key)
        .ok()
        .map(|path| read_secret_file(&path, &file_key));
    let from_env = std::env::var(env_key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    pick_secret_source(from_bundle, from_file, from_env)
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
    let chat_send_route = post(api_chat_send_handler).route_layer(middleware::from_fn_with_state(
        state.clone(),
        chat_send_boundary_middleware,
    ));
    Router::new()
        .route("/evaluate", evaluate_route)
        .route("/healthz", get(health_handler))
        .route("/readyz", get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .route("/audit/recent", get(audit_recent_handler))
        .route("/security/status", get(security_status_handler))
        .route("/api/state", get(api_state_handler))
        .route("/api/chat/send", chat_send_route)
        .with_state(state)
}

#[cfg(feature = "network")]
fn chat_send_capability(state: &AppState) -> ChatSendCapability {
    let Some(path) = state.p2p_db_path.as_deref() else {
        return ChatSendCapability {
            available: false,
            mode: "core_unavailable",
            reason: "p2p_db_path_missing",
            error_message: "chat send unavailable: p2p_db_path_missing",
        };
    };
    let path = path.trim();
    if path.is_empty() {
        return ChatSendCapability {
            available: false,
            mode: "core_unavailable",
            reason: "p2p_db_path_missing",
            error_message: "chat send unavailable: p2p_db_path_missing",
        };
    }
    if OfflineStore::open(path).is_err() {
        return ChatSendCapability {
            available: false,
            mode: "core_unavailable",
            reason: "p2p_store_unavailable",
            error_message: "chat send unavailable: p2p_store_unavailable",
        };
    }

    ChatSendCapability {
        available: true,
        mode: "core",
        reason: "",
        error_message: "",
    }
}

#[cfg(not(feature = "network"))]
fn chat_send_capability(_state: &AppState) -> ChatSendCapability {
    ChatSendCapability {
        available: false,
        mode: "core_unavailable",
        reason: "network_feature_disabled",
        error_message: "chat send unavailable: network_feature_disabled",
    }
}

fn is_loopback_connect_info(connect_info: &ConnectInfo<SocketAddr>) -> bool {
    let ConnectInfo(addr) = connect_info;
    addr.ip().is_loopback()
}

async fn api_state_handler(State(state): State<AppState>) -> impl IntoResponse {
    if matches!(
        state.security_level,
        SecurityLevel::Elevated | SecurityLevel::Incident
    ) && !state.expose_api_state
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(HEADER_NEXO_REASON, API_STATE_EXPOSURE_DISABLED_REASON)],
            Json(serde_json::json!({
                "status": "unavailable",
                "reason": API_STATE_EXPOSURE_DISABLED_REASON
            })),
        )
            .into_response();
    }

    let records = state.audit_store.recent(200).unwrap_or_default();
    let chat_send = chat_send_capability(&state);
    let now_sync = now_utc_ms();
    let now_timestamp = now_utc_ms();
    (
        StatusCode::OK,
        Json(build_state_response(
            &state,
            &records,
            now_sync,
            now_timestamp,
            &chat_send,
            DEFAULT_STATE_CHAT_LIMIT,
        )),
    )
        .into_response()
}

async fn api_chat_send_handler(
    State(state): State<AppState>,
    connect_info: ConnectInfo<SocketAddr>,
    body: Bytes,
) -> impl IntoResponse {
    let req: ChatSendRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(_) => {
            let request_id = Uuid::new_v4().to_string();
            return error_response(
                StatusCode::BAD_REQUEST,
                &state,
                &request_id,
                "invalid JSON payload",
            );
        }
    };
    let request_id = Uuid::new_v4().to_string();
    let channel = req.channel.unwrap_or_else(|| "global".to_string());
    let text = req.text;
    // This route is intended for the local UI surface. Keep origin fixed.
    let origin = "ui_dashboard".to_string();

    if !is_loopback_connect_info(&connect_info) {
        return error_response(
            StatusCode::FORBIDDEN,
            &state,
            &request_id,
            "chat send unavailable: local_only",
        );
    }

    if channel != "global" {
        return error_response(
            StatusCode::BAD_REQUEST,
            &state,
            &request_id,
            "channel must be global",
        );
    }
    if text.trim().is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            &state,
            &request_id,
            "text must not be empty",
        );
    }
    if text.len() > MAX_CHAT_MESSAGE_BYTES {
        return error_response(
            StatusCode::BAD_REQUEST,
            &state,
            &request_id,
            "text must be <= 32 bytes",
        );
    }
    let capability = chat_send_capability(&state);
    if !capability.available {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &state,
            &request_id,
            capability.error_message,
        );
    }

    let now_ms = now_utc_ms();
    let message = match store_chat_message(
        state.p2p_db_path.as_deref(),
        &origin,
        &channel,
        &text,
        now_ms,
    ) {
        Ok(message) => message,
        Err(ChatSendError::BadRequest(msg)) => {
            return error_response(StatusCode::BAD_REQUEST, &state, &request_id, msg);
        }
        Err(ChatSendError::ServiceUnavailable(msg)) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, &state, &request_id, msg);
        }
    };

    signed_json_response(
        StatusCode::OK,
        &state,
        &request_id,
        &ChatSendResponse {
            status: "inserted".to_string(),
            message,
            send_mode: "core".to_string(),
        },
    )
}

#[cfg(feature = "network")]
fn store_chat_message(
    p2p_db_path: Option<&str>,
    origin: &str,
    channel: &str,
    text: &str,
    now_ms: u64,
) -> Result<StateChatMessage, ChatSendError> {
    let Some(path) = p2p_db_path else {
        return Err(ChatSendError::ServiceUnavailable("p2p chat unavailable"));
    };
    let path = path.trim();
    if path.is_empty() {
        return Err(ChatSendError::ServiceUnavailable("p2p chat unavailable"));
    }

    let store = OfflineStore::open(path)
        .map_err(|_| ChatSendError::ServiceUnavailable("p2p chat store unavailable"))?;
    let nonce = store
        .next_nonce(origin)
        .map_err(|_| ChatSendError::ServiceUnavailable("p2p chat nonce unavailable"))?;
    let msg = CanonicalMessage::new_with_nonce(origin.to_string(), now_ms, nonce, text.as_bytes())
        .map_err(ChatSendError::BadRequest)?;
    store
        .insert_message_with_channel(&msg, channel, now_ms, 120_000)
        .map_err(|_| ChatSendError::ServiceUnavailable("failed to persist chat message"))?;

    Ok(StateChatMessage {
        hash: crate::message::event_hash(&msg),
        origin: msg.sender_id,
        channel: channel.to_string(),
        text: String::from_utf8_lossy(&msg.content).into_owned(),
        timestamp: msg.timestamp_utc_ms,
    })
}

#[cfg(not(feature = "network"))]
fn store_chat_message(
    _p2p_db_path: Option<&str>,
    _origin: &str,
    _channel: &str,
    text: &str,
    _now_ms: u64,
) -> Result<StateChatMessage, ChatSendError> {
    if text.trim().is_empty() {
        return Err(ChatSendError::BadRequest("text must not be empty"));
    }
    if text.len() > MAX_CHAT_MESSAGE_BYTES {
        return Err(ChatSendError::BadRequest("text must be <= 32 bytes"));
    }
    Err(ChatSendError::ServiceUnavailable("p2p chat unavailable"))
}

async fn chat_send_boundary_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Err(msg) = validate_json_content_type(&parts.headers) {
        let request_id = extract_header(&parts.headers, HEADER_REQUEST_ID)
            .map(ToString::to_string)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, &state, &request_id, msg);
    }

    let body_bytes = match to_bytes(body, MAX_CHAT_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
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

    let request = Request::from_parts(parts, Body::from(body_bytes));
    next.run(request).await
}

fn auth_error_response(state: &AppState, request_id: String, err: AuthError) -> Response {
    let (status, message) = match err {
        AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
        AuthError::RequestTimeout(msg) => (StatusCode::REQUEST_TIMEOUT, msg),
        AuthError::Conflict(msg) => (StatusCode::CONFLICT, msg),
        AuthError::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
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

fn extract_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
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

fn validate_json_content_type(headers: &HeaderMap) -> Result<(), &'static str> {
    if headers.get_all(HEADER_CONTENT_TYPE).iter().count() > 1 {
        return Err("duplicate content-type header");
    }
    if !is_json_content_type(headers) {
        return Err("content-type must be application/json");
    }
    Ok(())
}

pub fn compute_signature(
    secret: &str,
    key_id: &str,
    request_id: &str,
    timestamp_ms: u64,
    body: &[u8],
) -> String {
    compute_signature_with_nonce(secret, key_id, request_id, timestamp_ms, timestamp_ms, body)
}

pub fn compute_signature_with_nonce(
    secret: &str,
    key_id: &str,
    request_id: &str,
    timestamp_ms: u64,
    nonce: u64,
    body: &[u8],
) -> String {
    let msg = signing_message(key_id, request_id, timestamp_ms, nonce, body);
    bytes_to_hex(&hmac_blake3(secret.as_bytes(), &msg))
}

pub fn derive_client_public_key_base64(seed_b64: &str) -> String {
    let seed = base64::engine::general_purpose::STANDARD
        .decode(seed_b64)
        .unwrap_or_else(|_| panic!("invalid base64 seed"));
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("client seed must be 32 bytes"));
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    base64::engine::general_purpose::STANDARD.encode(signing.verifying_key().to_bytes())
}

pub fn compute_client_signature_base64(
    seed_b64: &str,
    client_id: &str,
    key_id: &str,
    request_id: &str,
    timestamp_ms: u64,
    body: &[u8],
) -> String {
    compute_client_signature_base64_with_nonce(
        seed_b64,
        client_id,
        key_id,
        request_id,
        timestamp_ms,
        timestamp_ms,
        body,
    )
}

pub fn compute_client_signature_base64_with_nonce(
    seed_b64: &str,
    client_id: &str,
    key_id: &str,
    request_id: &str,
    timestamp_ms: u64,
    nonce: u64,
    body: &[u8],
) -> String {
    let seed = base64::engine::general_purpose::STANDARD
        .decode(seed_b64)
        .unwrap_or_else(|_| panic!("invalid base64 seed"));
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("client seed must be 32 bytes"));
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let msg = client_signature_message(client_id, key_id, request_id, timestamp_ms, nonce, body);
    let sig = ed25519_dalek::Signer::sign(&signing, &msg);
    base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
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
    headers.insert(
        HEADER_NONCE,
        timestamp_ms.to_string().parse().expect("nonce header"),
    );
    headers.insert(HEADER_KEY_ID, BENCH_KEY_ID.parse().expect("key id header"));
    validate_security_headers(state, &headers, body).is_ok()
}

fn signing_message(
    key_id: &str,
    request_id: &str,
    timestamp_ms: u64,
    nonce: u64,
    body: &[u8],
) -> Vec<u8> {
    fn push_part(buf: &mut Vec<u8>, part: &[u8]) {
        buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
        buf.extend_from_slice(part);
    }
    let mut out = Vec::with_capacity(body.len() + 96);
    push_part(&mut out, key_id.as_bytes());
    push_part(&mut out, request_id.as_bytes());
    push_part(&mut out, timestamp_ms.to_string().as_bytes());
    push_part(&mut out, nonce.to_string().as_bytes());
    push_part(&mut out, body);
    out
}

fn client_signature_message(
    client_id: &str,
    key_id: &str,
    request_id: &str,
    timestamp_ms: u64,
    nonce: u64,
    body: &[u8],
) -> Vec<u8> {
    fn push_part(buf: &mut Vec<u8>, part: &[u8]) {
        buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
        buf.extend_from_slice(part);
    }
    let mut out = Vec::with_capacity(body.len() + 128);
    push_part(&mut out, b"nexo_client_sig_v1");
    push_part(&mut out, client_id.as_bytes());
    push_part(&mut out, key_id.as_bytes());
    push_part(&mut out, request_id.as_bytes());
    push_part(&mut out, timestamp_ms.to_string().as_bytes());
    push_part(&mut out, nonce.to_string().as_bytes());
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
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Mutex, OnceLock};
    use tower::util::ServiceExt;

    #[cfg(feature = "network")]
    use crate::offline_store::StoreInsertStatus;

    use super::*;

    fn test_state() -> AppState {
        let path = std::env::temp_dir().join(format!("nexo_api_test_{}.jsonl", Uuid::new_v4()));
        AppState::for_tests(path)
    }

    fn lock_path_for_test(path: &std::path::Path) -> PathBuf {
        let mut os = path.as_os_str().to_os_string();
        os.push(".lock");
        PathBuf::from(os)
    }

    fn find_zig_executable() -> Option<&'static str> {
        for binary in ["zig", "zig.exe"] {
            let probe = Command::new(binary).arg("version").output();
            if probe.is_ok_and(|out| out.status.success()) {
                return Some(binary);
            }
        }
        None
    }

    fn verify_with_zig_offline(audit_path: &std::path::Path) -> Result<String, String> {
        let Some(zig_bin) = find_zig_executable() else {
            return Err("zig not found in PATH".to_string());
        };

        let zig_workdir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tools")
            .join("zig");
        let output = Command::new(zig_bin)
            .current_dir(&zig_workdir)
            .arg("build")
            .arg("run")
            .arg("--")
            .arg("verify")
            .arg(audit_path)
            .output()
            .map_err(|err| format!("failed to execute zig verifier: {err}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");
        if !output.status.success() {
            return Err(format!(
                "zig verifier failed with status {}: {}",
                output.status, combined
            ));
        }
        Ok(combined)
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_env_var(name: &str, value: Option<String>) {
        if let Some(v) = value {
            std::env::set_var(name, v);
        } else {
            std::env::remove_var(name);
        }
    }

    fn signed_request(
        payload: serde_json::Value,
        secret: &str,
        key_id: &str,
        request_id: &str,
        timestamp_ms: u64,
    ) -> Request<Body> {
        signed_request_with_nonce(
            payload,
            secret,
            key_id,
            request_id,
            timestamp_ms,
            timestamp_ms,
        )
    }

    fn signed_request_with_nonce(
        payload: serde_json::Value,
        secret: &str,
        key_id: &str,
        request_id: &str,
        timestamp_ms: u64,
        nonce: u64,
    ) -> Request<Body> {
        let body = payload.to_string();
        let signature = compute_signature_with_nonce(
            secret,
            key_id,
            request_id,
            timestamp_ms,
            nonce,
            body.as_bytes(),
        );
        Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .header("x-signature", signature)
            .header("x-request-id", request_id)
            .header("x-timestamp", timestamp_ms.to_string())
            .header("x-nonce", nonce.to_string())
            .header("x-key-id", key_id)
            .body(Body::from(body))
            .expect("request")
    }

    fn signed_request_with_headers(
        payload: serde_json::Value,
        secret: &str,
        key_id: &str,
        request_id: &str,
        timestamp_ms: u64,
        extra_headers: &[(&str, String)],
    ) -> Request<Body> {
        signed_request_with_headers_and_nonce(
            payload,
            secret,
            key_id,
            request_id,
            timestamp_ms,
            timestamp_ms,
            extra_headers,
        )
    }

    fn signed_request_with_headers_and_nonce(
        payload: serde_json::Value,
        secret: &str,
        key_id: &str,
        request_id: &str,
        timestamp_ms: u64,
        nonce: u64,
        extra_headers: &[(&str, String)],
    ) -> Request<Body> {
        let body = payload.to_string();
        let signature = compute_signature_with_nonce(
            secret,
            key_id,
            request_id,
            timestamp_ms,
            nonce,
            body.as_bytes(),
        );
        let mut req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .header("x-signature", signature)
            .header("x-request-id", request_id)
            .header("x-timestamp", timestamp_ms.to_string())
            .header("x-nonce", nonce.to_string())
            .header("x-key-id", key_id);
        for (k, v) in extra_headers {
            req = req.header(*k, v);
        }
        req.body(Body::from(body)).expect("request")
    }

    fn signed_request_with_headers_and_remote_addr(
        payload: serde_json::Value,
        secret: &str,
        key_id: &str,
        request_id: &str,
        timestamp_ms: u64,
        extra_headers: &[(&str, String)],
        remote_addr: SocketAddr,
    ) -> Request<Body> {
        let mut req = signed_request_with_headers(
            payload,
            secret,
            key_id,
            request_id,
            timestamp_ms,
            extra_headers,
        );
        req.extensions_mut().insert(ConnectInfo(remote_addr));
        req
    }

    fn admin_get_request(path: &str, auth: Option<&str>) -> Request<Body> {
        let mut req = Request::builder().method("GET").uri(path);
        if let Some(value) = auth {
            req = req.header(HEADER_AUTHORIZATION, value);
        }
        req.body(Body::empty()).expect("request")
    }

    fn chat_send_request(
        payload: serde_json::Value,
        remote_addr: Option<SocketAddr>,
    ) -> Request<Body> {
        chat_send_request_with_content_types(
            payload.to_string(),
            &["application/json"],
            remote_addr,
        )
    }

    fn chat_send_request_with_content_types(
        body: String,
        content_types: &[&str],
        remote_addr: Option<SocketAddr>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method("POST").uri("/api/chat/send");
        for content_type in content_types {
            builder = builder.header(HEADER_CONTENT_TYPE, *content_type);
        }
        let mut req = builder.body(Body::from(body)).expect("request");
        if let Some(addr) = remote_addr {
            req.extensions_mut().insert(ConnectInfo(addr));
        }
        req
    }

    #[cfg(feature = "network")]
    fn expected_chat_send_unavailable_reason() -> &'static str {
        "p2p_db_path_missing"
    }

    #[cfg(not(feature = "network"))]
    fn expected_chat_send_unavailable_reason() -> &'static str {
        "network_feature_disabled"
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
    async fn api_state_handler_returns_expected_state_payload() {
        let mut state = test_state();
        state.security_level = SecurityLevel::Normal;
        let app = app_with_state(state);
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id": "state_user",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true,
            "request_id": "a4f3a8f6-6f5b-4fd0-b0aa-6e7c2c8f8f4a",
            "calc_version": "plca_v1"
        });

        let evaluate_req = signed_request(
            req_body,
            "test_active_secret",
            "active",
            "a4f3a8f6-6f5b-4fd0-b0aa-6e7c2c8f8f4a",
            now,
        );
        let eval_resp = app
            .clone()
            .oneshot(evaluate_req)
            .await
            .expect("evaluate response");
        assert_eq!(eval_resp.status(), StatusCode::OK);

        let state_req = Request::builder()
            .method("GET")
            .uri("/api/state")
            .body(Body::empty())
            .expect("state request");
        let state_resp = app.oneshot(state_req).await.expect("state response");
        assert_eq!(state_resp.status(), StatusCode::OK);

        let state_body = state_resp
            .into_body()
            .collect()
            .await
            .expect("state body bytes")
            .to_bytes();
        let state_json: Value = serde_json::from_slice(&state_body).expect("state json");

        assert_eq!(state_json["system_status"], "operational");
        assert_eq!(state_json["peers_count"], 1);
        assert!(state_json["recent_events"].is_array());
        assert!(state_json["recent_flow"].is_array());
        assert!(state_json["recent_ai_insights"].is_array());
        assert_eq!(
            state_json["recent_events"][0]["type"],
            "system_event:approved"
        );
        assert_eq!(state_json["recent_flow"][0]["kind"], "event");
        assert_eq!(
            state_json["recent_flow"][0]["hash"],
            state_json["recent_events"][0]["hash"]
        );
        assert_eq!(
            state_json["recent_flow"][0]["origin"],
            state_json["recent_events"][0]["origin"]
        );
        assert!(
            state_json["recent_flow"][0]["timestamp"]
                .as_u64()
                .unwrap_or(0)
                >= state_json["recent_ai_insights"][0]["timestamp"]
                    .as_u64()
                    .unwrap_or(0)
        );
        assert_eq!(
            state_json["ai_last_insight"],
            "No anomaly patterns observed in this window."
        );
        assert!(state_json["recent_chat_messages"].is_array());
        assert_eq!(state_json["chat_send_available"], false);
        assert_eq!(state_json["chat_send_mode"], "core_unavailable");
        assert_eq!(
            state_json["chat_send_reason"],
            expected_chat_send_unavailable_reason()
        );
        assert_eq!(state_json["write_status"], "read_only");
        assert_eq!(state_json["audit_chain_status"], "ok");
        assert_eq!(state_json["audit_chain_checked_records"], 1);
        assert!(
            state_json["audit_chain_last_record_hash"]
                .as_str()
                .unwrap_or_default()
                .len()
                > 10
        );
        assert_eq!(state_json["audit_chain_error"], "");
        assert_eq!(state_json["latest_change_kind"], "event");
        assert_eq!(state_json["latest_change_summary"], "approved decision");
        assert_eq!(state_json["latest_change_source"], "core_decision");
        assert_eq!(
            state_json["latest_change_origin"],
            state_json["recent_flow"][0]["origin"]
        );
        assert_eq!(state_json["last_operator_action_kind"], "");
        assert_eq!(state_json["last_operator_action_summary"], "");
        assert_eq!(state_json["last_operator_action_origin"], "");
        assert_eq!(state_json["last_operator_action_timestamp"], 0);
        assert_eq!(state_json["last_operator_action_channel"], "");
    }

    #[tokio::test]
    async fn api_state_handler_returns_503_in_hostile_mode_when_exposure_disabled() {
        let mut state = test_state();
        state.security_level = SecurityLevel::Incident;
        state.expose_api_state = false;
        let app = app_with_state(state);

        let state_req = Request::builder()
            .method("GET")
            .uri("/api/state")
            .body(Body::empty())
            .expect("state request");
        let state_resp = app.oneshot(state_req).await.expect("state response");
        assert_eq!(state_resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            state_resp
                .headers()
                .get(HEADER_NEXO_REASON)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default(),
            API_STATE_EXPOSURE_DISABLED_REASON
        );

        let state_body = state_resp
            .into_body()
            .collect()
            .await
            .expect("state body bytes")
            .to_bytes();
        let state_json: Value = serde_json::from_slice(&state_body).expect("state json");
        assert_eq!(state_json["status"], "unavailable");
        assert_eq!(state_json["reason"], API_STATE_EXPOSURE_DISABLED_REASON);
    }

    #[cfg(feature = "network")]
    #[tokio::test]
    async fn api_state_handler_exposes_recent_chat_messages_from_db() {
        let db_path = std::env::temp_dir().join(format!("nexo_state_chat_{}.db", Uuid::new_v4()));
        let db_path_str = db_path.to_str().expect("db path");

        let store = OfflineStore::open(db_path_str).expect("open offline store");
        let payload = b"hello-offline-flow";
        let msg = crate::message::CanonicalMessage::new_with_nonce(
            "chat_node_a",
            now_utc_ms(),
            1,
            payload,
        )
        .expect("chat message");
        let status = store
            .insert_message_with_channel(&msg, "global", now_utc_ms(), 120_000)
            .expect("insert");
        assert_eq!(status, StoreInsertStatus::Inserted);

        let mut state = test_state();
        state.security_level = SecurityLevel::Normal;
        state.p2p_db_path = Some(db_path_str.to_string());
        let app = app_with_state(state);

        let state_req = Request::builder()
            .method("GET")
            .uri("/api/state")
            .body(Body::empty())
            .expect("state request");
        let state_resp = app.oneshot(state_req).await.expect("state response");
        assert_eq!(state_resp.status(), StatusCode::OK);

        let state_body = state_resp
            .into_body()
            .collect()
            .await
            .expect("state body bytes")
            .to_bytes();
        let state_json: Value = serde_json::from_slice(&state_body).expect("state json");

        let chat_messages = state_json["recent_chat_messages"]
            .as_array()
            .expect("chat messages");
        assert_eq!(chat_messages.len(), 1);
        assert_eq!(chat_messages[0]["origin"], "chat_node_a");
        assert_eq!(chat_messages[0]["channel"], "global");
        assert_eq!(chat_messages[0]["text"], "hello-offline-flow");

        assert!(state_json["recent_flow"].is_array());
        assert_eq!(state_json["recent_flow"][0]["kind"], "chat");
        assert_eq!(
            state_json["recent_flow"][0]["hash"],
            state_json["recent_chat_messages"][0]["hash"]
        );
        assert_eq!(state_json["chat_send_available"], true);
        assert_eq!(state_json["chat_send_mode"], "core");
        assert_eq!(state_json["chat_send_reason"], "");
        assert_eq!(state_json["write_status"], "writable");
        assert_eq!(state_json["latest_change_kind"], "chat");
        assert_eq!(state_json["latest_change_summary"], "hello-offline-flow");
        assert_eq!(state_json["latest_change_source"], "passive_observation");
        assert_eq!(state_json["last_operator_action_kind"], "");
        assert_eq!(state_json["last_operator_action_summary"], "");
    }

    #[cfg(feature = "network")]
    #[tokio::test]
    async fn api_chat_send_handler_persists_message_to_db() {
        let db_path = std::env::temp_dir().join(format!("nexo_ui_chat_{}.db", Uuid::new_v4()));
        let db_path_str = db_path.to_str().expect("db path");

        let mut state = test_state();
        state.p2p_db_path = Some(db_path_str.to_string());
        let app = app_with_state(state);

        let req = chat_send_request(
            serde_json::json!({
                "origin": "spoofed_origin",
                "channel": "global",
                "text": "hello-ui-core"
            }),
            Some("127.0.0.1:41000".parse().expect("loopback")),
        );
        let resp = app.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("chat send body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("chat send json");
        assert_eq!(json["status"], "inserted");
        assert_eq!(json["send_mode"], "core");
        assert_eq!(json["message"]["origin"], "ui_dashboard");
        assert_eq!(json["message"]["channel"], "global");
        assert_eq!(json["message"]["text"], "hello-ui-core");

        let state_req = Request::builder()
            .method("GET")
            .uri("/api/state")
            .body(Body::empty())
            .expect("state request");
        let state_resp = app.oneshot(state_req).await.expect("state response");
        assert_eq!(state_resp.status(), StatusCode::OK);

        let state_body = state_resp
            .into_body()
            .collect()
            .await
            .expect("state body bytes")
            .to_bytes();
        let state_json: Value = serde_json::from_slice(&state_body).expect("state json");
        assert_eq!(
            state_json["recent_chat_messages"][0]["origin"],
            "ui_dashboard"
        );
        assert_eq!(
            state_json["recent_chat_messages"][0]["text"],
            "hello-ui-core"
        );
        assert_eq!(state_json["recent_flow"][0]["kind"], "chat");
        assert_eq!(state_json["latest_change_source"], "operator_action");
        assert_eq!(state_json["last_operator_action_kind"], "chat");
        assert_eq!(state_json["last_operator_action_summary"], "hello-ui-core");
        assert_eq!(state_json["last_operator_action_origin"], "ui_dashboard");
        assert_eq!(state_json["last_operator_action_channel"], "global");
        assert!(
            state_json["last_operator_action_timestamp"]
                .as_u64()
                .unwrap_or(0)
                > 0
        );
    }

    #[tokio::test]
    async fn api_chat_send_handler_rejects_invalid_channel() {
        let app = app_with_state(test_state());
        let req = chat_send_request(
            serde_json::json!({
                "channel": "ai",
                "text": "hello-ui-core"
            }),
            Some("127.0.0.1:41001".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_chat_send_handler_rejects_empty_text() {
        let app = app_with_state(test_state());
        let req = chat_send_request(
            serde_json::json!({
                "channel": "global",
                "text": "   "
            }),
            Some("127.0.0.1:41002".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(json["error"], "text must not be empty");
    }

    #[tokio::test]
    async fn api_chat_send_handler_rejects_when_capability_is_unavailable() {
        let app = app_with_state(test_state());
        let req = chat_send_request(
            serde_json::json!({
                "channel": "global",
                "text": "hello-ui-core"
            }),
            Some("127.0.0.1:41002".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(
            json["error"],
            format!(
                "chat send unavailable: {}",
                expected_chat_send_unavailable_reason()
            )
        );
    }

    #[tokio::test]
    async fn api_chat_send_handler_rejects_non_loopback_request() {
        let app = app_with_state(test_state());
        let req = chat_send_request(
            serde_json::json!({
                "channel": "global",
                "text": "hello-ui-core"
            }),
            Some("10.0.0.5:41003".parse().expect("remote")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(json["error"], "chat send unavailable: local_only");
    }

    #[tokio::test]
    async fn api_chat_send_handler_rejects_long_message() {
        let app = app_with_state(test_state());
        let long_text = "x".repeat(33);
        let req = chat_send_request(
            serde_json::json!({
                "origin": "ui_dashboard",
                "channel": "global",
                "text": long_text
            }),
            Some("127.0.0.1:41004".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn api_chat_send_missing_content_type_returns_415() {
        let app = app_with_state(test_state());
        let req = chat_send_request_with_content_types(
            serde_json::json!({
                "channel": "global",
                "text": "hello-ui-core"
            })
            .to_string(),
            &[],
            Some("127.0.0.1:41005".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(json["error"], "content-type must be application/json");
    }

    #[tokio::test]
    async fn api_chat_send_non_json_content_type_returns_415() {
        let app = app_with_state(test_state());
        let req = chat_send_request_with_content_types(
            serde_json::json!({
                "channel": "global",
                "text": "hello-ui-core"
            })
            .to_string(),
            &["text/plain"],
            Some("127.0.0.1:41006".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(json["error"], "content-type must be application/json");
    }

    #[tokio::test]
    async fn api_chat_send_duplicate_content_type_returns_415() {
        let app = app_with_state(test_state());
        let req = chat_send_request_with_content_types(
            serde_json::json!({
                "channel": "global",
                "text": "hello-ui-core"
            })
            .to_string(),
            &["application/json", "application/json"],
            Some("127.0.0.1:41007".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(json["error"], "duplicate content-type header");
    }

    #[tokio::test]
    async fn api_chat_send_application_json_with_charset_is_accepted() {
        let app = app_with_state(test_state());
        let req = chat_send_request_with_content_types(
            serde_json::json!({
                "channel": "global",
                "text": "hello-ui-core"
            })
            .to_string(),
            &["application/json; charset=utf-8"],
            Some("127.0.0.1:41008".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(
            json["error"],
            format!(
                "chat send unavailable: {}",
                expected_chat_send_unavailable_reason()
            )
        );
    }

    #[tokio::test]
    async fn api_chat_send_oversized_body_returns_400() {
        let app = app_with_state(test_state());
        let oversized = format!(
            "{{\"channel\":\"global\",\"text\":\"x\",\"padding\":\"{}\"}}",
            "y".repeat(MAX_CHAT_REQUEST_BODY_BYTES)
        );
        let req = chat_send_request_with_content_types(
            oversized,
            &["application/json"],
            Some("127.0.0.1:41009".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(json["error"], "request body too large");
    }

    #[tokio::test]
    async fn api_chat_send_wrong_content_type_with_oversized_body_returns_415() {
        let app = app_with_state(test_state());
        let req = chat_send_request_with_content_types(
            "x".repeat(MAX_CHAT_REQUEST_BODY_BYTES + 1024),
            &["text/plain"],
            Some("127.0.0.1:41010".parse().expect("loopback")),
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(json["error"], "content-type must be application/json");
    }

    #[tokio::test]
    async fn admin_endpoints_are_404_by_default() {
        let app = app_with_state(test_state());

        let r1 = app
            .clone()
            .oneshot(admin_get_request("/audit/recent", None))
            .await
            .expect("audit/recent");
        assert_eq!(r1.status(), StatusCode::NOT_FOUND);

        let r2 = app
            .oneshot(admin_get_request("/security/status", None))
            .await
            .expect("security/status");
        assert_eq!(r2.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_endpoints_return_401_when_enabled_without_token() {
        let mut state = test_state();
        state.admin_api_enabled = true;
        state.admin_api_token = Some("admin-test-token".to_string());
        let app = app_with_state(state);

        let r1 = app
            .clone()
            .oneshot(admin_get_request("/audit/recent", None))
            .await
            .expect("audit/recent");
        assert_eq!(r1.status(), StatusCode::UNAUTHORIZED);

        let r2 = app
            .oneshot(admin_get_request("/security/status", None))
            .await
            .expect("security/status");
        assert_eq!(r2.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_endpoints_return_200_with_valid_bearer_token() {
        let mut state = test_state();
        state.admin_api_enabled = true;
        state.admin_api_token = Some("admin-test-token".to_string());
        let app = app_with_state(state);

        let auth = "Bearer admin-test-token";

        let r1 = app
            .clone()
            .oneshot(admin_get_request("/audit/recent", Some(auth)))
            .await
            .expect("audit/recent");
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = app
            .oneshot(admin_get_request("/security/status", Some(auth)))
            .await
            .expect("security/status");
        assert_eq!(r2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_is_404_by_default() {
        let app = app_with_state(test_state());
        let resp = app
            .oneshot(admin_get_request("/metrics", None))
            .await
            .expect("metrics");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn metrics_is_401_when_enabled_without_token() {
        let mut state = test_state();
        state.admin_api_enabled = true;
        state.admin_api_token = Some("admin-test-token".to_string());
        let app = app_with_state(state);
        let resp = app
            .oneshot(admin_get_request("/metrics", None))
            .await
            .expect("metrics");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn metrics_is_200_with_valid_token() {
        let mut state = test_state();
        state.admin_api_enabled = true;
        state.admin_api_token = Some("admin-test-token".to_string());
        let app = app_with_state(state);
        let resp = app
            .oneshot(admin_get_request(
                "/metrics",
                Some("Bearer admin-test-token"),
            ))
            .await
            .expect("metrics");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_endpoint_rejects_duplicate_authorization_header() {
        let mut state = test_state();
        state.admin_api_enabled = true;
        state.admin_api_token = Some("admin-test-token".to_string());
        let app = app_with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/security/status")
            .header(HEADER_AUTHORIZATION, "Bearer admin-test-token")
            .header(HEADER_AUTHORIZATION, "Bearer admin-test-token")
            .body(Body::empty())
            .expect("request");

        let resp = app.oneshot(req).await.expect("security/status");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
            .header("x-nonce", now.to_string())
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
            .header("x-nonce", now.to_string())
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
    async fn duplicate_x_signature_header_is_rejected() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"dup_sig",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request_with_headers(
            req_body,
            "test_active_secret",
            "active",
            "304deece-b224-4d16-8e1d-3efca0327ec4",
            now,
            &[("x-signature", "deadbeef".to_string())],
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn duplicate_x_request_id_header_is_rejected() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"dup_reqid",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request_with_headers(
            req_body,
            "test_active_secret",
            "active",
            "6ce9d8e5-6f0d-4fe4-bf6c-dfa8d06d2e6f",
            now,
            &[(
                "x-request-id",
                "4a8587a3-b0ef-4607-9bd9-2be42f645e7f".to_string(),
            )],
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn single_critical_headers_still_work() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"single_ok",
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
            "4d0bcf2f-df5f-45f5-b5f9-a56336ef8f02",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn redis_backend_unavailable_fails_closed_with_503() {
        let mut state = test_state();
        state.redis_guard = Some(RedisGuardConfig {
            client: redis::Client::open("redis://127.0.0.1:1/").expect("redis client"),
            key_prefix: "nexo_test".to_string(),
        });
        state.redis_op_timeout_ms = 10;
        let app = app_with_state(state);
        let now = now_utc_ms();
        let req_body = serde_json::json!({
            "user_id":"redis_unavailable",
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
            "a527aca8-a4db-4119-8838-15029e5135f2",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
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
    async fn evaluate_fails_closed_when_audit_lock_preexists_and_does_not_append() {
        let path =
            std::env::temp_dir().join(format!("nexo_api_audit_lock_fail_{}.jsonl", Uuid::new_v4()));
        let lock_path = lock_path_for_test(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
        fs::write(&lock_path, "locked").expect("create lock file");

        let app = app_with_state(AppState::for_tests(path.clone()));
        let now = now_utc_ms();
        let request_id = "4a6cbef7-2f34-4d7b-8cf5-b92724a63e9b";
        let req_body = serde_json::json!({
            "user_id":"lock_fail_user",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(req_body, "test_active_secret", "active", request_id, now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"], "failed to persist audit record");
        assert!(json.get("final_decision").is_none());

        let persisted = fs::read_to_string(&path).expect("read audit file after failure");
        assert!(persisted.trim().is_empty());
        assert!(lock_path.exists(), "pre-existing lock file should remain");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
    }

    #[tokio::test]
    async fn same_request_id_after_audit_lock_failure_returns_replay_conflict() {
        let path = std::env::temp_dir().join(format!(
            "nexo_api_replay_after_lock_failure_{}.jsonl",
            Uuid::new_v4()
        ));
        let lock_path = lock_path_for_test(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
        fs::write(&lock_path, "locked").expect("create lock file");

        let app = app_with_state(AppState::for_tests(path.clone()));
        let now = now_utc_ms();
        let request_id = "4b3ca3d2-7f69-4cb1-bd76-dfc53fd78e7d";
        let req_body = serde_json::json!({
            "user_id":"replay_after_lock_fail_user",
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
            request_id,
            now,
        );
        let req2 = signed_request(req_body, "test_active_secret", "active", request_id, now);

        let r1 = app.clone().oneshot(req1).await.expect("first response");
        assert_eq!(r1.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let r2 = app.oneshot(req2).await.expect("second response");
        assert_eq!(r2.status(), StatusCode::CONFLICT);
        let body = r2
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"], "replay detected: X-Request-Id already used");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
    }

    #[tokio::test]
    async fn evaluate_fails_closed_with_malformed_audit_tail_and_does_not_repair() {
        let path = std::env::temp_dir().join(format!(
            "nexo_api_malformed_tail_failure_{}.jsonl",
            Uuid::new_v4()
        ));
        let lock_path = lock_path_for_test(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
        let original = "this is not json\n";
        fs::write(&path, original).expect("write malformed audit tail");

        let app = app_with_state(AppState::for_tests(path.clone()));
        let now = now_utc_ms();
        let request_id = "2210e9c4-120c-4d8f-93d0-07899ca70d79";
        let req_body = serde_json::json!({
            "user_id":"malformed_tail_user",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(req_body, "test_active_secret", "active", request_id, now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"], "failed to persist audit record");
        assert!(json.get("final_decision").is_none());

        let after = fs::read_to_string(&path).expect("read audit file after failure");
        assert_eq!(after, original);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
    }

    #[tokio::test]
    async fn evaluate_success_persists_audit_record_with_chain_fields() {
        let path =
            std::env::temp_dir().join(format!("nexo_api_persist_success_{}.jsonl", Uuid::new_v4()));
        let lock_path = lock_path_for_test(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
        let app = app_with_state(AppState::for_tests(path.clone()));
        let now = now_utc_ms();
        let request_id = "31e9ff8c-8091-4296-a7a2-301e8bfb1897";
        let req_body = serde_json::json!({
            "user_id":"persisted_success_user",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(req_body, "test_active_secret", "active", request_id, now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);

        let persisted = fs::read_to_string(&path).expect("read persisted audit file");
        let lines: Vec<&str> = persisted
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 1, "expected single persisted audit record");
        let record: Value = serde_json::from_str(lines[0]).expect("parse persisted audit record");
        assert_eq!(record["request_id"], request_id);
        assert!(record["final_decision"].is_string());
        assert!(record["audit_hash"].is_string());
        assert_eq!(record["prev_record_hash"], Value::Null);
        let record_hash = record["record_hash"].as_str().expect("record_hash string");
        assert_eq!(record_hash.len(), 64);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
    }

    #[tokio::test]
    async fn evaluate_success_artifact_is_verified_by_zig_e2e() {
        let path =
            std::env::temp_dir().join(format!("nexo_api_zig_e2e_verify_{}.jsonl", Uuid::new_v4()));
        let lock_path = lock_path_for_test(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);

        let app = app_with_state(AppState::for_tests(path.clone()));
        let now = now_utc_ms();
        let request_id = "4f9b5d77-10df-4a72-9c64-2f982c06a4dd";
        let req_body = serde_json::json!({
            "user_id":"zig_e2e_user",
            "amount_cents":175_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1200,
            "ui_hash_valid":true
        });
        let req = signed_request(req_body, "test_active_secret", "active", request_id, now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);

        let persisted = fs::read_to_string(&path).expect("read persisted audit artifact");
        let lines: Vec<&str> = persisted
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 1, "expected exactly one persisted record");

        if find_zig_executable().is_none() {
            eprintln!("skipping zig verification in test: zig not found in PATH");
        } else {
            let verify_output = verify_with_zig_offline(&path)
                .expect("zig verifier must accept persisted runtime artifact");
            assert!(
                verify_output.contains("ok=1"),
                "unexpected zig verifier output: {verify_output}"
            );
        }

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
    }

    #[tokio::test]
    async fn readyz_remains_ready_without_preflight_even_if_existing_audit_is_malformed() {
        let path = std::env::temp_dir().join(format!(
            "nexo_readyz_no_preflight_malformed_{}.jsonl",
            Uuid::new_v4()
        ));
        let lock_path = lock_path_for_test(&path);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
        fs::write(&path, "not-json\n").expect("write malformed audit file");

        let app = app_with_state(AppState::for_tests(path.clone()));
        let req = Request::builder()
            .method("GET")
            .uri("/readyz")
            .body(Body::empty())
            .expect("request");
        let resp = app.oneshot(req).await.expect("readyz response");
        assert_eq!(resp.status(), StatusCode::OK);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&lock_path);
    }

    #[test]
    fn audit_preflight_helper_is_noop_when_disabled() {
        let path = std::env::temp_dir().join(format!(
            "nexo_preflight_helper_disabled_{}.jsonl",
            Uuid::new_v4()
        ));
        let _ = fs::remove_file(&path);
        fs::write(&path, "not-json\n").expect("write malformed audit file");
        let store = AuditStore::new(path.clone(), 10);

        apply_audit_preflight_requirement(&store, false)
            .expect("preflight helper must be noop when requirement is disabled");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn audit_preflight_helper_fails_when_enabled_and_artifact_is_malformed() {
        let path = std::env::temp_dir().join(format!(
            "nexo_preflight_helper_enabled_{}.jsonl",
            Uuid::new_v4()
        ));
        let _ = fs::remove_file(&path);
        fs::write(&path, "not-json\n").expect("write malformed audit file");
        let store = AuditStore::new(path.clone(), 10);

        let err = apply_audit_preflight_requirement(&store, true)
            .expect_err("preflight helper must fail when requirement is enabled");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn app_state_from_env_fails_closed_when_audit_preflight_required_and_artifact_is_malformed() {
        let _guard = env_lock().lock().expect("env lock");
        let path = std::env::temp_dir().join(format!(
            "nexo_from_env_preflight_enabled_{}.jsonl",
            Uuid::new_v4()
        ));
        let _ = fs::remove_file(&path);
        fs::write(&path, "not-json\n").expect("write malformed audit file");
        let path_str = path.display().to_string();

        let previous_audit_path = std::env::var("NEXO_AUDIT_PATH").ok();
        let previous_require_preflight = std::env::var("NEXO_REQUIRE_AUDIT_PREFLIGHT").ok();
        let previous_hmac_secret = std::env::var("NEXO_HMAC_SECRET").ok();
        let previous_hmac_secret_file = std::env::var("NEXO_HMAC_SECRET_FILE").ok();
        let previous_secret_provider = std::env::var("NEXO_SECRET_PROVIDER").ok();
        let previous_require_persistent_replay =
            std::env::var("NEXO_REQUIRE_PERSISTENT_REPLAY").ok();
        let previous_admin_api_enabled = std::env::var("NEXO_ADMIN_API_ENABLED").ok();

        std::env::set_var("NEXO_AUDIT_PATH", &path_str);
        std::env::set_var("NEXO_REQUIRE_AUDIT_PREFLIGHT", "true");
        std::env::set_var("NEXO_HMAC_SECRET", "test_active_secret");
        std::env::remove_var("NEXO_HMAC_SECRET_FILE");
        std::env::remove_var("NEXO_SECRET_PROVIDER");
        std::env::set_var("NEXO_REQUIRE_PERSISTENT_REPLAY", "false");
        std::env::set_var("NEXO_ADMIN_API_ENABLED", "false");

        let result = std::panic::catch_unwind(AppState::from_env);
        let (is_err, msg) = match result {
            Ok(_) => (false, String::new()),
            Err(payload) => (
                true,
                payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                    .unwrap_or_default(),
            ),
        };

        restore_env_var("NEXO_AUDIT_PATH", previous_audit_path);
        restore_env_var("NEXO_REQUIRE_AUDIT_PREFLIGHT", previous_require_preflight);
        restore_env_var("NEXO_HMAC_SECRET", previous_hmac_secret);
        restore_env_var("NEXO_HMAC_SECRET_FILE", previous_hmac_secret_file);
        restore_env_var("NEXO_SECRET_PROVIDER", previous_secret_provider);
        restore_env_var(
            "NEXO_REQUIRE_PERSISTENT_REPLAY",
            previous_require_persistent_replay,
        );
        restore_env_var("NEXO_ADMIN_API_ENABLED", previous_admin_api_enabled);

        assert!(
            is_err,
            "from_env must fail closed when preflight is required and artifact is malformed"
        );
        assert!(msg.contains("NEXO_REQUIRE_AUDIT_PREFLIGHT preflight failed"));
        assert!(msg.contains(path_str.as_str()));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn healthz_remains_shallow_liveness_even_with_malformed_audit_file() {
        let path =
            std::env::temp_dir().join(format!("nexo_healthz_shallow_{}.jsonl", Uuid::new_v4()));
        let _ = fs::remove_file(&path);
        fs::write(&path, "not-json\n").expect("write malformed audit file");

        let app = app_with_state(AppState::for_tests(path.clone()));
        let req = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())
            .expect("request");
        let resp = app.oneshot(req).await.expect("healthz response");
        assert_eq!(resp.status(), StatusCode::OK);

        let _ = fs::remove_file(path);
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
    async fn evaluate_http_valid_payload_with_explicit_nonce_returns_200() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let nonce = now.saturating_add(17);
        let request_id = "9d59ed1f-7e88-4f95-84c3-5242ac6fd94c";
        let payload = serde_json::json!({
            "user_id":"u_valid_nonce",
            "amount_cents":55_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1200,
            "ui_hash_valid":true,
            "request_id": request_id
        });
        let req = signed_request_with_nonce(
            payload,
            "test_active_secret",
            "active",
            request_id,
            now,
            nonce,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn evaluate_http_invalid_payload_returns_400() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let nonce = now.saturating_add(31);
        let request_id = "2fd8b499-c213-4d36-8731-0fbe3f6d4eaa";
        let payload = serde_json::json!({
            "user_id":"u_invalid_payload",
            "amount_cents":"not-a-number",
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1200,
            "ui_hash_valid":true,
            "request_id": request_id
        });
        let req = signed_request_with_nonce(
            payload,
            "test_active_secret",
            "active",
            request_id,
            now,
            nonce,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn evaluate_http_rejects_reused_nonce_for_same_origin() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let nonce = now.saturating_add(37);
        let payload_a = serde_json::json!({
            "user_id":"u_nonce_once",
            "amount_cents":51_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true,
            "request_id":"46acd47c-08b0-4dc5-bd42-1d58991e4014"
        });
        let payload_b = serde_json::json!({
            "user_id":"u_nonce_twice",
            "amount_cents":52_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now.saturating_add(1),
            "risk_bps":1000,
            "ui_hash_valid":true,
            "request_id":"9a65dc9b-a544-4a8d-98c7-6ba50f4fac6c"
        });

        let first = signed_request_with_nonce(
            payload_a,
            "test_active_secret",
            "active",
            "46acd47c-08b0-4dc5-bd42-1d58991e4014",
            now,
            nonce,
        );
        let second = signed_request_with_nonce(
            payload_b,
            "test_active_secret",
            "active",
            "9a65dc9b-a544-4a8d-98c7-6ba50f4fac6c",
            now.saturating_add(1),
            nonce,
        );

        let first_resp = app.clone().oneshot(first).await.expect("first response");
        assert_eq!(first_resp.status(), StatusCode::OK);
        let second_resp = app.oneshot(second).await.expect("second response");
        assert_eq!(second_resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn evaluate_http_hash_mismatch_returns_401() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let nonce = now.saturating_add(41);
        let request_id = "8e81ccf1-b8cf-4bf2-b653-42d67d0fe9e6";
        let signed_payload = serde_json::json!({
            "user_id":"u_hash_mismatch",
            "amount_cents":70_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true,
            "request_id": request_id
        });
        let tampered_payload = serde_json::json!({
            "user_id":"u_hash_mismatch",
            "amount_cents":170_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true,
            "request_id": request_id
        });
        let signed_body = signed_payload.to_string();
        let signature = compute_signature_with_nonce(
            "test_active_secret",
            "active",
            request_id,
            now,
            nonce,
            signed_body.as_bytes(),
        );
        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .header("x-signature", signature)
            .header("x-request-id", request_id)
            .header("x-timestamp", now.to_string())
            .header("x-nonce", nonce.to_string())
            .header("x-key-id", "active")
            .body(Body::from(tampered_payload.to_string()))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn evaluate_http_header_drift_request_id_mismatch_returns_400() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let nonce = now.saturating_add(59);
        let header_request_id = "49a09617-9e7b-428e-afad-dd0c2f32a437";
        let body_request_id = "51431d98-a53f-4df8-8075-c08725aa3b79";
        let payload = serde_json::json!({
            "user_id":"u_header_drift",
            "amount_cents":80_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true,
            "request_id": body_request_id
        });
        let req = signed_request_with_nonce(
            payload,
            "test_active_secret",
            "active",
            header_request_id,
            now,
            nonce,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
            .header("x-nonce", now.to_string())
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
            .header("x-nonce", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(body))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn missing_content_type_returns_415() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_missing_ct",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let body = payload.to_string();
        let request_id = "ec4e7231-eca8-40b7-a36d-61b46166ec77";
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
            .header("x-signature", signature)
            .header("x-request-id", request_id)
            .header("x-timestamp", now.to_string())
            .header("x-nonce", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(body))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn duplicate_content_type_returns_415() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_dup_ct",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let body = payload.to_string();
        let request_id = "0ece2a47-49d9-4810-a240-c3136a4fb34f";
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
            .header("content-type", "application/json")
            .header("content-type", "application/json")
            .header("x-signature", signature)
            .header("x-request-id", request_id)
            .header("x-timestamp", now.to_string())
            .header("x-nonce", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(body))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(json["error"], "duplicate content-type header");
    }

    #[tokio::test]
    async fn application_json_with_charset_is_accepted() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_json_charset",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let body = payload.to_string();
        let request_id = "c4bbebc6-c7a4-4b17-aac0-9743cb31ef6b";
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
            .header("content-type", "application/json; charset=utf-8")
            .header("x-signature", signature)
            .header("x-request-id", request_id)
            .header("x-timestamp", now.to_string())
            .header("x-nonce", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(body))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oversized_body_returns_body_too_large_even_with_invalid_signature() {
        let app = app_with_state(test_state());
        let now = now_utc_ms();
        let request_id = "2cac0fbd-d30b-4791-9ca7-c11250f838f6";
        let oversized = "x".repeat(MAX_REQUEST_BODY_BYTES + 1);
        let req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .header("x-signature", "deadbeef")
            .header("x-request-id", request_id)
            .header("x-timestamp", now.to_string())
            .header("x-nonce", now.to_string())
            .header("x-key-id", "active")
            .body(Body::from(oversized))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(json["error"], "request body too large");
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

    #[tokio::test]
    async fn forwarded_headers_are_ignored_by_default_for_rate_limit_identity() {
        let mut state = test_state();
        state.trust_proxy_headers = false;
        state.rate_limiter = Arc::new(RateLimiter::new(60_000, 1, 10_000));

        let app = app_with_state(state);
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_rl",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });

        let remote: SocketAddr = "127.0.0.1:41001".parse().expect("loopback");
        let req1 = signed_request_with_headers_and_remote_addr(
            payload.clone(),
            "test_active_secret",
            "active",
            "a7774f19-7c6a-4b04-9d47-5bf1c6f86b11",
            now,
            &[(HEADER_FORWARDED_FOR, "203.0.113.10".to_string())],
            remote,
        );
        let resp1 = app.clone().oneshot(req1).await.expect("response");
        assert_eq!(resp1.status(), StatusCode::OK);

        // Attempt to evade rate limit by spoofing X-Forwarded-For. This must fail by default.
        let req2 = signed_request_with_headers_and_remote_addr(
            payload,
            "test_active_secret",
            "active",
            "b5f2e10b-1b1a-4ae1-8b8c-66f762e6d971",
            now,
            &[(HEADER_FORWARDED_FOR, "203.0.113.11".to_string())],
            remote,
        );
        let resp2 = app.oneshot(req2).await.expect("response");
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn forwarded_headers_are_used_only_when_proxy_trust_is_enabled() {
        let mut state = test_state();
        state.trust_proxy_headers = true;
        state.rate_limiter = Arc::new(RateLimiter::new(60_000, 1, 10_000));

        let app = app_with_state(state);
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_rl",
            "amount_cents":50_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });

        let remote: SocketAddr = "127.0.0.1:41002".parse().expect("loopback");
        let req1 = signed_request_with_headers_and_remote_addr(
            payload.clone(),
            "test_active_secret",
            "active",
            "bf04edc1-52d3-4f8f-8f44-0f40c3cbe0a7",
            now,
            &[(HEADER_FORWARDED_FOR, "203.0.113.20".to_string())],
            remote,
        );
        let resp1 = app.clone().oneshot(req1).await.expect("response");
        assert_eq!(resp1.status(), StatusCode::OK);

        // When explicitly trusted, different X-Forwarded-For values produce different rate-limit identities.
        let req2 = signed_request_with_headers_and_remote_addr(
            payload,
            "test_active_secret",
            "active",
            "ccbdd4b3-4b9f-4d0a-8755-5cd2b5cba4d5",
            now.saturating_add(1),
            &[(HEADER_FORWARDED_FOR, "203.0.113.21".to_string())],
            remote,
        );
        let resp2 = app.oneshot(req2).await.expect("response");
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mtls_required_rejects_missing_attestation() {
        let mut state = test_state();
        state.mtls = Some(MtlsConfig {
            verified_header: HEADER_CLIENT_CERT_VERIFIED.to_string(),
            verified_value: "true".to_string(),
            client_id_header: HEADER_CLIENT_ID.to_string(),
            allowed_client_ids: None,
        });
        let app = app_with_state(state);
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_mtls",
            "amount_cents":10_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(
            payload,
            "test_active_secret",
            "active",
            "f2bbd501-cf68-468f-8e3f-d07f3a96209d",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn edge_guard_required_rejects_missing_header() {
        let mut state = test_state();
        state.edge_guard = Some(EdgeGuardConfig {
            header: HEADER_EDGE_AUTH.to_string(),
            secret: "edge-secret".to_string(),
        });
        let app = app_with_state(state);
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_edge",
            "amount_cents":10_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request(
            payload,
            "test_active_secret",
            "active",
            "31b930a1-0725-4011-8bf0-27f061203377",
            now,
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn edge_guard_required_accepts_valid_header() {
        let mut state = test_state();
        state.edge_guard = Some(EdgeGuardConfig {
            header: HEADER_EDGE_AUTH.to_string(),
            secret: "edge-secret".to_string(),
        });
        let app = app_with_state(state);
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_edge_ok",
            "amount_cents":10_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request_with_headers(
            payload,
            "test_active_secret",
            "active",
            "95fb761d-b798-4381-b0f1-9037c8a43f8a",
            now,
            &[(HEADER_EDGE_AUTH, "edge-secret".to_string())],
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mtls_required_accepts_valid_attestation() {
        let mut state = test_state();
        state.mtls = Some(MtlsConfig {
            verified_header: HEADER_CLIENT_CERT_VERIFIED.to_string(),
            verified_value: "true".to_string(),
            client_id_header: HEADER_CLIENT_ID.to_string(),
            allowed_client_ids: None,
        });
        let app = app_with_state(state);
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_mtls_ok",
            "amount_cents":10_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request_with_headers(
            payload,
            "test_active_secret",
            "active",
            "5e09338f-f3e8-4f57-b38f-5f0a61d70ee1",
            now,
            &[(HEADER_CLIENT_CERT_VERIFIED, "true".to_string())],
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn client_signature_required_rejects_missing_signature() {
        let mut state = test_state();
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        state.client_sig = Some(ClientSignatureConfig {
            client_id_header: HEADER_CLIENT_ID.to_string(),
            signature_header: HEADER_CLIENT_SIGNATURE.to_string(),
            public_keys: HashMap::from([("client-a".to_string(), signing.verifying_key())]),
        });
        let app = app_with_state(state);
        let now = now_utc_ms();
        let payload = serde_json::json!({
            "user_id":"u_sig_missing",
            "amount_cents":10_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let req = signed_request_with_headers(
            payload,
            "test_active_secret",
            "active",
            "0f02f7f5-f4c3-4bbf-ac43-9515caa1273c",
            now,
            &[(HEADER_CLIENT_ID, "client-a".to_string())],
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn client_signature_required_accepts_valid_signature() {
        let mut state = test_state();
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let verifying = signing.verifying_key();
        state.client_sig = Some(ClientSignatureConfig {
            client_id_header: HEADER_CLIENT_ID.to_string(),
            signature_header: HEADER_CLIENT_SIGNATURE.to_string(),
            public_keys: HashMap::from([("client-a".to_string(), verifying)]),
        });
        let app = app_with_state(state);
        let now = now_utc_ms();
        let request_id = "5c3574e4-3148-4f3f-aad8-08e291f0da4f";
        let payload = serde_json::json!({
            "user_id":"u_sig_ok",
            "amount_cents":10_000,
            "is_pep":false,
            "has_active_kyc":true,
            "timestamp_utc_ms":now,
            "risk_bps":1000,
            "ui_hash_valid":true
        });
        let body = payload.to_string();
        let msg =
            client_signature_message("client-a", "active", request_id, now, now, body.as_bytes());
        let sig = signing.sign(&msg);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let req = signed_request_with_headers(
            payload,
            "test_active_secret",
            "active",
            request_id,
            now,
            &[
                (HEADER_CLIENT_ID, "client-a".to_string()),
                (HEADER_CLIENT_SIGNATURE, sig_b64),
            ],
        );
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn evaluate_keeps_blake3_for_normal_low_risk() {
        let mut state = test_state();
        state.security_level = SecurityLevel::Normal;
        state.high_threshold_cents = 5_000_000;
        state.shake_bits = 512;
        let cfg = state.profile.engine_config();
        let app = app_with_state(state);
        let now = now_utc_ms();
        let request_id = "4ea0b45e-5987-4300-b17a-7c8bfab6c8f4";
        let payload = serde_json::json!({
            "user_id": "u_blake3_default",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true,
            "request_id": request_id
        });
        let req = signed_request(payload, "test_active_secret", "active", request_id, now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["hash_algo"], "blake3");
        let tx = TransactionIntent::new(
            "u_blake3_default",
            50_000,
            false,
            true,
            now,
            now,
            1_000,
            true,
        )
        .expect("tx");
        let (_decision, trace, _blake3_hash) = evaluate_with_config(&tx, cfg);
        let expected = audit_hash_with_algo(&trace, AuditHashAlgo::Blake3);
        assert_eq!(json["audit_hash"], expected);
    }

    #[tokio::test]
    async fn evaluate_uses_shake512_for_normal_high_risk() {
        let mut state = test_state();
        state.security_level = SecurityLevel::Normal;
        state.high_threshold_cents = 5_000_000;
        state.shake_bits = 512;
        let cfg = state.profile.engine_config();
        let app = app_with_state(state);
        let now = now_utc_ms();
        let request_id = "f9132745-80ec-49b7-b6f7-57f9d17ea8dc";
        let payload = serde_json::json!({
            "user_id": "u_shake_high_risk",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 8_500,
            "ui_hash_valid": true,
            "request_id": request_id
        });
        let req = signed_request(payload, "test_active_secret", "active", request_id, now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["hash_algo"], "shake256-512");
        let tx = TransactionIntent::new(
            "u_shake_high_risk",
            50_000,
            false,
            true,
            now,
            now,
            8_500,
            true,
        )
        .expect("tx");
        let (_decision, trace, _blake3_hash) = evaluate_with_config(&tx, cfg);
        let expected = audit_hash_with_algo(&trace, AuditHashAlgo::Shake256_512);
        assert_eq!(json["audit_hash"], expected);
    }

    #[tokio::test]
    async fn evaluate_uses_hybrid_when_incident() {
        let mut state = test_state();
        state.security_level = SecurityLevel::Incident;
        state.shake_bits = 256;
        let cfg = state.profile.engine_config();
        let app = app_with_state(state);
        let now = now_utc_ms();
        let request_id = "8f87384e-9a3f-4348-bbf8-f43fd2870520";
        let payload = serde_json::json!({
            "user_id": "u_incident_hybrid",
            "amount_cents": 10_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true,
            "request_id": request_id
        });
        let req = signed_request(payload, "test_active_secret", "active", request_id, now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["hash_algo"], "shake256-512+blake3-256");
        assert_eq!(json["audit_hash"].as_str().unwrap_or_default().len(), 192);
        let tx = TransactionIntent::new(
            "u_incident_hybrid",
            10_000,
            false,
            true,
            now,
            now,
            1_000,
            true,
        )
        .expect("tx");
        let (_decision, trace, _blake3_hash) = evaluate_with_config(&tx, cfg);
        let expected = audit_hash_with_algo(&trace, AuditHashAlgo::HybridShake512Blake3_256);
        assert_eq!(json["audit_hash"], expected);
    }

    #[tokio::test]
    async fn evaluate_includes_sha3_shadow_when_enabled() {
        let mut state = test_state();
        state.security_level = SecurityLevel::Normal;
        state.shake_bits = 512;
        state.sha3_shadow_enabled = true;
        let cfg = state.profile.engine_config();
        let app = app_with_state(state);
        let now = now_utc_ms();
        let request_id = "fb6f36f3-8452-4f60-8c6f-327f64ccaa53";
        let payload = serde_json::json!({
            "user_id": "u_shadow_on",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true,
            "request_id": request_id
        });
        let req = signed_request(payload, "test_active_secret", "active", request_id, now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["hash_algo"], "blake3");
        let tx = TransactionIntent::new("u_shadow_on", 50_000, false, true, now, now, 1_000, true)
            .expect("tx");
        let (_decision, trace, _blake3_hash) = evaluate_with_config(&tx, cfg);
        let expected_sha3 = audit_hash_with_algo(&trace, AuditHashAlgo::Shake256_512);
        assert_eq!(json["sha3_shadow"], expected_sha3);
        assert_eq!(json["shadow_hash_algo"], "shake256-512");
    }

    #[tokio::test]
    async fn evaluate_omits_sha3_shadow_when_disabled() {
        let mut state = test_state();
        state.security_level = SecurityLevel::Normal;
        state.sha3_shadow_enabled = false;
        let app = app_with_state(state);
        let now = now_utc_ms();
        let request_id = "5ff68fa1-b57e-4afd-be6f-f5cf95fe6f21";
        let payload = serde_json::json!({
            "user_id": "u_shadow_off",
            "amount_cents": 50_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": now,
            "risk_bps": 1_000,
            "ui_hash_valid": true,
            "request_id": request_id
        });
        let req = signed_request(payload, "test_active_secret", "active", request_id, now);
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body bytes")
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["hash_algo"], "blake3");
        assert!(json.get("sha3_shadow").is_none());
    }

    #[test]
    fn policy_switching_is_deterministic() {
        let a = select_audit_hash_algo(SecurityLevel::Normal, 7_999, 4_999_999, 5_000_000, 512);
        let b = select_audit_hash_algo(SecurityLevel::Normal, 7_999, 4_999_999, 5_000_000, 512);
        let c = select_audit_hash_algo(SecurityLevel::Normal, 8_000, 4_999_999, 5_000_000, 512);
        let d = select_audit_hash_algo(SecurityLevel::Incident, 1_000, 10_000, 5_000_000, 256);
        assert_eq!(a, b);
        assert_eq!(a, AuditHashAlgo::Blake3);
        assert_eq!(c, AuditHashAlgo::Shake256_512);
        assert_eq!(d, AuditHashAlgo::HybridShake512Blake3_256);
    }

    #[test]
    fn runtime_policy_never_selects_sha3_256() {
        let levels = [
            SecurityLevel::Normal,
            SecurityLevel::Elevated,
            SecurityLevel::Incident,
        ];
        let risk_values = [0u16, 7_999, 8_000, 10_000];
        let amount_values = [0u64, 4_999_999, 5_000_000, 9_999_999];
        let shake_bits_values = [256u16, 384, 512];

        for level in levels {
            for risk_bps in risk_values {
                for amount_cents in amount_values {
                    for shake_bits in shake_bits_values {
                        let selected = select_audit_hash_algo(
                            level,
                            risk_bps,
                            amount_cents,
                            5_000_000,
                            shake_bits,
                        );
                        assert_ne!(
                            selected,
                            AuditHashAlgo::Sha3_256,
                            "runtime policy must never emit sha3-256"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn runtime_policy_hash_algo_strings_do_not_include_sha3_256() {
        let emitted = [
            select_audit_hash_algo(SecurityLevel::Normal, 1_000, 10_000, 5_000_000, 256),
            select_audit_hash_algo(SecurityLevel::Normal, 9_000, 10_000, 5_000_000, 384),
            select_audit_hash_algo(SecurityLevel::Normal, 1_000, 5_000_000, 5_000_000, 512),
            select_audit_hash_algo(SecurityLevel::Incident, 1_000, 10_000, 5_000_000, 512),
        ];

        for algo in emitted {
            assert_ne!(algo.as_str(), "sha3-256");
        }
    }

    #[test]
    fn parse_vault_bundle_kv_v2_layout() {
        let payload = serde_json::json!({
            "data": {
                "data": {
                    "hmac_secret": "active_secret",
                    "hmac_secret_prev": "prev_secret",
                    "hmac_key_id": "active",
                    "hmac_key_id_prev": "previous"
                },
                "metadata": {
                    "version": 1
                }
            }
        });
        let bundle = parse_vault_bundle(
            &payload,
            "hmac_secret",
            "hmac_secret_prev",
            "hmac_key_id",
            "hmac_key_id_prev",
        )
        .expect("bundle");
        assert_eq!(bundle.active_secret.as_deref(), Some("active_secret"));
        assert_eq!(bundle.previous_secret.as_deref(), Some("prev_secret"));
        assert_eq!(bundle.active_key_id.as_deref(), Some("active"));
        assert_eq!(bundle.previous_key_id.as_deref(), Some("previous"));
    }

    #[test]
    fn parse_vault_bundle_kv_v1_layout() {
        let payload = serde_json::json!({
            "data": {
                "hmac_secret": "active_secret",
                "hmac_key_id": "active"
            }
        });
        let bundle = parse_vault_bundle(
            &payload,
            "hmac_secret",
            "hmac_secret_prev",
            "hmac_key_id",
            "hmac_key_id_prev",
        )
        .expect("bundle");
        assert_eq!(bundle.active_secret.as_deref(), Some("active_secret"));
        assert_eq!(bundle.active_key_id.as_deref(), Some("active"));
        assert!(bundle.previous_secret.is_none());
        assert!(bundle.previous_key_id.is_none());
    }

    #[test]
    fn pick_secret_source_uses_priority_bundle_file_env() {
        assert_eq!(
            pick_secret_source(
                Some("bundle_secret"),
                Some("file_secret".to_string()),
                Some("env_secret".to_string())
            ),
            Some("bundle_secret".to_string())
        );
        assert_eq!(
            pick_secret_source(
                None,
                Some("file_secret".to_string()),
                Some("env_secret".to_string())
            ),
            Some("file_secret".to_string())
        );
        assert_eq!(
            pick_secret_source(None, None, Some("env_secret".to_string())),
            Some("env_secret".to_string())
        );
    }

    #[test]
    fn parse_vault_bundle_rejects_invalid_shape() {
        let payload = serde_json::json!({"no_data": {}});
        let err = parse_vault_bundle(
            &payload,
            "hmac_secret",
            "hmac_secret_prev",
            "hmac_key_id",
            "hmac_key_id_prev",
        )
        .expect_err("expected parse error");
        assert_eq!(err, "vault payload missing data field");
    }

    #[test]
    fn parse_azure_access_token_response_ok() {
        let payload = serde_json::json!({
            "access_token": "token123",
            "expires_in": "3599"
        });
        assert_eq!(
            parse_azure_access_token_response(&payload),
            Some("token123".to_string())
        );
    }

    #[test]
    fn parse_azure_access_token_response_missing() {
        let payload = serde_json::json!({"token_type": "Bearer"});
        assert!(parse_azure_access_token_response(&payload).is_none());
    }

    #[test]
    fn parse_azure_secret_value_ok() {
        let payload = serde_json::json!({
            "value": "very_secret",
            "id": "https://vault.vault.azure.net/secrets/x"
        });
        assert_eq!(
            parse_azure_secret_value(&payload),
            Some("very_secret".to_string())
        );
    }

    #[test]
    fn build_azure_secret_url_contains_api_version() {
        let url = build_azure_secret_url("https://nexo-kv.vault.azure.net", "my-secret", "7.4");
        assert_eq!(
            url.as_str(),
            "https://nexo-kv.vault.azure.net/secrets/my-secret?api-version=7.4"
        );
    }

    #[test]
    fn parse_gcp_access_token_response_ok() {
        let payload = serde_json::json!({
            "access_token": "gcp_token_1",
            "expires_in": 3599
        });
        assert_eq!(
            parse_gcp_access_token_response(&payload),
            Some("gcp_token_1".to_string())
        );
    }

    #[test]
    fn parse_gcp_secret_access_payload_ok() {
        let payload = serde_json::json!({
            "payload": {
                "data": "c2VjcmV0X3ZhbHVl"
            }
        });
        assert_eq!(
            parse_gcp_secret_access_payload(&payload),
            Some("secret_value".to_string())
        );
    }

    #[test]
    fn build_gcp_secret_access_url_ok() {
        let url = build_gcp_secret_access_url("proj-1", "hmac-active");
        assert_eq!(
            url.as_str(),
            "https://secretmanager.googleapis.com/v1/projects/proj-1/secrets/hmac-active/versions/latest:access"
        );
    }

    #[test]
    fn parse_generic_secret_bundle_ok() {
        let payload = serde_json::json!({
            "hmac_secret": "active_s",
            "hmac_secret_prev": "prev_s",
            "hmac_key_id": "active",
            "hmac_key_id_prev": "previous"
        });
        let bundle = super::parse_generic_secret_bundle(
            &payload,
            "hmac_secret",
            "hmac_secret_prev",
            "hmac_key_id",
            "hmac_key_id_prev",
        )
        .expect("bundle");
        assert_eq!(bundle.active_secret.as_deref(), Some("active_s"));
        assert_eq!(bundle.previous_secret.as_deref(), Some("prev_s"));
        assert_eq!(bundle.active_key_id.as_deref(), Some("active"));
        assert_eq!(bundle.previous_key_id.as_deref(), Some("previous"));
    }
}
