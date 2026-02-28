use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use aws_config::BehaviorVersion;
use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use dashmap::DashMap;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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
const DEFAULT_SECRET_PROVIDER: &str = "none";
const DEFAULT_VAULT_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_AZURE_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_AZURE_API_VERSION: &str = "7.4";
const DEFAULT_GCP_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_AWS_RUNTIME_TIMEOUT_MS: u64 = 5_000;

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
const HEADER_CLIENT_CERT_VERIFIED: &str = "x-client-cert-verified";
const HEADER_CLIENT_ID: &str = "x-client-id";
const HEADER_CLIENT_SIGNATURE: &str = "x-client-signature";

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
    pub mtls: Option<MtlsConfig>,
    pub client_sig: Option<ClientSignatureConfig>,
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
}

#[derive(Debug)]
enum AuthError {
    Unauthorized(&'static str),
    RequestTimeout(&'static str),
    Conflict(&'static str),
}

#[derive(Debug, Clone, Default)]
struct SecretBundle {
    active_secret: Option<String>,
    previous_secret: Option<String>,
    active_key_id: Option<String>,
    previous_key_id: Option<String>,
}

impl AppState {
    pub fn from_env() -> Self {
        let path =
            std::env::var("NEXO_AUDIT_PATH").unwrap_or_else(|_| DEFAULT_AUDIT_PATH.to_string());
        let retention = std::env::var("NEXO_AUDIT_RETENTION")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_RETENTION);
        let bundle = load_secret_bundle_from_env();
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
        let mtls = load_mtls_config_from_env();
        let client_sig = load_client_signature_config_from_env();

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
            mtls,
            client_sig,
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
            mtls: None,
            client_sig: None,
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
            mtls: None,
            client_sig: None,
        }
    }
}

fn load_secret_bundle_from_env() -> Option<SecretBundle> {
    let provider = std::env::var("NEXO_SECRET_PROVIDER")
        .unwrap_or_else(|_| DEFAULT_SECRET_PROVIDER.to_string())
        .to_ascii_lowercase();

    match provider.as_str() {
        "" | "none" => None,
        "vault" => Some(load_vault_bundle_from_env()),
        "azure" => Some(load_azure_bundle_from_env()),
        "gcp" => Some(load_gcp_bundle_from_env()),
        "aws" => Some(load_aws_bundle_from_env()),
        other => panic!("unsupported NEXO_SECRET_PROVIDER '{other}'"),
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
        prev_record_hash: None,
        record_hash: None,
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
    verify_mtls_attestation(state, headers)?;
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

    verify_client_signature(state, headers, &request_id, timestamp_ms, key_id, body)?;

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

fn verify_mtls_attestation(state: &AppState, headers: &HeaderMap) -> Result<(), AuthError> {
    let Some(cfg) = &state.mtls else {
        return Ok(());
    };
    let verified = extract_header(headers, &cfg.verified_header)
        .ok_or(AuthError::Unauthorized("mTLS attestation header missing"))?
        .to_ascii_lowercase();
    if verified != cfg.verified_value {
        return Err(AuthError::Unauthorized("mTLS attestation invalid"));
    }
    if let Some(allowed) = &cfg.allowed_client_ids {
        let client_id = extract_header(headers, &cfg.client_id_header)
            .ok_or(AuthError::Unauthorized("client id missing for mTLS policy"))?;
        if !allowed.contains(client_id) {
            return Err(AuthError::Unauthorized(
                "client id not allowed by mTLS policy",
            ));
        }
    }
    Ok(())
}

fn verify_client_signature(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &str,
    timestamp_ms: u64,
    key_id: &str,
    body: &[u8],
) -> Result<(), AuthError> {
    let Some(cfg) = &state.client_sig else {
        return Ok(());
    };
    let client_id = extract_header(headers, &cfg.client_id_header)
        .ok_or(AuthError::Unauthorized("missing client id header"))?;
    let sig_b64 = extract_header(headers, &cfg.signature_header)
        .ok_or(AuthError::Unauthorized("missing client signature header"))?;
    let pubkey = cfg
        .public_keys
        .get(client_id)
        .ok_or(AuthError::Unauthorized("unknown client id"))?;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|_| AuthError::Unauthorized("invalid client signature format"))?;
    let sig_bytes: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::Unauthorized("invalid client signature length"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    let msg = client_signature_message(client_id, key_id, request_id, timestamp_ms, body);
    pubkey
        .verify(&msg, &signature)
        .map_err(|_| AuthError::Unauthorized("invalid client signature"))?;
    Ok(())
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

fn extract_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
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

fn client_signature_message(
    client_id: &str,
    key_id: &str,
    request_id: &str,
    timestamp_ms: u64,
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
    let mtls_mode = if state.mtls.is_some() {
        "required"
    } else {
        "disabled"
    };
    let client_signature_mode = if state.client_sig.is_some() {
        "required"
    } else {
        "disabled"
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
            mtls_mode: mtls_mode.to_string(),
            client_signature_mode: client_signature_mode.to_string(),
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
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::collections::HashMap;
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

    fn signed_request_with_headers(
        payload: serde_json::Value,
        secret: &str,
        key_id: &str,
        request_id: &str,
        timestamp_ms: u64,
        extra_headers: &[(&str, String)],
    ) -> Request<Body> {
        let body = payload.to_string();
        let signature =
            compute_signature(secret, key_id, request_id, timestamp_ms, body.as_bytes());
        let mut req = Request::builder()
            .method("POST")
            .uri("/evaluate")
            .header("content-type", "application/json")
            .header("x-signature", signature)
            .header("x-request-id", request_id)
            .header("x-timestamp", timestamp_ms.to_string())
            .header("x-key-id", key_id);
        for (k, v) in extra_headers {
            req = req.header(*k, v);
        }
        req.body(Body::from(body)).expect("request")
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
        let msg = client_signature_message("client-a", "active", request_id, now, body.as_bytes());
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
