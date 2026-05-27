use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use uuid::Uuid;

use super::{
    extract_header, AppState, AuditQuery, AuditRecentResponse, ErrorResponse,
    SecurityStatusResponse, HEADER_AUTHORIZATION,
};
use crate::telemetry::MetricsSnapshot;

pub(super) async fn metrics_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.admin_api_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_valid_admin_bearer_token(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let snapshot: MetricsSnapshot = state.metrics.snapshot();
    (StatusCode::OK, Json(snapshot)).into_response()
}

pub(super) async fn audit_recent_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    if !state.admin_api_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_valid_admin_bearer_token(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

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

pub(super) async fn security_status_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.admin_api_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_valid_admin_bearer_token(&state, &headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

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
    let edge_guard_mode = if state.edge_guard.is_some() {
        "required"
    } else {
        "disabled"
    };
    let distributed_guard_mode = if state.redis_guard.is_some() {
        "redis"
    } else {
        "in_memory"
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
            edge_guard_mode: edge_guard_mode.to_string(),
            distributed_guard_mode: distributed_guard_mode.to_string(),
        }),
    )
        .into_response()
}

fn is_valid_admin_bearer_token(state: &AppState, headers: &HeaderMap) -> bool {
    let auth_count = headers.get_all(HEADER_AUTHORIZATION).iter().count();
    if auth_count != 1 {
        return false;
    }
    let Some(expected) = state.admin_api_token.as_deref() else {
        return false;
    };
    let Some(raw) = extract_header(headers, HEADER_AUTHORIZATION) else {
        return false;
    };
    let Some(provided) = raw.strip_prefix("Bearer ") else {
        return false;
    };
    provided == expected
}
