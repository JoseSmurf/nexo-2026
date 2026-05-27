use std::net::SocketAddr;
use std::time::Instant;

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::{info, warn};
use uuid::Uuid;

use super::auth::validate_security_headers;
use super::rate_limit::distributed_rate_limit_allow;
use super::replay::{distributed_nonce_check_and_store, distributed_replay_check_and_store};
use super::{
    auth_error_response, error_response, extract_header, is_uuid_v4, now_utc_ms,
    signed_json_response, AppState, EvaluateRequest, EvaluateResponse, HEADER_FORWARDED_FOR,
    HEADER_REAL_IP, HEADER_REQUEST_ID, HEADER_SIGNATURE, MAX_REQUEST_BODY_BYTES, MAX_USER_ID_LEN,
};
use crate::audit_store::AuditRecord;
use crate::transport::http_adapter::{build_transport_envelope, HttpTransportEnvelopeInput};
use crate::{evaluate_with_config, TransactionIntent};

pub(super) async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Err(msg) = super::validate_json_content_type(&parts.headers) {
        let request_id = extract_header(&parts.headers, HEADER_REQUEST_ID)
            .map(ToString::to_string)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, &state, &request_id, msg);
    }

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
    let connect_info = parts.extensions.get::<ConnectInfo<SocketAddr>>();
    let ip = extract_client_ip(connect_info, &parts.headers, state.trust_proxy_headers);
    let user_id = extract_user_id_from_body(&body_bytes).unwrap_or_else(|| "unknown".to_string());

    let allow_result = if state.redis_guard.is_some() {
        distributed_rate_limit_allow(&state, &ip, &user_id, now).await
    } else {
        Ok(state.rate_limiter.allow(&ip, &user_id, now))
    };
    let allowed = match allow_result {
        Ok(v) => v,
        Err(msg) => {
            let request_id = extract_header(&parts.headers, HEADER_REQUEST_ID)
                .map(ToString::to_string)
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            return error_response(StatusCode::SERVICE_UNAVAILABLE, &state, &request_id, msg);
        }
    };
    if !allowed {
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

pub(super) async fn evaluate_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let start = Instant::now();
    let (header_request_id, header_timestamp, header_nonce, key_used_id) =
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

    if state.redis_guard.is_some() {
        if let Err(err) = distributed_replay_check_and_store(&state, &header_request_id).await {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            return auth_error_response(&state, header_request_id, err);
        }
        if let Err(err) =
            distributed_nonce_check_and_store(&state, &key_used_id, header_nonce).await
        {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            return auth_error_response(&state, header_request_id, err);
        }
    }

    let payload_json: serde_json::Value = match serde_json::from_slice(&body) {
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

    let signature_header = match extract_header(&headers, HEADER_SIGNATURE) {
        Some(value) => value,
        None => {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            return auth_error_response(
                &state,
                header_request_id.clone(),
                super::errors::AuthError::Unauthorized("missing X-Signature header"),
            );
        }
    };

    if let Err(err) = build_transport_envelope(HttpTransportEnvelopeInput {
        request_id: &header_request_id,
        timestamp_utc_ms: header_timestamp,
        nonce: header_nonce,
        key_id: &key_used_id,
        signature: signature_header,
        payload_json: &payload_json,
    }) {
        state
            .metrics
            .observe_error(start.elapsed().as_nanos() as u64);
        warn!(
            request_id = %header_request_id,
            error = %err,
            "evaluate rejected invalid transport envelope"
        );
        return error_response(
            StatusCode::BAD_REQUEST,
            &state,
            &header_request_id,
            "invalid transport envelope",
        );
    }

    let req: EvaluateRequest = match serde_json::from_value(payload_json) {
        Ok(req) => req,
        Err(_) => {
            state
                .metrics
                .observe_error(start.elapsed().as_nanos() as u64);
            return error_response(
                StatusCode::BAD_REQUEST,
                &state,
                &header_request_id,
                "invalid evaluate request payload",
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

    let (final_decision, trace, blake3_hash) =
        evaluate_with_config(&tx, state.profile.engine_config());
    let (audit_hash, selected_hash_algo, sha3_shadow) =
        super::audit::resolve_audit_hash(&state, &tx, &trace, &blake3_hash);
    let hash_algo = selected_hash_algo.as_str().to_string();

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
        hash_algo: hash_algo.clone(),
        sha3_shadow: sha3_shadow.clone(),
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
        hash_algo,
        shadow_hash_algo: if sha3_shadow.is_some() {
            Some(
                super::audit::shake_algo_from_bits(state.shake_bits)
                    .as_str()
                    .to_string(),
            )
        } else {
            None
        },
        sha3_shadow,
    };
    signed_json_response(StatusCode::OK, &state, &header_request_id, &response)
}

fn peer_ip_from_connect_info(connect_info: Option<&ConnectInfo<SocketAddr>>) -> Option<String> {
    let ConnectInfo(addr) = connect_info?;
    Some(addr.ip().to_string())
}

fn extract_client_ip(
    connect_info: Option<&ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    trust_proxy_headers: bool,
) -> String {
    if trust_proxy_headers {
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
        return peer_ip_from_connect_info(connect_info).unwrap_or_else(|| "unknown".to_string());
    }

    // Default fail-safe posture: do not trust spoofable forwarded identity headers.
    peer_ip_from_connect_info(connect_info).unwrap_or_else(|| "unknown".to_string())
}

fn extract_user_id_from_body(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("user_id")?.as_str().map(ToString::to_string)
}
