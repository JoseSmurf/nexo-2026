use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier};

use axum::http::HeaderMap;

use super::errors::AuthError;
use super::replay::{enforce_replay_capacity, maybe_purge_replay_cache};
use super::{
    client_signature_message, decode_hex_32, extract_header, hmac_blake3, is_uuid_v4,
    is_valid_key_id, now_utc_ms, signing_message, timing_safe_eq_32, AppState, HEADER_KEY_ID,
    HEADER_REQUEST_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP, MAX_KEY_ID_LEN, MAX_REQUEST_ID_LEN,
};

pub(super) fn validate_security_headers(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(String, u64, String), AuthError> {
    if headers.get_all(HEADER_SIGNATURE).iter().count() > 1 {
        return Err(AuthError::Unauthorized("duplicate X-Signature header"));
    }
    if headers.get_all(HEADER_REQUEST_ID).iter().count() > 1 {
        return Err(AuthError::Unauthorized("duplicate X-Request-Id header"));
    }
    if headers.get_all(HEADER_KEY_ID).iter().count() > 1 {
        return Err(AuthError::Unauthorized("duplicate X-Key-Id header"));
    }
    if headers.get_all(HEADER_TIMESTAMP).iter().count() > 1 {
        return Err(AuthError::Unauthorized("duplicate X-Timestamp header"));
    }

    verify_edge_guard(state, headers)?;
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

    if state.redis_guard.is_none() {
        maybe_purge_replay_cache(state, now);
        enforce_replay_capacity(state);
        if state.replay_cache.contains_key(&request_id) {
            return Err(AuthError::Conflict(
                "replay detected: X-Request-Id already used",
            ));
        }
    }

    let signing_bytes = signing_message(key_id, &request_id, timestamp_ms, body);
    let expected = hmac_blake3(&key.secret, &signing_bytes);
    if !timing_safe_eq_32(&signature, &expected) {
        return Err(AuthError::Unauthorized("invalid request signature"));
    }

    if state.redis_guard.is_none() {
        state.replay_cache.insert(request_id.clone(), now);
    }
    state
        .key_usage
        .entry(key.id.clone())
        .and_modify(|v| *v += 1)
        .or_insert(1);
    Ok((request_id, timestamp_ms, key.id.clone()))
}

fn verify_edge_guard(state: &AppState, headers: &HeaderMap) -> Result<(), AuthError> {
    let Some(cfg) = &state.edge_guard else {
        return Ok(());
    };
    let provided = extract_header(headers, &cfg.header)
        .ok_or(AuthError::Unauthorized("missing edge attestation header"))?;
    if provided != cfg.secret {
        return Err(AuthError::Unauthorized("invalid edge attestation header"));
    }
    Ok(())
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
