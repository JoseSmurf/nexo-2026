use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier};

use axum::http::HeaderMap;

use super::errors::AuthError;
use super::replay::{
    enforce_replay_capacity, local_replay_and_nonce_check, local_replay_and_nonce_store,
    maybe_purge_replay_cache,
};
use super::{
    client_signature_message, decode_hex_32, extract_header, hmac_blake3, is_uuid_v4,
    is_valid_key_id, now_utc_ms, signing_message, timing_safe_eq_32, AppState, HEADER_KEY_ID,
    HEADER_NONCE, HEADER_REQUEST_ID, HEADER_SIGNATURE, HEADER_TIMESTAMP, MAX_KEY_ID_LEN,
    MAX_REQUEST_ID_LEN,
};

pub(super) fn validate_security_headers(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(String, u64, u64, String), AuthError> {
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
    if headers.get_all(HEADER_NONCE).iter().count() > 1 {
        return Err(AuthError::Unauthorized("duplicate X-Nonce header"));
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
    let nonce = extract_header(headers, HEADER_NONCE)
        .ok_or(AuthError::Unauthorized("missing X-Nonce header"))?
        .parse::<u64>()
        .map_err(|_| AuthError::Unauthorized("invalid X-Nonce header"))?;
    if nonce == 0 {
        return Err(AuthError::Unauthorized("invalid X-Nonce header"));
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

    verify_client_signature(
        state,
        headers,
        &request_id,
        timestamp_ms,
        nonce,
        key_id,
        body,
    )?;

    let mut nonce_cache_key = None;
    if state.redis_guard.is_none() {
        maybe_purge_replay_cache(state, now);
        enforce_replay_capacity(state);
        nonce_cache_key = Some(local_replay_and_nonce_check(
            state,
            &request_id,
            key_id,
            nonce,
        )?);
    }

    let signing_bytes = signing_message(key_id, &request_id, timestamp_ms, nonce, body);
    let expected = hmac_blake3(&key.secret, &signing_bytes);
    if !timing_safe_eq_32(&signature, &expected) {
        return Err(AuthError::Unauthorized("invalid request signature"));
    }

    if let Some(nonce_key) = nonce_cache_key.as_deref() {
        local_replay_and_nonce_store(state, &request_id, nonce_key, now);
    }

    state
        .key_usage
        .entry(key.id.clone())
        .and_modify(|v| *v += 1)
        .or_insert(1);
    Ok((request_id, timestamp_ms, nonce, key.id.clone()))
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
    nonce: u64,
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
    let msg = client_signature_message(client_id, key_id, request_id, timestamp_ms, nonce, body);
    pubkey
        .verify(&msg, &signature)
        .map_err(|_| AuthError::Unauthorized("invalid client signature"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{BENCH_HMAC_SECRET, BENCH_KEY_ID};
    use axum::http::{HeaderMap, HeaderValue};
    use serde_json::json;
    use uuid::Uuid;

    fn signed_input(
        state: &AppState,
        request_id: &str,
        timestamp_ms: u64,
        nonce: u64,
    ) -> (Vec<u8>, HeaderMap) {
        let body = json!({
            "user_id": "auth_test_user",
            "amount_cents": 150_000,
            "is_pep": false,
            "has_active_kyc": true,
            "timestamp_utc_ms": timestamp_ms,
            "risk_bps": 1200,
            "ui_hash_valid": true,
            "request_id": request_id
        })
        .to_string()
        .into_bytes();

        let key_id = state.auth.active.id.clone();
        let signature = super::super::compute_signature_with_nonce(
            BENCH_HMAC_SECRET,
            &key_id,
            request_id,
            timestamp_ms,
            nonce,
            &body,
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_SIGNATURE,
            HeaderValue::from_str(&signature).expect("signature header"),
        );
        headers.insert(
            HEADER_REQUEST_ID,
            HeaderValue::from_str(request_id).expect("request id header"),
        );
        headers.insert(
            HEADER_TIMESTAMP,
            HeaderValue::from_str(&timestamp_ms.to_string()).expect("timestamp header"),
        );
        headers.insert(
            HEADER_NONCE,
            HeaderValue::from_str(&nonce.to_string()).expect("nonce header"),
        );
        headers.insert(
            HEADER_KEY_ID,
            HeaderValue::from_str(&key_id).expect("key id header"),
        );

        (body, headers)
    }

    #[test]
    fn valid_signed_headers_are_accepted_and_key_usage_is_recorded() {
        let state = AppState::for_bench();
        let request_id = Uuid::new_v4().to_string();
        let timestamp = now_utc_ms();
        let nonce = timestamp.saturating_add(111);
        let (body, headers) = signed_input(&state, &request_id, timestamp, nonce);

        let (parsed_request_id, parsed_timestamp, parsed_nonce, used_key_id) =
            validate_security_headers(&state, &headers, &body).expect("valid headers");

        assert_eq!(parsed_request_id, request_id);
        assert_eq!(parsed_timestamp, timestamp);
        assert_eq!(parsed_nonce, nonce);
        assert_eq!(used_key_id, BENCH_KEY_ID);
        assert_eq!(
            state.key_usage.get(BENCH_KEY_ID).map(|v| *v.value()),
            Some(1),
            "key usage should be tracked on successful auth"
        );
    }

    #[test]
    fn duplicate_signature_header_is_rejected_fail_closed() {
        let state = AppState::for_bench();
        let request_id = Uuid::new_v4().to_string();
        let timestamp = now_utc_ms();
        let nonce = timestamp.saturating_add(222);
        let (body, mut headers) = signed_input(&state, &request_id, timestamp, nonce);
        headers.append(HEADER_SIGNATURE, HeaderValue::from_static("00"));

        let err = validate_security_headers(&state, &headers, &body).expect_err("must fail");
        assert!(matches!(
            err,
            AuthError::Unauthorized("duplicate X-Signature header")
        ));
    }

    #[test]
    fn zero_nonce_is_rejected_fail_closed() {
        let state = AppState::for_bench();
        let request_id = Uuid::new_v4().to_string();
        let timestamp = now_utc_ms();
        let (body, headers) = signed_input(&state, &request_id, timestamp, 0);

        let err = validate_security_headers(&state, &headers, &body).expect_err("must fail");
        assert!(matches!(
            err,
            AuthError::Unauthorized("invalid X-Nonce header")
        ));
    }

    #[test]
    fn stale_timestamp_is_rejected_with_timeout() {
        let state = AppState::for_bench();
        let request_id = Uuid::new_v4().to_string();
        let now = now_utc_ms();
        let stale_timestamp = now.saturating_sub(state.auth_window_ms.saturating_add(1));
        let nonce = stale_timestamp.saturating_add(333);
        let (body, headers) = signed_input(&state, &request_id, stale_timestamp, nonce);

        let err = validate_security_headers(&state, &headers, &body).expect_err("must fail");
        assert!(matches!(
            err,
            AuthError::RequestTimeout("timestamp outside configured security window")
        ));
    }

    #[test]
    fn nonce_reuse_for_same_sender_is_rejected_fail_closed() {
        let state = AppState::for_bench();
        let timestamp = now_utc_ms();
        let nonce = timestamp.saturating_add(444);

        let request_id_a = Uuid::new_v4().to_string();
        let (body_a, headers_a) = signed_input(&state, &request_id_a, timestamp, nonce);
        validate_security_headers(&state, &headers_a, &body_a).expect("first request should pass");

        let request_id_b = Uuid::new_v4().to_string();
        let (body_b, headers_b) = signed_input(&state, &request_id_b, timestamp, nonce);
        let err =
            validate_security_headers(&state, &headers_b, &body_b).expect_err("must reject reuse");
        assert!(matches!(
            err,
            AuthError::Conflict("replay detected: X-Nonce already used for sender")
        ));
    }
}
