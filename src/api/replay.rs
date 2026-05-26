use std::sync::atomic::Ordering;
use std::time::Duration;

use super::errors::AuthError;
use super::AppState;

fn nonce_replay_key(origin: &str, nonce: u64) -> String {
    format!("nonce:{origin}:{nonce}")
}

pub(super) fn validate_persistent_replay_requirement(
    require_persistent_replay: bool,
    redis_configured: bool,
) -> Result<(), &'static str> {
    if require_persistent_replay && !redis_configured {
        return Err("NEXO_REQUIRE_PERSISTENT_REPLAY=true requires a persistent replay backend (set NEXO_REDIS_URL)");
    }
    Ok(())
}

pub(super) fn maybe_purge_replay_cache(state: &AppState, now_ms: u64) {
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

pub(super) fn enforce_replay_capacity(state: &AppState) {
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

pub(super) async fn distributed_replay_check_and_store(
    state: &AppState,
    request_id: &str,
) -> Result<(), AuthError> {
    let Some(redis_guard) = &state.redis_guard else {
        return Ok(());
    };
    let key = format!("{}:replay:{}", redis_guard.key_prefix, request_id);
    let mut conn = tokio::time::timeout(
        Duration::from_millis(state.redis_op_timeout_ms),
        redis_guard.client.get_multiplexed_async_connection(),
    )
    .await
    .map_err(|_| AuthError::ServiceUnavailable("replay backend unavailable"))?
    .map_err(|_| AuthError::ServiceUnavailable("replay backend unavailable"))?;
    let mut cmd_set = redis::cmd("SET");
    cmd_set
        .arg(&key)
        .arg("1")
        .arg("PX")
        .arg(state.replay_ttl_ms)
        .arg("NX");
    let result: Option<String> = tokio::time::timeout(
        Duration::from_millis(state.redis_op_timeout_ms),
        cmd_set.query_async(&mut conn),
    )
    .await
    .map_err(|_| AuthError::ServiceUnavailable("replay backend unavailable"))?
    .map_err(|_| AuthError::ServiceUnavailable("replay backend unavailable"))?;
    if result.is_none() {
        return Err(AuthError::Conflict(
            "replay detected: X-Request-Id already used",
        ));
    }
    Ok(())
}

pub(super) async fn distributed_nonce_check_and_store(
    state: &AppState,
    origin: &str,
    nonce: u64,
) -> Result<(), AuthError> {
    let Some(redis_guard) = &state.redis_guard else {
        return Ok(());
    };
    let key = format!(
        "{}:{}",
        redis_guard.key_prefix,
        nonce_replay_key(origin, nonce)
    );
    let mut conn = tokio::time::timeout(
        Duration::from_millis(state.redis_op_timeout_ms),
        redis_guard.client.get_multiplexed_async_connection(),
    )
    .await
    .map_err(|_| AuthError::ServiceUnavailable("replay backend unavailable"))?
    .map_err(|_| AuthError::ServiceUnavailable("replay backend unavailable"))?;
    let mut cmd_set = redis::cmd("SET");
    cmd_set
        .arg(&key)
        .arg("1")
        .arg("PX")
        .arg(state.replay_ttl_ms)
        .arg("NX");
    let result: Option<String> = tokio::time::timeout(
        Duration::from_millis(state.redis_op_timeout_ms),
        cmd_set.query_async(&mut conn),
    )
    .await
    .map_err(|_| AuthError::ServiceUnavailable("replay backend unavailable"))?
    .map_err(|_| AuthError::ServiceUnavailable("replay backend unavailable"))?;
    if result.is_none() {
        return Err(AuthError::Conflict(
            "replay detected: X-Nonce already used for sender",
        ));
    }
    Ok(())
}

pub(super) fn local_replay_and_nonce_check(
    state: &AppState,
    request_id: &str,
    origin: &str,
    nonce: u64,
) -> Result<String, AuthError> {
    if state.replay_cache.contains_key(request_id) {
        return Err(AuthError::Conflict(
            "replay detected: X-Request-Id already used",
        ));
    }
    let nonce_key = nonce_replay_key(origin, nonce);
    if state.replay_cache.contains_key(&nonce_key) {
        return Err(AuthError::Conflict(
            "replay detected: X-Nonce already used for sender",
        ));
    }
    Ok(nonce_key)
}

pub(super) fn local_replay_and_nonce_store(
    state: &AppState,
    request_id: &str,
    nonce_key: &str,
    now_ms: u64,
) {
    state.replay_cache.insert(request_id.to_string(), now_ms);
    state.replay_cache.insert(nonce_key.to_string(), now_ms);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_replay_not_required_allows_no_redis() {
        validate_persistent_replay_requirement(false, false).expect("should be allowed");
    }

    #[test]
    fn persistent_replay_required_without_redis_is_invalid() {
        validate_persistent_replay_requirement(true, false)
            .expect_err("must fail closed when persistent replay is required");
    }

    #[test]
    fn persistent_replay_required_with_redis_is_valid() {
        validate_persistent_replay_requirement(true, true).expect("should be allowed");
    }
}
