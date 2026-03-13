use std::sync::atomic::Ordering;
use std::time::Duration;

use super::errors::AuthError;
use super::AppState;

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
