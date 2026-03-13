use std::sync::atomic::Ordering;
use std::time::Duration;

use super::AppState;

pub(super) async fn distributed_rate_limit_allow(
    state: &AppState,
    ip_key: &str,
    user_key: &str,
    now_ms: u64,
) -> Result<bool, &'static str> {
    let Some(redis_guard) = &state.redis_guard else {
        return Ok(state.rate_limiter.allow(ip_key, user_key, now_ms));
    };
    let window_id = now_ms / state.rate_limiter.window_ms.max(1);
    let key_ip = format!("{}:rl:ip:{}:{}", redis_guard.key_prefix, ip_key, window_id);
    let key_user = format!(
        "{}:rl:user:{}:{}",
        redis_guard.key_prefix, user_key, window_id
    );
    let ttl_ms = (state.rate_limiter.window_ms.saturating_mul(2)).max(1000);

    let mut conn = tokio::time::timeout(
        Duration::from_millis(state.redis_op_timeout_ms),
        redis_guard.client.get_multiplexed_async_connection(),
    )
    .await
    .map_err(|_| "rate limit backend unavailable")?
    .map_err(|_| "rate limit backend unavailable")?;
    let mut cmd_ip_incr = redis::cmd("INCR");
    cmd_ip_incr.arg(&key_ip);
    let ip_count: i64 = tokio::time::timeout(
        Duration::from_millis(state.redis_op_timeout_ms),
        cmd_ip_incr.query_async(&mut conn),
    )
    .await
    .map_err(|_| "rate limit backend unavailable")?
    .map_err(|_| "rate limit backend unavailable")?;
    if ip_count == 1 {
        let mut cmd_ip_expire = redis::cmd("PEXPIRE");
        cmd_ip_expire.arg(&key_ip).arg(ttl_ms);
        let _: () = tokio::time::timeout(
            Duration::from_millis(state.redis_op_timeout_ms),
            cmd_ip_expire.query_async(&mut conn),
        )
        .await
        .map_err(|_| "rate limit backend unavailable")?
        .map_err(|_| "rate limit backend unavailable")?;
    }
    let mut cmd_user_incr = redis::cmd("INCR");
    cmd_user_incr.arg(&key_user);
    let user_count: i64 = tokio::time::timeout(
        Duration::from_millis(state.redis_op_timeout_ms),
        cmd_user_incr.query_async(&mut conn),
    )
    .await
    .map_err(|_| "rate limit backend unavailable")?
    .map_err(|_| "rate limit backend unavailable")?;
    if user_count == 1 {
        let mut cmd_user_expire = redis::cmd("PEXPIRE");
        cmd_user_expire.arg(&key_user).arg(ttl_ms);
        let _: () = tokio::time::timeout(
            Duration::from_millis(state.redis_op_timeout_ms),
            cmd_user_expire.query_async(&mut conn),
        )
        .await
        .map_err(|_| "rate limit backend unavailable")?
        .map_err(|_| "rate limit backend unavailable")?;
    }

    let allowed = ip_count <= state.rate_limiter.limit_per_ip as i64
        && user_count <= state.rate_limiter.limit_per_user as i64;
    if !allowed {
        state.rate_limiter.hits.fetch_add(1, Ordering::Relaxed);
    }
    Ok(allowed)
}
