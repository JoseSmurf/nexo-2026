use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use serde_json::json;
use tower::util::ServiceExt;
use uuid::Uuid;

use syntax_engine::telemetry::MetricsSnapshot;
fn percentile(sorted: &[u128], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((pct / 100.0) * (sorted.len().saturating_sub(1) as f64)).round() as usize;
    sorted[rank] as f64
}

#[tokio::main]
async fn main() {
    let total_requests: usize = std::env::var("NEXO_LOAD_REQUESTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);
    let concurrency: usize = std::env::var("NEXO_LOAD_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let max_p95_us: Option<f64> = std::env::var("NEXO_LOAD_MAX_P95_US")
        .ok()
        .and_then(|v| v.parse().ok());
    let max_p99_us: Option<f64> = std::env::var("NEXO_LOAD_MAX_P99_US")
        .ok()
        .and_then(|v| v.parse().ok());
    let max_error_rate_pct: Option<f64> = std::env::var("NEXO_ALERT_MAX_ERROR_RATE_PCT")
        .ok()
        .and_then(|v| v.parse().ok());
    let max_401: Option<u64> = std::env::var("NEXO_ALERT_MAX_401")
        .ok()
        .and_then(|v| v.parse().ok());
    let max_408: Option<u64> = std::env::var("NEXO_ALERT_MAX_408")
        .ok()
        .and_then(|v| v.parse().ok());
    let max_409: Option<u64> = std::env::var("NEXO_ALERT_MAX_409")
        .ok()
        .and_then(|v| v.parse().ok());
    let max_429: Option<u64> = std::env::var("NEXO_ALERT_MAX_429")
        .ok()
        .and_then(|v| v.parse().ok());

    let state = syntax_engine::api::AppState::for_bench();
    let metrics = state.metrics.clone();
    let app = syntax_engine::api::app_with_state(state);

    let mut latencies_ns = Vec::with_capacity(total_requests);
    let mut ok = 0usize;
    let mut idx = 0usize;

    while idx < total_requests {
        let batch = (total_requests - idx).min(concurrency);
        let mut handles = Vec::with_capacity(batch);
        for _ in 0..batch {
            idx += 1;
            let req_id = Uuid::new_v4().to_string();
            let timestamp = chrono_like_now_ms();
            let req_body = json!({
                "user_id": "load_user",
                "amount_cents": 50_000,
                "is_pep": false,
                "has_active_kyc": true,
                "timestamp_utc_ms": timestamp,
                "risk_bps": 1_000,
                "ui_hash_valid": true,
                "request_id": req_id
            });
            let body_str = req_body.to_string();
            let signature = syntax_engine::api::compute_signature(
                syntax_engine::api::BENCH_HMAC_SECRET,
                syntax_engine::api::BENCH_KEY_ID,
                &req_id,
                timestamp,
                body_str.as_bytes(),
            );
            let app_clone = app.clone();
            handles.push(tokio::spawn(async move {
                let req = Request::builder()
                    .method("POST")
                    .uri("/evaluate")
                    .header("content-type", "application/json")
                    .header("x-signature", signature)
                    .header("x-request-id", req_id)
                    .header("x-timestamp", timestamp.to_string())
                    .header("x-key-id", syntax_engine::api::BENCH_KEY_ID)
                    .body(Body::from(body_str))
                    .expect("request");
                let start = Instant::now();
                let resp = app_clone.oneshot(req).await.expect("response");
                let elapsed = start.elapsed().as_nanos();
                (resp.status().is_success(), elapsed)
            }));
        }

        for handle in handles {
            let (is_ok, elapsed) = handle.await.expect("join");
            if is_ok {
                ok += 1;
            }
            latencies_ns.push(elapsed);
        }
    }

    latencies_ns.sort_unstable();
    let p50 = percentile(&latencies_ns, 50.0) / 1_000.0;
    let p95 = percentile(&latencies_ns, 95.0) / 1_000.0;
    let p99 = percentile(&latencies_ns, 99.0) / 1_000.0;
    let avg = latencies_ns.iter().sum::<u128>() as f64 / latencies_ns.len() as f64 / 1_000.0;

    println!("load_test total_requests={total_requests} concurrency={concurrency}");
    println!("ok_responses={ok}/{}", total_requests);
    println!("latency_us avg={avg:.2} p50={p50:.2} p95={p95:.2} p99={p99:.2}");

    let snapshot: MetricsSnapshot = metrics.snapshot();
    let error_rate_pct = if snapshot.requests_total == 0 {
        0.0
    } else {
        (snapshot.requests_error as f64 / snapshot.requests_total as f64) * 100.0
    };
    println!(
        "ops_metrics total={} errors={} error_rate_pct={:.4} unauthorized={} timeout={} conflict={} too_many={}",
        snapshot.requests_total,
        snapshot.requests_error,
        error_rate_pct,
        snapshot.unauthorized_total,
        snapshot.request_timeout_total,
        snapshot.conflict_total,
        snapshot.too_many_requests_total
    );

    if let Some(max) = max_p95_us {
        if p95 > max {
            eprintln!("p95 budget exceeded: {p95:.2}us > {max:.2}us");
            std::process::exit(1);
        }
    }
    if let Some(max) = max_p99_us {
        if p99 > max {
            eprintln!("p99 budget exceeded: {p99:.2}us > {max:.2}us");
            std::process::exit(1);
        }
    }
    if let Some(max) = max_error_rate_pct {
        if error_rate_pct > max {
            eprintln!("error_rate budget exceeded: {error_rate_pct:.4}% > {max:.4}%");
            std::process::exit(1);
        }
    }
    if let Some(max) = max_401 {
        if snapshot.unauthorized_total > max {
            eprintln!(
                "unauthorized budget exceeded: {} > {}",
                snapshot.unauthorized_total, max
            );
            std::process::exit(1);
        }
    }
    if let Some(max) = max_408 {
        if snapshot.request_timeout_total > max {
            eprintln!(
                "request_timeout budget exceeded: {} > {}",
                snapshot.request_timeout_total, max
            );
            std::process::exit(1);
        }
    }
    if let Some(max) = max_409 {
        if snapshot.conflict_total > max {
            eprintln!(
                "conflict budget exceeded: {} > {}",
                snapshot.conflict_total, max
            );
            std::process::exit(1);
        }
    }
    if let Some(max) = max_429 {
        if snapshot.too_many_requests_total > max {
            eprintln!(
                "too_many_requests budget exceeded: {} > {}",
                snapshot.too_many_requests_total, max
            );
            std::process::exit(1);
        }
    }
}

fn chrono_like_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as u64
}
