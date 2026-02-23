use std::time::Instant;

use axum::body::Body;
use axum::http::Request;
use syntax_engine::{evaluate_with_config, EngineConfig, TransactionIntent};
use tower::util::ServiceExt;

fn main() {
    let engine_budget_ns: f64 = std::env::var("NEXO_ENGINE_BUDGET_NS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5_000.0);
    let http_budget_us: f64 = std::env::var("NEXO_HTTP_BUDGET_US")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30.0);

    let tx = TransactionIntent::new(
        "perf_user",
        50_000,
        false,
        true,
        now_ms().saturating_sub(1_000),
        now_ms(),
        1_000,
        true,
    )
    .expect("valid tx");

    let iterations = 100_000usize;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = evaluate_with_config(&tx, EngineConfig::default());
    }
    let engine_avg_ns = start.elapsed().as_nanos() as f64 / iterations as f64;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let http_iterations = 5_000usize;
    let app = syntax_engine::api::app_with_state(syntax_engine::api::AppState::for_bench());

    let http_start = Instant::now();
    rt.block_on(async {
        for i in 0..http_iterations {
            let timestamp = now_ms();
            let request_id = format!("perf-{i}");
            let req_body = serde_json::json!({
                "user_id": "perf_user",
                "amount_cents": 50_000,
                "is_pep": false,
                "has_active_kyc": true,
                "timestamp_utc_ms": timestamp,
                "risk_bps": 1_000,
                "ui_hash_valid": true,
                "request_id": request_id
            });
            let body_str = req_body.to_string();
            let signature = syntax_engine::api::compute_signature(
                syntax_engine::api::BENCH_HMAC_SECRET,
                syntax_engine::api::BENCH_KEY_ID,
                &request_id,
                timestamp,
                body_str.as_bytes(),
            );
            let req = Request::builder()
                .method("POST")
                .uri("/evaluate")
                .header("content-type", "application/json")
                .header("x-signature", signature)
                .header("x-request-id", request_id)
                .header("x-timestamp", timestamp.to_string())
                .header("x-key-id", syntax_engine::api::BENCH_KEY_ID)
                .body(Body::from(body_str))
                .expect("request");
            let resp = app.clone().oneshot(req).await.expect("response");
            assert!(resp.status().is_success());
        }
    });
    let http_avg_us = http_start.elapsed().as_nanos() as f64 / http_iterations as f64 / 1_000.0;

    println!("perf_budget engine_avg_ns={engine_avg_ns:.2} budget_ns={engine_budget_ns:.2}");
    println!("perf_budget http_avg_us={http_avg_us:.2} budget_us={http_budget_us:.2}");

    if engine_avg_ns > engine_budget_ns {
        eprintln!("engine budget exceeded");
        std::process::exit(1);
    }
    if http_avg_us > http_budget_us {
        eprintln!("http budget exceeded");
        std::process::exit(1);
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as u64
}
