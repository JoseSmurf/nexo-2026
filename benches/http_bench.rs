use axum::body::Body;
use axum::http::{Request, StatusCode};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use http_body_util::BodyExt;
use serde_json::json;
use std::cell::Cell;
use tower::util::ServiceExt;

fn bench_http_evaluate(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("http_evaluate");

    let payloads = [
        ("approved", "bench_ok", 50_000u64, false, true, 1_000u16),
        ("blocked", "bench_block", 150_000u64, true, false, 4_500u16),
    ];

    for (name, user_id, amount_cents, is_pep, has_active_kyc, risk_bps) in payloads {
        let state = syntax_engine::api::AppState::for_bench();
        let app = syntax_engine::api::app_with_state(state);
        let seq = Cell::new(0u64);
        group.bench_function(BenchmarkId::new("scenario", name), |b| {
            b.iter(|| {
                let next = seq.get().wrapping_add(1);
                seq.set(next);
                let request_id = format!("bench-{}-{}-{}", name, now_utc_ms(), next);
                let timestamp = now_utc_ms();
                let payload = json!({
                    "user_id": user_id,
                    "amount_cents": amount_cents,
                    "is_pep": is_pep,
                    "has_active_kyc": has_active_kyc,
                    "timestamp_utc_ms": timestamp,
                    "risk_bps": risk_bps,
                    "ui_hash_valid": true,
                    "request_id": request_id
                });
                let body_str = payload.to_string();
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

                let body = rt.block_on(async {
                    let resp = app.clone().oneshot(req).await.expect("api response");

                    assert_eq!(resp.status(), StatusCode::OK);
                    resp.into_body()
                        .collect()
                        .await
                        .expect("body bytes")
                        .to_bytes()
                });
                black_box(body);
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_http_evaluate);
criterion_main!(benches);

fn now_utc_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as u64
}
