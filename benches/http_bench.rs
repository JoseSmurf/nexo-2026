use axum::body::Body;
use axum::http::{Request, StatusCode};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use http_body_util::BodyExt;
use tower::util::ServiceExt;

fn bench_http_evaluate(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("http_evaluate");

    let payloads = [
        (
            "approved",
            r#"{"user_id":"bench_ok","amount_cents":50000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":1736986840000,"risk_bps":1000,"ui_hash_valid":true}"#,
        ),
        (
            "blocked",
            r#"{"user_id":"bench_block","amount_cents":150000,"is_pep":true,"has_active_kyc":false,"timestamp_utc_ms":1736986840000,"risk_bps":4500,"ui_hash_valid":true}"#,
        ),
    ];

    for (name, payload) in payloads {
        let payload = payload.to_owned();
        let app = syntax_engine::api::app();
        group.bench_with_input(BenchmarkId::new("scenario", name), &payload, |b, payload| {
            b.iter(|| {
                let req = Request::builder()
                    .method("POST")
                    .uri("/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.clone()))
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
