use criterion::{criterion_group, criterion_main, Criterion};

fn bench_security_layer(c: &mut Criterion) {
    let state = syntax_engine::api::AppState::for_bench();
    let body = br#"{"user_id":"bench","amount_cents":50000,"is_pep":false,"has_active_kyc":true,"timestamp_utc_ms":0,"risk_bps":1000,"ui_hash_valid":true}"#;
    let mut idx: u64 = 0;

    c.bench_function("security/auth_replay_rotation", |b| {
        b.iter(|| {
            idx = idx.wrapping_add(1);
            let request_id = format!("sec-bench-{idx}");
            let ts = syntax_engine::api::now_utc_ms();
            let ok = syntax_engine::api::benchmark_security_check(&state, body, &request_id, ts);
            assert!(ok);
        });
    });
}

criterion_group!(benches, bench_security_layer);
criterion_main!(benches);
