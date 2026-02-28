use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use syntax_engine::{evaluate_with_config, EngineConfig, TransactionIntent};

fn build_tx(
    amount_cents: u64,
    is_pep: bool,
    has_active_kyc: bool,
    risk_bps: u16,
    ui_hash_valid: bool,
) -> TransactionIntent<'static> {
    let server_time_ms = 1_736_986_900_000u64;
    let timestamp_utc_ms = server_time_ms - 60_000;
    TransactionIntent::new(
        "bench_user",
        amount_cents,
        is_pep,
        has_active_kyc,
        timestamp_utc_ms,
        server_time_ms,
        risk_bps,
        ui_hash_valid,
    )
    .expect("benchmark transaction must be valid")
}

fn bench_evaluate(c: &mut Criterion) {
    let cfg = EngineConfig {
        tz_offset_minutes: -180,
        night_start: 20,
        night_end: 6,
        night_limit_cents: 100_000,
        aml_amount_cents: 5_000_000,
        aml_risk_bps: 9_000,
    };
    let mut group = c.benchmark_group("evaluate");

    let approved = build_tx(50_000, false, true, 1_000, true);
    group.bench_with_input(
        BenchmarkId::new("scenario", "approved"),
        &approved,
        |b, tx| {
            b.iter(|| {
                black_box(evaluate_with_config(black_box(tx), black_box(cfg)));
            })
        },
    );

    let flagged = build_tx(5_000_000, false, true, 1_000, true);
    group.bench_with_input(
        BenchmarkId::new("scenario", "flagged"),
        &flagged,
        |b, tx| {
            b.iter(|| {
                black_box(evaluate_with_config(black_box(tx), black_box(cfg)));
            })
        },
    );

    let blocked = build_tx(5_000_000, true, false, 9_000, false);
    group.bench_with_input(
        BenchmarkId::new("scenario", "blocked"),
        &blocked,
        |b, tx| {
            b.iter(|| {
                black_box(evaluate_with_config(black_box(tx), black_box(cfg)));
            })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_evaluate);
criterion_main!(benches);
