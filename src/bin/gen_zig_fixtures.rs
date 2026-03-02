use std::fs;
use std::path::Path;

use syntax_engine::audit_store::AuditRecord;
use syntax_engine::{audit_hash_with_algo, AuditHashAlgo, Decision, FinalDecision, Severity};

fn flagged_trace() -> Vec<Decision> {
    vec![
        Decision::Approved,
        Decision::Approved,
        Decision::FlaggedForReview {
            rule_id: "AML-FATF-REVIEW-001",
            reason: "Transaction requires AML review.",
            severity: Severity::Alta,
            measured: 150_000,
            threshold: 5_000_000,
        },
    ]
}

fn write_fixture(
    path: &Path,
    request_id: &str,
    hash_algo: AuditHashAlgo,
    timestamp_utc_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let trace = flagged_trace();
    let audit_hash = audit_hash_with_algo(&trace, hash_algo);
    let record = AuditRecord {
        request_id: request_id.to_string(),
        calc_version: Some("fixture_rust_v1".to_string()),
        profile_name: "br_default_v1".to_string(),
        profile_version: "2026.02".to_string(),
        timestamp_utc_ms,
        user_id: "rust_fixture_user".to_string(),
        amount_cents: 150_000,
        risk_bps: 9_999,
        final_decision: FinalDecision::Flagged,
        trace: serde_json::to_value(&trace)?,
        audit_hash,
        hash_algo: hash_algo.as_str().to_string(),
        sha3_shadow: None,
        prev_record_hash: None,
        record_hash: None,
    };

    let line = serde_json::to_string(&record)?;
    fs::write(path, format!("{line}\n"))?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures_dir = Path::new("fixtures");
    fs::create_dir_all(fixtures_dir)?;

    write_fixture(
        &fixtures_dir.join("audit_rust_blake3.jsonl"),
        "a9c90815-5b55-4af3-b6df-315da4d211a1",
        AuditHashAlgo::Blake3,
        1_771_845_406_862,
    )?;
    write_fixture(
        &fixtures_dir.join("audit_rust_shake512.jsonl"),
        "14781ecf-c0af-432f-b0d3-1f11f168438a",
        AuditHashAlgo::Shake256_512,
        1_771_845_406_863,
    )?;
    write_fixture(
        &fixtures_dir.join("audit_rust_hybrid.jsonl"),
        "98c57e1f-a391-4146-af1f-0e4fb7ae5a17",
        AuditHashAlgo::HybridShake512Blake3_256,
        1_771_845_406_864,
    )?;

    println!("generated fixtures/audit_rust_blake3.jsonl");
    println!("generated fixtures/audit_rust_shake512.jsonl");
    println!("generated fixtures/audit_rust_hybrid.jsonl");
    Ok(())
}
