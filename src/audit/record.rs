use crate::audit_store::AuditRecord;

fn hash_field(h: &mut blake3::Hasher, tag: &[u8], data: &[u8]) {
    h.update(&(tag.len() as u32).to_le_bytes());
    h.update(tag);
    h.update(&(data.len() as u32).to_le_bytes());
    h.update(data);
}

pub fn compute_record_hash(record: &AuditRecord) -> String {
    let mut h = blake3::Hasher::new();
    hash_field(&mut h, b"schema", b"audit_record_v2");
    hash_field(&mut h, b"request_id", record.request_id.as_bytes());
    hash_field(&mut h, b"profile_name", record.profile_name.as_bytes());
    hash_field(
        &mut h,
        b"profile_version",
        record.profile_version.as_bytes(),
    );
    hash_field(
        &mut h,
        b"calc_version",
        record.calc_version.as_deref().unwrap_or("").as_bytes(),
    );
    hash_field(&mut h, b"user_id", record.user_id.as_bytes());
    hash_field(&mut h, b"audit_hash", record.audit_hash.as_bytes());
    hash_field(&mut h, b"hash_algo", record.hash_algo.as_bytes());
    hash_field(
        &mut h,
        b"sha3_shadow",
        record.sha3_shadow.as_deref().unwrap_or("").as_bytes(),
    );
    hash_field(
        &mut h,
        b"final_decision",
        format!("{:?}", record.final_decision).as_bytes(),
    );
    hash_field(
        &mut h,
        b"trace_json",
        serde_json::to_string(&record.trace)
            .unwrap_or_else(|_| "[]".to_string())
            .as_bytes(),
    );
    hash_field(
        &mut h,
        b"prev_record_hash",
        record.prev_record_hash.as_deref().unwrap_or("").as_bytes(),
    );
    h.update(&record.timestamp_utc_ms.to_le_bytes());
    h.update(&record.amount_cents.to_le_bytes());
    h.update(&record.risk_bps.to_le_bytes());
    h.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::compute_record_hash;
    use crate::audit_store::AuditRecord;
    use crate::FinalDecision;
    use serde_json::json;

    fn sample_record() -> AuditRecord {
        AuditRecord {
            request_id: "known-request-001".to_string(),
            calc_version: Some("fixture_rust_v1".to_string()),
            profile_name: "br_default_v1".to_string(),
            profile_version: "2026.02".to_string(),
            timestamp_utc_ms: 1_771_845_406_862,
            user_id: "rust_fixture_user".to_string(),
            amount_cents: 150_000,
            risk_bps: 9_999,
            final_decision: FinalDecision::Flagged,
            trace: json!([
                "Approved",
                "Approved",
                {
                    "FlaggedForReview": {
                        "measured": 150000,
                        "reason": "Transaction requires AML review.",
                        "rule_id": "AML-FATF-REVIEW-001",
                        "severity": "Alta",
                        "threshold": 5000000
                    }
                }
            ]),
            audit_hash: "bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"
                .to_string(),
            hash_algo: "blake3".to_string(),
            sha3_shadow: None,
            prev_record_hash: None,
            record_hash: None,
        }
    }

    #[test]
    fn compute_record_hash_is_stable_for_known_input() {
        let record = sample_record();
        assert_eq!(
            compute_record_hash(&record),
            "fa75306f29d04f6aafcec77d7dfceb7b44386284e87df8b8c51f5071d01d663f"
        );
    }

    #[test]
    fn identical_audit_records_produce_identical_record_hashes() {
        let record_a = sample_record();
        let record_b = sample_record();
        assert_eq!(
            compute_record_hash(&record_a),
            compute_record_hash(&record_b)
        );
    }
}
