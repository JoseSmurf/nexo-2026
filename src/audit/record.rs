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
