use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest as Sha3Digest, Sha3_256, Shake256,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditHashAlgo {
    Blake3,
    // LEGACY / NOT USED IN RUNTIME POLICY:
    // kept only for historical offline verification of old audit records.
    Sha3_256,
    Shake256_256,
    Shake256_384,
    Shake256_512,
    HybridShake512Blake3_256,
}

impl AuditHashAlgo {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditHashAlgo::Blake3 => "blake3",
            AuditHashAlgo::Sha3_256 => "sha3-256",
            AuditHashAlgo::Shake256_256 => "shake256-256",
            AuditHashAlgo::Shake256_384 => "shake256-384",
            AuditHashAlgo::Shake256_512 => "shake256-512",
            AuditHashAlgo::HybridShake512Blake3_256 => "shake256-512+blake3-256",
        }
    }
}

fn hash_field(h: &mut blake3::Hasher, tag: &[u8], data: &[u8]) {
    h.update(&(tag.len() as u32).to_le_bytes());
    h.update(tag);
    h.update(&(data.len() as u32).to_le_bytes());
    h.update(data);
}

fn hash_field_sha3(h: &mut Sha3_256, tag: &[u8], data: &[u8]) {
    Sha3Digest::update(h, (tag.len() as u32).to_le_bytes());
    Sha3Digest::update(h, tag);
    Sha3Digest::update(h, (data.len() as u32).to_le_bytes());
    Sha3Digest::update(h, data);
}

fn hash_field_shake(h: &mut Shake256, tag: &[u8], data: &[u8]) {
    Update::update(h, &(tag.len() as u32).to_le_bytes());
    Update::update(h, tag);
    Update::update(h, &(data.len() as u32).to_le_bytes());
    Update::update(h, data);
}

fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn audit_hash_with_algo(trace: &[crate::Decision], algo: AuditHashAlgo) -> String {
    match algo {
        AuditHashAlgo::Blake3 => {
            let mut h = blake3::Hasher::new();
            hash_field(&mut h, b"schema", b"trace_v4");

            for d in trace {
                match *d {
                    crate::Decision::Approved => hash_field(&mut h, b"D:A", &[]),
                    crate::Decision::FlaggedForReview {
                        rule_id,
                        reason,
                        severity,
                        measured,
                        threshold,
                    } => {
                        hash_field(&mut h, b"D:F", rule_id.as_bytes());
                        hash_field(&mut h, b"R", reason.as_bytes());
                        h.update(&[severity.rank()]);
                        h.update(&measured.to_le_bytes());
                        h.update(&threshold.to_le_bytes());
                    }
                    crate::Decision::Blocked {
                        rule_id,
                        reason,
                        severity,
                        measured,
                        threshold,
                    } => {
                        hash_field(&mut h, b"D:B", rule_id.as_bytes());
                        hash_field(&mut h, b"R", reason.as_bytes());
                        h.update(&[severity.rank()]);
                        h.update(&measured.to_le_bytes());
                        h.update(&threshold.to_le_bytes());
                    }
                }
            }

            h.finalize().to_hex().to_string()
        }
        AuditHashAlgo::Sha3_256 => {
            let mut h = Sha3_256::new();
            hash_field_sha3(&mut h, b"schema", b"trace_v4");

            for d in trace {
                match *d {
                    crate::Decision::Approved => hash_field_sha3(&mut h, b"D:A", &[]),
                    crate::Decision::FlaggedForReview {
                        rule_id,
                        reason,
                        severity,
                        measured,
                        threshold,
                    } => {
                        hash_field_sha3(&mut h, b"D:F", rule_id.as_bytes());
                        hash_field_sha3(&mut h, b"R", reason.as_bytes());
                        Sha3Digest::update(&mut h, [severity.rank()]);
                        Sha3Digest::update(&mut h, measured.to_le_bytes());
                        Sha3Digest::update(&mut h, threshold.to_le_bytes());
                    }
                    crate::Decision::Blocked {
                        rule_id,
                        reason,
                        severity,
                        measured,
                        threshold,
                    } => {
                        hash_field_sha3(&mut h, b"D:B", rule_id.as_bytes());
                        hash_field_sha3(&mut h, b"R", reason.as_bytes());
                        Sha3Digest::update(&mut h, [severity.rank()]);
                        Sha3Digest::update(&mut h, measured.to_le_bytes());
                        Sha3Digest::update(&mut h, threshold.to_le_bytes());
                    }
                }
            }

            let digest = Sha3Digest::finalize(h);
            bytes_to_hex_lower(digest.as_slice())
        }
        AuditHashAlgo::Shake256_256 | AuditHashAlgo::Shake256_384 | AuditHashAlgo::Shake256_512 => {
            let output_bytes = match algo {
                AuditHashAlgo::Shake256_256 => 32usize,
                AuditHashAlgo::Shake256_384 => 48usize,
                AuditHashAlgo::Shake256_512 => 64usize,
                _ => unreachable!(),
            };
            let mut h = Shake256::default();
            hash_field_shake(&mut h, b"schema", b"trace_v4");

            for d in trace {
                match *d {
                    crate::Decision::Approved => hash_field_shake(&mut h, b"D:A", &[]),
                    crate::Decision::FlaggedForReview {
                        rule_id,
                        reason,
                        severity,
                        measured,
                        threshold,
                    } => {
                        hash_field_shake(&mut h, b"D:F", rule_id.as_bytes());
                        hash_field_shake(&mut h, b"R", reason.as_bytes());
                        Update::update(&mut h, &[severity.rank()]);
                        Update::update(&mut h, &measured.to_le_bytes());
                        Update::update(&mut h, &threshold.to_le_bytes());
                    }
                    crate::Decision::Blocked {
                        rule_id,
                        reason,
                        severity,
                        measured,
                        threshold,
                    } => {
                        hash_field_shake(&mut h, b"D:B", rule_id.as_bytes());
                        hash_field_shake(&mut h, b"R", reason.as_bytes());
                        Update::update(&mut h, &[severity.rank()]);
                        Update::update(&mut h, &measured.to_le_bytes());
                        Update::update(&mut h, &threshold.to_le_bytes());
                    }
                }
            }

            let mut out = vec![0u8; output_bytes];
            let mut xof = h.finalize_xof();
            xof.read(&mut out);
            bytes_to_hex_lower(&out)
        }
        AuditHashAlgo::HybridShake512Blake3_256 => {
            let shake = audit_hash_with_algo(trace, AuditHashAlgo::Shake256_512);
            let blake = audit_hash_with_algo(trace, AuditHashAlgo::Blake3);
            let mut out = String::with_capacity(shake.len() + blake.len());
            out.push_str(&shake);
            out.push_str(&blake);
            out
        }
    }
}

pub fn audit_hash(trace: &[crate::Decision]) -> String {
    audit_hash_with_algo(trace, AuditHashAlgo::Blake3)
}

#[cfg(test)]
mod tests {
    use super::{audit_hash, audit_hash_with_algo, AuditHashAlgo};
    use crate::{Decision, Severity};

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

    #[test]
    fn semantic_trace_hash_is_stable_for_known_blake3_input() {
        let trace = flagged_trace();
        assert_eq!(
            audit_hash(&trace),
            "bf5cfda1e218837d2f8a597f8011b4096a38e8578db23ef6aeeede292b4649f3"
        );
    }

    #[test]
    fn equal_semantic_traces_produce_equal_hashes() {
        let trace_a = flagged_trace();
        let trace_b = flagged_trace();

        assert_eq!(audit_hash(&trace_a), audit_hash(&trace_b));
        assert_eq!(
            audit_hash_with_algo(&trace_a, AuditHashAlgo::Shake256_512),
            audit_hash_with_algo(&trace_b, AuditHashAlgo::Shake256_512)
        );
    }
}
