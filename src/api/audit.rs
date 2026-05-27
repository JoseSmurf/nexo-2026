use crate::{audit_hash_with_algo, AuditHashAlgo, Decision, TransactionIntent};

use super::{AppState, SecurityLevel, ADAPTIVE_RISK_BPS_THRESHOLD};

pub(super) fn resolve_audit_hash(
    state: &AppState,
    tx: &TransactionIntent,
    trace: &[Decision],
    blake3_hash: &str,
) -> (String, AuditHashAlgo, Option<String>) {
    let selected = select_audit_hash_algo(
        state.security_level,
        tx.risk_bps,
        tx.amount_cents,
        state.high_threshold_cents,
        state.shake_bits,
    );
    let audit_hash = match selected {
        AuditHashAlgo::Blake3 => blake3_hash.to_string(),
        _ => audit_hash_with_algo(trace, selected),
    };
    let sha3_shadow = if state.sha3_shadow_enabled && selected == AuditHashAlgo::Blake3 {
        Some(audit_hash_with_algo(
            trace,
            shake_algo_from_bits(state.shake_bits),
        ))
    } else {
        None
    };
    (audit_hash, selected, sha3_shadow)
}

pub(super) fn shake_algo_from_bits(bits: u16) -> AuditHashAlgo {
    match bits {
        256 => AuditHashAlgo::Shake256_256,
        384 => AuditHashAlgo::Shake256_384,
        _ => AuditHashAlgo::Shake256_512,
    }
}

pub(super) fn select_audit_hash_algo(
    level: SecurityLevel,
    risk_bps: u16,
    amount_cents: u64,
    high_threshold_cents: u64,
    shake_bits: u16,
) -> AuditHashAlgo {
    if level == SecurityLevel::Incident {
        return AuditHashAlgo::HybridShake512Blake3_256;
    }
    if risk_bps >= ADAPTIVE_RISK_BPS_THRESHOLD || amount_cents >= high_threshold_cents {
        return shake_algo_from_bits(shake_bits);
    }
    AuditHashAlgo::Blake3
}
