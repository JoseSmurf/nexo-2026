use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Baixa,
    Alta,
    Grave,
    Critica,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Baixa => 0,
            Severity::Alta => 1,
            Severity::Grave => 2,
            Severity::Critica => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approved,
    FlaggedForReview {
        rule_id: &'static str,
        reason: &'static str,
        severity: Severity,
        measured: u64,
        threshold: u64,
    },
    Blocked {
        rule_id: &'static str,
        reason: &'static str,
        severity: Severity,
        measured: u64,
        threshold: u64,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TransactionIntent<'a> {
    pub user_id: &'a str,
    pub amount_cents: u64,
    pub is_pep: bool,
    pub has_active_kyc: bool,
    pub timestamp_utc_ms: u64,
    pub risk_bps: u16,
    pub ui_hash_valid: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    pub tz_offset_minutes: i16,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self { tz_offset_minutes: -180 }
    }
}

impl<'a> TransactionIntent<'a> {
    pub fn new(
        user_id: &'a str,
        amount_cents: u64,
        is_pep: bool,
        has_active_kyc: bool,
        timestamp_utc_ms: u64,
        server_time_ms: u64,
        risk_bps: u16,
        ui_hash_valid: bool,
    ) -> Result<Self, &'static str> {
        if amount_cents == 0 {
            return Err("REJECTED: zero amount");
        }
        if risk_bps >= 10_000 {
            return Err("REJECTED: risk >= 100%");
        }

        let max_drift_ms = 5 * 60 * 1000;

        if timestamp_utc_ms > server_time_ms.saturating_add(max_drift_ms) {
            return Err("REJECTED: future timestamp");
        }
        if timestamp_utc_ms < server_time_ms.saturating_sub(max_drift_ms) {
            return Err("REJECTED: replay detected");
        }

        Ok(Self {
            user_id,
            amount_cents,
            is_pep,
            has_active_kyc,
            timestamp_utc_ms,
            risk_bps,
            ui_hash_valid,
        })
    }
}

const NIGHT_LIMIT_CENTS: u64 = 100_000;
const AML_RISK_BPS: u16 = 9_000;
const AML_AMOUNT_CENTS: u64 = 5_000_000;

fn policy_hour(timestamp_utc_ms: u64, offset_minutes: i16) -> u8 {
    let utc_s = (timestamp_utc_ms / 1000) as i64;
    let local_s = utc_s + (offset_minutes as i64 * 60);
    let mut sec_day = local_s % 86_400;
    if sec_day < 0 {
        sec_day += 86_400;
    }
    (sec_day / 3600) as u8
}

fn rule_ui_integrity(tx: &TransactionIntent) -> Decision {
    if !tx.ui_hash_valid {
        Decision::Blocked {
            rule_id: "UI-FRAUD-001",
            reason: "UI integrity verification failed.",
            severity: Severity::Critica,
            measured: 1,
            threshold: 0,
        }
    } else {
        Decision::Approved
    }
}

fn rule_night_limit(tx: &TransactionIntent, cfg: EngineConfig) -> Decision {
    let hour = policy_hour(tx.timestamp_utc_ms, cfg.tz_offset_minutes);
    if (hour >= 20 || hour <= 6) && tx.amount_cents > NIGHT_LIMIT_CENTS {
        Decision::Blocked {
            rule_id: "BCB-NIGHT-001",
            reason: "Night transaction limit exceeded.",
            severity: Severity::Grave,
            measured: tx.amount_cents,
            threshold: NIGHT_LIMIT_CENTS,
        }
    } else {
        Decision::Approved
    }
}

fn rule_aml(tx: &TransactionIntent) -> Decision {
    if tx.is_pep && !tx.has_active_kyc {
        return Decision::Blocked {
            rule_id: "KYC-PEP-002",
            reason: "PEP without active KYC.",
            severity: Severity::Grave,
            measured: 1,
            threshold: 0,
        };
    }

    let high_risk = tx.risk_bps >= AML_RISK_BPS;
    let high_amount = tx.amount_cents >= AML_AMOUNT_CENTS;

    if high_risk && high_amount {
        return Decision::Blocked {
            rule_id: "AML-FATF-001",
            reason: "High-risk and high-amount transaction.",
            severity: Severity::Critica,
            measured: tx.amount_cents,
            threshold: AML_AMOUNT_CENTS,
        };
    }

    if high_risk || high_amount {
        return Decision::FlaggedForReview {
            rule_id: "AML-FATF-REVIEW-001",
            reason: "Transaction requires AML review.",
            severity: Severity::Alta,
            measured: tx.amount_cents,
            threshold: AML_AMOUNT_CENTS,
        };
    }

    Decision::Approved
}

fn hash_field(h: &mut blake3::Hasher, tag: &[u8], data: &[u8]) {
    h.update(&(tag.len() as u32).to_le_bytes());
    h.update(tag);
    h.update(&(data.len() as u32).to_le_bytes());
    h.update(data);
}

pub fn audit_hash(trace: &[Decision]) -> String {
    let mut h = blake3::Hasher::new();
    hash_field(&mut h, b"schema", b"trace_v4");

    for d in trace {
        match *d {
            Decision::Approved => hash_field(&mut h, b"D:A", &[]),
            Decision::FlaggedForReview { rule_id, reason, severity, measured, threshold } => {
                hash_field(&mut h, b"D:F", rule_id.as_bytes());
                hash_field(&mut h, b"R", reason.as_bytes());
                h.update(&[severity.rank()]);
                h.update(&measured.to_le_bytes());
                h.update(&threshold.to_le_bytes());
            }
            Decision::Blocked { rule_id, reason, severity, measured, threshold } => {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalDecision {
    Approved,
    Flagged,
    Blocked,
}

pub fn evaluate(tx: &TransactionIntent) -> (FinalDecision, Vec<Decision>, String) {
    evaluate_with_config(tx, EngineConfig::default())
}

pub fn evaluate_with_config(
    tx: &TransactionIntent,
    cfg: EngineConfig,
) -> (FinalDecision, Vec<Decision>, String) {
    let trace = vec![
        rule_ui_integrity(tx),
        rule_night_limit(tx, cfg),
        rule_aml(tx),
    ];

    let final_decision = if trace.iter().any(|d| matches!(d, Decision::Blocked { .. })) {
        FinalDecision::Blocked
    } else if trace.iter().any(|d| matches!(d, Decision::FlaggedForReview { .. })) {
        FinalDecision::Flagged
    } else {
        FinalDecision::Approved
    };

    let hash = audit_hash(&trace);
    (final_decision, trace, hash)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approves_safe_transaction() {
        let server_time = 1_736_986_900_000;

        let tx = TransactionIntent::new(
            "user_normal",
            50_000,   // valor baixo
            false,    // não é PEP
            true,     // KYC ativo
            server_time - 60_000,
            server_time,
            1_000,    // risco baixo
            true,     // UI hash válido ✅
        ).unwrap();

        let (final_decision, _trace, _hash) = evaluate(&tx);

        assert_eq!(final_decision, FinalDecision::Approved);
    }
}
