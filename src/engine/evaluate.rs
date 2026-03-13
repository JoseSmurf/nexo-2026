use crate::profile::RuleProfile;
use crate::{Decision, EngineConfig, FinalDecision, Severity, TransactionIntent};

use super::trace::DecisionTrace;

/// Deterministic rule evaluation entrypoint.
///
/// `profile` is currently not used to keep exact parity with the existing
/// `evaluate_with_config` behavior. It remains part of the contract so callers
/// can pass profile data now, and future engine refactors can consume it
/// without changing this call shape.
pub fn evaluate(
    intent: &TransactionIntent,
    _profile: &RuleProfile,
    config: &EngineConfig,
) -> (FinalDecision, DecisionTrace) {
    // Contract: trace order is fixed and versioned by audit_hash(schema=trace_v4).
    // Reordering rules here changes forensic hashes and must be treated as breaking.
    let mut trace = DecisionTrace::new();
    trace.push(rule_ui_integrity(intent));
    trace.push(rule_night_limit(intent, config));
    trace.push(rule_aml(intent, config));

    let final_decision = if trace.iter().any(|d| matches!(d, Decision::Blocked { .. })) {
        FinalDecision::Blocked
    } else if trace
        .iter()
        .any(|d| matches!(d, Decision::FlaggedForReview { .. }))
    {
        FinalDecision::Flagged
    } else {
        FinalDecision::Approved
    };

    (final_decision, trace)
}

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

fn rule_night_limit(tx: &TransactionIntent, cfg: &EngineConfig) -> Decision {
    let hour = policy_hour(tx.timestamp_utc_ms, cfg.tz_offset_minutes);
    let is_night = if cfg.night_start <= cfg.night_end {
        hour >= cfg.night_start && hour <= cfg.night_end
    } else {
        hour >= cfg.night_start || hour <= cfg.night_end
    };

    if is_night && tx.amount_cents > cfg.night_limit_cents {
        Decision::Blocked {
            rule_id: "BCB-NIGHT-001",
            reason: "Night transaction limit exceeded.",
            severity: Severity::Grave,
            measured: tx.amount_cents,
            threshold: cfg.night_limit_cents,
        }
    } else {
        Decision::Approved
    }
}

fn rule_aml(tx: &TransactionIntent, cfg: &EngineConfig) -> Decision {
    if tx.is_pep && !tx.has_active_kyc {
        return Decision::Blocked {
            rule_id: "KYC-PEP-002",
            reason: "PEP without active KYC.",
            severity: Severity::Grave,
            measured: 1,
            threshold: 0,
        };
    }

    let high_risk = tx.risk_bps >= cfg.aml_risk_bps;
    let high_amount = tx.amount_cents >= cfg.aml_amount_cents;

    if high_risk && high_amount {
        return Decision::Blocked {
            rule_id: "AML-FATF-001",
            reason: "High-risk and high-amount transaction.",
            severity: Severity::Critica,
            measured: tx.amount_cents,
            threshold: cfg.aml_amount_cents,
        };
    }

    if high_risk || high_amount {
        return Decision::FlaggedForReview {
            rule_id: "AML-FATF-REVIEW-001",
            reason: "Transaction requires AML review.",
            severity: Severity::Alta,
            measured: tx.amount_cents,
            threshold: cfg.aml_amount_cents,
        };
    }

    Decision::Approved
}

#[cfg(test)]
mod tests {
    use crate::engine::evaluate;
    use crate::profile::RuleProfile;
    use crate::{EngineConfig, TransactionIntent};

    fn sample_profile() -> RuleProfile {
        RuleProfile {
            name: "br_default_v1",
            version: "2026.02",
            country: "BR",
            tz_offset_minutes: -180,
            night_start: 20,
            night_end: 6,
            night_limit_cents: 100_000,
            aml_amount_cents: 5_000_000,
            aml_risk_bps: 9_000,
        }
    }

    fn sample_config() -> EngineConfig {
        EngineConfig {
            tz_offset_minutes: -180,
            night_start: 20,
            night_end: 6,
            night_limit_cents: 100_000,
            aml_amount_cents: 5_000_000,
            aml_risk_bps: 9_000,
        }
    }

    fn sample_intent() -> TransactionIntent<'static> {
        let st = 1_736_986_900_000u64;
        TransactionIntent::new("user_x", 50_000, false, true, st - 60_000, st, 1_000, true).unwrap()
    }

    #[test]
    fn evaluate_reproducible_for_identical_input() {
        let profile = sample_profile();
        let config = sample_config();
        let intent = sample_intent();

        let (expected_decision, expected_trace) = evaluate(&intent, &profile, &config);

        for _ in 0..1_000 {
            let (decision, trace) = evaluate(&intent, &profile, &config);
            assert_eq!(decision, expected_decision);
            assert_eq!(trace, expected_trace);
        }
    }
}
