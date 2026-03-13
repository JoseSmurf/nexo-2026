use crate::profile::RuleProfile;
use crate::{evaluate_with_config, EngineConfig, FinalDecision, TransactionIntent};

use super::trace::DecisionTrace;

pub fn evaluate(
    intent: &TransactionIntent,
    _profile: &RuleProfile,
    config: &EngineConfig,
) -> (FinalDecision, DecisionTrace) {
    let (decision, trace, _hash) = evaluate_with_config(
        intent,
        EngineConfig {
            tz_offset_minutes: config.tz_offset_minutes,
            night_start: config.night_start,
            night_end: config.night_end,
            night_limit_cents: config.night_limit_cents,
            aml_amount_cents: config.aml_amount_cents,
            aml_risk_bps: config.aml_risk_bps,
        },
    );

    (decision, trace)
}
