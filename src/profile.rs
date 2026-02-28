use serde::Serialize;

use crate::EngineConfig;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RuleProfile {
    pub name: &'static str,
    pub version: &'static str,
    pub country: &'static str,
    pub tz_offset_minutes: i16,
    pub night_limit_cents: u64,
    pub aml_amount_cents: u64,
    pub aml_risk_bps: u16,
}

impl RuleProfile {
    pub fn engine_config(self) -> EngineConfig {
        EngineConfig {
            tz_offset_minutes: self.tz_offset_minutes,
            night_limit_cents: self.night_limit_cents,
            aml_amount_cents: self.aml_amount_cents,
            aml_risk_bps: self.aml_risk_bps,
        }
    }
}

pub fn profile_from_env() -> RuleProfile {
    match std::env::var("NEXO_PROFILE")
        .unwrap_or_else(|_| "br_default_v1".to_string())
        .as_str()
    {
        "us_default_v1" => RuleProfile {
            name: "us_default_v1",
            version: "2026.02",
            country: "US",
            tz_offset_minutes: -300,
            night_limit_cents: 500_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        },
        "eu_default_v1" => RuleProfile {
            name: "eu_default_v1",
            version: "2026.02",
            country: "EU",
            tz_offset_minutes: 60,
            night_limit_cents: 300_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        },
        "cn_default_v1" => RuleProfile {
            name: "cn_default_v1",
            version: "2026.02",
            country: "CN",
            tz_offset_minutes: 480,
            night_limit_cents: 400_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        },
        _ => RuleProfile {
            name: "br_default_v1",
            version: "2026.02",
            country: "BR",
            tz_offset_minutes: -180,
            night_limit_cents: 100_000,
            aml_amount_cents: 5_000_000,
            aml_risk_bps: 9_000,
        },
    }
}
