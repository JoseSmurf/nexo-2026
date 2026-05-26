use serde::Serialize;
use std::fmt;

use crate::EngineConfig;

pub const DEFAULT_PROFILE_NAME: &str = "br_default_v1";

const VALID_PROFILE_NAMES: &[&str] = &[
    "br_default_v1",
    "us_default_v1",
    "eu_default_v1",
    "cn_default_v1",
    "ae_default_v1",
    "in_default_v1",
    "jp_default_v1",
    "gb_default_v1",
    "kr_default_v1",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileConfigError {
    pub code: &'static str,
    pub message: String,
    pub checklist: [&'static str; 3],
}

impl ProfileConfigError {
    fn invalid_profile(name: &str) -> Self {
        Self {
            code: "NEXO_PROFILE_INVALID",
            message: format!(
                "unsupported NEXO_PROFILE '{name}'; unknown profiles are not allowed. Valid built-in profiles: {}",
                VALID_PROFILE_NAMES.join(", ")
            ),
            checklist: [
                "Set NEXO_PROFILE to one valid built-in profile name.",
                "Check for typos or casing drift in NEXO_PROFILE.",
                "Unset NEXO_PROFILE to fallback to default br_default_v1.",
            ],
        }
    }

    fn invalid_profile_non_unicode() -> Self {
        Self {
            code: "NEXO_PROFILE_INVALID_UNICODE",
            message: format!(
                "unsupported NEXO_PROFILE value; unknown profiles are not allowed. Valid built-in profiles: {}",
                VALID_PROFILE_NAMES.join(", ")
            ),
            checklist: [
                "Ensure NEXO_PROFILE is valid UTF-8.",
                "Set NEXO_PROFILE to one valid built-in profile name.",
                "Unset NEXO_PROFILE to fallback to default br_default_v1.",
            ],
        }
    }
}

impl fmt::Display for ProfileConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} | checklist=[1] {} [2] {} [3] {}",
            self.code, self.message, self.checklist[0], self.checklist[1], self.checklist[2]
        )
    }
}

impl std::error::Error for ProfileConfigError {}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RuleProfile {
    pub name: &'static str,
    pub version: &'static str,
    pub country: &'static str,
    pub tz_offset_minutes: i16,
    pub night_start: u8,
    pub night_end: u8,
    pub night_limit_cents: u64,
    pub aml_amount_cents: u64,
    pub aml_risk_bps: u16,
}

impl RuleProfile {
    pub fn engine_config(self) -> EngineConfig {
        EngineConfig {
            tz_offset_minutes: self.tz_offset_minutes,
            night_start: self.night_start,
            night_end: self.night_end,
            night_limit_cents: self.night_limit_cents,
            aml_amount_cents: self.aml_amount_cents,
            aml_risk_bps: self.aml_risk_bps,
        }
    }
}

pub fn profile_by_name(name: &str) -> Option<RuleProfile> {
    match name {
        "br_default_v1" => Some(RuleProfile {
            name: "br_default_v1",
            version: "2026.02",
            country: "BR",
            tz_offset_minutes: -180,
            night_start: 20,
            night_end: 6,
            night_limit_cents: 100_000,
            aml_amount_cents: 5_000_000,
            aml_risk_bps: 9_000,
        }),
        "us_default_v1" => Some(RuleProfile {
            name: "us_default_v1",
            version: "2026.02",
            country: "US",
            tz_offset_minutes: -300,
            night_start: 23,
            night_end: 5,
            night_limit_cents: 500_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }),
        "eu_default_v1" => Some(RuleProfile {
            name: "eu_default_v1",
            version: "2026.02",
            country: "EU",
            tz_offset_minutes: 60,
            night_start: 22,
            night_end: 6,
            night_limit_cents: 300_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }),
        "cn_default_v1" => Some(RuleProfile {
            name: "cn_default_v1",
            version: "2026.02",
            country: "CN",
            tz_offset_minutes: 480,
            night_start: 23,
            night_end: 5,
            night_limit_cents: 400_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }),
        "ae_default_v1" => Some(RuleProfile {
            name: "ae_default_v1",
            version: "2026.02",
            country: "AE",
            tz_offset_minutes: 240,
            night_start: 22,
            night_end: 6,
            night_limit_cents: 300_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }),
        "in_default_v1" => Some(RuleProfile {
            name: "in_default_v1",
            version: "2026.02",
            country: "IN",
            tz_offset_minutes: 330,
            night_start: 22,
            night_end: 6,
            night_limit_cents: 200_000,
            aml_amount_cents: 8_000_000,
            aml_risk_bps: 9_000,
        }),
        "jp_default_v1" => Some(RuleProfile {
            name: "jp_default_v1",
            version: "2026.02",
            country: "JP",
            tz_offset_minutes: 540,
            night_start: 23,
            night_end: 5,
            night_limit_cents: 450_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }),
        "gb_default_v1" => Some(RuleProfile {
            name: "gb_default_v1",
            version: "2026.02",
            country: "GB",
            tz_offset_minutes: 0,
            night_start: 22,
            night_end: 6,
            night_limit_cents: 350_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }),
        "kr_default_v1" => Some(RuleProfile {
            name: "kr_default_v1",
            version: "2026.02",
            country: "KR",
            tz_offset_minutes: 540,
            night_start: 23,
            night_end: 5,
            night_limit_cents: 380_000,
            aml_amount_cents: 10_000_000,
            aml_risk_bps: 9_000,
        }),
        _ => None,
    }
}

pub fn profile_from_env() -> Result<RuleProfile, ProfileConfigError> {
    match std::env::var("NEXO_PROFILE") {
        Ok(name) => profile_by_name(name.as_str())
            .ok_or_else(|| ProfileConfigError::invalid_profile(name.as_str())),
        Err(std::env::VarError::NotPresent) => profile_by_name(DEFAULT_PROFILE_NAME)
            .ok_or_else(|| ProfileConfigError::invalid_profile(DEFAULT_PROFILE_NAME)),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(ProfileConfigError::invalid_profile_non_unicode())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_profile_env(previous: Option<String>) {
        if let Some(value) = previous {
            std::env::set_var("NEXO_PROFILE", value);
        } else {
            std::env::remove_var("NEXO_PROFILE");
        }
    }

    #[test]
    fn known_profile_lookup_returns_expected_profile() {
        let profile = profile_by_name("jp_default_v1").expect("known profile");
        assert_eq!(profile.name, "jp_default_v1");
        assert_eq!(profile.version, "2026.02");
        assert_eq!(profile.country, "JP");
        assert_eq!(profile.tz_offset_minutes, 540);
        assert_eq!(profile.night_limit_cents, 450_000);
    }

    #[test]
    fn unknown_profile_lookup_returns_none() {
        assert!(profile_by_name("unknown_profile").is_none());
    }

    #[test]
    fn default_profile_constant_maps_to_br_profile() {
        let profile = profile_by_name(DEFAULT_PROFILE_NAME).expect("default profile");
        assert_eq!(profile.name, "br_default_v1");
        assert_eq!(profile.country, "BR");
    }

    #[test]
    fn rule_profile_engine_config_maps_decision_fields_only() {
        let profile = profile_by_name("us_default_v1").expect("known profile");
        let cfg = profile.engine_config();
        assert_eq!(cfg.tz_offset_minutes, profile.tz_offset_minutes);
        assert_eq!(cfg.night_start, profile.night_start);
        assert_eq!(cfg.night_end, profile.night_end);
        assert_eq!(cfg.night_limit_cents, profile.night_limit_cents);
        assert_eq!(cfg.aml_amount_cents, profile.aml_amount_cents);
        assert_eq!(cfg.aml_risk_bps, profile.aml_risk_bps);
    }

    #[test]
    fn unset_profile_env_defaults_to_br() {
        let _guard = env_lock().lock().expect("env lock");
        let previous = std::env::var("NEXO_PROFILE").ok();
        std::env::remove_var("NEXO_PROFILE");

        let profile = profile_from_env().expect("default profile should load");
        assert_eq!(profile.name, DEFAULT_PROFILE_NAME);

        restore_profile_env(previous);
    }

    #[test]
    fn unknown_explicit_profile_env_returns_structured_error_fail_closed() {
        let _guard = env_lock().lock().expect("env lock");
        let previous = std::env::var("NEXO_PROFILE").ok();
        std::env::set_var("NEXO_PROFILE", "typo_profile_v1");

        let err = profile_from_env().expect_err("unknown profile must fail closed");
        assert_eq!(err.code, "NEXO_PROFILE_INVALID");
        let msg = err.to_string();
        assert!(msg.contains("typo_profile_v1"));
        assert!(msg.contains("unknown profiles are not allowed"));
        assert!(msg.contains("br_default_v1"));
        assert!(msg.contains("kr_default_v1"));

        restore_profile_env(previous);
    }
}
