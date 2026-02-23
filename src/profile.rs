use serde::Serialize;

use crate::EngineConfig;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RuleProfile {
    pub name: &'static str,
    pub version: &'static str,
    pub country: &'static str,
    pub tz_offset_minutes: i16,
}

impl RuleProfile {
    pub fn engine_config(self) -> EngineConfig {
        EngineConfig {
            tz_offset_minutes: self.tz_offset_minutes,
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
        },
        "eu_default_v1" => RuleProfile {
            name: "eu_default_v1",
            version: "2026.02",
            country: "EU",
            tz_offset_minutes: 60,
        },
        _ => RuleProfile {
            name: "br_default_v1",
            version: "2026.02",
            country: "BR",
            tz_offset_minutes: -180,
        },
    }
}
