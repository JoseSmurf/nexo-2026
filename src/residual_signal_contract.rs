use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const RESIDUAL_SIGNAL_SCHEMA_VERSION_V1: &str = "nexo_residual_signal_v1";
pub const RESIDUAL_SIGNAL_CLASSIFIER_VERSION_V1: &str = "julia_residual_signal_classifier_v1";
pub const RESIDUAL_SIGNAL_FEATURE_ORDER_V1: [&str; 6] = [
    "rtt_ms",
    "jitter_ms",
    "loss_pct",
    "retransmission_pct",
    "handoff_count",
    "staleness_s",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResidualSignalArtifact {
    pub schema_version: String,
    pub classifier_version: String,
    pub generated_at_ts_ms: u64,
    pub feature_order: Vec<String>,
    pub weights: ResidualSignalWeights,
    pub retain_threshold: f64,
    pub samples: Vec<ResidualSignalSample>,
    pub summary: ResidualSignalSummary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResidualSignalWeights {
    pub rtt: f64,
    pub jitter: f64,
    pub loss: f64,
    pub retransmission: f64,
    pub handoff: f64,
    pub staleness: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResidualSignalSample {
    pub node_id: String,
    pub network_type: String,
    pub timestamp_utc_ms: u64,
    pub rtt_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub retransmission_pct: f64,
    pub handoff_count: u64,
    pub staleness_s: f64,
    pub robust_z: ResidualSignalRobustZ,
    pub residual_value_score: f64,
    pub residual_class: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResidualSignalRobustZ {
    pub rtt: f64,
    pub jitter: f64,
    pub loss: f64,
    pub retransmission: f64,
    pub handoff: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResidualSignalSummary {
    pub total_samples: usize,
    pub retained_samples: usize,
    pub discarded_samples: usize,
    pub retention_ratio: f64,
    pub mean_residual_value_score: f64,
    pub is_runtime_authority: bool,
    pub is_global_truth: bool,
    pub reason: String,
}

impl ResidualSignalArtifact {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RESIDUAL_SIGNAL_SCHEMA_VERSION_V1 {
            bail!("REJECTED: unsupported residual signal schema_version");
        }
        if self.classifier_version != RESIDUAL_SIGNAL_CLASSIFIER_VERSION_V1 {
            bail!("REJECTED: unsupported residual signal classifier_version");
        }
        if self.generated_at_ts_ms == 0 {
            bail!("REJECTED: invalid generated_at_ts_ms");
        }

        let expected_order: Vec<String> = RESIDUAL_SIGNAL_FEATURE_ORDER_V1
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        if self.feature_order != expected_order {
            bail!("REJECTED: invalid residual feature_order contract");
        }
        if !(0.0..=1.0).contains(&self.retain_threshold) {
            bail!("REJECTED: invalid retain_threshold");
        }
        validate_weights(&self.weights)?;

        if self.summary.total_samples != self.samples.len() {
            bail!("REJECTED: summary.total_samples mismatch");
        }
        if self.summary.retained_samples + self.summary.discarded_samples != self.samples.len() {
            bail!("REJECTED: summary retained/discarded mismatch");
        }
        if self.summary.is_runtime_authority {
            bail!("REJECTED: residual classifier artifact cannot be runtime authority");
        }
        if self.summary.is_global_truth {
            bail!("REJECTED: residual classifier artifact cannot be global truth");
        }
        if self.summary.reason.trim().is_empty() {
            bail!("REJECTED: summary.reason must not be empty");
        }

        let mut retained = 0usize;
        for sample in &self.samples {
            validate_sample(sample, self.retain_threshold)?;
            if sample.residual_class == "retain" {
                retained += 1;
            }
        }
        if retained != self.summary.retained_samples {
            bail!("REJECTED: retained sample count mismatch");
        }
        if !is_sorted_samples(&self.samples) {
            bail!("REJECTED: residual samples must be sorted deterministically");
        }

        Ok(())
    }
}

pub fn parse_and_validate_residual_signal_artifact(json: &str) -> Result<ResidualSignalArtifact> {
    let artifact: ResidualSignalArtifact = serde_json::from_str(json)
        .with_context(|| "failed to parse residual signal artifact JSON")?;
    artifact.validate()?;
    Ok(artifact)
}

fn validate_weights(weights: &ResidualSignalWeights) -> Result<()> {
    let values = [
        weights.rtt,
        weights.jitter,
        weights.loss,
        weights.retransmission,
        weights.handoff,
        weights.staleness,
    ];
    for value in values {
        if !value.is_finite() || value < 0.0 {
            bail!("REJECTED: invalid residual weight value");
        }
    }
    Ok(())
}

fn validate_sample(sample: &ResidualSignalSample, threshold: f64) -> Result<()> {
    if sample.node_id.trim().is_empty() {
        bail!("REJECTED: residual sample node_id must not be empty");
    }
    if !matches!(
        sample.network_type.as_str(),
        "wifi" | "cellular" | "ethernet" | "unknown"
    ) {
        bail!("REJECTED: invalid residual sample network_type");
    }

    ensure_nonnegative(sample.rtt_ms, "rtt_ms")?;
    ensure_nonnegative(sample.jitter_ms, "jitter_ms")?;
    ensure_percentage(sample.loss_pct, "loss_pct")?;
    ensure_percentage(sample.retransmission_pct, "retransmission_pct")?;
    ensure_nonnegative(sample.staleness_s, "staleness_s")?;
    ensure_unit_interval(sample.residual_value_score, "residual_value_score")?;
    ensure_finite(sample.robust_z.rtt, "robust_z.rtt")?;
    ensure_finite(sample.robust_z.jitter, "robust_z.jitter")?;
    ensure_finite(sample.robust_z.loss, "robust_z.loss")?;
    ensure_finite(sample.robust_z.retransmission, "robust_z.retransmission")?;
    ensure_finite(sample.robust_z.handoff, "robust_z.handoff")?;

    if !matches!(sample.residual_class.as_str(), "retain" | "discard") {
        bail!("REJECTED: invalid residual_class");
    }
    let should_retain = sample.residual_value_score >= threshold;
    if should_retain != (sample.residual_class == "retain") {
        bail!("REJECTED: residual_class does not match threshold contract");
    }

    Ok(())
}

fn is_sorted_samples(samples: &[ResidualSignalSample]) -> bool {
    samples.windows(2).all(|pair| {
        let left = &pair[0];
        let right = &pair[1];
        (
            left.timestamp_utc_ms,
            left.node_id.as_str(),
            left.network_type.as_str(),
            left.rtt_ms.to_bits(),
            left.jitter_ms.to_bits(),
        ) <= (
            right.timestamp_utc_ms,
            right.node_id.as_str(),
            right.network_type.as_str(),
            right.rtt_ms.to_bits(),
            right.jitter_ms.to_bits(),
        )
    })
}

fn ensure_nonnegative(value: f64, field: &str) -> Result<()> {
    ensure_finite(value, field)?;
    if value < 0.0 {
        bail!("REJECTED: {field} must be >= 0");
    }
    Ok(())
}

fn ensure_percentage(value: f64, field: &str) -> Result<()> {
    ensure_nonnegative(value, field)?;
    if value > 100.0 {
        bail!("REJECTED: {field} must be <= 100");
    }
    Ok(())
}

fn ensure_unit_interval(value: f64, field: &str) -> Result<()> {
    ensure_finite(value, field)?;
    if !(0.0..=1.0).contains(&value) {
        bail!("REJECTED: {field} must be in [0, 1]");
    }
    Ok(())
}

fn ensure_finite(value: f64, field: &str) -> Result<()> {
    if !value.is_finite() {
        bail!("REJECTED: {field} must be finite");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates_julia_residual_contract_fixture() {
        let fixture = include_str!("../fixtures/residual_signal_artifact_sample.json");
        let artifact = parse_and_validate_residual_signal_artifact(fixture).expect("artifact");
        assert_eq!(artifact.schema_version, RESIDUAL_SIGNAL_SCHEMA_VERSION_V1);
        assert_eq!(artifact.samples.len(), artifact.summary.total_samples);
        assert!(!artifact.summary.is_runtime_authority);
        assert!(!artifact.summary.is_global_truth);
    }

    #[test]
    fn fails_closed_for_schema_version_drift() {
        let fixture = include_str!("../fixtures/residual_signal_artifact_sample.json");
        let mut value: serde_json::Value =
            serde_json::from_str(fixture).expect("fixture should parse to Value");
        value["schema_version"] = serde_json::Value::String("invalid_v0".to_string());
        let mutated = serde_json::to_string(&value).expect("json");
        let err = parse_and_validate_residual_signal_artifact(&mutated).expect_err("must fail");
        assert!(err
            .to_string()
            .contains("unsupported residual signal schema_version"));
    }

    #[test]
    fn fails_closed_when_sample_order_drifts() {
        let fixture = include_str!("../fixtures/residual_signal_artifact_sample.json");
        let mut value: serde_json::Value =
            serde_json::from_str(fixture).expect("fixture should parse to Value");
        let samples = value
            .get_mut("samples")
            .and_then(serde_json::Value::as_array_mut)
            .expect("samples array");
        samples.reverse();
        let mutated = serde_json::to_string(&value).expect("json");
        let err = parse_and_validate_residual_signal_artifact(&mutated).expect_err("must fail");
        assert!(err
            .to_string()
            .contains("residual samples must be sorted deterministically"));
    }
}
