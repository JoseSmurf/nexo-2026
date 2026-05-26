use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

const PROVIDER_ORCHESTRATOR_LOG_PATH: &str = "logs/provider_orchestrator_decision.jsonl";
const ORCHESTRATION_RULE: &str = "weighted_latency_jitter_loss_cost_v1";
const MODE_SCORE_MIN_V1: &str = "score_min_v1";
const MODE_FAILOVER_THRESHOLD_V1: &str = "failover_threshold_v1";

const WEIGHT_LATENCY: u64 = 50;
const WEIGHT_JITTER: u64 = 20;
const WEIGHT_LOSS_BPS: u64 = 30;
const WEIGHT_COST_MICROUNITS: u64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderMetric {
    pub id: String,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_bps: u16,
    pub cost_microunits: u32,
    pub region: String,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderSelection {
    pub primary_id: String,
    pub fallback_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CandidateScore {
    id: String,
    score: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailoverThresholds {
    pub max_latency_ms: u32,
    pub max_jitter_ms: u32,
    pub max_loss_bps: u16,
}

impl FailoverThresholds {
    pub fn permissive() -> Self {
        Self {
            max_latency_ms: u32::MAX,
            max_jitter_ms: u32::MAX,
            max_loss_bps: u16::MAX,
        }
    }

    fn is_degraded(self, provider: &ProviderMetric) -> bool {
        provider.latency_ms > self.max_latency_ms
            || provider.jitter_ms > self.max_jitter_ms
            || provider.loss_bps > self.max_loss_bps
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ProviderOrchestrationContent {
    timestamp_utc_ms: u64,
    providers: Vec<ProviderMetric>,
    primary_id: String,
    fallback_id: Option<String>,
    rule: String,
    selection_mode: String,
    #[serde(default)]
    previous_primary_id: Option<String>,
    #[serde(default)]
    failover_triggered: bool,
    #[serde(default)]
    thresholds: Option<FailoverThresholds>,
    candidates: Vec<CandidateScore>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProviderOrchestrationArtifact {
    timestamp_utc_ms: u64,
    providers: Vec<ProviderMetric>,
    primary_id: String,
    fallback_id: Option<String>,
    rule: String,
    #[serde(default = "default_selection_mode")]
    selection_mode: String,
    #[serde(default)]
    previous_primary_id: Option<String>,
    #[serde(default)]
    failover_triggered: bool,
    #[serde(default)]
    thresholds: Option<FailoverThresholds>,
    candidates: Vec<CandidateScore>,
    hash: String,
}

pub fn select_route(providers: Vec<ProviderMetric>) -> Result<ProviderSelection, anyhow::Error> {
    select_route_with_path(
        providers,
        Path::new(PROVIDER_ORCHESTRATOR_LOG_PATH),
        MODE_SCORE_MIN_V1,
        None,
        None,
        false,
    )
}

fn select_route_with_path(
    providers: Vec<ProviderMetric>,
    log_path: &Path,
    selection_mode: &str,
    previous_primary_id: Option<String>,
    thresholds: Option<FailoverThresholds>,
    failover_triggered: bool,
) -> Result<ProviderSelection, anyhow::Error> {
    if providers.is_empty() {
        return Err(anyhow!(
            "provider orchestrator requires at least one provider"
        ));
    }

    let mut candidates: Vec<(String, u64)> = providers
        .iter()
        .filter(|provider| provider.healthy)
        .map(|provider| (provider.id.clone(), score_provider(provider)))
        .collect();

    if candidates.is_empty() {
        return Err(anyhow!(
            "provider orchestrator found no healthy providers (fail-closed)"
        ));
    }

    candidates.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    let primary_id = candidates
        .first()
        .map(|entry| entry.0.clone())
        .ok_or_else(|| anyhow!("provider orchestrator failed to select primary provider"))?;
    let fallback_id = candidates.get(1).map(|entry| entry.0.clone());

    let timestamp_utc_ms = current_timestamp_utc_ms()?;
    let content = ProviderOrchestrationContent {
        timestamp_utc_ms,
        providers: providers.clone(),
        primary_id: primary_id.clone(),
        fallback_id: fallback_id.clone(),
        rule: ORCHESTRATION_RULE.to_string(),
        selection_mode: selection_mode.to_string(),
        previous_primary_id,
        failover_triggered,
        thresholds,
        candidates: candidates
            .iter()
            .map(|entry| CandidateScore {
                id: entry.0.clone(),
                score: entry.1,
            })
            .collect(),
    };

    let content_json = serde_json::to_vec(&content)
        .context("failed to serialize provider orchestration content")?;
    let hash = blake3::hash(&content_json).to_hex().to_string();

    let artifact = ProviderOrchestrationArtifact {
        timestamp_utc_ms: content.timestamp_utc_ms,
        providers: content.providers,
        primary_id: content.primary_id.clone(),
        fallback_id: content.fallback_id.clone(),
        rule: content.rule,
        selection_mode: content.selection_mode,
        previous_primary_id: content.previous_primary_id,
        failover_triggered: content.failover_triggered,
        thresholds: content.thresholds,
        candidates: content.candidates,
        hash,
    };
    append_artifact_jsonl(&artifact, log_path)?;

    Ok(ProviderSelection {
        primary_id,
        fallback_id,
    })
}

pub fn select_route_with_failover(
    providers: Vec<ProviderMetric>,
    previous_primary_id: Option<&str>,
    thresholds: FailoverThresholds,
) -> Result<ProviderSelection, anyhow::Error> {
    select_route_with_failover_to_path(
        providers,
        previous_primary_id,
        thresholds,
        Path::new(PROVIDER_ORCHESTRATOR_LOG_PATH),
    )
}

pub fn select_route_with_failover_to_path(
    providers: Vec<ProviderMetric>,
    previous_primary_id: Option<&str>,
    thresholds: FailoverThresholds,
    log_path: &Path,
) -> Result<ProviderSelection, anyhow::Error> {
    if providers.is_empty() {
        return Err(anyhow!(
            "provider orchestrator requires at least one provider"
        ));
    }

    let mut filtered = providers.clone();
    for provider in &mut filtered {
        if provider.healthy && thresholds.is_degraded(provider) {
            provider.healthy = false;
        }
    }

    let failover_triggered = previous_primary_id
        .and_then(|id| providers.iter().find(|provider| provider.id == id))
        .map(|provider| provider.healthy && thresholds.is_degraded(provider))
        .unwrap_or(false);

    select_route_with_path(
        filtered,
        log_path,
        MODE_FAILOVER_THRESHOLD_V1,
        previous_primary_id.map(ToString::to_string),
        Some(thresholds),
        failover_triggered,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactVerifySummary {
    pub total: usize,
    pub ok: usize,
    pub invalid: usize,
}

pub fn verify_artifact_file(path: &Path) -> Result<ArtifactVerifySummary, anyhow::Error> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read artifact file {}", path.display()))?;

    let mut summary = ArtifactVerifySummary {
        total: 0,
        ok: 0,
        invalid: 0,
    };

    for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
        summary.total += 1;
        if verify_artifact_line(line).is_ok() {
            summary.ok += 1;
        } else {
            summary.invalid += 1;
        }
    }

    Ok(summary)
}

pub fn verify_artifact_line(line: &str) -> Result<(), anyhow::Error> {
    let artifact: ProviderOrchestrationArtifact =
        serde_json::from_str(line).context("provider artifact line is malformed JSON")?;

    if artifact.rule != ORCHESTRATION_RULE {
        return Err(anyhow!(
            "provider artifact rule mismatch: expected {}, got {}",
            ORCHESTRATION_RULE,
            artifact.rule
        ));
    }

    let content = ProviderOrchestrationContent {
        timestamp_utc_ms: artifact.timestamp_utc_ms,
        providers: artifact.providers.clone(),
        primary_id: artifact.primary_id.clone(),
        fallback_id: artifact.fallback_id.clone(),
        rule: artifact.rule.clone(),
        selection_mode: artifact.selection_mode,
        previous_primary_id: artifact.previous_primary_id,
        failover_triggered: artifact.failover_triggered,
        thresholds: artifact.thresholds,
        candidates: artifact.candidates.clone(),
    };

    let content_json = serde_json::to_vec(&content)
        .context("failed to serialize provider artifact content for hash recompute")?;
    let recomputed_hash = blake3::hash(&content_json).to_hex().to_string();
    if recomputed_hash != artifact.hash {
        return Err(anyhow!("provider artifact hash mismatch"));
    }

    let expected = derive_candidates_from_artifact(&artifact.providers, artifact.thresholds)?;
    if expected.is_empty() {
        return Err(anyhow!(
            "provider artifact has no valid candidates after policy filtering"
        ));
    }

    if artifact.candidates != expected {
        return Err(anyhow!(
            "provider artifact candidates drifted from deterministic rule"
        ));
    }

    if artifact.primary_id != expected[0].id {
        return Err(anyhow!(
            "provider artifact primary_id does not match best candidate"
        ));
    }

    let expected_fallback = expected.get(1).map(|candidate| candidate.id.clone());
    if artifact.fallback_id != expected_fallback {
        return Err(anyhow!(
            "provider artifact fallback_id does not match deterministic ordering"
        ));
    }

    Ok(())
}

fn derive_candidates_from_artifact(
    providers: &[ProviderMetric],
    thresholds: Option<FailoverThresholds>,
) -> Result<Vec<CandidateScore>, anyhow::Error> {
    let mut effective = providers.to_vec();
    if let Some(thresholds) = thresholds {
        for provider in &mut effective {
            if provider.healthy && thresholds.is_degraded(provider) {
                provider.healthy = false;
            }
        }
    }

    let mut candidates: Vec<CandidateScore> = effective
        .into_iter()
        .filter(|provider| provider.healthy)
        .map(|provider| CandidateScore {
            id: provider.id.clone(),
            score: score_provider(&provider),
        })
        .collect();

    candidates.sort_by(|a, b| a.score.cmp(&b.score).then_with(|| a.id.cmp(&b.id)));
    if candidates.is_empty() {
        return Err(anyhow!(
            "provider orchestrator found no healthy providers (fail-closed)"
        ));
    }
    Ok(candidates)
}

fn default_selection_mode() -> String {
    MODE_SCORE_MIN_V1.to_string()
}

fn score_provider(provider: &ProviderMetric) -> u64 {
    (provider.latency_ms as u64 * WEIGHT_LATENCY)
        + (provider.jitter_ms as u64 * WEIGHT_JITTER)
        + (provider.loss_bps as u64 * WEIGHT_LOSS_BPS)
        + (provider.cost_microunits as u64 * WEIGHT_COST_MICROUNITS)
}

fn current_timestamp_utc_ms() -> Result<u64, anyhow::Error> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?;
    let millis = u64::try_from(duration.as_millis()).context("timestamp overflowed u64")?;
    Ok(millis)
}

fn append_artifact_jsonl(
    artifact: &ProviderOrchestrationArtifact,
    log_path: &Path,
) -> Result<(), anyhow::Error> {
    if let Some(parent) = log_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create provider orchestrator log directory at {}",
                    parent.display()
                )
            })?;
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| {
            format!(
                "failed to open provider orchestrator log file at {}",
                log_path.display()
            )
        })?;

    serde_json::to_writer(&mut file, artifact)
        .context("failed to write provider orchestrator artifact")?;
    file.write_all(b"\n")
        .context("failed to terminate provider orchestrator artifact JSONL line")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_provider(
        id: &str,
        latency_ms: u32,
        jitter_ms: u32,
        loss_bps: u16,
        cost_microunits: u32,
        healthy: bool,
    ) -> ProviderMetric {
        ProviderMetric {
            id: id.to_string(),
            latency_ms,
            jitter_ms,
            loss_bps,
            cost_microunits,
            region: "test-region".to_string(),
            healthy,
        }
    }

    fn test_log_path(test_name: &str) -> std::path::PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be >= UNIX_EPOCH")
            .as_nanos();
        std::env::temp_dir().join(format!("nexo-provider-orch-{test_name}-{ts}.jsonl"))
    }

    #[test]
    fn selects_primary_and_fallback_deterministically() {
        let providers = vec![
            sample_provider("slow", 80, 20, 50, 10, true),
            sample_provider("fast", 15, 3, 10, 20, true),
            sample_provider("mid", 30, 8, 20, 15, true),
        ];

        let selection = select_route_with_path(
            providers,
            &test_log_path("deterministic"),
            MODE_SCORE_MIN_V1,
            None,
            None,
            false,
        )
        .expect("should work");
        assert_eq!(selection.primary_id, "fast");
        assert_eq!(selection.fallback_id.as_deref(), Some("mid"));
    }

    #[test]
    fn fails_closed_when_no_healthy_provider_exists() {
        let providers = vec![
            sample_provider("a", 10, 1, 0, 1, false),
            sample_provider("b", 11, 1, 0, 1, false),
        ];
        let err = select_route_with_path(
            providers,
            &test_log_path("no-healthy"),
            MODE_SCORE_MIN_V1,
            None,
            None,
            false,
        )
        .expect_err("must fail closed");
        assert!(err.to_string().contains("no healthy providers"));
    }

    #[test]
    fn tie_breaks_by_provider_id() {
        let providers = vec![
            sample_provider("beta", 10, 1, 0, 1, true),
            sample_provider("alpha", 10, 1, 0, 1, true),
        ];
        let selection = select_route_with_path(
            providers,
            &test_log_path("tie-break"),
            MODE_SCORE_MIN_V1,
            None,
            None,
            false,
        )
        .expect("should work");
        assert_eq!(selection.primary_id, "alpha");
        assert_eq!(selection.fallback_id.as_deref(), Some("beta"));
    }

    #[test]
    fn failover_thresholds_promote_healthier_candidate() {
        let providers = vec![
            sample_provider("previous_primary", 120, 50, 200, 1, true),
            sample_provider("fallback_good", 20, 3, 10, 20, true),
            sample_provider("extra", 30, 4, 12, 30, true),
        ];
        let selection = select_route_with_failover(
            providers,
            Some("previous_primary"),
            FailoverThresholds {
                max_latency_ms: 80,
                max_jitter_ms: 30,
                max_loss_bps: 100,
            },
        )
        .expect("failover should select a healthier route");
        assert_eq!(selection.primary_id, "fallback_good");
    }

    #[test]
    fn verifies_recent_artifact_line() {
        let log_path = test_log_path("verify");
        let providers = vec![
            sample_provider("a", 12, 2, 4, 10, true),
            sample_provider("b", 13, 2, 4, 10, true),
        ];
        let selection =
            select_route_with_path(providers, &log_path, MODE_SCORE_MIN_V1, None, None, false)
                .expect("selection should succeed");
        assert_eq!(selection.primary_id, "a");

        let line = fs::read_to_string(&log_path)
            .expect("artifact should exist")
            .lines()
            .last()
            .expect("artifact line")
            .to_string();
        verify_artifact_line(&line).expect("artifact line should verify");
    }

    #[test]
    fn rejects_tampered_artifact_line_fail_closed() {
        let log_path = test_log_path("tamper");
        let providers = vec![
            sample_provider("a", 12, 2, 4, 10, true),
            sample_provider("b", 13, 2, 4, 10, true),
        ];
        select_route_with_path(providers, &log_path, MODE_SCORE_MIN_V1, None, None, false)
            .expect("selection should succeed");

        let line = fs::read_to_string(&log_path)
            .expect("artifact should exist")
            .lines()
            .last()
            .expect("artifact line")
            .to_string();

        let mut parsed: serde_json::Value =
            serde_json::from_str(&line).expect("artifact line should parse");
        parsed["primary_id"] = serde_json::Value::String("tampered-primary".to_string());
        let tampered = serde_json::to_string(&parsed).expect("tampered line should serialize");

        let err = verify_artifact_line(&tampered).expect_err("tampered line must fail closed");
        assert!(err.to_string().contains("hash mismatch"));
    }
}
