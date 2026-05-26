use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

const PROVIDER_ORCHESTRATOR_LOG_PATH: &str = "logs/provider_orchestrator_decision.jsonl";
const ORCHESTRATION_RULE: &str = "weighted_latency_jitter_loss_cost_v1";

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

#[derive(Debug, Clone, Serialize)]
struct CandidateScore {
    id: String,
    score: u64,
}

#[derive(Debug, Serialize)]
struct ProviderOrchestrationContent {
    timestamp_utc_ms: u64,
    providers: Vec<ProviderMetric>,
    primary_id: String,
    fallback_id: Option<String>,
    rule: &'static str,
    candidates: Vec<CandidateScore>,
}

#[derive(Debug, Serialize)]
struct ProviderOrchestrationArtifact {
    timestamp_utc_ms: u64,
    providers: Vec<ProviderMetric>,
    primary_id: String,
    fallback_id: Option<String>,
    rule: &'static str,
    candidates: Vec<CandidateScore>,
    hash: String,
}

pub fn select_route(providers: Vec<ProviderMetric>) -> Result<ProviderSelection, anyhow::Error> {
    select_route_with_path(providers, Path::new(PROVIDER_ORCHESTRATOR_LOG_PATH))
}

fn select_route_with_path(
    providers: Vec<ProviderMetric>,
    log_path: &Path,
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
        rule: ORCHESTRATION_RULE,
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
        candidates: content.candidates,
        hash,
    };
    append_artifact_jsonl(&artifact, log_path)?;

    Ok(ProviderSelection {
        primary_id,
        fallback_id,
    })
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

        let selection = select_route_with_path(providers, &test_log_path("deterministic"))
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
        let err = select_route_with_path(providers, &test_log_path("no-healthy"))
            .expect_err("must fail closed");
        assert!(err.to_string().contains("no healthy providers"));
    }

    #[test]
    fn tie_breaks_by_provider_id() {
        let providers = vec![
            sample_provider("beta", 10, 1, 0, 1, true),
            sample_provider("alpha", 10, 1, 0, 1, true),
        ];
        let selection =
            select_route_with_path(providers, &test_log_path("tie-break")).expect("should work");
        assert_eq!(selection.primary_id, "alpha");
        assert_eq!(selection.fallback_id.as_deref(), Some("beta"));
    }
}
