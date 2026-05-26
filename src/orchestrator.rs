use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use serde::Serialize;

const ORCHESTRATOR_DECISION_LOG_PATH: &str = "logs/orchestrator_decision.jsonl";
const ORCHESTRATION_RULE: &str = "menor_latencia";

#[derive(Debug, Clone, Serialize)]
pub struct ServerMetric {
    pub id: String,
    pub latency_ms: u32,
}

#[derive(Debug, Serialize)]
struct OrchestratorDecisionContent {
    timestamp_utc_ms: u64,
    servers: Vec<ServerMetric>,
    choice: String,
    rule: &'static str,
}

#[derive(Debug, Serialize)]
struct OrchestratorDecisionArtifact {
    timestamp_utc_ms: u64,
    servers: Vec<ServerMetric>,
    choice: String,
    rule: &'static str,
    hash: String,
}

pub fn orchestrate(servers: Vec<ServerMetric>) -> Result<String, anyhow::Error> {
    let selected = servers
        .iter()
        .min_by_key(|server| server.latency_ms)
        .ok_or_else(|| anyhow!("orchestrator requires at least one server metric"))?;

    let timestamp_utc_ms = current_timestamp_utc_ms()?;
    let content = OrchestratorDecisionContent {
        timestamp_utc_ms,
        servers: servers.clone(),
        choice: selected.id.clone(),
        rule: ORCHESTRATION_RULE,
    };

    let content_json =
        serde_json::to_vec(&content).context("failed to serialize orchestrator content")?;
    let hash = blake3::hash(&content_json).to_hex().to_string();

    let artifact = OrchestratorDecisionArtifact {
        timestamp_utc_ms: content.timestamp_utc_ms,
        servers: content.servers,
        choice: content.choice.clone(),
        rule: content.rule,
        hash,
    };

    append_artifact_jsonl(&artifact)?;
    Ok(content.choice)
}

fn current_timestamp_utc_ms() -> Result<u64, anyhow::Error> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?;
    let millis = u64::try_from(duration.as_millis()).context("timestamp overflowed u64")?;
    Ok(millis)
}

fn append_artifact_jsonl(artifact: &OrchestratorDecisionArtifact) -> Result<(), anyhow::Error> {
    fs::create_dir_all("logs").context("failed to create logs directory")?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(ORCHESTRATOR_DECISION_LOG_PATH)
        .with_context(|| {
            format!(
                "failed to open orchestrator log file at {}",
                ORCHESTRATOR_DECISION_LOG_PATH
            )
        })?;

    serde_json::to_writer(&mut file, artifact).context("failed to write orchestrator artifact")?;
    file.write_all(b"\n")
        .context("failed to terminate orchestrator artifact JSONL line")?;
    Ok(())
}
