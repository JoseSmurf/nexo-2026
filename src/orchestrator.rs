use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};

const ORCHESTRATOR_DECISION_LOG_PATH: &str = "logs/orchestrator_decision.jsonl";
const ORCHESTRATION_RULE: &str = "menor_latencia";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    orchestrate_with_path(servers, Path::new(ORCHESTRATOR_DECISION_LOG_PATH))
}

fn orchestrate_with_path(
    servers: Vec<ServerMetric>,
    log_path: &Path,
) -> Result<String, anyhow::Error> {
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

    append_artifact_jsonl(&artifact, log_path)?;
    Ok(content.choice)
}

fn current_timestamp_utc_ms() -> Result<u64, anyhow::Error> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?;
    let millis = u64::try_from(duration.as_millis()).context("timestamp overflowed u64")?;
    Ok(millis)
}

fn append_artifact_jsonl(
    artifact: &OrchestratorDecisionArtifact,
    log_path: &Path,
) -> Result<(), anyhow::Error> {
    if let Some(parent) = log_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create log directory at {}", parent.display()))?;
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .with_context(|| {
            format!(
                "failed to open orchestrator log file at {}",
                log_path.display()
            )
        })?;

    serde_json::to_writer(&mut file, artifact).context("failed to write orchestrator artifact")?;
    file.write_all(b"\n")
        .context("failed to terminate orchestrator artifact JSONL line")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct ArtifactLine {
        timestamp_utc_ms: u64,
        servers: Vec<ServerMetric>,
        choice: String,
        rule: String,
        hash: String,
    }

    #[derive(Debug, Serialize)]
    struct ArtifactContent<'a> {
        timestamp_utc_ms: u64,
        servers: &'a [ServerMetric],
        choice: &'a str,
        rule: &'a str,
    }

    fn test_log_path(test_name: &str) -> std::path::PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be >= UNIX_EPOCH")
            .as_nanos();
        std::env::temp_dir().join(format!("nexo-orchestrator-{test_name}-{ts}.jsonl"))
    }

    fn read_artifacts(path: &Path) -> Vec<ArtifactLine> {
        let raw = fs::read_to_string(path).expect("artifact file should be readable");
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<ArtifactLine>(line).expect("line should be valid JSON"))
            .collect()
    }

    #[test]
    fn chooses_lowest_latency_server() {
        let log_path = test_log_path("lowest-latency");
        let servers = vec![
            ServerMetric {
                id: "alpha".to_string(),
                latency_ms: 18,
            },
            ServerMetric {
                id: "beta".to_string(),
                latency_ms: 9,
            },
            ServerMetric {
                id: "gamma".to_string(),
                latency_ms: 30,
            },
        ];

        let choice =
            orchestrate_with_path(servers.clone(), &log_path).expect("orchestrate should succeed");
        assert_eq!(choice, "beta");

        let lines = read_artifacts(&log_path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].choice, "beta");
        assert_eq!(lines[0].rule, ORCHESTRATION_RULE);
        assert_eq!(lines[0].servers, servers);
    }

    #[test]
    fn returns_error_for_empty_server_list() {
        let log_path = test_log_path("empty-list");
        let err = orchestrate_with_path(Vec::new(), &log_path)
            .expect_err("empty list must fail closed");
        assert!(
            err.to_string()
                .contains("orchestrator requires at least one server metric")
        );
    }

    #[test]
    fn writes_hash_of_content_without_hash_field() {
        let log_path = test_log_path("hash-content");
        let servers = vec![
            ServerMetric {
                id: "s1".to_string(),
                latency_ms: 40,
            },
            ServerMetric {
                id: "s2".to_string(),
                latency_ms: 10,
            },
        ];

        orchestrate_with_path(servers, &log_path).expect("orchestrate should succeed");
        let lines = read_artifacts(&log_path);
        let line = lines.first().expect("one line should be present");

        let content = ArtifactContent {
            timestamp_utc_ms: line.timestamp_utc_ms,
            servers: &line.servers,
            choice: &line.choice,
            rule: &line.rule,
        };
        let content_json = serde_json::to_vec(&content).expect("content should serialize");
        let recomputed = blake3::hash(&content_json).to_hex().to_string();

        assert_eq!(line.hash, recomputed);
    }

    #[test]
    fn appends_jsonl_records() {
        let log_path = test_log_path("append");
        let first = vec![
            ServerMetric {
                id: "r1".to_string(),
                latency_ms: 50,
            },
            ServerMetric {
                id: "r2".to_string(),
                latency_ms: 20,
            },
        ];
        let second = vec![
            ServerMetric {
                id: "r3".to_string(),
                latency_ms: 70,
            },
            ServerMetric {
                id: "r4".to_string(),
                latency_ms: 12,
            },
        ];

        orchestrate_with_path(first, &log_path).expect("first record should be written");
        orchestrate_with_path(second, &log_path).expect("second record should be appended");

        let lines = read_artifacts(&log_path);
        assert_eq!(lines.len(), 2);
    }
}
