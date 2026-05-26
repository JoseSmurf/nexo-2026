use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use syntax_engine::residual_signal_contract::parse_and_validate_residual_signal_artifact;

const DEFAULT_INPUT_PATH: &str = "fixtures/residual_signal_artifact_sample.json";
const DEFAULT_FLOW_LOG_PATH: &str = "logs/operational_flow.jsonl";

#[derive(Debug, Serialize)]
struct ResidualBridgeFlowRecord {
    schema: &'static str,
    bridge_version: &'static str,
    timestamp_utc_ms: u64,
    kind: &'static str,
    origin: String,
    channel: &'static str,
    summary: String,
    residual_schema_version: String,
    residual_classifier_version: String,
    retained_samples: usize,
    discarded_samples: usize,
    retention_ratio: f64,
    is_runtime_authority: bool,
    is_global_truth: bool,
}

fn now_utc_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX_EPOCH")?;
    u64::try_from(duration.as_millis()).context("timestamp overflow while converting to u64")
}

fn append_jsonl_line(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create operational flow directory {}",
                    parent.display()
                )
            })?;
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open operational flow log at {}", path.display()))?;
    file.write_all(line.as_bytes())
        .context("failed to append operational flow JSONL line")?;
    file.write_all(b"\n")
        .context("failed to append operational flow newline")?;
    Ok(())
}

fn parse_args() -> (PathBuf, PathBuf) {
    let mut args = std::env::args().skip(1);
    let input = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_INPUT_PATH));
    let output = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_FLOW_LOG_PATH));
    (input, output)
}

fn run(input_path: &Path, output_path: &Path) -> Result<()> {
    let raw = fs::read_to_string(input_path).with_context(|| {
        format!(
            "failed to read residual artifact at {}",
            input_path.display()
        )
    })?;
    let artifact = parse_and_validate_residual_signal_artifact(&raw)
        .context("residual artifact contract validation failed")?;

    let record = ResidualBridgeFlowRecord {
        schema: "nexo_operational_flow_v1",
        bridge_version: "nexo_residual_bridge_v1",
        timestamp_utc_ms: now_utc_ms()?,
        kind: "ai",
        origin: format!("observer:{}", artifact.classifier_version),
        channel: "observer_bridge",
        summary: format!(
            "residual artifact validated (retained={} discarded={} retention_ratio={:.4})",
            artifact.summary.retained_samples,
            artifact.summary.discarded_samples,
            artifact.summary.retention_ratio
        ),
        residual_schema_version: artifact.schema_version,
        residual_classifier_version: artifact.classifier_version,
        retained_samples: artifact.summary.retained_samples,
        discarded_samples: artifact.summary.discarded_samples,
        retention_ratio: artifact.summary.retention_ratio,
        is_runtime_authority: artifact.summary.is_runtime_authority,
        is_global_truth: artifact.summary.is_global_truth,
    };

    let line = serde_json::to_string(&record).context("failed to serialize bridge flow record")?;
    append_jsonl_line(output_path, &line)?;
    Ok(())
}

fn main() {
    let (input_path, output_path) = parse_args();
    if let Err(err) = run(&input_path, &output_path) {
        eprintln!("residual_signal_bridge failed: {err}");
        std::process::exit(1);
    }
    println!(
        "residual_signal_bridge ok: input={} output={}",
        input_path.display(),
        output_path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_appends_operational_flow_record() {
        let input = PathBuf::from("fixtures/residual_signal_artifact_sample.json");
        let output = std::env::temp_dir().join(format!(
            "nexo_residual_bridge_{}.jsonl",
            now_utc_ms().expect("ts")
        ));
        run(&input, &output).expect("bridge run should succeed");

        let raw = fs::read_to_string(&output).expect("output jsonl should be readable");
        let line = raw
            .lines()
            .last()
            .expect("output should contain at least one line");
        let value: serde_json::Value = serde_json::from_str(line).expect("line should be JSON");
        assert_eq!(value["schema"], "nexo_operational_flow_v1");
        assert_eq!(value["kind"], "ai");
        assert_eq!(value["channel"], "observer_bridge");
        assert!(value["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("residual artifact validated"));

        let _ = fs::remove_file(output);
    }
}
