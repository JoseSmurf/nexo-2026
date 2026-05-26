use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use syntax_engine::provider_orchestrator::{
    self, FailoverThresholds, ProviderMetric, ProviderSelection,
};

const DEFAULT_ARTIFACT_PATH: &str = "logs/provider_orchestrator_cycle.jsonl";
const DEFAULT_REPORT_PATH: &str = "logs/provider_orchestrator_cycle_report.json";

#[derive(Debug, Deserialize)]
struct CycleEnvelope {
    cycles: Vec<CycleEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CycleInput {
    Envelope(CycleEnvelope),
    Entries(Vec<CycleEntry>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CycleEntry {
    ProvidersOnly(Vec<ProviderMetric>),
    Named {
        providers: Vec<ProviderMetric>,
        label: Option<String>,
    },
}

#[derive(Debug, Serialize)]
struct CycleReport {
    total_cycles: usize,
    successful_cycles: usize,
    failed_cycles: usize,
    failover_events: usize,
    failover_rate_pct: f64,
    primary_churn_pct: f64,
    primary_latency_p95_ms: f64,
    selected_primary_sequence: Vec<String>,
    artifact_path: String,
    artifact_verify_total: usize,
    artifact_verify_ok: usize,
    artifact_verify_invalid: usize,
    slo: SloEvaluation,
}

#[derive(Debug, Serialize)]
struct SloEvaluation {
    max_p95_latency_ms: Option<f64>,
    max_churn_pct: Option<f64>,
    max_invalid_artifacts: Option<usize>,
    pass_p95_latency: bool,
    pass_churn_pct: bool,
    pass_invalid_artifacts: bool,
    overall_pass: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("provider_orch_cycle: {}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 4 {
        return Err(anyhow!(
            "usage: provider_orch_cycle <provider_metrics_cycle.json> [artifact_path] [report_path]"
        ));
    }

    let input_path = &args[1];
    let artifact_path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| DEFAULT_ARTIFACT_PATH.to_string());
    let report_path = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| DEFAULT_REPORT_PATH.to_string());

    let cycles = parse_cycle_file(input_path)?;
    if cycles.is_empty() {
        return Err(anyhow!(
            "provider_orch_cycle: no cycles found in input metrics file"
        ));
    }

    truncate_file(&artifact_path)?;

    let thresholds = load_failover_thresholds();
    let mut previous_primary: Option<String> = None;
    let mut successful_cycles = 0usize;
    let mut failed_cycles = 0usize;
    let mut failover_events = 0usize;
    let mut selected_primary_sequence: Vec<String> = Vec::new();
    let mut primary_latencies: Vec<u32> = Vec::new();

    for cycle in &cycles {
        let selection = provider_orchestrator::select_route_with_failover_to_path(
            cycle.providers.clone(),
            previous_primary.as_deref(),
            thresholds,
            Path::new(&artifact_path),
        );

        let selection = match selection {
            Ok(selection) => selection,
            Err(_) => {
                failed_cycles += 1;
                continue;
            }
        };

        update_metrics_for_selection(
            cycle,
            &selection,
            &mut previous_primary,
            &mut failover_events,
            &mut selected_primary_sequence,
            &mut primary_latencies,
        )?;

        successful_cycles += 1;
    }

    let verify_summary = provider_orchestrator::verify_artifact_file(Path::new(&artifact_path))
        .with_context(|| format!("failed to verify artifact file {}", artifact_path))?;
    let p95_latency = percentile_u32(&primary_latencies, 95.0);
    let transitions = successful_cycles.saturating_sub(1);
    let churn_pct = if transitions == 0 {
        0.0
    } else {
        (failover_events as f64 / transitions as f64) * 100.0
    };
    let failover_rate_pct = churn_pct;

    let slo = evaluate_slo(p95_latency, churn_pct, verify_summary.invalid);

    let report = CycleReport {
        total_cycles: cycles.len(),
        successful_cycles,
        failed_cycles,
        failover_events,
        failover_rate_pct,
        primary_churn_pct: churn_pct,
        primary_latency_p95_ms: p95_latency,
        selected_primary_sequence,
        artifact_path: artifact_path.clone(),
        artifact_verify_total: verify_summary.total,
        artifact_verify_ok: verify_summary.ok,
        artifact_verify_invalid: verify_summary.invalid,
        slo,
    };

    write_report(&report_path, &report)?;
    println!(
        "provider_orch_cycle: cycles={} ok={} fail={} p95_latency_ms={:.2} churn_pct={:.2} artifact_invalid={} report={}",
        report.total_cycles,
        report.successful_cycles,
        report.failed_cycles,
        report.primary_latency_p95_ms,
        report.primary_churn_pct,
        report.artifact_verify_invalid,
        report_path
    );

    if !report.slo.overall_pass {
        std::process::exit(1);
    }

    Ok(())
}

#[derive(Debug)]
struct CycleMaterialized {
    providers: Vec<ProviderMetric>,
    #[allow(dead_code)]
    label: Option<String>,
}

fn parse_cycle_file(path: &str) -> Result<Vec<CycleMaterialized>, anyhow::Error> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read cycle input file {}", path))?;
    let parsed: CycleInput = serde_json::from_str(&content)
        .with_context(|| format!("invalid cycle input JSON {}", path))?;

    let entries = match parsed {
        CycleInput::Envelope(envelope) => envelope.cycles,
        CycleInput::Entries(entries) => entries,
    };

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        match entry {
            CycleEntry::ProvidersOnly(providers) => out.push(CycleMaterialized {
                providers,
                label: None,
            }),
            CycleEntry::Named { providers, label } => {
                out.push(CycleMaterialized { providers, label })
            }
        }
    }
    Ok(out)
}

fn update_metrics_for_selection(
    cycle: &CycleMaterialized,
    selection: &ProviderSelection,
    previous_primary: &mut Option<String>,
    failover_events: &mut usize,
    selected_primary_sequence: &mut Vec<String>,
    primary_latencies: &mut Vec<u32>,
) -> Result<(), anyhow::Error> {
    if let Some(previous) = previous_primary.as_deref() {
        if previous != selection.primary_id {
            *failover_events += 1;
        }
    }
    *previous_primary = Some(selection.primary_id.clone());
    selected_primary_sequence.push(selection.primary_id.clone());

    let primary = cycle
        .providers
        .iter()
        .find(|provider| provider.id == selection.primary_id)
        .ok_or_else(|| anyhow!("selected primary id not found in cycle provider list"))?;
    primary_latencies.push(primary.latency_ms);
    Ok(())
}

fn truncate_file(path: &str) -> Result<(), anyhow::Error> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create artifact parent {}", parent.display())
            })?;
        }
    }
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("failed to create/clear artifact file {}", path))?;
    Ok(())
}

fn write_report(path: &str, report: &CycleReport) -> Result<(), anyhow::Error> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create report parent {}", parent.display()))?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("failed to open report path {}", path))?;
    serde_json::to_writer_pretty(&mut file, report).context("failed to serialize cycle report")?;
    file.write_all(b"\n")
        .context("failed to finalize report newline")?;
    Ok(())
}

fn load_failover_thresholds() -> FailoverThresholds {
    let max_latency_ms = env::var("NEXO_PROVIDER_ORCH_MAX_LATENCY_MS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let max_jitter_ms = env::var("NEXO_PROVIDER_ORCH_MAX_JITTER_MS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let max_loss_bps = env::var("NEXO_PROVIDER_ORCH_MAX_LOSS_BPS")
        .ok()
        .and_then(|v| v.parse::<u16>().ok());

    match (max_latency_ms, max_jitter_ms, max_loss_bps) {
        (Some(latency), Some(jitter), Some(loss)) => FailoverThresholds {
            max_latency_ms: latency,
            max_jitter_ms: jitter,
            max_loss_bps: loss,
        },
        _ => FailoverThresholds::permissive(),
    }
}

fn percentile_u32(values: &[u32], pct: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = (((sorted.len() - 1) as f64) * (pct / 100.0)).round() as usize;
    sorted[idx] as f64
}

fn evaluate_slo(p95_latency_ms: f64, churn_pct: f64, invalid_artifacts: usize) -> SloEvaluation {
    let max_p95_latency_ms = env::var("NEXO_PROVIDER_ORCH_SLO_MAX_P95_LATENCY_MS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok());
    let max_churn_pct = env::var("NEXO_PROVIDER_ORCH_SLO_MAX_CHURN_PCT")
        .ok()
        .and_then(|v| v.parse::<f64>().ok());
    let max_invalid_artifacts = env::var("NEXO_PROVIDER_ORCH_SLO_MAX_INVALID_ARTIFACTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());

    let pass_p95_latency = max_p95_latency_ms
        .map(|max| p95_latency_ms <= max)
        .unwrap_or(true);
    let pass_churn_pct = max_churn_pct.map(|max| churn_pct <= max).unwrap_or(true);
    let pass_invalid_artifacts = max_invalid_artifacts
        .map(|max| invalid_artifacts <= max)
        .unwrap_or(true);

    SloEvaluation {
        max_p95_latency_ms,
        max_churn_pct,
        max_invalid_artifacts,
        pass_p95_latency,
        pass_churn_pct,
        pass_invalid_artifacts,
        overall_pass: pass_p95_latency && pass_churn_pct && pass_invalid_artifacts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_envelope_cycle_input() {
        let raw = r#"{
            "cycles":[
                {"providers":[{"id":"a","latency_ms":10,"jitter_ms":1,"loss_bps":2,"cost_microunits":3,"region":"x","healthy":true}]}
            ]
        }"#;
        let parsed: CycleInput = serde_json::from_str(raw).expect("parse should work");
        match parsed {
            CycleInput::Envelope(envelope) => assert_eq!(envelope.cycles.len(), 1),
            CycleInput::Entries(_) => panic!("expected envelope"),
        }
    }

    #[test]
    fn percentile_uses_stable_round_index() {
        let data = vec![10_u32, 20, 30, 40, 50];
        let p95 = percentile_u32(&data, 95.0);
        assert_eq!(p95, 50.0);
    }
}
