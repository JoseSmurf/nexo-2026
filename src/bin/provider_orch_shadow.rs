use std::env;
use std::fs;

use serde::Deserialize;
use syntax_engine::provider_orchestrator::{self, ProviderMetric};

fn main() {
    if !orchestrator_enabled() {
        eprintln!("provider_orch_shadow: disabled (set NEXO_PROVIDER_ORCH=1 to enable)");
        return;
    }

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: provider_orch_shadow <providers_metrics.json>");
        std::process::exit(2);
    }

    let input_path = &args[1];
    let content = fs::read_to_string(input_path).unwrap_or_else(|err| {
        eprintln!(
            "provider_orch_shadow: failed to read {}: {}",
            input_path, err
        );
        std::process::exit(2);
    });

    let providers: Vec<ProviderMetric> = parse_provider_metrics(&content).unwrap_or_else(|err| {
        eprintln!(
            "provider_orch_shadow: invalid metrics file {}: {}",
            input_path, err
        );
        std::process::exit(2);
    });

    let selection = provider_orchestrator::select_route(providers).unwrap_or_else(|err| {
        eprintln!("provider_orch_shadow: route selection failed: {}", err);
        std::process::exit(1);
    });

    println!("provider_orch_shadow: primary={}", selection.primary_id);
    if let Some(fallback) = selection.fallback_id {
        println!("provider_orch_shadow: fallback={}", fallback);
    } else {
        println!("provider_orch_shadow: fallback=none");
    }
    println!("provider_orch_shadow: artifact=logs/provider_orchestrator_decision.jsonl");
}

fn orchestrator_enabled() -> bool {
    matches!(
        env::var("NEXO_PROVIDER_ORCH").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

#[derive(Debug, Deserialize)]
struct ProviderMetricList {
    providers: Vec<ProviderMetric>,
}

fn parse_provider_metrics(content: &str) -> Result<Vec<ProviderMetric>, serde_json::Error> {
    if let Ok(list) = serde_json::from_str::<ProviderMetricList>(content) {
        return Ok(list.providers);
    }
    serde_json::from_str::<Vec<ProviderMetric>>(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wrapped_provider_metrics() {
        let raw = r#"{
            "providers":[
                {"id":"a","latency_ms":11,"jitter_ms":2,"loss_bps":3,"cost_microunits":4,"region":"x","healthy":true}
            ]
        }"#;
        let providers = parse_provider_metrics(raw).expect("wrapped providers should parse");
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id, "a");
    }

    #[test]
    fn parses_array_provider_metrics() {
        let raw = r#"[
            {"id":"a","latency_ms":11,"jitter_ms":2,"loss_bps":3,"cost_microunits":4,"region":"x","healthy":true},
            {"id":"b","latency_ms":15,"jitter_ms":3,"loss_bps":5,"cost_microunits":1,"region":"y","healthy":true}
        ]"#;
        let providers = parse_provider_metrics(raw).expect("array providers should parse");
        assert_eq!(providers.len(), 2);
        assert_eq!(providers[1].id, "b");
    }
}
