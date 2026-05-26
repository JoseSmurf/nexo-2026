use std::env;
use std::path::Path;

use syntax_engine::provider_orchestrator;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: provider_orch_verify <provider_orchestrator_decision.jsonl>");
        std::process::exit(2);
    }

    let path = Path::new(&args[1]);
    let summary = provider_orchestrator::verify_artifact_file(path).unwrap_or_else(|err| {
        eprintln!(
            "provider_orch_verify: failed to verify artifact file: {}",
            err
        );
        std::process::exit(2);
    });

    println!(
        "provider_orch_verify: total={} ok={} invalid={}",
        summary.total, summary.ok, summary.invalid
    );
    if summary.invalid > 0 {
        std::process::exit(1);
    }
}
