use std::path::PathBuf;
use std::process::{Command, ExitStatus};

use anyhow::{bail, Context, Result};

fn run_and_require_success(command: &mut Command, label: &str) -> Result<ExitStatus> {
    let status = command
        .status()
        .with_context(|| format!("failed to execute {label}"))?;
    if !status.success() {
        bail!("{label} failed with exit status {status}");
    }
    Ok(status)
}

fn main() -> Result<()> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    if cfg!(windows) {
        let script = repo_root.join("scripts").join("run_trust_core_checks.ps1");
        run_and_require_success(
            Command::new("powershell")
                .arg("-NoProfile")
                .arg("-ExecutionPolicy")
                .arg("Bypass")
                .arg("-File")
                .arg(script),
            "scripts/run_trust_core_checks.ps1",
        )?;
    } else {
        let script = repo_root.join("scripts").join("run_trust_core_checks.sh");
        run_and_require_success(
            Command::new("bash").arg(script),
            "scripts/run_trust_core_checks.sh",
        )?;
    }

    println!("trust_core_validate: all trust-core checks passed");
    Ok(())
}
