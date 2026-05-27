use std::fs;

use anyhow::{Context, Result};
use syntax_engine::residual_signal_contract::parse_and_validate_residual_signal_artifact;

fn run(path: &str) -> Result<String> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read residual signal artifact at {path}"))?;

    parse_and_validate_residual_signal_artifact(&raw)
        .with_context(|| format!("residual signal contract validation failed for {path}"))?;

    Ok(blake3::hash(raw.as_bytes()).to_hex().to_string())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: residual_signal_hash <artifact.json>");
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("usage: residual_signal_hash <artifact.json>");
        std::process::exit(2);
    }

    match run(&path) {
        Ok(hash_hex) => println!("{hash_hex}"),
        Err(err) => {
            eprintln!("residual_signal_hash failed: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_valid_fixture() {
        let hash = run("fixtures/residual_signal_artifact_sample.json").expect("hash should work");
        assert_eq!(hash.len(), 64);
        assert!(hash
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn rejects_invalid_fixture() {
        let invalid = r#"{"schema_version":"invalid_v0"}"#;
        let path = std::env::temp_dir().join("nexo_residual_signal_hash_invalid.json");
        fs::write(&path, invalid).expect("write invalid fixture");
        let err = run(path.to_str().expect("utf-8 path")).expect_err("must fail closed");
        assert!(err.to_string().contains("contract validation failed"));
        let _ = fs::remove_file(path);
    }
}
