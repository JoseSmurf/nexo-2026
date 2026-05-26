use std::fs;
use std::path::Path;

use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::Value;
use syntax_engine::transport::envelope::TransportEnvelope;

const FIXTURE_PATH: &str = "fixtures/transport_envelope_cross_platform.json";
const REQUEST_ID: &str = "564a7218-13e5-46c9-84f6-bf4c53ff533f";
const TIMESTAMP_UTC_MS: u64 = 1_772_000_000_000;
const NONCE: u64 = 1_772_000_000_000;
const KEY_ID: &str = "active";
const SIGNATURE: &str = "contract-signature-v1";

#[derive(Debug, Serialize)]
struct Fixture {
    request_id: &'static str,
    timestamp_utc_ms: u64,
    nonce: u64,
    key_id: &'static str,
    signature: &'static str,
    expected_payload_hash: String,
    expected_signing_message_hex: String,
    payloads: PayloadVariants,
}

#[derive(Debug, Serialize)]
struct PayloadVariants {
    android: String,
    ios: String,
    cli: String,
}

fn payload_android() -> String {
    format!(
        "{{\"request_id\":\"{REQUEST_ID}\",\"user_id\":\"contract_user\",\"amount_cents\":150000,\"risk_bps\":1234,\"timestamp_utc_ms\":{TIMESTAMP_UTC_MS},\"has_active_kyc\":true,\"is_pep\":false,\"ui_hash_valid\":true}}"
    )
}

fn payload_ios() -> String {
    format!(
        "{{\"amount_cents\":150000,\"has_active_kyc\":true,\"is_pep\":false,\"request_id\":\"{REQUEST_ID}\",\"risk_bps\":1234,\"timestamp_utc_ms\":{TIMESTAMP_UTC_MS},\"ui_hash_valid\":true,\"user_id\":\"contract_user\"}}"
    )
}

fn payload_cli() -> String {
    format!(
        "{{\"risk_bps\":1234,\"timestamp_utc_ms\":{TIMESTAMP_UTC_MS},\"ui_hash_valid\":true,\"request_id\":\"{REQUEST_ID}\",\"user_id\":\"contract_user\",\"is_pep\":false,\"has_active_kyc\":true,\"amount_cents\":150000}}"
    )
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("hex encoding should not fail");
    }
    out
}

fn envelope_for(payload: &Value) -> Result<TransportEnvelope> {
    TransportEnvelope::from_payload_json(
        REQUEST_ID,
        TIMESTAMP_UTC_MS,
        NONCE,
        KEY_ID,
        SIGNATURE,
        payload,
    )
}

fn main() -> Result<()> {
    let android = payload_android();
    let ios = payload_ios();
    let cli = payload_cli();
    let android_value: Value = serde_json::from_str(&android)?;
    let ios_value: Value = serde_json::from_str(&ios)?;
    let cli_value: Value = serde_json::from_str(&cli)?;

    let env_android = envelope_for(&android_value)?;
    let env_ios = envelope_for(&ios_value)?;
    let env_cli = envelope_for(&cli_value)?;

    if env_android.payload_hash != env_ios.payload_hash
        || env_android.payload_hash != env_cli.payload_hash
    {
        return Err(anyhow!(
            "cross-platform payload hash drift detected while generating fixture"
        ));
    }

    let signing_hex = bytes_to_hex(&env_android.signing_message_bytes());
    let signing_hex_ios = bytes_to_hex(&env_ios.signing_message_bytes());
    let signing_hex_cli = bytes_to_hex(&env_cli.signing_message_bytes());
    if signing_hex != signing_hex_ios || signing_hex != signing_hex_cli {
        return Err(anyhow!(
            "cross-platform signing message drift detected while generating fixture"
        ));
    }

    let fixture = Fixture {
        request_id: REQUEST_ID,
        timestamp_utc_ms: TIMESTAMP_UTC_MS,
        nonce: NONCE,
        key_id: KEY_ID,
        signature: SIGNATURE,
        expected_payload_hash: env_android.payload_hash,
        expected_signing_message_hex: signing_hex,
        payloads: PayloadVariants { android, ios, cli },
    };

    if let Some(parent) = Path::new(FIXTURE_PATH).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut out = serde_json::to_string_pretty(&fixture)?;
    out.push('\n');
    fs::write(FIXTURE_PATH, out)?;
    println!("generated {FIXTURE_PATH}");
    Ok(())
}
