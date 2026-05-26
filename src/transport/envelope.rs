use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::{Uuid, Version};

use crate::message::validate_persistable_timestamp_ms;

pub const TRANSPORT_ENVELOPE_SCHEMA_V1: &str = "nexo_transport_envelope_v1";
const PAYLOAD_HASH_HEX_LEN: usize = 64;
const MAX_KEY_ID_LEN: usize = 64;
const MAX_SIGNATURE_LEN: usize = 1024;
const MAX_REQUEST_ID_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportEnvelope {
    pub schema: String,
    pub request_id: String,
    pub timestamp_utc_ms: u64,
    pub nonce: u64,
    pub key_id: String,
    pub payload_hash: String,
    pub signature: String,
}

impl TransportEnvelope {
    pub fn new(
        request_id: impl Into<String>,
        timestamp_utc_ms: u64,
        nonce: u64,
        key_id: impl Into<String>,
        payload_hash: impl Into<String>,
        signature: impl Into<String>,
    ) -> Result<Self> {
        let request_id = request_id.into();
        let key_id = key_id.into();
        let payload_hash = payload_hash.into();
        let signature = signature.into();

        validate_request_id(&request_id)?;
        validate_persistable_timestamp_ms(timestamp_utc_ms).map_err(|err| anyhow::anyhow!(err))?;
        validate_key_id(&key_id)?;
        validate_payload_hash(&payload_hash)?;
        validate_signature(&signature)?;

        Ok(Self {
            schema: TRANSPORT_ENVELOPE_SCHEMA_V1.to_string(),
            request_id,
            timestamp_utc_ms,
            nonce,
            key_id,
            payload_hash,
            signature,
        })
    }

    pub fn from_payload_bytes(
        request_id: impl Into<String>,
        timestamp_utc_ms: u64,
        nonce: u64,
        key_id: impl Into<String>,
        signature: impl Into<String>,
        payload_bytes: &[u8],
    ) -> Result<Self> {
        let payload_hash = payload_hash_hex(payload_bytes);
        Self::new(
            request_id,
            timestamp_utc_ms,
            nonce,
            key_id,
            payload_hash,
            signature,
        )
    }

    pub fn from_payload_json(
        request_id: impl Into<String>,
        timestamp_utc_ms: u64,
        nonce: u64,
        key_id: impl Into<String>,
        signature: impl Into<String>,
        payload: &Value,
    ) -> Result<Self> {
        let payload_hash = payload_hash_hex_from_json(payload)?;
        Self::new(
            request_id,
            timestamp_utc_ms,
            nonce,
            key_id,
            payload_hash,
            signature,
        )
    }

    pub fn verify_payload_bytes(&self, payload_bytes: &[u8]) -> bool {
        self.payload_hash == payload_hash_hex(payload_bytes)
    }

    pub fn verify_payload_json(&self, payload: &Value) -> Result<bool> {
        Ok(self.payload_hash == payload_hash_hex_from_json(payload)?)
    }

    pub fn signing_message_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        push_part(&mut out, self.schema.as_bytes());
        push_part(&mut out, self.request_id.as_bytes());
        push_part(&mut out, self.timestamp_utc_ms.to_string().as_bytes());
        push_part(&mut out, self.nonce.to_string().as_bytes());
        push_part(&mut out, self.key_id.as_bytes());
        push_part(&mut out, self.payload_hash.as_bytes());
        out
    }
}

pub fn payload_hash_hex(payload_bytes: &[u8]) -> String {
    blake3::hash(payload_bytes).to_hex().to_string()
}

pub fn payload_hash_hex_from_json(payload: &Value) -> Result<String> {
    let canonical = canonical_json_bytes(payload)?;
    Ok(payload_hash_hex(&canonical))
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = String::new();
    write_canonical_json(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical_json(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(v) => {
            if *v {
                out.push_str("true");
            } else {
                out.push_str("false");
            }
        }
        Value::Number(v) => out.push_str(&v.to_string()),
        Value::String(v) => out.push_str(&serde_json::to_string(v)?),
        Value::Array(values) => {
            out.push('[');
            for (idx, item) in values.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            for (idx, (key, item)) in entries.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                write_canonical_json(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<()> {
    if request_id.is_empty() || request_id.len() > MAX_REQUEST_ID_LEN {
        bail!("REJECTED: invalid request_id (expected UUID v4)");
    }
    let parsed = Uuid::parse_str(request_id)
        .map_err(|_| anyhow::anyhow!("REJECTED: invalid request_id (expected UUID v4)"))?;
    if parsed.get_version() != Some(Version::Random) {
        bail!("REJECTED: invalid request_id (expected UUID v4)");
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<()> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN {
        bail!("REJECTED: invalid key_id");
    }
    if !key_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("REJECTED: invalid key_id");
    }
    Ok(())
}

fn validate_payload_hash(payload_hash: &str) -> Result<()> {
    if payload_hash.len() != PAYLOAD_HASH_HEX_LEN {
        bail!("REJECTED: invalid payload_hash");
    }
    if !payload_hash
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("REJECTED: invalid payload_hash");
    }
    Ok(())
}

fn validate_signature(signature: &str) -> Result<()> {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_LEN {
        bail!("REJECTED: invalid signature");
    }
    if !signature.is_ascii() {
        bail!("REJECTED: invalid signature");
    }
    Ok(())
}

fn push_part(buf: &mut Vec<u8>, part: &[u8]) {
    buf.extend_from_slice(&(part.len() as u32).to_le_bytes());
    buf.extend_from_slice(part);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request_id_v4() -> &'static str {
        "564a7218-13e5-46c9-84f6-bf4c53ff533f"
    }

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        let value = json!({
            "z": 1,
            "a": {
                "b": 2,
                "a": 1
            }
        });

        let canonical = canonical_json_bytes(&value).expect("canonical bytes");
        assert_eq!(canonical, br#"{"a":{"a":1,"b":2},"z":1}"#);
    }

    #[test]
    fn payload_hash_from_json_is_order_independent_for_objects() {
        let left = json!({
            "request_id": request_id_v4(),
            "amount_cents": 150000,
            "risk_bps": 1234
        });
        let right = json!({
            "risk_bps": 1234,
            "amount_cents": 150000,
            "request_id": request_id_v4()
        });

        let left_hash = payload_hash_hex_from_json(&left).expect("left hash");
        let right_hash = payload_hash_hex_from_json(&right).expect("right hash");
        assert_eq!(left_hash, right_hash);
    }

    #[test]
    fn envelope_from_json_verifies_payload_json() {
        let payload = json!({
            "request_id": request_id_v4(),
            "timestamp_utc_ms": 1_772_000_000_000u64,
            "amount_cents": 150000
        });
        let env = TransportEnvelope::from_payload_json(
            request_id_v4(),
            1_772_000_000_000,
            7,
            "active",
            "dummy-signature-v1",
            &payload,
        )
        .expect("envelope");

        assert!(env.verify_payload_json(&payload).expect("verify"));
    }

    #[test]
    fn envelope_rejects_invalid_payload_hash() {
        let err = TransportEnvelope::new(
            request_id_v4(),
            1_772_000_000_000,
            7,
            "active",
            "ABC",
            "dummy-signature-v1",
        )
        .expect_err("must fail");
        assert!(err.to_string().contains("invalid payload_hash"));
    }

    #[test]
    fn envelope_rejects_non_v4_request_id() {
        let err = TransportEnvelope::new(
            "4a6cbef7-2f34-1d7b-8cf5-b92724a63e9b",
            1_772_000_000_000,
            7,
            "active",
            "0ea6af9f5f76dbeb0f0aaf77f02102a3134628f5486103f0c73fd6e6cf03b9f1",
            "dummy-signature-v1",
        )
        .expect_err("must fail");
        assert!(err.to_string().contains("UUID v4"));
    }

    #[test]
    fn signing_message_bytes_is_deterministic() {
        let env = TransportEnvelope::new(
            request_id_v4(),
            1_772_000_000_000,
            7,
            "active",
            "0ea6af9f5f76dbeb0f0aaf77f02102a3134628f5486103f0c73fd6e6cf03b9f1",
            "dummy-signature-v1",
        )
        .expect("envelope");

        let a = env.signing_message_bytes();
        let b = env.signing_message_bytes();
        assert_eq!(a, b);
    }
}
