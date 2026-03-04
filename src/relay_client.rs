use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::network_udp::SignedEvent;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResult {
    pub inserted: usize,
    pub duplicates: usize,
}

#[derive(Debug, Deserialize)]
struct PushResponse {
    inserted: usize,
    duplicates: usize,
}

#[derive(Debug, Serialize)]
struct PushRequest<'a> {
    items: &'a [Value],
}

#[derive(Debug, Deserialize)]
struct PullResponse {
    items: Vec<Value>,
}

fn bytes_to_value(bytes: &[u8]) -> Value {
    Value::Array(
        bytes
            .iter()
            .map(|b| Value::Number(serde_json::Number::from(*b)))
            .collect(),
    )
}

fn value_to_bytes(value: &Value, field: &str) -> Result<Vec<u8>, String> {
    let Value::Array(items) = value else {
        return Err(format!("invalid {field}: expected array"));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::Number(n) = item else {
            return Err(format!("invalid {field}: non-number byte"));
        };
        let Some(v) = n.as_u64() else {
            return Err(format!("invalid {field}: non-u64 byte"));
        };
        if v > u8::MAX as u64 {
            return Err(format!("invalid {field}: byte out of range"));
        }
        out.push(v as u8);
    }
    Ok(out)
}

fn to_fixed<const N: usize>(value: &[u8], field: &str) -> Result<[u8; N], String> {
    if value.len() != N {
        return Err(format!("invalid {field} length: expected {N}"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(value);
    Ok(out)
}

pub fn signed_event_to_json_value(event: &SignedEvent) -> Value {
    let mut map = Map::new();
    map.insert(
        "sender_id".to_string(),
        Value::String(event.sender_id.clone()),
    );
    map.insert(
        "timestamp_utc_ms".to_string(),
        Value::Number(serde_json::Number::from(event.timestamp_utc_ms)),
    );
    map.insert(
        "nonce".to_string(),
        Value::Number(serde_json::Number::from(event.nonce)),
    );
    map.insert(
        "content_hash".to_string(),
        bytes_to_value(&event.content_hash),
    );
    map.insert(
        "origin_event_hash".to_string(),
        bytes_to_value(&event.origin_event_hash),
    );
    map.insert(
        "hops_remaining".to_string(),
        Value::Number(serde_json::Number::from(event.hops_remaining)),
    );
    map.insert("payload".to_string(), bytes_to_value(&event.payload));
    map.insert(
        "crypto_nonce".to_string(),
        match event.crypto_nonce {
            Some(v) => bytes_to_value(&v),
            None => Value::Null,
        },
    );
    map.insert(
        "sender_pubkey".to_string(),
        bytes_to_value(&event.sender_pubkey),
    );
    map.insert("signature".to_string(), bytes_to_value(&event.signature));
    Value::Object(map)
}

pub fn signed_event_from_json_value(value: Value) -> Result<SignedEvent, String> {
    let Value::Object(mut map) = value else {
        return Err("invalid sync item: expected object".to_string());
    };

    let sender_id = match map.remove("sender_id") {
        Some(Value::String(v)) if !v.trim().is_empty() => v,
        _ => return Err("invalid sender_id".to_string()),
    };
    let timestamp_utc_ms = match map.remove("timestamp_utc_ms") {
        Some(Value::Number(v)) => v
            .as_u64()
            .ok_or_else(|| "invalid timestamp_utc_ms".to_string())?,
        _ => return Err("invalid timestamp_utc_ms".to_string()),
    };
    let nonce = match map.remove("nonce") {
        Some(Value::Number(v)) => v.as_u64().ok_or_else(|| "invalid nonce".to_string())?,
        _ => return Err("invalid nonce".to_string()),
    };
    let content_hash = to_fixed::<32>(
        &value_to_bytes(
            &map.remove("content_hash")
                .ok_or_else(|| "missing content_hash".to_string())?,
            "content_hash",
        )?,
        "content_hash",
    )?;
    let origin_event_hash = to_fixed::<32>(
        &value_to_bytes(
            &map.remove("origin_event_hash")
                .ok_or_else(|| "missing origin_event_hash".to_string())?,
            "origin_event_hash",
        )?,
        "origin_event_hash",
    )?;
    let hops_remaining = match map.remove("hops_remaining") {
        Some(Value::Number(v)) => {
            let v = v
                .as_u64()
                .ok_or_else(|| "invalid hops_remaining".to_string())?;
            if v > u8::MAX as u64 {
                return Err("invalid hops_remaining".to_string());
            }
            v as u8
        }
        _ => return Err("invalid hops_remaining".to_string()),
    };
    let payload = value_to_bytes(
        &map.remove("payload")
            .ok_or_else(|| "missing payload".to_string())?,
        "payload",
    )?;
    let crypto_nonce = match map.remove("crypto_nonce") {
        Some(Value::Null) | None => None,
        Some(v) => Some(to_fixed::<24>(
            &value_to_bytes(&v, "crypto_nonce")?,
            "crypto_nonce",
        )?),
    };
    let sender_pubkey = to_fixed::<32>(
        &value_to_bytes(
            &map.remove("sender_pubkey")
                .ok_or_else(|| "missing sender_pubkey".to_string())?,
            "sender_pubkey",
        )?,
        "sender_pubkey",
    )?;
    let signature = to_fixed::<64>(
        &value_to_bytes(
            &map.remove("signature")
                .ok_or_else(|| "missing signature".to_string())?,
            "signature",
        )?,
        "signature",
    )?;

    Ok(SignedEvent {
        sender_id,
        timestamp_utc_ms,
        nonce,
        content_hash,
        origin_event_hash,
        hops_remaining,
        payload,
        crypto_nonce,
        sender_pubkey,
        signature,
    })
}

pub fn clamp_pull_limit(limit: usize) -> usize {
    limit.clamp(1, 200)
}

pub async fn push_items(relay_url: &str, items: &[SignedEvent]) -> Result<PushResult, String> {
    let base = relay_url.trim_end_matches('/');
    let values: Vec<Value> = items.iter().map(signed_event_to_json_value).collect();
    let client = Client::new();
    let resp = client
        .post(format!("{base}/push"))
        .json(&PushRequest { items: &values })
        .send()
        .await
        .map_err(|e| format!("relay push request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("relay push status={}", resp.status()));
    }
    let body: PushResponse = resp
        .json()
        .await
        .map_err(|e| format!("relay push parse failed: {e}"))?;
    Ok(PushResult {
        inserted: body.inserted,
        duplicates: body.duplicates,
    })
}

pub async fn pull_items(
    relay_url: &str,
    since_ms: u64,
    limit: usize,
) -> Result<Vec<SignedEvent>, String> {
    let base = relay_url.trim_end_matches('/');
    let clamped = clamp_pull_limit(limit);
    let client = Client::new();
    let resp = client
        .get(format!("{base}/pull?since_ms={since_ms}&limit={}", clamped))
        .send()
        .await
        .map_err(|e| format!("relay pull request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("relay pull status={}", resp.status()));
    }
    let body: PullResponse = resp
        .json()
        .await
        .map_err(|e| format!("relay pull parse failed: {e}"))?;
    let mut out = Vec::with_capacity(body.items.len());
    for item in body.items {
        out.push(signed_event_from_json_value(item)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> SignedEvent {
        SignedEvent {
            sender_id: "node_a".to_string(),
            timestamp_utc_ms: 123,
            nonce: 7,
            content_hash: [1u8; 32],
            origin_event_hash: [2u8; 32],
            hops_remaining: 4,
            payload: b"hello".to_vec(),
            crypto_nonce: Some([3u8; 24]),
            sender_pubkey: [4u8; 32],
            signature: [5u8; 64],
        }
    }

    #[test]
    fn signed_event_json_roundtrip_is_deterministic() {
        let event = sample_event();
        let json_a = signed_event_to_json_value(&event);
        let json_b = signed_event_to_json_value(&event);
        assert_eq!(
            serde_json::to_string(&json_a).expect("json_a"),
            serde_json::to_string(&json_b).expect("json_b")
        );
        let decoded = signed_event_from_json_value(json_a).expect("decode");
        assert_eq!(decoded, event);
    }

    #[test]
    fn clamp_pull_limit_is_fail_closed() {
        assert_eq!(clamp_pull_limit(0), 1);
        assert_eq!(clamp_pull_limit(1), 1);
        assert_eq!(clamp_pull_limit(200), 200);
        assert_eq!(clamp_pull_limit(201), 200);
    }
}
