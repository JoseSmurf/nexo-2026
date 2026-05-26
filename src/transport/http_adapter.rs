use anyhow::{Context, Result};
use serde_json::Value;

use super::envelope::{payload_hash_hex_from_json, TransportEnvelope};

#[derive(Debug, Clone)]
pub struct HttpTransportEnvelopeInput<'a> {
    pub request_id: &'a str,
    pub timestamp_utc_ms: u64,
    pub nonce: u64,
    pub key_id: &'a str,
    pub signature: &'a str,
    pub payload_json: &'a Value,
}

pub fn build_transport_envelope(
    input: HttpTransportEnvelopeInput<'_>,
) -> Result<TransportEnvelope> {
    let payload_hash = payload_hash_hex_from_json(input.payload_json)
        .context("REJECTED: failed to canonicalize HTTP payload")?;
    TransportEnvelope::new(
        input.request_id,
        input.timestamp_utc_ms,
        input.nonce,
        input.key_id,
        payload_hash,
        input.signature,
    )
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::Value;

    use super::{build_transport_envelope, HttpTransportEnvelopeInput};

    const FIXTURE: &str = include_str!("../../fixtures/transport_envelope_cross_platform.json");

    #[derive(Debug, Deserialize)]
    struct CrossPlatformFixture {
        request_id: String,
        timestamp_utc_ms: u64,
        nonce: u64,
        key_id: String,
        signature: String,
        expected_payload_hash: String,
        payloads: PayloadVariants,
    }

    #[derive(Debug, Deserialize)]
    struct PayloadVariants {
        android: Value,
        ios: Value,
        cli: Value,
    }

    fn load_fixture() -> CrossPlatformFixture {
        serde_json::from_str(FIXTURE).expect("fixture should be valid JSON")
    }

    #[test]
    fn transport_envelope_cross_platform_contract() {
        let fixture = load_fixture();

        let variants = [
            &fixture.payloads.android,
            &fixture.payloads.ios,
            &fixture.payloads.cli,
        ];

        let mut envelopes = Vec::with_capacity(variants.len());
        for payload in variants {
            let envelope = build_transport_envelope(HttpTransportEnvelopeInput {
                request_id: &fixture.request_id,
                timestamp_utc_ms: fixture.timestamp_utc_ms,
                nonce: fixture.nonce,
                key_id: &fixture.key_id,
                signature: &fixture.signature,
                payload_json: payload,
            })
            .expect("transport envelope should be built");
            assert_eq!(
                envelope.payload_hash, fixture.expected_payload_hash,
                "payload hash must match fixture contract"
            );
            envelopes.push(envelope);
        }

        assert_eq!(envelopes[0].payload_hash, envelopes[1].payload_hash);
        assert_eq!(envelopes[1].payload_hash, envelopes[2].payload_hash);
        assert_eq!(
            envelopes[0].signing_message_bytes(),
            envelopes[1].signing_message_bytes()
        );
        assert_eq!(
            envelopes[1].signing_message_bytes(),
            envelopes[2].signing_message_bytes()
        );
    }
}
