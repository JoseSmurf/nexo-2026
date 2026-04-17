use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const MAX_PERSISTABLE_TIMESTAMP_MS: u64 = i64::MAX as u64;

pub const fn is_persistable_timestamp_ms(timestamp_utc_ms: u64) -> bool {
    timestamp_utc_ms <= MAX_PERSISTABLE_TIMESTAMP_MS
}

pub fn validate_persistable_timestamp_ms(timestamp_utc_ms: u64) -> Result<(), &'static str> {
    if is_persistable_timestamp_ms(timestamp_utc_ms) {
        Ok(())
    } else {
        Err("REJECTED: timestamp_out_of_persistable_range")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalMessage {
    pub sender_id: String,
    pub timestamp_utc_ms: u64,
    pub nonce: u64,
    pub content: Vec<u8>,
}

impl CanonicalMessage {
    pub const MAX_CONTENT_BYTES: usize = 32;

    pub fn new(
        sender_id: impl Into<String>,
        timestamp_utc_ms: u64,
        content: impl AsRef<[u8]>,
    ) -> Result<Self, &'static str> {
        Self::new_with_nonce(sender_id, timestamp_utc_ms, 0, content)
    }

    pub fn new_with_nonce(
        sender_id: impl Into<String>,
        timestamp_utc_ms: u64,
        nonce: u64,
        content: impl AsRef<[u8]>,
    ) -> Result<Self, &'static str> {
        let sender_id = sender_id.into();
        if sender_id.trim().is_empty() {
            return Err("REJECTED: empty sender_id");
        }
        validate_persistable_timestamp_ms(timestamp_utc_ms)?;
        let content = content.as_ref();
        if content.is_empty() {
            return Err("REJECTED: empty content");
        }
        if content.len() > Self::MAX_CONTENT_BYTES {
            return Err("REJECTED: content_bytes > 32");
        }
        Ok(Self {
            sender_id,
            timestamp_utc_ms,
            nonce,
            content: content.to_vec(),
        })
    }
}

fn hash_field(h: &mut blake3::Hasher, tag: &[u8], data: &[u8]) {
    h.update(&(tag.len() as u32).to_le_bytes());
    h.update(tag);
    h.update(&(data.len() as u32).to_le_bytes());
    h.update(data);
}

pub fn content_hash_bytes(content: &[u8]) -> [u8; 32] {
    *blake3::hash(content).as_bytes()
}

pub fn content_hash(content: &[u8]) -> String {
    blake3::hash(content).to_hex().to_string()
}

pub fn event_hash_bytes_from_parts(
    sender_id: &str,
    timestamp_utc_ms: u64,
    nonce: u64,
    content_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    hash_field(&mut h, b"schema", b"msg_v2");
    hash_field(&mut h, b"sender_id", sender_id.as_bytes());
    hash_field(&mut h, b"timestamp_utc_ms", &timestamp_utc_ms.to_le_bytes());
    hash_field(&mut h, b"nonce", &nonce.to_le_bytes());
    hash_field(&mut h, b"content_hash", content_hash);
    *h.finalize().as_bytes()
}

pub fn signed_envelope_hash_bytes(
    sender_id: &str,
    timestamp_utc_ms: u64,
    nonce: u64,
    content_hash: &[u8; 32],
    origin_event_hash: &[u8; 32],
    hops_remaining: u8,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    hash_field(&mut h, b"schema", b"msg_sig_v1");
    hash_field(&mut h, b"sender_id", sender_id.as_bytes());
    hash_field(&mut h, b"timestamp_utc_ms", &timestamp_utc_ms.to_le_bytes());
    hash_field(&mut h, b"nonce", &nonce.to_le_bytes());
    hash_field(&mut h, b"content_hash", content_hash);
    hash_field(&mut h, b"origin_event_hash", origin_event_hash);
    hash_field(&mut h, b"hops_remaining", &[hops_remaining]);
    *h.finalize().as_bytes()
}

pub fn event_hash_bytes(message: &CanonicalMessage) -> [u8; 32] {
    let chash = content_hash_bytes(&message.content);
    event_hash_bytes_from_parts(
        &message.sender_id,
        message.timestamp_utc_ms,
        message.nonce,
        &chash,
    )
}

pub fn event_hash(message: &CanonicalMessage) -> String {
    blake3::Hash::from(event_hash_bytes(message))
        .to_hex()
        .to_string()
}

pub fn sign_event_hash(
    event_hash: &[u8; 32],
    keypair_bytes: &[u8; 64],
) -> Result<[u8; 64], &'static str> {
    let signing = SigningKey::from_keypair_bytes(keypair_bytes)
        .map_err(|_| "REJECTED: invalid keypair bytes")?;
    Ok(signing.sign(event_hash).to_bytes())
}

pub fn verify_event_hash_signature(
    event_hash: &[u8; 32],
    pubkey_bytes: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> bool {
    let Ok(pubkey) = VerifyingKey::from_bytes(pubkey_bytes) else {
        return false;
    };
    let sig = Signature::from_bytes(sig_bytes);
    pubkey.verify(event_hash, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_content_above_32_bytes() {
        let payload = vec![b'a'; 33];
        let err = CanonicalMessage::new("user", 1, payload).expect_err("must fail");
        assert_eq!(err, "REJECTED: content_bytes > 32");
    }

    #[test]
    fn validates_bytes_not_chars() {
        let s = "ááááááááááááááááá";
        assert!(s.len() > CanonicalMessage::MAX_CONTENT_BYTES);
        let err = CanonicalMessage::new("user", 1, s.as_bytes()).expect_err("must fail");
        assert_eq!(err, "REJECTED: content_bytes > 32");
    }

    #[test]
    fn content_hash_is_deterministic() {
        let h1 = content_hash(b"hello");
        let h2 = content_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn event_hash_changes_when_content_changes() {
        let a = CanonicalMessage::new_with_nonce("u", 10, 1, b"hello").expect("valid");
        let b = CanonicalMessage::new_with_nonce("u", 10, 1, b"world").expect("valid");
        assert_ne!(event_hash(&a), event_hash(&b));
        let c = CanonicalMessage::new_with_nonce("u", 10, 2, b"hello").expect("valid");
        assert_ne!(event_hash(&a), event_hash(&c));
    }

    #[test]
    fn event_hash_parts_matches_message_hash() {
        let msg = CanonicalMessage::new_with_nonce("user", 1000, 9, b"abc").expect("msg");
        let chash = content_hash_bytes(&msg.content);
        let from_parts =
            event_hash_bytes_from_parts(&msg.sender_id, msg.timestamp_utc_ms, msg.nonce, &chash);
        assert_eq!(event_hash_bytes(&msg), from_parts);
    }

    #[test]
    fn signed_envelope_hash_changes_with_hops() {
        let msg = CanonicalMessage::new_with_nonce("user", 1000, 9, b"abc").expect("msg");
        let chash = content_hash_bytes(&msg.content);
        let origin = event_hash_bytes(&msg);
        let a = signed_envelope_hash_bytes(
            &msg.sender_id,
            msg.timestamp_utc_ms,
            msg.nonce,
            &chash,
            &origin,
            4,
        );
        let b = signed_envelope_hash_bytes(
            &msg.sender_id,
            msg.timestamp_utc_ms,
            msg.nonce,
            &chash,
            &origin,
            3,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn signature_valid_passes_verification() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = signing.verifying_key();
        let keypair = signing.to_keypair_bytes();
        let msg = CanonicalMessage::new_with_nonce("alice", 10, 1, b"hello").expect("msg");
        let hash = event_hash_bytes(&msg);
        let sig = sign_event_hash(&hash, &keypair).expect("sign");
        assert!(verify_event_hash_signature(
            &hash,
            &verifying.to_bytes(),
            &sig
        ));
    }

    #[test]
    fn signature_invalid_is_rejected() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let verifying = signing.verifying_key();
        let keypair = signing.to_keypair_bytes();
        let msg = CanonicalMessage::new_with_nonce("alice", 11, 2, b"hello").expect("msg");
        let hash = event_hash_bytes(&msg);
        let mut sig = sign_event_hash(&hash, &keypair).expect("sign");
        sig[0] ^= 0xFF;
        assert!(!verify_event_hash_signature(
            &hash,
            &verifying.to_bytes(),
            &sig
        ));
    }

    #[test]
    fn persistable_timestamp_allows_i64_max() {
        assert_eq!(validate_persistable_timestamp_ms(i64::MAX as u64), Ok(()));
        assert!(is_persistable_timestamp_ms(i64::MAX as u64));
    }

    #[test]
    fn persistable_timestamp_rejects_above_i64_max() {
        let invalid = (i64::MAX as u64).saturating_add(1);
        assert_eq!(
            validate_persistable_timestamp_ms(invalid),
            Err("REJECTED: timestamp_out_of_persistable_range")
        );
        assert_eq!(
            CanonicalMessage::new_with_nonce("alice", invalid, 1, b"hello"),
            Err("REJECTED: timestamp_out_of_persistable_range")
        );
        assert_eq!(
            validate_persistable_timestamp_ms(u64::MAX),
            Err("REJECTED: timestamp_out_of_persistable_range")
        );
    }
}
