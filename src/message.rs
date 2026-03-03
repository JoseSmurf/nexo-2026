use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalMessage {
    pub sender_id: String,
    pub timestamp_utc_ms: u64,
    pub content: Vec<u8>,
}

impl CanonicalMessage {
    pub const MAX_CONTENT_BYTES: usize = 32;

    pub fn new(
        sender_id: impl Into<String>,
        timestamp_utc_ms: u64,
        content: impl AsRef<[u8]>,
    ) -> Result<Self, &'static str> {
        let sender_id = sender_id.into();
        if sender_id.trim().is_empty() {
            return Err("REJECTED: empty sender_id");
        }
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

pub fn event_hash_bytes(message: &CanonicalMessage) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    hash_field(&mut h, b"schema", b"msg_v1");
    hash_field(&mut h, b"sender_id", message.sender_id.as_bytes());
    hash_field(
        &mut h,
        b"timestamp_utc_ms",
        &message.timestamp_utc_ms.to_le_bytes(),
    );
    hash_field(&mut h, b"content", &message.content);
    *h.finalize().as_bytes()
}

pub fn event_hash(message: &CanonicalMessage) -> String {
    blake3::Hash::from(event_hash_bytes(message))
        .to_hex()
        .to_string()
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
        let a = CanonicalMessage::new("u", 10, b"hello").expect("valid");
        let b = CanonicalMessage::new("u", 10, b"world").expect("valid");
        assert_ne!(event_hash(&a), event_hash(&b));
    }
}
