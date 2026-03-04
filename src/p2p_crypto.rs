use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use getrandom::getrandom;

pub fn parse_shared_key_hex(raw: &str) -> Result<[u8; 32], &'static str> {
    let bytes = hex::decode(raw).map_err(|_| "REJECTED: invalid shared key hex")?;
    if bytes.len() != 32 {
        return Err("REJECTED: shared key must be 32 bytes (64 hex)");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn random_aead_nonce() -> Result<[u8; 24], &'static str> {
    let mut nonce = [0u8; 24];
    getrandom(&mut nonce).map_err(|_| "REJECTED: aead nonce rng failed")?;
    Ok(nonce)
}

pub fn encrypt_content(
    plaintext: &[u8],
    shared_key: &[u8; 32],
    aead_nonce: &[u8; 24],
) -> Result<Vec<u8>, &'static str> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(shared_key));
    cipher
        .encrypt(XNonce::from_slice(aead_nonce), plaintext)
        .map_err(|_| "REJECTED: encrypt failed")
}

pub fn decrypt_content(
    ciphertext: &[u8],
    shared_key: &[u8; 32],
    aead_nonce: &[u8; 24],
) -> Result<Vec<u8>, &'static str> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(shared_key));
    cipher
        .decrypt(XNonce::from_slice(aead_nonce), ciphertext)
        .map_err(|_| "REJECTED: decrypt failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip_ok() {
        let key = [11u8; 32];
        let nonce = [22u8; 24];
        let plaintext = b"hello-crypto";
        let ciphertext = encrypt_content(plaintext, &key, &nonce).expect("enc");
        assert_ne!(ciphertext, plaintext);
        let recovered = decrypt_content(&ciphertext, &key, &nonce).expect("dec");
        assert_eq!(recovered, plaintext);
    }
}
