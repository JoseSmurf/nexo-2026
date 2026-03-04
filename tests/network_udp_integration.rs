#![cfg(feature = "network")]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use syntax_engine::message::{
    content_hash_bytes, event_hash_bytes_from_parts, sign_event_hash, verify_event_hash_signature,
    CanonicalMessage,
};
use syntax_engine::network_udp::{SignedEvent, UdpFrame, UdpNode};
#[cfg(feature = "crypto")]
use syntax_engine::p2p_crypto::{decrypt_content, encrypt_content};

#[tokio::test]
async fn udp_unicast_ack_retry_loopback_two_nodes() {
    let node_a = UdpNode::bind("127.0.0.1:0").await.expect("bind a");
    let node_b = UdpNode::bind("127.0.0.1:0").await.expect("bind b");
    let b_addr = node_b.local_addr().expect("addr b");

    let recv_task = tokio::spawn(async move {
        let (frame, from) = node_b.recv_frame().await.expect("recv");
        let UdpFrame::Event(ev) = frame else {
            panic!("expected event frame");
        };
        let hash = event_hash_bytes_from_parts(
            &ev.sender_id,
            ev.timestamp_utc_ms,
            ev.nonce,
            &ev.content_hash,
        );
        assert!(verify_event_hash_signature(
            &hash,
            &ev.sender_pubkey,
            &ev.signature
        ));
        assert!(ev.crypto_nonce.is_none());
        assert_eq!(ev.sender_id, "node-a");
        assert_eq!(ev.payload, b"hello".to_vec());
        assert_eq!(content_hash_bytes(&ev.payload), ev.content_hash);
        node_b.send_ack(from, hash).await.expect("ack");
    });

    let msg = CanonicalMessage::new("node-a", 10, b"hello").expect("msg");
    let signing = SigningKey::from_bytes(&[5u8; 32]);
    let pubkey = signing.verifying_key().to_bytes();
    let seckey = signing.to_keypair_bytes();
    let content_hash = content_hash_bytes(&msg.content);
    let hash = event_hash_bytes_from_parts(
        &msg.sender_id,
        msg.timestamp_utc_ms,
        msg.nonce,
        &content_hash,
    );
    let sig = sign_event_hash(&hash, &seckey).expect("sig");
    let ev = SignedEvent {
        sender_id: msg.sender_id,
        timestamp_utc_ms: msg.timestamp_utc_ms,
        nonce: msg.nonce,
        content_hash,
        origin_event_hash: hash,
        hops_remaining: 4,
        payload: msg.content,
        crypto_nonce: None,
        sender_pubkey: pubkey,
        signature: sig,
    };
    node_a
        .send_with_ack(b_addr, &ev, 3, Duration::from_millis(200))
        .await
        .expect("ack confirmed");

    recv_task.await.expect("join");
}

#[tokio::test]
async fn udp_unicast_fails_closed_when_no_ack() {
    let node_a = UdpNode::bind("127.0.0.1:0").await.expect("bind a");
    let node_b = UdpNode::bind("127.0.0.1:0").await.expect("bind b");
    let b_addr = node_b.local_addr().expect("addr b");
    drop(node_b);

    let msg = CanonicalMessage::new("node-a", 10, b"hello").expect("msg");
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = signing.verifying_key().to_bytes();
    let seckey = signing.to_keypair_bytes();
    let content_hash = content_hash_bytes(&msg.content);
    let hash = event_hash_bytes_from_parts(
        &msg.sender_id,
        msg.timestamp_utc_ms,
        msg.nonce,
        &content_hash,
    );
    let sig = sign_event_hash(&hash, &seckey).expect("sig");
    let ev = SignedEvent {
        sender_id: msg.sender_id,
        timestamp_utc_ms: msg.timestamp_utc_ms,
        nonce: msg.nonce,
        content_hash,
        origin_event_hash: hash,
        hops_remaining: 4,
        payload: msg.content,
        crypto_nonce: None,
        sender_pubkey: pubkey,
        signature: sig,
    };
    let err = node_a
        .send_with_ack(b_addr, &ev, 2, Duration::from_millis(30))
        .await
        .expect_err("must timeout");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn udp_discovery_loopback_roundtrip() {
    let node_a = UdpNode::bind("127.0.0.1:0").await.expect("bind a");
    let node_b = UdpNode::bind("127.0.0.1:0").await.expect("bind b");
    let b_addr = node_b.local_addr().expect("addr b");

    let responder = tokio::spawn(async move {
        let (frame, from) = node_b.recv_frame().await.expect("recv discover");
        assert_eq!(frame, UdpFrame::Discover);
        let local = node_b.local_addr().expect("local");
        node_b.send_here(from, local).await.expect("send here");
    });

    node_a.send_discover(b_addr).await.expect("send discover");
    let (frame, _from) = node_a.recv_frame().await.expect("recv here");
    let UdpFrame::Here(addr) = frame else {
        panic!("expected here response");
    };
    assert_eq!(addr, b_addr);

    responder.await.expect("join");
}

#[cfg(feature = "crypto")]
#[tokio::test]
async fn udp_encrypted_event_roundtrip_accepts_and_decrypts() {
    let node_a = UdpNode::bind("127.0.0.1:0").await.expect("bind a");
    let node_b = UdpNode::bind("127.0.0.1:0").await.expect("bind b");
    let b_addr = node_b.local_addr().expect("addr b");
    let shared = [33u8; 32];
    let aead_nonce = [44u8; 24];
    let plaintext = b"hello-enc".to_vec();
    let expected_plaintext = plaintext.clone();
    let ciphertext = encrypt_content(&plaintext, &shared, &aead_nonce).expect("encrypt");

    let recv_task = tokio::spawn(async move {
        let (frame, from) = node_b.recv_frame().await.expect("recv");
        let UdpFrame::Event(ev) = frame else {
            panic!("expected event frame");
        };
        let hash = event_hash_bytes_from_parts(
            &ev.sender_id,
            ev.timestamp_utc_ms,
            ev.nonce,
            &ev.content_hash,
        );
        assert!(verify_event_hash_signature(
            &hash,
            &ev.sender_pubkey,
            &ev.signature
        ));
        let nonce = ev.crypto_nonce.expect("crypto nonce");
        let recovered = decrypt_content(&ev.payload, &shared, &nonce).expect("decrypt");
        assert_eq!(recovered, expected_plaintext);
        assert_eq!(content_hash_bytes(&recovered), ev.content_hash);
        node_b.send_ack(from, hash).await.expect("ack");
    });

    let signing = SigningKey::from_bytes(&[12u8; 32]);
    let pubkey = signing.verifying_key().to_bytes();
    let seckey = signing.to_keypair_bytes();
    let content_hash = content_hash_bytes(&plaintext);
    let hash = event_hash_bytes_from_parts("node-a", 20, 2, &content_hash);
    let sig = sign_event_hash(&hash, &seckey).expect("sig");
    let ev = SignedEvent {
        sender_id: "node-a".to_string(),
        timestamp_utc_ms: 20,
        nonce: 2,
        content_hash,
        origin_event_hash: hash,
        hops_remaining: 4,
        payload: ciphertext,
        crypto_nonce: Some(aead_nonce),
        sender_pubkey: pubkey,
        signature: sig,
    };
    node_a
        .send_with_ack(b_addr, &ev, 3, Duration::from_millis(200))
        .await
        .expect("ack confirmed");
    recv_task.await.expect("join");
}
