#![cfg(feature = "network")]

use std::time::Duration;

use ed25519_dalek::SigningKey;
use syntax_engine::message::{
    event_hash_bytes, sign_event_hash, verify_event_hash_signature, CanonicalMessage,
};
use syntax_engine::network_udp::{UdpFrame, UdpNode};

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
        let msg = ev.msg;
        assert!(verify_event_hash_signature(
            &event_hash_bytes(&msg),
            &ev.sender_pubkey,
            &ev.signature
        ));
        assert_eq!(msg.sender_id, "node-a");
        assert_eq!(msg.content, b"hello".to_vec());
        node_b
            .send_ack(from, event_hash_bytes(&msg))
            .await
            .expect("ack");
    });

    let msg = CanonicalMessage::new("node-a", 10, b"hello").expect("msg");
    let signing = SigningKey::from_bytes(&[5u8; 32]);
    let pubkey = signing.verifying_key().to_bytes();
    let seckey = signing.to_keypair_bytes();
    let sig = sign_event_hash(&event_hash_bytes(&msg), &seckey).expect("sig");
    node_a
        .send_with_ack(b_addr, &msg, pubkey, sig, 3, Duration::from_millis(200))
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
    let sig = sign_event_hash(&event_hash_bytes(&msg), &seckey).expect("sig");
    let err = node_a
        .send_with_ack(b_addr, &msg, pubkey, sig, 2, Duration::from_millis(30))
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
