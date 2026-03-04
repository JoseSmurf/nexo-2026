#![cfg(feature = "network")]

use std::time::Duration;

use syntax_engine::message::CanonicalMessage;
use syntax_engine::network_udp::{UdpFrame, UdpNode};

#[tokio::test]
async fn udp_unicast_ack_retry_loopback_two_nodes() {
    let node_a = UdpNode::bind("127.0.0.1:0").await.expect("bind a");
    let node_b = UdpNode::bind("127.0.0.1:0").await.expect("bind b");
    let b_addr = node_b.local_addr().expect("addr b");

    let recv_task = tokio::spawn(async move {
        let (msg, from) = node_b.recv_event().await.expect("recv");
        assert_eq!(msg.sender_id, "node-a");
        assert_eq!(msg.content, b"hello".to_vec());
        node_b
            .send_ack(from, syntax_engine::message::event_hash_bytes(&msg))
            .await
            .expect("ack");
    });

    let msg = CanonicalMessage::new("node-a", 10, b"hello").expect("msg");
    node_a
        .send_with_ack(b_addr, &msg, 3, Duration::from_millis(200))
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
    let err = node_a
        .send_with_ack(b_addr, &msg, 2, Duration::from_millis(30))
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
