use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::message::{event_hash_bytes, CanonicalMessage};

const PACKET_EVENT: u8 = 1;
const PACKET_ACK: u8 = 2;

pub struct UdpNode {
    socket: UdpSocket,
}

impl UdpNode {
    pub async fn bind(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { socket })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn send_with_ack(
        &self,
        target: SocketAddr,
        msg: &CanonicalMessage,
        retries: u8,
        ack_timeout: Duration,
    ) -> io::Result<()> {
        let expected = event_hash_bytes(msg);
        let packet = encode_event(msg);
        let mut buf = [0u8; 1024];

        for _ in 0..retries {
            self.socket.send_to(&packet, target).await?;
            let recv = timeout(ack_timeout, self.socket.recv_from(&mut buf)).await;
            let Ok(Ok((n, from))) = recv else {
                continue;
            };
            if from != target {
                continue;
            }
            let Ok(hash) = decode_ack(&buf[..n]) else {
                continue;
            };
            if hash == expected {
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "REJECTED: ack not received",
        ))
    }

    pub async fn recv_event(&self) -> io::Result<(CanonicalMessage, SocketAddr)> {
        let mut buf = [0u8; 1024];
        let (n, from) = self.socket.recv_from(&mut buf).await?;
        let msg =
            decode_event(&buf[..n]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok((msg, from))
    }

    pub async fn send_ack(&self, target: SocketAddr, event_hash: [u8; 32]) -> io::Result<()> {
        let packet = encode_ack(event_hash);
        let _ = self.socket.send_to(&packet, target).await?;
        Ok(())
    }
}

fn encode_event(msg: &CanonicalMessage) -> Vec<u8> {
    let sender = msg.sender_id.as_bytes();
    let content = &msg.content;
    let mut out = Vec::with_capacity(1 + 8 + 1 + sender.len() + 1 + content.len());
    out.push(PACKET_EVENT);
    out.extend_from_slice(&msg.timestamp_utc_ms.to_le_bytes());
    out.push(sender.len() as u8);
    out.extend_from_slice(sender);
    out.push(content.len() as u8);
    out.extend_from_slice(content);
    out
}

fn decode_event(buf: &[u8]) -> Result<CanonicalMessage, &'static str> {
    if buf.len() < 11 || buf[0] != PACKET_EVENT {
        return Err("REJECTED: invalid event packet");
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&buf[1..9]);
    let timestamp_utc_ms = u64::from_le_bytes(ts);

    let sender_len = buf[9] as usize;
    let sender_start = 10;
    let sender_end = sender_start + sender_len;
    if sender_end >= buf.len() {
        return Err("REJECTED: malformed sender");
    }
    let sender =
        std::str::from_utf8(&buf[sender_start..sender_end]).map_err(|_| "REJECTED: sender utf8")?;
    let content_len = buf[sender_end] as usize;
    let content_start = sender_end + 1;
    let content_end = content_start + content_len;
    if content_end != buf.len() {
        return Err("REJECTED: malformed content");
    }
    CanonicalMessage::new(sender, timestamp_utc_ms, &buf[content_start..content_end])
}

fn encode_ack(hash: [u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = PACKET_ACK;
    out[1..].copy_from_slice(&hash);
    out
}

fn decode_ack(buf: &[u8]) -> Result<[u8; 32], &'static str> {
    if buf.len() != 33 || buf[0] != PACKET_ACK {
        return Err("REJECTED: invalid ack packet");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[1..]);
    Ok(out)
}
