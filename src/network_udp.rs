use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::message::event_hash_bytes_from_parts;

const PACKET_EVENT: u8 = 1;
const PACKET_ACK: u8 = 2;
const PACKET_DISCOVER: u8 = 3;
const PACKET_HERE: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEvent {
    pub sender_id: String,
    pub timestamp_utc_ms: u64,
    pub nonce: u64,
    pub content_hash: [u8; 32],
    pub payload: Vec<u8>,
    pub crypto_nonce: Option<[u8; 24]>,
    pub sender_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpFrame {
    Event(SignedEvent),
    Discover,
    Here(SocketAddr),
}

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

    pub fn set_broadcast(&self, enabled: bool) -> io::Result<()> {
        self.socket.set_broadcast(enabled)
    }

    pub async fn send_with_ack(
        &self,
        target: SocketAddr,
        event: &SignedEvent,
        retries: u8,
        ack_timeout: Duration,
    ) -> io::Result<()> {
        let expected = event_hash_bytes_from_parts(
            &event.sender_id,
            event.timestamp_utc_ms,
            event.nonce,
            &event.content_hash,
        );
        let packet =
            encode_event(event).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
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

    pub async fn recv_frame(&self) -> io::Result<(UdpFrame, SocketAddr)> {
        let mut buf = [0u8; 1024];
        let (n, from) = self.socket.recv_from(&mut buf).await?;
        let frame =
            decode_frame(&buf[..n]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok((frame, from))
    }

    pub async fn send_ack(&self, target: SocketAddr, event_hash: [u8; 32]) -> io::Result<()> {
        let packet = encode_ack(event_hash);
        let _ = self.socket.send_to(&packet, target).await?;
        Ok(())
    }

    pub async fn send_discover(&self, target: SocketAddr) -> io::Result<()> {
        let packet = encode_discover();
        let _ = self.socket.send_to(&packet, target).await?;
        Ok(())
    }

    pub async fn send_here(&self, target: SocketAddr, addr: SocketAddr) -> io::Result<()> {
        let packet = encode_here(addr);
        let _ = self.socket.send_to(&packet, target).await?;
        Ok(())
    }
}

fn encode_event(event: &SignedEvent) -> Result<Vec<u8>, &'static str> {
    let sender = event.sender_id.as_bytes();
    if sender.is_empty() || sender.len() > 255 {
        return Err("REJECTED: invalid sender length");
    }
    if event.payload.is_empty() || event.payload.len() > 255 {
        return Err("REJECTED: invalid payload length");
    }

    let overhead = 1
        + 8
        + 8
        + 1
        + sender.len()
        + 32
        + 1
        + if event.crypto_nonce.is_some() { 24 } else { 0 }
        + 1
        + event.payload.len()
        + 32
        + 64;

    let mut out = Vec::with_capacity(overhead);
    out.push(PACKET_EVENT);
    out.extend_from_slice(&event.timestamp_utc_ms.to_le_bytes());
    out.extend_from_slice(&event.nonce.to_le_bytes());
    out.push(sender.len() as u8);
    out.extend_from_slice(sender);
    out.extend_from_slice(&event.content_hash);
    out.push(if event.crypto_nonce.is_some() { 1 } else { 0 });
    if let Some(nonce) = event.crypto_nonce {
        out.extend_from_slice(&nonce);
    }
    out.push(event.payload.len() as u8);
    out.extend_from_slice(&event.payload);
    out.extend_from_slice(&event.sender_pubkey);
    out.extend_from_slice(&event.signature);
    Ok(out)
}

fn decode_event(buf: &[u8]) -> Result<SignedEvent, &'static str> {
    if buf.len() < 1 + 8 + 8 + 1 + 32 + 1 + 1 + 32 + 64 || buf[0] != PACKET_EVENT {
        return Err("REJECTED: invalid event packet");
    }

    let mut ts = [0u8; 8];
    ts.copy_from_slice(&buf[1..9]);
    let timestamp_utc_ms = u64::from_le_bytes(ts);

    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&buf[9..17]);
    let nonce = u64::from_le_bytes(nonce);

    let sender_len = buf[17] as usize;
    let sender_start = 18;
    let sender_end = sender_start + sender_len;
    if sender_end >= buf.len() {
        return Err("REJECTED: malformed sender");
    }
    let sender_id =
        std::str::from_utf8(&buf[sender_start..sender_end]).map_err(|_| "REJECTED: sender utf8")?;
    if sender_id.trim().is_empty() {
        return Err("REJECTED: empty sender");
    }

    let mut idx = sender_end;

    if idx + 32 + 1 > buf.len() {
        return Err("REJECTED: malformed content hash");
    }
    let mut content_hash = [0u8; 32];
    content_hash.copy_from_slice(&buf[idx..idx + 32]);
    idx += 32;

    let crypto_flag = buf[idx];
    idx += 1;
    let crypto_nonce = match crypto_flag {
        0 => None,
        1 => {
            if idx + 24 > buf.len() {
                return Err("REJECTED: malformed crypto nonce");
            }
            let mut out = [0u8; 24];
            out.copy_from_slice(&buf[idx..idx + 24]);
            idx += 24;
            Some(out)
        }
        _ => return Err("REJECTED: invalid crypto flag"),
    };

    if idx >= buf.len() {
        return Err("REJECTED: malformed payload");
    }
    let payload_len = buf[idx] as usize;
    idx += 1;
    if payload_len == 0 || idx + payload_len > buf.len() {
        return Err("REJECTED: malformed payload");
    }
    let payload = buf[idx..idx + payload_len].to_vec();
    idx += payload_len;

    if idx + 32 + 64 != buf.len() {
        return Err("REJECTED: malformed signature envelope");
    }
    let mut sender_pubkey = [0u8; 32];
    sender_pubkey.copy_from_slice(&buf[idx..idx + 32]);
    idx += 32;

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&buf[idx..idx + 64]);

    Ok(SignedEvent {
        sender_id: sender_id.to_string(),
        timestamp_utc_ms,
        nonce,
        content_hash,
        payload,
        crypto_nonce,
        sender_pubkey,
        signature,
    })
}

fn encode_discover() -> [u8; 1] {
    [PACKET_DISCOVER]
}

fn encode_here(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32);
    out.push(PACKET_HERE);
    out.extend_from_slice(addr.to_string().as_bytes());
    out
}

fn decode_here(buf: &[u8]) -> Result<SocketAddr, &'static str> {
    if buf.len() <= 1 || buf[0] != PACKET_HERE {
        return Err("REJECTED: invalid here packet");
    }
    let raw = std::str::from_utf8(&buf[1..]).map_err(|_| "REJECTED: here utf8")?;
    raw.parse::<SocketAddr>()
        .map_err(|_| "REJECTED: here socket addr")
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

fn decode_frame(buf: &[u8]) -> Result<UdpFrame, &'static str> {
    if buf.is_empty() {
        return Err("REJECTED: empty packet");
    }
    match buf[0] {
        PACKET_EVENT => Ok(UdpFrame::Event(decode_event(buf)?)),
        PACKET_DISCOVER => {
            if buf.len() != 1 {
                return Err("REJECTED: invalid discover packet");
            }
            Ok(UdpFrame::Discover)
        }
        PACKET_HERE => Ok(UdpFrame::Here(decode_here(buf)?)),
        _ => Err("REJECTED: unknown packet type"),
    }
}
