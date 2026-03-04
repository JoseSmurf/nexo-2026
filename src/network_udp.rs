use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::message::{event_hash_bytes, CanonicalMessage};

const PACKET_EVENT: u8 = 1;
const PACKET_ACK: u8 = 2;
const PACKET_DISCOVER: u8 = 3;
const PACKET_HERE: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEvent {
    pub msg: CanonicalMessage,
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
        msg: &CanonicalMessage,
        sender_pubkey: [u8; 32],
        signature: [u8; 64],
        retries: u8,
        ack_timeout: Duration,
    ) -> io::Result<()> {
        let expected = event_hash_bytes(msg);
        let packet = encode_event(msg, sender_pubkey, signature);
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
        let (frame, from) = self.recv_frame().await?;
        let UdpFrame::Event(ev) = frame else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "REJECTED: non-event packet",
            ));
        };
        Ok((ev.msg, from))
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

fn encode_event(msg: &CanonicalMessage, sender_pubkey: [u8; 32], signature: [u8; 64]) -> Vec<u8> {
    let sender = msg.sender_id.as_bytes();
    let content = &msg.content;
    let mut out = Vec::with_capacity(1 + 8 + 8 + 1 + sender.len() + 1 + content.len() + 32 + 64);
    out.push(PACKET_EVENT);
    out.extend_from_slice(&msg.timestamp_utc_ms.to_le_bytes());
    out.extend_from_slice(&msg.nonce.to_le_bytes());
    out.push(sender.len() as u8);
    out.extend_from_slice(sender);
    out.push(content.len() as u8);
    out.extend_from_slice(content);
    out.extend_from_slice(&sender_pubkey);
    out.extend_from_slice(&signature);
    out
}

fn decode_event(buf: &[u8]) -> Result<SignedEvent, &'static str> {
    if buf.len() < (19 + 32 + 64) || buf[0] != PACKET_EVENT {
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
    let sender =
        std::str::from_utf8(&buf[sender_start..sender_end]).map_err(|_| "REJECTED: sender utf8")?;
    let content_len = buf[sender_end] as usize;
    let content_start = sender_end + 1;
    let content_end = content_start + content_len;
    let sig_start = content_end;
    let sig_end = sig_start + 32 + 64;
    if sig_end != buf.len() {
        return Err("REJECTED: malformed content");
    }
    let msg = CanonicalMessage::new_with_nonce(
        sender,
        timestamp_utc_ms,
        nonce,
        &buf[content_start..content_end],
    )?;
    let mut sender_pubkey = [0u8; 32];
    sender_pubkey.copy_from_slice(&buf[sig_start..sig_start + 32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&buf[sig_start + 32..sig_end]);
    Ok(SignedEvent {
        msg,
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
