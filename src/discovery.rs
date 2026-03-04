use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::time::timeout;

use crate::network_udp::{UdpFrame, UdpNode};

const MAX_PEERS: usize = 64;
const DISCOVERY_INTERVAL_MS: u64 = 2_000;

#[derive(Clone)]
pub struct DiscoveryHandle {
    peers: Arc<RwLock<BTreeMap<String, SocketAddr>>>,
}

impl DiscoveryHandle {
    pub fn get_known_peers(&self) -> Vec<SocketAddr> {
        get_known_peers(self)
    }
}

pub async fn start_discovery(bind_addr: &str) -> Result<DiscoveryHandle, String> {
    let advertised = bind_addr
        .parse::<SocketAddr>()
        .map_err(|_| "invalid discovery bind addr".to_string())?;

    let local_bind = match advertised {
        SocketAddr::V4(v4) => format!("{}:0", v4.ip()),
        SocketAddr::V6(v6) => format!("[{}]:0", v6.ip()),
    };
    let node = UdpNode::bind(&local_bind)
        .await
        .map_err(|e| format!("discovery bind failed: {e}"))?;
    node.set_broadcast(true)
        .map_err(|e| format!("discovery set broadcast failed: {e}"))?;

    let peers = Arc::new(RwLock::new(BTreeMap::<String, SocketAddr>::new()));
    let loop_peers = Arc::clone(&peers);
    let self_id = advertised.to_string();
    let target = SocketAddr::new(advertised.ip(), advertised.port());

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(DISCOVERY_INTERVAL_MS));
        loop {
            ticker.tick().await;
            if node.send_discover(target).await.is_err() {
                continue;
            }

            let recv = timeout(Duration::from_millis(300), node.recv_frame()).await;
            let Ok(Ok((frame, _from))) = recv else {
                continue;
            };
            let UdpFrame::Here(addr) = frame else {
                continue;
            };
            let node_id = addr.to_string();
            if node_id == self_id {
                continue;
            }
            if let Ok(mut map) = loop_peers.write() {
                if map.contains_key(&node_id) || map.len() < MAX_PEERS {
                    map.insert(node_id, addr);
                }
            }
        }
    });

    Ok(DiscoveryHandle { peers })
}

pub fn get_known_peers(handle: &DiscoveryHandle) -> Vec<SocketAddr> {
    match handle.peers.read() {
        Ok(map) => map.values().copied().collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_ignores_self() {
        let handle = DiscoveryHandle {
            peers: Arc::new(RwLock::new(BTreeMap::new())),
        };
        assert!(get_known_peers(&handle).is_empty());
    }

    #[test]
    fn discovery_adds_peer_ordered_by_node_id() {
        let peers = Arc::new(RwLock::new(BTreeMap::new()));
        {
            let mut map = peers.write().expect("write");
            map.insert(
                "node_b".to_string(),
                "127.0.0.1:9002".parse().expect("addr b"),
            );
            map.insert(
                "node_a".to_string(),
                "127.0.0.1:9001".parse().expect("addr a"),
            );
        }
        let handle = DiscoveryHandle { peers };
        let out = get_known_peers(&handle);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], "127.0.0.1:9001".parse::<SocketAddr>().expect("a"));
        assert_eq!(out[1], "127.0.0.1:9002".parse::<SocketAddr>().expect("b"));
    }
}
