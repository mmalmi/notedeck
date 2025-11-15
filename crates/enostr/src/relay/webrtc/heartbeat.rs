use crate::Result;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time;
use tracing::{debug, info};

use super::signaling::SignalingMessage;

/// Online status for a peer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnlineStatus {
    Online,
    Offline,
}

/// Peer online state tracker
#[derive(Debug, Clone)]
pub struct PeerOnlineState {
    #[allow(dead_code)]
    pub pubkey: String,
    pub status: OnlineStatus,
    pub last_seen: Instant,
}

impl PeerOnlineState {
    pub fn new(pubkey: String) -> Self {
        Self {
            pubkey,
            status: OnlineStatus::Offline,
            last_seen: Instant::now(),
        }
    }

    /// Mark peer as online
    pub fn mark_online(&mut self) {
        self.status = OnlineStatus::Online;
        self.last_seen = Instant::now();
    }

    /// Check if peer should be marked offline (no heartbeat in 15 seconds)
    pub fn should_mark_offline(&self) -> bool {
        self.last_seen.elapsed() > Duration::from_secs(15)
    }
}

/// Heartbeat manager compatible with iris-client
/// - Sends "hello" messages every 10 seconds
/// - Marks peers offline after 15 seconds without hello
pub struct HeartbeatManager {
    /// Online peers and their last heartbeat time
    peers: HashMap<String, PeerOnlineState>,

    /// Channel to send outgoing heartbeat messages
    outgoing_tx: Option<mpsc::UnboundedSender<SignalingMessage>>,

    /// Running state
    running: bool,
}

impl HeartbeatManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            outgoing_tx: None,
            running: false,
        }
    }

    /// Start the heartbeat manager
    /// Sends hello messages every 10 seconds and checks for offline peers
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        let (tx, _rx) = mpsc::unbounded_channel();
        self.outgoing_tx = Some(tx.clone());
        self.running = true;

        // Spawn heartbeat sender task
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                // Generate new UUID for each heartbeat to allow tracking session restarts
                let peer_id = uuid::Uuid::new_v4().to_string();
                let hello = SignalingMessage::hello(peer_id);
                if tx.send(hello).is_err() {
                    break;
                }
                debug!("WebRTC: Sent heartbeat (hello)");
            }
        });

        // Spawn offline checker task
        let _peers = self.peers.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                // This will be handled by check_offline_peers() method
            }
        });

        info!("WebRTC: Heartbeat manager started");
        Ok(())
    }

    /// Stop the heartbeat manager
    pub fn stop(&mut self) {
        self.running = false;
        self.outgoing_tx = None;
        info!("WebRTC: Heartbeat manager stopped");
    }

    /// Handle received hello message from a peer
    pub fn handle_hello(&mut self, peer_pubkey: String) {
        let peer = self.peers
            .entry(peer_pubkey.clone())
            .or_insert_with(|| PeerOnlineState::new(peer_pubkey.clone()));

        let was_offline = peer.status == OnlineStatus::Offline;
        peer.mark_online();

        if was_offline {
            info!("WebRTC: Peer {} is now online", peer_pubkey);
        }

        debug!("WebRTC: Received heartbeat from {}", peer_pubkey);
    }

    /// Check for offline peers and update their status
    pub fn check_offline_peers(&mut self) -> Vec<String> {
        let mut newly_offline = Vec::new();

        for (pubkey, peer) in self.peers.iter_mut() {
            if peer.status == OnlineStatus::Online && peer.should_mark_offline() {
                peer.status = OnlineStatus::Offline;
                newly_offline.push(pubkey.clone());
                info!("WebRTC: Peer {} is now offline", pubkey);
            }
        }

        newly_offline
    }

    /// Get online status for a peer
    pub fn get_status(&self, peer_pubkey: &str) -> Option<OnlineStatus> {
        self.peers.get(peer_pubkey).map(|p| p.status.clone())
    }

    /// Get all online peers
    pub fn get_online_peers(&self) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.status == OnlineStatus::Online)
            .map(|(pubkey, _)| pubkey.clone())
            .collect()
    }

    /// Get all peers (online and offline)
    pub fn get_all_peers(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }

    /// Remove a peer from tracking
    pub fn remove_peer(&mut self, peer_pubkey: &str) {
        self.peers.remove(peer_pubkey);
        debug!("WebRTC: Removed peer {} from heartbeat tracking", peer_pubkey);
    }

    /// Get the outgoing message channel
    pub fn get_outgoing_channel(&self) -> Option<mpsc::UnboundedSender<SignalingMessage>> {
        self.outgoing_tx.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_online_state() {
        let mut peer = PeerOnlineState::new("test_pubkey".to_string());
        assert_eq!(peer.status, OnlineStatus::Offline);

        peer.mark_online();
        assert_eq!(peer.status, OnlineStatus::Online);

        // Should not be marked offline immediately
        assert!(!peer.should_mark_offline());
    }

    #[tokio::test]
    async fn test_heartbeat_manager() {
        let mut manager = HeartbeatManager::new();

        // Handle hello from a peer
        manager.handle_hello("peer1".to_string());
        assert_eq!(manager.get_status("peer1"), Some(OnlineStatus::Online));

        // Check that peer is in online peers list
        let online = manager.get_online_peers();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0], "peer1");
    }
}
