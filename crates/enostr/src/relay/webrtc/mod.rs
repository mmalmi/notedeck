// WebRTC relay module for peer-to-peer Nostr communication
// Compatible with iris-client WebRTC protocol

pub mod stun_server;
pub mod peer_connection;
pub mod heartbeat;
pub mod signaling;
pub mod mutual_follows;

pub use stun_server::StunServer;
pub use peer_connection::{PeerConnection, PeerConnectionManager};
pub use heartbeat::{HeartbeatManager, OnlineStatus};
pub use signaling::{SignalingMessage, SignalingType};
pub use mutual_follows::MutualFollowDetector;

use crate::relay::RelayStatus;
use crate::{ClientMessage, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;
use parking_lot::RwLock as SyncRwLock;

/// WebRTC relay that manages peer connections for direct communication
#[derive(Clone)]
pub struct WebRTCRelay {
    pub status: RelayStatus,
    pub peer_manager: Arc<RwLock<PeerConnectionManager>>,
    pub heartbeat_manager: Arc<RwLock<HeartbeatManager>>,
    pub stun_server: Option<Arc<StunServer>>,
    /// Cached peer count for fast synchronous access
    peer_count: Arc<AtomicUsize>,
    /// Cached peer pubkeys for fast synchronous access
    peer_pubkeys: Arc<SyncRwLock<Vec<String>>>,
    /// Cached online peers for fast synchronous access
    online_peers: Arc<SyncRwLock<Vec<String>>>,
}

impl WebRTCRelay {
    pub fn new(enable_stun_server: bool) -> Result<Self> {
        let peer_manager = Arc::new(RwLock::new(PeerConnectionManager::new()));
        let heartbeat_manager = Arc::new(RwLock::new(HeartbeatManager::new()));

        let stun_server = if enable_stun_server {
            Some(Arc::new(StunServer::new()?))
        } else {
            None
        };

        Ok(Self {
            status: RelayStatus::Disconnected,
            peer_manager,
            heartbeat_manager,
            stun_server,
            peer_count: Arc::new(AtomicUsize::new(0)),
            peer_pubkeys: Arc::new(SyncRwLock::new(Vec::new())),
            online_peers: Arc::new(SyncRwLock::new(Vec::new())),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        // Start heartbeat manager
        self.heartbeat_manager.write().await.start().await?;

        // Start STUN server if enabled
        if let Some(stun_server) = &self.stun_server {
            stun_server.start().await?;
        }

        self.status = RelayStatus::Connected;
        Ok(())
    }

    pub async fn send(&self, _msg: &ClientMessage) -> Result<()> {
        // WebRTC relay sends messages through peer connections
        // This will be implemented to route messages to the appropriate peers
        Ok(())
    }

    pub fn url(&self) -> &str {
        "webrtc"
    }

    /// Get the number of connected WebRTC peers (synchronous, cached)
    pub fn connected_peer_count(&self) -> usize {
        self.peer_count.load(Ordering::Relaxed)
    }

    /// Update the cached peer count and pubkeys (should be called when peers connect/disconnect)
    pub async fn update_peer_count(&self) {
        let peers = self.peer_manager.read().await.connected_peers();
        self.peer_count.store(peers.len(), Ordering::Relaxed);
        *self.peer_pubkeys.write() = peers;
    }

    /// Get all connected peer pubkeys (synchronous, cached)
    pub fn get_peer_pubkeys(&self) -> Vec<String> {
        self.peer_pubkeys.read().clone()
    }

    /// Update the cached online peers list (should be called when online status changes)
    pub async fn update_online_peers(&self) {
        let online = self.heartbeat_manager.read().await.get_online_peers();
        *self.online_peers.write() = online;
    }

    /// Get all online peer pubkeys (synchronous, cached)
    pub fn get_online_peers(&self) -> Vec<String> {
        self.online_peers.read().clone()
    }

    /// Check if a peer is online (synchronous, cached)
    pub fn is_peer_online(&self, pubkey: &str) -> bool {
        self.online_peers.read().contains(&pubkey.to_string())
    }
}
