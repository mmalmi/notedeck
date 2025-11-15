use crate::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use interceptor::registry::Registry;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use bytes::Bytes;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use super::signaling::SignalingMessage;

/// State of a peer connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerConnectionState {
    New,
    Connecting,
    Connected,
    Disconnected,
    Failed,
    Closed,
}

/// WebRTC peer connection for a single peer
/// Compatible with iris-client protocol (4 data channels)
pub struct PeerConnection {
    pub peer_pubkey: String,
    pub state: PeerConnectionState,
    pub pc: Arc<RTCPeerConnection>,

    // Four data channels as per iris-client protocol
    pub json_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,      // Nostr protocol (REQ/EVENT/EOSE/CLOSE)
    pub file_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,      // Binary file transfer
    pub call_signaling: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,    // Audio/video call signaling
    pub blob_channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,      // Content distribution

    // Channels for communication
    pub outgoing_messages: mpsc::UnboundedSender<SignalingMessage>,
    pub incoming_data: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl PeerConnection {
    /// Create a new peer connection
    /// Uses STUN servers compatible with iris-client (Google and Cloudflare)
    pub async fn new(
        peer_pubkey: String,
        outgoing_messages: mpsc::UnboundedSender<SignalingMessage>,
    ) -> Result<Self> {
        // Configure ICE servers (same as iris-client)
        let config = RTCConfiguration {
            ice_servers: vec![
                RTCIceServer {
                    urls: vec!["stun:stun.l.google.com:19302".to_owned()],
                    ..Default::default()
                },
                RTCIceServer {
                    urls: vec!["stun:stun.cloudflare.com:3478".to_owned()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        // Create a MediaEngine and register default codecs
        let mut m = MediaEngine::default();

        // Create a InterceptorRegistry
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut m)
            .map_err(|e| crate::Error::Generic(format!("Failed to register interceptors: {}", e)))?;

        // Create the API object with the MediaEngine
        let api = APIBuilder::new()
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .build();

        // Create a new RTCPeerConnection
        let pc = Arc::new(
            api.new_peer_connection(config)
                .await
                .map_err(|e| crate::Error::Generic(format!("Failed to create peer connection: {}", e)))?,
        );

        let (incoming_tx, incoming_data) = mpsc::unbounded_channel();

        let mut peer_conn = Self {
            peer_pubkey: peer_pubkey.clone(),
            state: PeerConnectionState::New,
            pc: pc.clone(),
            json_channel: Arc::new(RwLock::new(None)),
            file_channel: Arc::new(RwLock::new(None)),
            call_signaling: Arc::new(RwLock::new(None)),
            blob_channel: Arc::new(RwLock::new(None)),
            outgoing_messages,
            incoming_data,
        };

        // Set up connection state handlers
        peer_conn.setup_handlers(incoming_tx).await?;

        Ok(peer_conn)
    }

    async fn setup_handlers(&mut self, incoming_tx: mpsc::UnboundedSender<Vec<u8>>) -> Result<()> {
        let pc = self.pc.clone();
        let peer_pubkey = self.peer_pubkey.clone();
        let outgoing = self.outgoing_messages.clone();

        // Handle ICE connection state changes
        pc.on_ice_connection_state_change(Box::new(move |state: RTCIceConnectionState| {
            let peer = peer_pubkey.clone();
            Box::pin(async move {
                info!("WebRTC: ICE connection state changed to {} for peer {}", state, peer);
            })
        }));

        // Handle peer connection state changes
        let peer_pubkey_clone = self.peer_pubkey.clone();
        pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
            let peer = peer_pubkey_clone.clone();
            Box::pin(async move {
                info!("WebRTC: Peer connection state changed to {} for peer {}", state, peer);
            })
        }));

        // Handle ICE candidates
        pc.on_ice_candidate(Box::new(move |candidate: Option<RTCIceCandidate>| {
            let outgoing = outgoing.clone();
            Box::pin(async move {
                if let Some(candidate) = candidate {
                    debug!("WebRTC: New ICE candidate: {:?}", candidate);
                    // Send candidate to peer via Nostr signaling
                    let candidate_json = candidate.to_json().ok()
                        .and_then(|init| serde_json::to_value(&init).ok());
                    let msg = SignalingMessage::candidate(candidate_json);
                    let _ = outgoing.send(msg);
                }
            })
        }));

        // Handle incoming data channels
        let json_channel = self.json_channel.clone();
        let file_channel = self.file_channel.clone();
        let call_signaling = self.call_signaling.clone();
        let blob_channel = self.blob_channel.clone();

        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let label = dc.label().to_owned();
            let json_ch = json_channel.clone();
            let file_ch = file_channel.clone();
            let call_ch = call_signaling.clone();
            let blob_ch = blob_channel.clone();
            let incoming = incoming_tx.clone();

            Box::pin(async move {
                info!("WebRTC: New data channel: {}", label);

                // Store the data channel based on its label
                match label.as_str() {
                    "jsonChannel" => *json_ch.write().await = Some(dc.clone()),
                    "fileChannel" => *file_ch.write().await = Some(dc.clone()),
                    "callSignaling" => *call_ch.write().await = Some(dc.clone()),
                    "blobChannel" => *blob_ch.write().await = Some(dc.clone()),
                    _ => warn!("WebRTC: Unknown data channel label: {}", label),
                }

                // Set up message handler for this channel
                let incoming = incoming.clone();
                let label_clone = label.clone();
                dc.on_message(Box::new(move |msg: DataChannelMessage| {
                    let incoming = incoming.clone();
                    let label = label_clone.clone();
                    Box::pin(async move {
                        debug!("WebRTC: Received message on {}: {} bytes", label, msg.data.len());
                        let _ = incoming.send(msg.data.to_vec());
                    })
                }));
            })
        }));

        Ok(())
    }

    /// Create an offer to initiate connection
    pub async fn create_offer(&self) -> Result<RTCSessionDescription> {
        // Create data channels (initiator creates all 4 channels)
        self.create_data_channels().await?;

        let offer = self.pc.create_offer(None).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to create offer: {}", e))
        })?;

        self.pc.set_local_description(offer.clone()).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to set local description: {}", e))
        })?;

        Ok(offer)
    }

    /// Handle received answer
    pub async fn set_remote_answer(&self, answer: RTCSessionDescription) -> Result<()> {
        self.pc.set_remote_description(answer).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to set remote description: {}", e))
        })
    }

    /// Handle received offer (when we're the answerer)
    pub async fn handle_offer(&self, offer: RTCSessionDescription) -> Result<RTCSessionDescription> {
        self.pc.set_remote_description(offer).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to set remote description: {}", e))
        })?;

        let answer = self.pc.create_answer(None).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to create answer: {}", e))
        })?;

        self.pc.set_local_description(answer.clone()).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to set local description: {}", e))
        })?;

        Ok(answer)
    }

    /// Add an ICE candidate
    pub async fn add_ice_candidate(&self, candidate: RTCIceCandidateInit) -> Result<()> {
        self.pc.add_ice_candidate(candidate).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to add ICE candidate: {}", e))
        })
    }

    /// Create all four data channels (iris-client compatible)
    async fn create_data_channels(&self) -> Result<()> {
        // JSON channel for Nostr protocol
        let json_dc = self.pc.create_data_channel("jsonChannel", None).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to create jsonChannel: {}", e))
        })?;
        *self.json_channel.write().await = Some(json_dc);

        // File channel for binary file transfers
        let file_dc = self.pc.create_data_channel("fileChannel", None).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to create fileChannel: {}", e))
        })?;
        *self.file_channel.write().await = Some(file_dc);

        // Call signaling channel
        let call_dc = self.pc.create_data_channel("callSignaling", None).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to create callSignaling: {}", e))
        })?;
        *self.call_signaling.write().await = Some(call_dc);

        // Blob channel for content distribution
        let blob_dc = self.pc.create_data_channel("blobChannel", None).await.map_err(|e| {
            crate::Error::Generic(format!("Failed to create blobChannel: {}", e))
        })?;
        *self.blob_channel.write().await = Some(blob_dc);

        Ok(())
    }

    /// Send data on the JSON channel
    pub async fn send_json(&self, data: &[u8]) -> Result<()> {
        if let Some(dc) = self.json_channel.read().await.as_ref() {
            let bytes = Bytes::from(data.to_vec());
            dc.send(&bytes).await.map_err(|e| {
                crate::Error::Generic(format!("Failed to send on jsonChannel: {}", e))
            })?;
            Ok(())
        } else {
            Err(crate::Error::Generic("jsonChannel not ready".to_string()))
        }
    }

    /// Close the peer connection
    pub async fn close(&self) -> Result<()> {
        self.pc.close().await.map_err(|e| {
            crate::Error::Generic(format!("Failed to close peer connection: {}", e))
        })
    }
}

/// Manager for all peer connections
pub struct PeerConnectionManager {
    peers: HashMap<String, Arc<RwLock<PeerConnection>>>,
    /// Track online peers with their peer IDs (pubkey:uuid format)
    online_peers: HashMap<String, String>, // pubkey -> peer_id mapping
    our_peer_id: Option<String>,
}

impl PeerConnectionManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            online_peers: HashMap::new(),
            our_peer_id: None,
        }
    }

    pub fn set_our_peer_id(&mut self, peer_id: String) {
        self.our_peer_id = Some(peer_id);
    }

    /// Add a new peer connection
    pub fn add_peer(&mut self, pubkey: String, peer: Arc<RwLock<PeerConnection>>) {
        self.peers.insert(pubkey, peer);
    }

    /// Get a peer connection by pubkey
    pub fn get_peer(&self, pubkey: &str) -> Option<Arc<RwLock<PeerConnection>>> {
        self.peers.get(pubkey).cloned()
    }

    /// Remove a peer connection
    pub fn remove_peer(&mut self, pubkey: &str) -> Option<Arc<RwLock<PeerConnection>>> {
        self.peers.remove(pubkey)
    }

    /// Handle incoming signaling message from a peer
    pub async fn handle_signaling(
        &mut self,
        peer_pubkey: &str,
        message: SignalingMessage,
        outgoing_tx: mpsc::UnboundedSender<(String, SignalingMessage)>,
    ) -> Result<()> {
        use super::signaling::SignalingType;

        match message.msg_type {
            SignalingType::Hello { peer_id } => {
                info!("Received hello from {} (peer_id: {})", peer_pubkey, peer_id);

                // Skip our own messages (same session)
                if let Some(our_id) = &self.our_peer_id {
                    if our_id == &peer_id {
                        info!("Ignoring hello from self (same peer_id)");
                        return Ok(());
                    }
                }

                // Track online peer
                self.online_peers.insert(peer_pubkey.to_string(), peer_id.clone());

                // Check if we already have a connection to this peer
                if self.get_peer(peer_pubkey).is_some() {
                    info!("Already have connection to peer {}", peer_pubkey);
                    return Ok(());
                }

                info!("Checking if should initiate connection");

                // Tie-breaking: only initiate if our peer_id is smaller (iris-compatible)
                let should_initiate = if let Some(our_id) = &self.our_peer_id {
                    let result = our_id < &peer_id;
                    info!("Tie-breaking: our_id={} vs their_id={}, should_initiate={}", our_id, peer_id, result);
                    result
                } else {
                    info!("No our_peer_id set, cannot initiate connection");
                    return Ok(());
                };

                if should_initiate {
                    info!("Initiating WebRTC connection to {} (our_id < their_id)", peer_pubkey);

                    // Create new peer connection
                    let (msg_tx, _msg_rx) = mpsc::unbounded_channel();
                    let new_peer = PeerConnection::new(peer_pubkey.to_string(), msg_tx).await?;
                    let peer_arc = Arc::new(RwLock::new(new_peer));
                    self.add_peer(peer_pubkey.to_string(), peer_arc.clone());

                    // Create and send offer
                    let offer_desc = {
                        let peer_lock = peer_arc.read().await;
                        peer_lock.create_offer().await?
                    };

                    let offer_msg = SignalingMessage::offer(offer_desc.sdp);
                    if let Err(e) = outgoing_tx.send((peer_pubkey.to_string(), offer_msg)) {
                        error!("Failed to queue offer message: {}", e);
                    } else {
                        info!("Sent offer to {}", peer_pubkey);
                    }
                } else {
                    info!("Waiting for peer {} to initiate (their_id < our_id)", peer_pubkey);
                }

                Ok(())
            }
            SignalingType::Offer { sdp } => {
                info!("Received offer from {}", peer_pubkey);

                // Get or create peer connection
                let peer = if let Some(p) = self.get_peer(peer_pubkey) {
                    p
                } else {
                    // Create new peer connection
                    let (msg_tx, _msg_rx) = mpsc::unbounded_channel();
                    let new_peer = PeerConnection::new(peer_pubkey.to_string(), msg_tx).await?;
                    let peer_arc = Arc::new(RwLock::new(new_peer));
                    self.add_peer(peer_pubkey.to_string(), peer_arc.clone());
                    peer_arc
                };

                // Process offer and create answer
                let peer_lock = peer.read().await;
                let offer_desc = RTCSessionDescription::offer(sdp).map_err(|e| {
                    crate::Error::Generic(format!("Failed to parse offer SDP: {}", e))
                })?;

                let answer_desc = peer_lock.handle_offer(offer_desc).await?;
                drop(peer_lock); // Release lock before sending

                // Send answer back
                let answer_msg = SignalingMessage::answer(answer_desc.sdp);
                if let Err(e) = outgoing_tx.send((peer_pubkey.to_string(), answer_msg)) {
                    error!("Failed to queue answer message: {}", e);
                }

                Ok(())
            }
            SignalingType::Answer { sdp } => {
                info!("Received answer from {}", peer_pubkey);

                if let Some(peer) = self.get_peer(peer_pubkey) {
                    let peer_lock = peer.read().await;
                    let answer_desc = RTCSessionDescription::answer(sdp).map_err(|e| {
                        crate::Error::Generic(format!("Failed to parse answer SDP: {}", e))
                    })?;
                    peer_lock.set_remote_answer(answer_desc).await?;
                } else {
                    warn!("Received answer from unknown peer: {}", peer_pubkey);
                }

                Ok(())
            }
            SignalingType::Candidate { candidate } => {
                info!("Received ICE candidate from {}", peer_pubkey);

                if let Some(peer) = self.get_peer(peer_pubkey) {
                    if let Some(candidate_value) = candidate {
                        // Parse candidate JSON
                        let candidate_init: RTCIceCandidateInit =
                            serde_json::from_value(candidate_value).map_err(|e| {
                                crate::Error::Generic(format!("Failed to parse ICE candidate: {}", e))
                            })?;

                        let peer_lock = peer.read().await;
                        peer_lock.add_ice_candidate(candidate_init).await?;
                    }
                } else {
                    warn!("Received ICE candidate from unknown peer: {}", peer_pubkey);
                }

                Ok(())
            }
        }
    }

    /// Get all connected peers
    pub fn connected_peers(&self) -> Vec<String> {
        self.peers.keys().cloned().collect()
    }

    /// Close all peer connections
    pub async fn close_all(&mut self) {
        for (pubkey, peer) in self.peers.drain() {
            if let Err(e) = peer.read().await.close().await {
                error!("Failed to close peer connection for {}: {}", pubkey, e);
            }
        }
    }
}
