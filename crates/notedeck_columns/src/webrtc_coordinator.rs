/// WebRTC coordinator that bridges sync egui event loop with async WebRTC operations
use crossbeam_channel::{Receiver, Sender, unbounded};
use enostr::{PeerConnectionManager, SignalingMessage};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info};

/// Message from event loop to WebRTC task
#[derive(Debug, Clone)]
pub struct IncomingSignalingEvent {
    pub peer_pubkey: String,
    pub message: SignalingMessage,
}

/// Message from WebRTC task to event loop (to publish)
#[derive(Debug, Clone)]
pub struct OutgoingSignalingEvent {
    pub peer_pubkey: String,
    pub message: SignalingMessage,
}

/// Handles WebRTC signaling coordination between sync and async contexts
pub struct WebRTCCoordinator {
    /// Send signaling events from sync context to async task
    incoming_tx: Sender<IncomingSignalingEvent>,
    /// Receive outgoing signaling events to publish
    pub outgoing_rx: Receiver<OutgoingSignalingEvent>,
    /// Send our peer ID to the async task
    peer_id_tx: Sender<String>,
}

impl WebRTCCoordinator {
    /// Create a new coordinator and spawn the async processing task
    pub fn new() -> Self {
        let (incoming_tx, incoming_rx) = unbounded::<IncomingSignalingEvent>();
        let (outgoing_tx, outgoing_rx) = unbounded::<OutgoingSignalingEvent>();
        let (peer_id_tx, peer_id_rx) = unbounded::<String>();

        // Spawn async task to process signaling
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
            rt.block_on(async move {
                Self::run_signaling_processor(incoming_rx, outgoing_tx, peer_id_rx).await;
            });
        });

        Self {
            incoming_tx,
            outgoing_rx,
            peer_id_tx,
        }
    }

    pub fn set_peer_id(&self, peer_id: String) {
        let _ = self.peer_id_tx.send(peer_id);
    }

    /// Send an incoming signaling event to be processed
    pub fn process_signaling(&self, peer_pubkey: String, message: SignalingMessage) {
        if let Err(e) = self.incoming_tx.send(IncomingSignalingEvent {
            peer_pubkey: peer_pubkey.clone(),
            message,
        }) {
            error!("Failed to send signaling event for peer {}: {}", peer_pubkey, e);
        }
    }

    /// Async task that processes incoming signaling and generates outgoing messages
    async fn run_signaling_processor(
        incoming_rx: Receiver<IncomingSignalingEvent>,
        outgoing_tx: Sender<OutgoingSignalingEvent>,
        peer_id_rx: Receiver<String>,
    ) {
        info!("WebRTC signaling processor started");
        let peer_manager = Arc::new(RwLock::new(PeerConnectionManager::new()));
        let (outgoing_mpsc_tx, mut outgoing_mpsc_rx) = mpsc::unbounded_channel::<(String, SignalingMessage)>();

        // Task to forward from mpsc to crossbeam channel
        let outgoing_forwarder_tx = outgoing_tx.clone();
        tokio::spawn(async move {
            while let Some((peer_pubkey, message)) = outgoing_mpsc_rx.recv().await {
                info!("Forwarding outgoing signaling for peer {}: {:?}", peer_pubkey, message.msg_type);
                if let Err(e) = outgoing_forwarder_tx.send(OutgoingSignalingEvent {
                    peer_pubkey: peer_pubkey.clone(),
                    message,
                }) {
                    error!("Failed to forward outgoing signaling for peer {}: {}", peer_pubkey, e);
                }
            }
        });

        loop {
            // Check for peer ID updates
            if let Ok(peer_id) = peer_id_rx.try_recv() {
                info!("Setting our peer ID: {}", peer_id);
                let mut manager = peer_manager.write().await;
                manager.set_our_peer_id(peer_id);
            }

            // Check for incoming signaling events (non-blocking)
            if let Ok(event) = incoming_rx.try_recv() {
                info!("Processing incoming signaling from peer {}: {:?}", event.peer_pubkey, event.message.msg_type);
                let mut manager = peer_manager.write().await;
                if let Err(e) = manager
                    .handle_signaling(&event.peer_pubkey, event.message, outgoing_mpsc_tx.clone())
                    .await
                {
                    error!(
                        "Failed to handle signaling from peer {}: {}",
                        event.peer_pubkey, e
                    );
                } else {
                    info!("Successfully handled signaling from peer {}", event.peer_pubkey);
                }
            }

            // Small delay to avoid busy loop
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }
}
