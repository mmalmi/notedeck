# WebRTC for Notedeck

WebRTC peer-to-peer relay implementation compatible with iris-client.

## Features

- **STUN Server**: Built-in STUN server for NAT traversal (port 3478)
- **Peer Connections**: WebRTC peer connections with 4 data channels (iris-compatible)
- **Online Heartbeat**: Automatic heartbeat system (10s intervals, 15s timeout)
- **Mutual Follows**: Integration with nostrdb for mutual follow detection
- **Signaling**: Nostr kind 30078 signaling protocol (iris-compatible)

## Architecture

### Data Channels (iris-compatible)

1. **jsonChannel**: Nostr protocol messages (REQ/EVENT/EOSE/CLOSE)
2. **fileChannel**: Binary file transfers
3. **callSignaling**: Audio/video call signaling
4. **blobChannel**: Content distribution with SHA-256 verification

### Heartbeat Protocol

- Sends "hello" message every 10 seconds via Nostr kind 30078
- Peers marked offline after 15 seconds without heartbeat
- Messages sent to all mutual follows + own pubkey (multi-device support)

### Signaling Protocol

Uses Nostr kind 30078 (APP_DATA) events with `#l="webrtc"` tag.

Message types:
- **offer**: WebRTC offer with SDP
- **answer**: WebRTC answer with SDP
- **candidate**: ICE candidate
- **hello**: Online heartbeat

## Usage

### Basic Setup

```rust
use enostr::relay::pool::PoolRelay;
use enostr::relay::webrtc::{WebRTCRelay, MutualFollowDetector};

// Create WebRTC relay with STUN server enabled
let webrtc_relay = PoolRelay::webrtc(true)?;

// Add to relay pool
relay_pool.relays.push(webrtc_relay);
```

### Starting the STUN Server

```rust
use enostr::relay::webrtc::StunServer;

// Start STUN server on default port (3478)
let stun_server = StunServer::new()?;
stun_server.start().await?;

// Custom port
let stun_server = StunServer::with_addr("0.0.0.0:3478".parse()?);
stun_server.start().await?;
```

### Managing Peer Connections

```rust
use enostr::relay::webrtc::{PeerConnection, PeerConnectionManager};
use tokio::sync::mpsc;

// Create peer connection manager
let mut peer_manager = PeerConnectionManager::new();

// Create outgoing message channel
let (tx, rx) = mpsc::unbounded_channel();

// Create peer connection
let peer = PeerConnection::new(
    "peer_pubkey_hex".to_string(),
    tx
).await?;

// Add to manager
peer_manager.add_peer("peer_pubkey_hex".to_string(), Arc::new(RwLock::new(peer)));

// Create offer (initiator)
let peer = peer_manager.get_peer("peer_pubkey_hex").unwrap();
let offer = peer.read().await.create_offer().await?;

// Handle answer (initiator)
peer.read().await.set_remote_answer(answer).await?;

// Or handle offer (responder)
let answer = peer.read().await.handle_offer(offer).await?;

// Add ICE candidate
let candidate_init = RTCIceCandidateInit { /* ... */ };
peer.read().await.add_ice_candidate(candidate_init).await?;

// Send JSON data
let data = b"[\"REQ\",\"sub1\",{\"kinds\":[1]}]";
peer.read().await.send_json(data).await?;
```

### Online Heartbeat System

```rust
use enostr::relay::webrtc::{HeartbeatManager, OnlineStatus};

// Create and start heartbeat manager
let mut heartbeat_manager = HeartbeatManager::new();
heartbeat_manager.start().await?;

// Handle received hello message
heartbeat_manager.handle_hello("peer_pubkey".to_string());

// Check online status
if let Some(status) = heartbeat_manager.get_status("peer_pubkey") {
    match status {
        OnlineStatus::Online => println!("Peer is online"),
        OnlineStatus::Offline => println!("Peer is offline"),
    }
}

// Get all online peers
let online_peers = heartbeat_manager.get_online_peers();

// Check for offline peers (call periodically)
let newly_offline = heartbeat_manager.check_offline_peers();
```

### Mutual Follow Detection

```rust
use enostr::relay::webrtc::MutualFollowDetector;
use nostrdb::Ndb;

// Create detector with nostrdb instance
let ndb = Ndb::new("./db", &Default::default())?;
let detector = MutualFollowDetector::new(ndb);

// Check if two pubkeys are mutual follows
let our_pk = [0u8; 32]; // Your pubkey
let their_pk = [1u8; 32]; // Their pubkey

if detector.are_mutual_follows(&our_pk, &their_pk)? {
    println!("Mutual follows!");
}

// Get all mutual follows for a pubkey
let mutual_follows = detector.get_mutual_follows(&our_pk)?;

// Check if should connect (mutual + distance <= 2)
if detector.should_connect(&our_pk, &their_pk)? {
    println!("Should establish WebRTC connection");
}

// Get follow distance
if let Some(distance) = detector.get_follow_distance(&our_pk, &their_pk)? {
    println!("Follow distance: {}", distance);
}
```

### Signaling Messages

```rust
use enostr::relay::webrtc::{SignalingMessage, SignalingType, WebRTCSignalingEvent};

// Create signaling messages
let offer_msg = SignalingMessage::offer("sdp_string".to_string());
let answer_msg = SignalingMessage::answer("sdp_string".to_string());
let candidate_msg = SignalingMessage::candidate(Some(candidate_json));
let hello_msg = SignalingMessage::hello();

// Serialize to JSON
let json = offer_msg.to_json()?;

// Deserialize from JSON
let msg = SignalingMessage::from_json(&json)?;

// Build Nostr event for signaling
let event = WebRTCSignalingEvent::new(
    "peer_pubkey".to_string(),
    offer_msg
);

let content = event.build_content()?; // Encrypt this with NIP-04/NIP-44
let tags = event.tags(); // [["l", "webrtc"], ["p", "peer_pubkey"]]
let kind = WebRTCSignalingEvent::kind(); // 30078
```

## Integration with Notedeck

### 1. Initialize WebRTC Relay

In your app initialization:

```rust
// Enable WebRTC with STUN server
let webrtc_relay = PoolRelay::webrtc(true)?;
relay_pool.relays.push(webrtc_relay);
```

### 2. Subscribe to WebRTC Events

Subscribe to kind 30078 events with `#l="webrtc"` tag:

```rust
let filter = Filter::new()
    .kinds([30078])
    .tag("l", ["webrtc"])
    .build();

relay_pool.subscribe("webrtc_sub".to_string(), vec![filter])?;
```

### 3. Handle Incoming Signaling

When you receive a kind 30078 event:

```rust
// Decrypt the content (NIP-04/NIP-44)
let decrypted_content = decrypt(&event.content, &our_keypair)?;

// Parse signaling message
let msg = SignalingMessage::from_json(&decrypted_content)?;

// Handle based on type
match msg.msg_type {
    SignalingType::Hello => {
        heartbeat_manager.handle_hello(peer_pubkey);
    }
    SignalingType::Offer { sdp } => {
        // Handle WebRTC offer
    }
    SignalingType::Answer { sdp } => {
        // Handle WebRTC answer
    }
    SignalingType::Candidate { candidate } => {
        // Handle ICE candidate
    }
}
```

### 4. Connection Flow

**Initiator (lower UUID)**:
1. Receive hello from peer
2. Check if mutual follows
3. Compare UUIDs (only lower UUID initiates)
4. Create offer
5. Encrypt and send via Nostr kind 30078
6. Wait for answer
7. Exchange ICE candidates
8. Connection established

**Responder (higher UUID)**:
1. Receive hello from peer
2. Wait for offer
3. Create answer
4. Encrypt and send via Nostr kind 30078
5. Exchange ICE candidates
6. Connection established

## Iris Compatibility

This implementation is fully compatible with iris-client:

- Uses same STUN servers (Google, Cloudflare)
- Same signaling protocol (Nostr kind 30078 with #l="webrtc")
- Same 4 data channels (jsonChannel, fileChannel, callSignaling, blobChannel)
- Same heartbeat interval (10s) and timeout (15s)
- Same tie-breaking mechanism (UUID comparison)
- Same mutual follow requirement

## Testing

Test basic functionality:

```bash
# Run tests
cd notedeck/crates/enostr
cargo test webrtc

# Test STUN server
cargo run --example stun_server

# Test peer connection
cargo test peer_connection
```

## Notes

- WebRTC connections require STUN/TURN servers for NAT traversal
- Signaling messages should be encrypted using NIP-04 or NIP-44
- Only connect to mutual follows for privacy/security
- Heartbeat ensures timely connection cleanup
- Follow distance check (<=2) prevents excessive connections
