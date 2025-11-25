/// Real WebRTC data channel test
///
/// Tests actual WebRTC peer-to-peer data channel:
/// - 2 PeerConnection instances
/// - Complete signaling exchange (offer/answer/ICE)
/// - Data channel establishment
/// - Send/receive test data
/// - No shortcuts - uses real webrtc crate
use enostr::{PeerConnection, SignalingMessage};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use webrtc::data_channel::RTCDataChannel;

/// Wait for data channel to open
async fn wait_for_channel_open(
    channel: Arc<RwLock<Option<Arc<RTCDataChannel>>>>,
    timeout_ms: u64,
) -> Result<Arc<RTCDataChannel>, Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();

    loop {
        if let Some(dc) = channel.read().await.as_ref() {
            if dc.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
                println!("Data channel opened!");
                return Ok(dc.clone());
            }
        }

        if start.elapsed().as_millis() > timeout_ms as u128 {
            return Err("Timeout waiting for data channel to open".into());
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn test_webrtc_data_channel_real() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Real WebRTC Data Channel Test ===\n");

    // Create signaling channels
    let (tx_a, mut rx_a) = mpsc::unbounded_channel::<SignalingMessage>();
    let (tx_b, mut rx_b) = mpsc::unbounded_channel::<SignalingMessage>();

    // Create peer connections
    println!("=== Creating peer connections ===");
    let peer_a = Arc::new(RwLock::new(
        PeerConnection::new("peer_b_pubkey".to_string(), "peer_a_id".to_string(), tx_a).await?
    ));
    let peer_b = Arc::new(RwLock::new(
        PeerConnection::new("peer_a_pubkey".to_string(), "peer_b_id".to_string(), tx_b).await?
    ));

    println!("Peer A created");
    println!("Peer B created\n");

    // Peer A creates offer (initiator)
    println!("=== Phase 1: Peer A creates offer ===");
    let offer = {
        let peer_a_lock = peer_a.read().await;
        peer_a_lock.create_offer().await?
    };

    let offer_sdp = offer.sdp.clone();
    println!("Offer created ({} bytes)\n", offer_sdp.len());

    // Peer B receives offer and creates answer
    println!("=== Phase 2: Peer B processes offer and creates answer ===");
    let answer = {
        let peer_b_lock = peer_b.read().await;
        peer_b_lock.handle_offer(offer).await?
    };

    let answer_sdp = answer.sdp.clone();
    println!("Answer created ({} bytes)\n", answer_sdp.len());

    // Peer A receives answer
    println!("=== Phase 3: Peer A processes answer ===");
    {
        let peer_a_lock = peer_a.read().await;
        peer_a_lock.set_remote_answer(answer).await?;
    }

    println!("Answer processed\n");

    // Wait for ICE candidates to be gathered
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Process and exchange ICE candidates
    println!("=== Phase 4: ICE candidate exchange ===");
    let mut ice_a_to_b = Vec::new();
    let mut ice_b_to_a = Vec::new();

    // Collect ICE candidates from both peers
    while let Ok(msg) = rx_a.try_recv() {
        if let SignalingMessage::Candidate { candidate, .. } = msg {
            println!("Peer A → B: ICE candidate");
            ice_a_to_b.push(candidate);
        }
    }

    while let Ok(msg) = rx_b.try_recv() {
        if let SignalingMessage::Candidate { candidate, .. } = msg {
            println!("Peer B → A: ICE candidate");
            ice_b_to_a.push(candidate);
        }
    }

    println!("Collected {} candidates from A, {} from B", ice_a_to_b.len(), ice_b_to_a.len());

    // Exchange ICE candidates
    for cand_json in ice_a_to_b {
        if let Ok(cand_str) = serde_json::to_string(&cand_json) {
            if let Ok(ice_init) = serde_json::from_str::<webrtc::ice_transport::ice_candidate::RTCIceCandidateInit>(&cand_str) {
                let peer_b_lock = peer_b.read().await;
                let _ = peer_b_lock.add_ice_candidate(ice_init).await;
            }
        }
    }

    for cand_json in ice_b_to_a {
        if let Ok(cand_str) = serde_json::to_string(&cand_json) {
            if let Ok(ice_init) = serde_json::from_str::<webrtc::ice_transport::ice_candidate::RTCIceCandidateInit>(&cand_str) {
                let peer_a_lock = peer_a.read().await;
                let _ = peer_a_lock.add_ice_candidate(ice_init).await;
            }
        }
    }

    println!("ICE candidates exchanged\n");

    // Wait for data channel to open
    println!("=== Phase 5: Wait for data channel ===");

    let dc_a = {
        let peer_a_lock = peer_a.read().await;
        wait_for_channel_open(peer_a_lock.json_channel.clone(), 3000).await?
    };

    println!("Data channel ready on Peer A\n");

    // Send test data
    println!("=== Phase 6: Send test data ===");

    let test_message = r#"["REQ","test_sub",{"kinds":[1],"limit":10}]"#;

    {
        let peer_a_lock = peer_a.read().await;
        peer_a_lock.send_json(test_message.as_bytes()).await?;
    }

    println!("Peer A sent: {}\n", test_message);

    // Wait for peer B to receive
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check peer B's incoming data
    println!("=== Phase 7: Verify reception ===");

    let received = {
        let mut peer_b_lock = peer_b.write().await;
        let mut messages = Vec::new();

        while let Ok(data) = peer_b_lock.incoming_data.try_recv() {
            let text = String::from_utf8_lossy(&data).to_string();
            println!("Peer B received: {}", text);
            messages.push(text);
        }

        messages
    };

    println!("\n=== Results ===");
    println!("Peer B received {} messages", received.len());

    // Assertions
    assert!(received.len() > 0, "Peer B should receive messages");
    assert!(received.iter().any(|m| m.contains("REQ")), "Should receive REQ message");

    println!("\n✅ Real WebRTC data channel works!\n");
    println!("What this proves:");
    println!("  - WebRTC peer connections established");
    println!("  - SDP offer/answer exchange completed");
    println!("  - ICE candidates exchanged");
    println!("  - Data channel opened successfully");
    println!("  - Data sent from Peer A");
    println!("  - Data received by Peer B");
    println!("  - Actual P2P communication working");

    // Cleanup
    peer_a.read().await.close().await?;
    peer_b.read().await.close().await?;

    Ok(())
}
