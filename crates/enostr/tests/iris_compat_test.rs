/// Iris-client compatibility test
///
/// Tests that notedeck's WebRTC signaling format is compatible with iris-client.
/// This validates the JSON structure matches what iris-client expects.

use enostr::SignalingMessage;
use serde_json::{json, Value};

/// Test Hello message format matches iris-client HelloMessage interface
#[test]
fn test_hello_message_iris_compat() {
    let peer_id = "abc123def456".to_string();
    let msg = SignalingMessage::hello(peer_id.clone());
    let json_str = msg.to_json().unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();

    // iris-client expects: { type: "hello", peerId: string }
    assert_eq!(parsed["type"], "hello");
    assert_eq!(parsed["peerId"], peer_id);

    // Should NOT have these fields
    assert!(parsed.get("peer_id").is_none(), "Should use peerId not peer_id");
    assert!(parsed.get("recipient").is_none(), "Hello should not have recipient");

    println!("Hello JSON: {}", json_str);
}

/// Test Offer message format matches iris-client OfferMessage interface
#[test]
fn test_offer_message_iris_compat() {
    let offer = json!({
        "type": "offer",
        "sdp": "v=0\r\no=- 12345 2 IN IP4 127.0.0.1\r\n..."
    });
    let recipient = "recipient_pubkey_hex".to_string();
    let peer_id = "sender_peer_id".to_string();

    let msg = SignalingMessage::offer(offer.clone(), recipient.clone(), peer_id.clone());
    let json_str = msg.to_json().unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();

    // iris-client expects: { type: "offer", offer: unknown, recipient: string, peerId: string }
    assert_eq!(parsed["type"], "offer");
    assert_eq!(parsed["recipient"], recipient);
    assert_eq!(parsed["peerId"], peer_id);
    assert!(parsed["offer"].is_object(), "offer should be an object");
    assert_eq!(parsed["offer"]["type"], "offer");
    assert!(parsed["offer"]["sdp"].as_str().unwrap().starts_with("v=0"));

    // Should NOT have snake_case versions
    assert!(parsed.get("peer_id").is_none(), "Should use peerId not peer_id");

    println!("Offer JSON: {}", json_str);
}

/// Test Answer message format matches iris-client AnswerMessage interface
#[test]
fn test_answer_message_iris_compat() {
    let answer = json!({
        "type": "answer",
        "sdp": "v=0\r\no=- 67890 2 IN IP4 127.0.0.1\r\n..."
    });
    let recipient = "recipient_pubkey_hex".to_string();
    let peer_id = "answerer_peer_id".to_string();

    let msg = SignalingMessage::answer(answer.clone(), recipient.clone(), peer_id.clone());
    let json_str = msg.to_json().unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();

    // iris-client expects: { type: "answer", answer: unknown, recipient: string, peerId: string }
    assert_eq!(parsed["type"], "answer");
    assert_eq!(parsed["recipient"], recipient);
    assert_eq!(parsed["peerId"], peer_id);
    assert!(parsed["answer"].is_object(), "answer should be an object");
    assert_eq!(parsed["answer"]["type"], "answer");

    println!("Answer JSON: {}", json_str);
}

/// Test Candidate message format matches iris-client CandidateMessage interface
#[test]
fn test_candidate_message_iris_compat() {
    let candidate = json!({
        "candidate": "candidate:1 1 UDP 2130706431 192.168.1.100 54321 typ host",
        "sdpMid": "0",
        "sdpMLineIndex": 0
    });
    let recipient = "recipient_pubkey_hex".to_string();
    let peer_id = "sender_peer_id".to_string();

    let msg = SignalingMessage::candidate(candidate.clone(), recipient.clone(), peer_id.clone());
    let json_str = msg.to_json().unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();

    // iris-client expects: { type: "candidate", candidate: unknown, recipient: string, peerId: string }
    assert_eq!(parsed["type"], "candidate");
    assert_eq!(parsed["recipient"], recipient);
    assert_eq!(parsed["peerId"], peer_id);
    assert!(parsed["candidate"].is_object(), "candidate should be an object");

    println!("Candidate JSON: {}", json_str);
}

/// Test deserialization of iris-client format messages
#[test]
fn test_deserialize_iris_client_hello() {
    // Exact format iris-client sends
    let iris_hello = r#"{"type":"hello","peerId":"abc123xyz789"}"#;

    let msg = SignalingMessage::from_json(iris_hello).unwrap();
    match msg {
        SignalingMessage::Hello { peer_id } => {
            assert_eq!(peer_id, "abc123xyz789");
        }
        _ => panic!("Expected Hello message"),
    }
}

#[test]
fn test_deserialize_iris_client_offer() {
    // Exact format iris-client sends
    let iris_offer = r#"{"type":"offer","offer":{"type":"offer","sdp":"test-sdp"},"recipient":"pubkey123","peerId":"peerid456"}"#;

    let msg = SignalingMessage::from_json(iris_offer).unwrap();
    match msg {
        SignalingMessage::Offer { offer, recipient, peer_id } => {
            assert_eq!(offer["type"], "offer");
            assert_eq!(offer["sdp"], "test-sdp");
            assert_eq!(recipient, "pubkey123");
            assert_eq!(peer_id, "peerid456");
        }
        _ => panic!("Expected Offer message"),
    }
}

#[test]
fn test_deserialize_iris_client_answer() {
    let iris_answer = r#"{"type":"answer","answer":{"type":"answer","sdp":"answer-sdp"},"recipient":"pubkey123","peerId":"peerid456"}"#;

    let msg = SignalingMessage::from_json(iris_answer).unwrap();
    match msg {
        SignalingMessage::Answer { answer, recipient, peer_id } => {
            assert_eq!(answer["type"], "answer");
            assert_eq!(answer["sdp"], "answer-sdp");
            assert_eq!(recipient, "pubkey123");
            assert_eq!(peer_id, "peerid456");
        }
        _ => panic!("Expected Answer message"),
    }
}

#[test]
fn test_deserialize_iris_client_candidate() {
    let iris_candidate = r#"{"type":"candidate","candidate":{"candidate":"cand","sdpMid":"0","sdpMLineIndex":0},"recipient":"pub","peerId":"peer"}"#;

    let msg = SignalingMessage::from_json(iris_candidate).unwrap();
    match msg {
        SignalingMessage::Candidate { candidate, recipient, peer_id } => {
            assert_eq!(candidate["candidate"], "cand");
            assert_eq!(candidate["sdpMid"], "0");
            assert_eq!(recipient, "pub");
            assert_eq!(peer_id, "peer");
        }
        _ => panic!("Expected Candidate message"),
    }
}

/// Test round-trip: serialize then deserialize
#[test]
fn test_round_trip_all_message_types() {
    // Hello
    let hello = SignalingMessage::hello("test-peer-id".to_string());
    let json = hello.to_json().unwrap();
    let parsed = SignalingMessage::from_json(&json).unwrap();
    assert!(matches!(parsed, SignalingMessage::Hello { .. }));

    // Offer
    let offer = SignalingMessage::offer(
        json!({"type": "offer", "sdp": "test"}),
        "recipient".to_string(),
        "peer".to_string(),
    );
    let json = offer.to_json().unwrap();
    let parsed = SignalingMessage::from_json(&json).unwrap();
    assert!(matches!(parsed, SignalingMessage::Offer { .. }));

    // Answer
    let answer = SignalingMessage::answer(
        json!({"type": "answer", "sdp": "test"}),
        "recipient".to_string(),
        "peer".to_string(),
    );
    let json = answer.to_json().unwrap();
    let parsed = SignalingMessage::from_json(&json).unwrap();
    assert!(matches!(parsed, SignalingMessage::Answer { .. }));

    // Candidate
    let candidate = SignalingMessage::candidate(
        json!({"candidate": "test"}),
        "recipient".to_string(),
        "peer".to_string(),
    );
    let json = candidate.to_json().unwrap();
    let parsed = SignalingMessage::from_json(&json).unwrap();
    assert!(matches!(parsed, SignalingMessage::Candidate { .. }));
}
