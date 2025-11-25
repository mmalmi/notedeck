use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Signaling message types compatible with iris-client
/// Uses Nostr kind 30078 (APP_DATA) with #l="webrtc" tag
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SignalingMessage {
    /// WebRTC offer (RTCSessionDescription)
    Offer {
        offer: Value,
        recipient: String,
        #[serde(rename = "peerId")]
        peer_id: String,
    },
    /// WebRTC answer (RTCSessionDescription)
    Answer {
        answer: Value,
        recipient: String,
        #[serde(rename = "peerId")]
        peer_id: String,
    },
    /// ICE candidate
    Candidate {
        candidate: Value,
        recipient: String,
        #[serde(rename = "peerId")]
        peer_id: String,
    },
    /// Online heartbeat (hello message)
    /// peerId is a session-unique UUID to distinguish multiple devices/tabs
    Hello {
        #[serde(rename = "peerId")]
        peer_id: String,
    },
}

impl SignalingMessage {
    /// Create an offer message
    /// offer should be an RTCSessionDescription object (with type and sdp fields)
    pub fn offer(offer: Value, recipient: String, peer_id: String) -> Self {
        Self::Offer {
            offer,
            recipient,
            peer_id,
        }
    }

    /// Create an answer message
    /// answer should be an RTCSessionDescription object (with type and sdp fields)
    pub fn answer(answer: Value, recipient: String, peer_id: String) -> Self {
        Self::Answer {
            answer,
            recipient,
            peer_id,
        }
    }

    /// Create a candidate message
    pub fn candidate(candidate: Value, recipient: String, peer_id: String) -> Self {
        Self::Candidate {
            candidate,
            recipient,
            peer_id,
        }
    }

    /// Create a hello (heartbeat) message
    /// peer_id should be a session-unique UUID (e.g., uuid::Uuid::new_v4().to_string())
    pub fn hello(peer_id: String) -> Self {
        Self::Hello { peer_id }
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| {
            crate::Error::Generic(format!("Failed to serialize signaling message: {}", e))
        })
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| {
            crate::Error::Generic(format!("Failed to deserialize signaling message: {}", e))
        })
    }
}

/// Nostr event builder for WebRTC signaling
/// Uses kind 30078 (APP_DATA) with #l="webrtc" tag (iris-compatible)
#[allow(dead_code)]
pub struct WebRTCSignalingEvent {
    /// Target peer's pubkey
    pub peer_pubkey: String,
    /// Signaling message
    pub message: SignalingMessage,
}

#[allow(dead_code)]
impl WebRTCSignalingEvent {
    pub fn new(peer_pubkey: String, message: SignalingMessage) -> Self {
        Self {
            peer_pubkey,
            message,
        }
    }

    /// Build the Nostr event content
    /// This should be encrypted using NIP-04 or NIP-44 before publishing
    pub fn build_content(&self) -> Result<String> {
        self.message.to_json()
    }

    /// Get the event kind (30078 - APP_DATA)
    pub fn kind() -> u16 {
        30078
    }

    /// Get required tags
    /// Returns: [["l", "webrtc"], ["p", peer_pubkey]]
    pub fn tags(&self) -> Vec<Vec<String>> {
        vec![
            vec!["l".to_string(), "webrtc".to_string()],
            vec!["p".to_string(), self.peer_pubkey.clone()],
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_signaling_message_serialization() {
        let offer_desc = json!({"type": "offer", "sdp": "test-sdp"});
        let offer = SignalingMessage::offer(
            offer_desc,
            "recipient-pubkey".to_string(),
            "test-peer-id".to_string(),
        );
        let json = offer.to_json().unwrap();
        assert!(json.contains("\"type\":\"offer\""));
        assert!(json.contains("\"offer\":{"));
        assert!(json.contains("\"recipient\":\"recipient-pubkey\""));
        assert!(json.contains("\"peerId\":\"test-peer-id\""));

        let hello = SignalingMessage::hello("test-peer-id".to_string());
        let json = hello.to_json().unwrap();
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("\"peerId\":\"test-peer-id\""));
    }

    #[test]
    fn test_signaling_message_deserialization() {
        // iris-client format
        let json = r#"{"type":"offer","offer":{"type":"offer","sdp":"test-sdp"},"recipient":"abc","peerId":"xyz"}"#;
        let msg = SignalingMessage::from_json(json).unwrap();
        match msg {
            SignalingMessage::Offer { offer, recipient, peer_id } => {
                assert_eq!(offer["sdp"], "test-sdp");
                assert_eq!(recipient, "abc");
                assert_eq!(peer_id, "xyz");
            }
            _ => panic!("Expected offer message"),
        }
    }
}
