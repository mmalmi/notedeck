use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Signaling message types compatible with iris-client
/// Uses Nostr kind 30078 (APP_DATA) with #l="webrtc" tag
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SignalingType {
    /// WebRTC offer
    Offer { sdp: String },
    /// WebRTC answer
    Answer { sdp: String },
    /// ICE candidate
    Candidate { candidate: Option<Value> },
    /// Online heartbeat (hello message)
    /// peerId is a session-unique UUID to distinguish multiple devices/tabs
    Hello { #[serde(rename = "peerId")] peer_id: String },
}

/// Signaling message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalingMessage {
    #[serde(flatten)]
    pub msg_type: SignalingType,

    /// Timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
}

impl SignalingMessage {
    /// Create an offer message
    pub fn offer(sdp: String) -> Self {
        Self {
            msg_type: SignalingType::Offer { sdp },
            timestamp: Some(Self::current_timestamp()),
        }
    }

    /// Create an answer message
    pub fn answer(sdp: String) -> Self {
        Self {
            msg_type: SignalingType::Answer { sdp },
            timestamp: Some(Self::current_timestamp()),
        }
    }

    /// Create a candidate message
    pub fn candidate(candidate: Option<Value>) -> Self {
        Self {
            msg_type: SignalingType::Candidate { candidate },
            timestamp: Some(Self::current_timestamp()),
        }
    }

    /// Create a hello (heartbeat) message
    /// peer_id should be a session-unique UUID (e.g., uuid::Uuid::new_v4().to_string())
    pub fn hello(peer_id: String) -> Self {
        Self {
            msg_type: SignalingType::Hello { peer_id },
            timestamp: Some(Self::current_timestamp()),
        }
    }

    /// Get current Unix timestamp in milliseconds
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
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

    #[test]
    fn test_signaling_message_serialization() {
        let offer = SignalingMessage::offer("test-sdp".to_string());
        let json = offer.to_json().unwrap();
        assert!(json.contains("\"type\":\"offer\""));
        assert!(json.contains("\"sdp\":\"test-sdp\""));

        let hello = SignalingMessage::hello("test-peer-id".to_string());
        let json = hello.to_json().unwrap();
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("\"peerId\":\"test-peer-id\""));
    }

    #[test]
    fn test_signaling_message_deserialization() {
        let json = r#"{"type":"offer","sdp":"test-sdp","timestamp":1234567890}"#;
        let msg = SignalingMessage::from_json(json).unwrap();
        match msg.msg_type {
            SignalingType::Offer { sdp } => assert_eq!(sdp, "test-sdp"),
            _ => panic!("Expected offer message"),
        }
    }
}
