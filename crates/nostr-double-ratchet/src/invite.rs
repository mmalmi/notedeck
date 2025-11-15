use crate::{Result, Session, Error, INVITE_EVENT_KIND, INVITE_RESPONSE_KIND};
use enostr::{Filter, Pubkey};
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp, UnsignedEvent};
use nostr::nips::nip44::{self, Version};
use base64::Engine;

#[derive(Clone)]
pub struct Invite {
    pub inviter_ephemeral_public_key: Pubkey,
    pub shared_secret: [u8; 32],
    pub inviter: Pubkey,
    pub inviter_ephemeral_private_key: Option<[u8; 32]>,
    pub device_id: Option<String>,
    pub max_uses: Option<usize>,
    pub used_by: Vec<Pubkey>,
    pub created_at: u64,
}

impl Invite {
    pub fn create_new(inviter: Pubkey, device_id: Option<String>, max_uses: Option<usize>) -> Result<Self> {
        let inviter_ephemeral_keys = Keys::generate();
        let inviter_ephemeral_public_key = Pubkey::new(inviter_ephemeral_keys.public_key().to_bytes());
        let inviter_ephemeral_private_key = inviter_ephemeral_keys.secret_key().to_secret_bytes();

        let shared_secret = Keys::generate().secret_key().to_secret_bytes();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(Self {
            inviter_ephemeral_public_key,
            shared_secret,
            inviter,
            inviter_ephemeral_private_key: Some(inviter_ephemeral_private_key),
            device_id,
            max_uses,
            used_by: Vec::new(),
            created_at: now,
        })
    }

    pub fn get_url(&self, root: &str) -> Result<String> {
        let data = serde_json::json!({
            "inviter": hex::encode(self.inviter.bytes()),
            "ephemeralKey": hex::encode(self.inviter_ephemeral_public_key.bytes()),
            "sharedSecret": hex::encode(self.shared_secret),
        });

        let url = format!("{}#{}", root, urlencoding::encode(&data.to_string()));
        Ok(url)
    }

    pub fn from_url(url: &str) -> Result<Self> {
        let hash = url.split('#').nth(1).ok_or(Error::Invite("No hash in URL".to_string()))?;
        let decoded = urlencoding::decode(hash).map_err(|e| Error::Invite(e.to_string()))?;
        let data: serde_json::Value = serde_json::from_str(&decoded)?;

        let inviter = crate::utils::pubkey_from_hex(
            data["inviter"].as_str().ok_or(Error::Invite("Missing inviter".to_string()))?
        )?;
        let ephemeral_key = crate::utils::pubkey_from_hex(
            data["ephemeralKey"].as_str().ok_or(Error::Invite("Missing ephemeralKey".to_string()))?
        )?;
        let shared_secret_hex = data["sharedSecret"].as_str().ok_or(Error::Invite("Missing sharedSecret".to_string()))?;
        let shared_secret_bytes = hex::decode(shared_secret_hex)?;
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&shared_secret_bytes);

        Ok(Self {
            inviter_ephemeral_public_key: ephemeral_key,
            shared_secret,
            inviter,
            inviter_ephemeral_private_key: None,
            device_id: None,
            max_uses: None,
            used_by: Vec::new(),
            created_at: 0,
        })
    }

    pub fn get_event(&self) -> Result<UnsignedEvent> {
        let device_id = self.device_id.as_ref().ok_or(Error::DeviceIdRequired)?;

        let tags = vec![
            Tag::parse(&["ephemeralKey".to_string(), hex::encode(self.inviter_ephemeral_public_key.bytes())])
                .map_err(|e| Error::InvalidEvent(e.to_string()))?,
            Tag::parse(&["sharedSecret".to_string(), hex::encode(self.shared_secret)])
                .map_err(|e| Error::InvalidEvent(e.to_string()))?,
            Tag::parse(&["d".to_string(), format!("double-ratchet/invites/{}", device_id)])
                .map_err(|e| Error::InvalidEvent(e.to_string()))?,
            Tag::parse(&["l".to_string(), "double-ratchet/invites".to_string()])
                .map_err(|e| Error::InvalidEvent(e.to_string()))?,
        ];

        let event = EventBuilder::new(Kind::from(INVITE_EVENT_KIND as u16), "")
            .tags(tags)
            .custom_created_at(Timestamp::from(self.created_at))
            .build(nostr::PublicKey::from_slice(self.inviter.bytes())?);

        Ok(event)
    }

    pub fn from_event(event: &nostr::Event) -> Result<Self> {
        let inviter = Pubkey::new(event.pubkey.to_bytes());

        let ephemeral_key = event.tags.iter().cloned()
            .find(|t| t.clone().to_vec().first().map(|s| s.as_str()) == Some("ephemeralKey"))
            .and_then(|t| t.to_vec().get(1).cloned())
            .ok_or(Error::Invite("Missing ephemeralKey tag".to_string()))?;

        let shared_secret_hex = event.tags.iter().cloned()
            .find(|t| t.clone().to_vec().first().map(|s| s.as_str()) == Some("sharedSecret"))
            .and_then(|t| t.to_vec().get(1).cloned())
            .ok_or(Error::Invite("Missing sharedSecret tag".to_string()))?;

        let device_tag = event.tags.iter().cloned()
            .find(|t| t.clone().to_vec().first().map(|s| s.as_str()) == Some("d"))
            .and_then(|t| t.to_vec().get(1).cloned());

        let device_id = device_tag.and_then(|d| d.split('/').nth(2).map(String::from));

        let inviter_ephemeral_public_key = crate::utils::pubkey_from_hex(&ephemeral_key)?;
        let shared_secret_bytes = hex::decode(&shared_secret_hex)?;
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&shared_secret_bytes);

        Ok(Self {
            inviter_ephemeral_public_key,
            shared_secret,
            inviter,
            inviter_ephemeral_private_key: None,
            device_id,
            max_uses: None,
            used_by: Vec::new(),
            created_at: event.created_at.as_u64(),
        })
    }

    pub fn accept(
        &self,
        invitee_public_key: Pubkey,
        invitee_private_key: [u8; 32],
        device_id: Option<String>,
    ) -> Result<(Session, nostr::Event)> {
        let invitee_session_keys = Keys::generate();
        let invitee_session_key = invitee_session_keys.secret_key().to_secret_bytes();
        let invitee_session_public_key = Pubkey::new(invitee_session_keys.public_key().to_bytes());

        let session = Session::init(
            self.inviter_ephemeral_public_key,
            invitee_session_key,
            true,
            self.shared_secret,
            None,
        )?;

        let payload = serde_json::json!({
            "sessionKey": hex::encode(invitee_session_public_key.bytes()),
            "deviceId": device_id,
        });

        let invitee_sk = nostr::SecretKey::from_slice(&invitee_private_key)?;
        let inviter_pk = nostr::PublicKey::from_slice(self.inviter.bytes())?;
        let dh_encrypted = nip44::encrypt(&invitee_sk, &inviter_pk, &payload.to_string(), Version::V2)?;

        let conversation_key = nip44::v2::ConversationKey::new(self.shared_secret);
        let encrypted_bytes = nip44::v2::encrypt_to_bytes(&conversation_key, &dh_encrypted)?;
        let inner_encrypted = base64::engine::general_purpose::STANDARD.encode(encrypted_bytes);

        let inner_event = serde_json::json!({
            "pubkey": hex::encode(invitee_public_key.bytes()),
            "content": inner_encrypted,
            "created_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });

        let random_sender_keys = Keys::generate();
        let random_sender_sk = random_sender_keys.secret_key();
        let inviter_ephemeral_pk = nostr::PublicKey::from_slice(self.inviter_ephemeral_public_key.bytes())?;

        let envelope_content = nip44::encrypt(
            random_sender_sk,
            &inviter_ephemeral_pk,
            &inner_event.to_string(),
            Version::V2,
        )?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let two_days = 2 * 24 * 60 * 60;
        let random_now = now - (rand::random::<u64>() % two_days);

        // Build and sign the event with ephemeral keys
        let unsigned_envelope = EventBuilder::new(Kind::from(INVITE_RESPONSE_KIND as u16), envelope_content)
            .tag(Tag::parse(&["p".to_string(), hex::encode(self.inviter_ephemeral_public_key.bytes())])
                .map_err(|e| Error::InvalidEvent(e.to_string()))?)
            .custom_created_at(Timestamp::from(random_now))
            .build(random_sender_keys.public_key());

        // Sign with the ephemeral keys before returning
        let signed_envelope = unsigned_envelope.sign_with_keys(&random_sender_keys)
            .map_err(|e| Error::InvalidEvent(e.to_string()))?;

        Ok((session, signed_envelope))
    }

    pub fn serialize(&self) -> Result<String> {
        let data = serde_json::json!({
            "inviterEphemeralPublicKey": hex::encode(self.inviter_ephemeral_public_key.bytes()),
            "sharedSecret": hex::encode(self.shared_secret),
            "inviter": hex::encode(self.inviter.bytes()),
            "inviterEphemeralPrivateKey": self.inviter_ephemeral_private_key.map(|k| hex::encode(k)),
            "deviceId": self.device_id,
            "maxUses": self.max_uses,
            "usedBy": self.used_by.iter().map(|pk| hex::encode(pk.bytes())).collect::<Vec<_>>(),
            "createdAt": self.created_at,
        });
        Ok(data.to_string())
    }

    pub fn deserialize(json: &str) -> Result<Self> {
        let data: serde_json::Value = serde_json::from_str(json)?;

        let inviter_ephemeral_public_key = crate::utils::pubkey_from_hex(
            data["inviterEphemeralPublicKey"].as_str().ok_or(Error::Invite("Missing field".to_string()))?
        )?;

        let shared_secret_hex = data["sharedSecret"].as_str().ok_or(Error::Invite("Missing sharedSecret".to_string()))?;
        let shared_secret_bytes = hex::decode(shared_secret_hex)?;
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&shared_secret_bytes);

        let inviter = crate::utils::pubkey_from_hex(
            data["inviter"].as_str().ok_or(Error::Invite("Missing inviter".to_string()))?
        )?;

        let inviter_ephemeral_private_key = if let Some(hex_str) = data["inviterEphemeralPrivateKey"].as_str() {
            let bytes = hex::decode(hex_str)?;
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            Some(array)
        } else {
            None
        };

        let used_by = if let Some(arr) = data["usedBy"].as_array() {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| crate::utils::pubkey_from_hex(s).ok())
                .collect()
        } else {
            Vec::new()
        };

        Ok(Self {
            inviter_ephemeral_public_key,
            shared_secret,
            inviter,
            inviter_ephemeral_private_key,
            device_id: data["deviceId"].as_str().map(String::from),
            max_uses: data["maxUses"].as_u64().map(|u| u as usize),
            used_by,
            created_at: data["createdAt"].as_u64().unwrap_or(0),
        })
    }

    pub fn listen(
        &self,
        pubsub: &dyn crate::NostrPubSub,
    ) -> Result<()> {
        let filter = Filter::new()
            .kinds(vec![INVITE_RESPONSE_KIND as u64])
            .pubkeys([self.inviter_ephemeral_public_key.bytes()])
            .build();

        pubsub.subscribe(filter)?;
        Ok(())
    }

    pub fn from_user(
        user_pubkey: Pubkey,
        pubsub: &dyn crate::NostrPubSub,
    ) -> Result<()> {
        let filter = Filter::new()
            .kinds(vec![INVITE_EVENT_KIND as u64])
            .authors([user_pubkey.bytes()])
            .build();

        pubsub.subscribe(filter)?;
        Ok(())
    }

    pub fn process_invite_response(&self, event: &nostr::Event, _inviter_private_key: [u8; 32]) -> Result<Option<(Session, Pubkey, Option<String>)>> {
        let inviter_ephemeral_private_key = self.inviter_ephemeral_private_key
            .ok_or(Error::Invite("Ephemeral key not available".to_string()))?;

        let inviter_ephemeral_sk = nostr::SecretKey::from_slice(&inviter_ephemeral_private_key)?;
        let sender_pk = nostr::PublicKey::from_slice(&event.pubkey.to_bytes())?;
        let decrypted = nip44::decrypt(&inviter_ephemeral_sk, &sender_pk, &event.content)?;
        let inner_event: serde_json::Value = serde_json::from_str(&decrypted)?;

        let invitee_identity_hex = inner_event["pubkey"].as_str()
            .ok_or(Error::Invite("Missing pubkey".to_string()))?;
        let invitee_identity = crate::utils::pubkey_from_hex(invitee_identity_hex)?;

        let inner_content = inner_event["content"].as_str()
            .ok_or(Error::Invite("Missing content".to_string()))?;

        let conversation_key = nip44::v2::ConversationKey::new(self.shared_secret);
        let ciphertext_bytes = base64::engine::general_purpose::STANDARD.decode(inner_content)
            .map_err(|e| Error::Serialization(e.to_string()))?;
        let dh_encrypted_ciphertext = String::from_utf8(nip44::v2::decrypt_to_bytes(&conversation_key, &ciphertext_bytes)?)
            .map_err(|e| Error::Serialization(e.to_string()))?;

        // Decrypt the DH-encrypted layer using inviter's key
        let inviter_sk = nostr::SecretKey::from_slice(&_inviter_private_key)?;
        let invitee_pk = nostr::PublicKey::from_slice(invitee_identity.bytes())?;
        let dh_decrypted = nip44::decrypt(&inviter_sk, &invitee_pk, &dh_encrypted_ciphertext)?;

        let payload: serde_json::Value = match serde_json::from_str(&dh_decrypted) {
            Ok(p) => p,
            Err(_) => {
                // Fallback: treat as raw hex session key
                let invitee_session_pubkey = crate::utils::pubkey_from_hex(&dh_decrypted)?;
                let session = Session::init(
                    invitee_session_pubkey,
                    inviter_ephemeral_private_key,
                    false, // Inviter is non-initiator, must receive first message to initialize ratchet
                    self.shared_secret,
                    Some(event.id.to_string()),
                )?;
                return Ok(Some((session, invitee_identity, None)));
            }
        };

        let invitee_session_key_hex = payload["sessionKey"].as_str()
            .ok_or(Error::Invite("Missing sessionKey".to_string()))?;
        let invitee_session_pubkey = crate::utils::pubkey_from_hex(invitee_session_key_hex)?;
        let device_id = payload["deviceId"].as_str().map(String::from);

        let session = Session::init(
            invitee_session_pubkey,
            inviter_ephemeral_private_key,
            false, // Inviter is non-initiator, must receive first message to initialize ratchet
            self.shared_secret,
            Some(event.id.to_string()),
        )?;

        Ok(Some((session, invitee_identity, device_id)))
    }
}
