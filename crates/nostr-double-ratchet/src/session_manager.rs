use crate::{
    InMemoryStorage, Invite, Result, StorageAdapter, UserRecord,
};
use enostr::{Filter, Pubkey};
use nostr::UnsignedEvent;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub enum SessionManagerEvent {
    Subscribe(String),
    Publish(UnsignedEvent),
    ReceivedEvent(UnsignedEvent),
    DecryptedMessage {
        sender: Pubkey,
        content: String,
        event_id: Option<String>,
    },
}

struct InviteState {
    invite: Invite,
    our_identity_key: [u8; 32],
}

pub struct SessionManager {
    user_records: Arc<Mutex<HashMap<Pubkey, UserRecord>>>,
    our_public_key: Pubkey,
    our_identity_key: [u8; 32],
    device_id: String,
    storage: Arc<dyn StorageAdapter>,
    event_tx: crossbeam_channel::Sender<SessionManagerEvent>,
    initialized: Arc<Mutex<bool>>,
    invite_state: Arc<Mutex<Option<InviteState>>>,
    pending_invites: Arc<Mutex<HashMap<Pubkey, Invite>>>,
}

impl SessionManager {
    pub fn new(
        our_public_key: Pubkey,
        our_identity_key: [u8; 32],
        device_id: String,
        event_tx: crossbeam_channel::Sender<SessionManagerEvent>,
        storage: Option<Arc<dyn StorageAdapter>>,
    ) -> Self {
        Self {
            user_records: Arc::new(Mutex::new(HashMap::new())),
            our_public_key,
            our_identity_key,
            device_id,
            storage: storage.unwrap_or_else(|| Arc::new(InMemoryStorage::new())),
            event_tx,
            initialized: Arc::new(Mutex::new(false)),
            invite_state: Arc::new(Mutex::new(None)),
            pending_invites: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn init(&self) -> Result<()> {
        let mut initialized = self.initialized.lock().unwrap();
        if *initialized {
            return Ok(());
        }
        *initialized = true;
        drop(initialized);

        self.load_all_user_records()?;

        let device_invite_key = self.device_invite_key(&self.device_id);
        let invite = match self.storage.get(&device_invite_key)? {
            Some(data) => Invite::deserialize(&data)?,
            None => Invite::create_new(
                self.our_public_key,
                Some(self.device_id.clone()),
                None,
            )?,
        };

        self.storage.put(&device_invite_key, invite.serialize()?)?;

        *self.invite_state.lock().unwrap() = Some(InviteState {
            invite: invite.clone(),
            our_identity_key: self.our_identity_key,
        });

        let filter = Filter::new()
            .kinds(vec![crate::INVITE_RESPONSE_KIND as u64])
            .pubkey([invite.inviter_ephemeral_public_key.bytes()])
            .build();

        let filter_json = filter.json()?;
        self.event_tx.send(SessionManagerEvent::Subscribe(filter_json))
            .map_err(|_| crate::Error::Storage("Failed to send subscribe".to_string()))?;

        let event = invite.get_event()?;
        self.event_tx.send(SessionManagerEvent::Publish(event))
            .map_err(|_| crate::Error::Storage("Failed to send publish".to_string()))?;

        Ok(())
    }

    pub fn send_text(&self, recipient: Pubkey, text: String) -> Result<Vec<String>> {
        // Setup recipient if not already done (triggers invite subscription)
        if recipient != self.our_public_key {
            let _ = self.setup_user(recipient);
        }

        // Also send to self (all own devices)
        let _ = self.setup_user(self.our_public_key);

        let mut event_ids = Vec::new();
        let mut user_records = self.user_records.lock().unwrap();

        // Send to recipient's devices
        if let Some(recipient_record) = user_records.get_mut(&recipient) {
            let mut active_sessions = recipient_record.get_active_sessions_mut();
            for session in active_sessions.iter_mut() {
                match session.send(text.clone()) {
                    Ok(unsigned_event) => {
                        if let Some(id) = unsigned_event.id {
                            event_ids.push(id.to_string());
                        }
                        let _ = self.event_tx.send(SessionManagerEvent::Publish(unsigned_event));
                    }
                    Err(_) => continue,
                }
            }
        }

        // Send to own devices (unless sending to self)
        if recipient != self.our_public_key {
            if let Some(self_record) = user_records.get_mut(&self.our_public_key) {
                let active_sessions = self_record.get_active_sessions_mut();
                for session in active_sessions {
                    match session.send(text.clone()) {
                        Ok(unsigned_event) => {
                            if let Some(id) = unsigned_event.id {
                                event_ids.push(id.to_string());
                            }
                            let _ = self.event_tx.send(SessionManagerEvent::Publish(unsigned_event));
                        }
                        Err(_) => continue,
                    }
                }
            }
        }

        drop(user_records);
        let _ = self.store_user_record(&recipient);
        if recipient != self.our_public_key {
            let _ = self.store_user_record(&self.our_public_key);
        }

        Ok(event_ids)
    }

    pub fn get_device_id(&self) -> &str {
        &self.device_id
    }

    pub fn get_user_pubkeys(&self) -> Vec<Pubkey> {
        self.user_records
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect()
    }

    pub fn get_total_sessions(&self) -> usize {
        self.user_records
            .lock()
            .unwrap()
            .values()
            .map(|ur| ur.device_records.values().filter(|dr| dr.active_session.is_some()).count())
            .sum()
    }

    pub fn get_our_pubkey(&self) -> Pubkey {
        self.our_public_key
    }

    fn device_invite_key(&self, device_id: &str) -> String {
        format!("device-invite/{}", device_id)
    }

    fn load_all_user_records(&self) -> Result<()> {
        Ok(())
    }

    fn store_user_record(&self, pubkey: &Pubkey) -> Result<()> {
        let user_records = self.user_records.lock().unwrap();
        if let Some(user_record) = user_records.get(pubkey) {
            let stored = user_record.to_stored();
            let key = format!("user/{}", hex::encode(pubkey.bytes()));
            let json = serde_json::to_string(&stored)?;
            self.storage.put(&key, json)?;
        }
        Ok(())
    }

    pub fn setup_user(&self, user_pubkey: Pubkey) -> Result<()> {
        let filter = Filter::new()
            .kinds(vec![crate::INVITE_EVENT_KIND as u64])
            .authors([user_pubkey.bytes()])
            .build();

        let filter_json = filter.json()?;
        self.event_tx.send(SessionManagerEvent::Subscribe(filter_json))
            .map_err(|_| crate::Error::Storage("Failed to send subscribe".to_string()))?;

        self.pending_invites.lock().unwrap().insert(user_pubkey, Invite {
            inviter_ephemeral_public_key: Pubkey::new([0u8; 32]),
            shared_secret: [0u8; 32],
            inviter: user_pubkey,
            inviter_ephemeral_private_key: None,
            device_id: None,
            max_uses: None,
            used_by: Vec::new(),
            created_at: 0,
        });

        Ok(())
    }

    pub fn process_received_event(&self, event: UnsignedEvent) {
        if event.kind.as_u16() == crate::INVITE_RESPONSE_KIND as u16 {
            if let Some(state) = self.invite_state.lock().unwrap().as_ref() {
                if let Ok(Some((sess, invitee_pubkey, device_id))) = state.invite.process_invite_response(&event, state.our_identity_key) {
                    if let Some(ref dev_id) = device_id {
                        if dev_id != &self.device_id {
                            let acceptance_key = format!("invite-accept/{}/{}", hex::encode(invitee_pubkey.bytes()), dev_id);
                            if self.storage.get(&acceptance_key).ok().flatten().is_none() {
                                let _ = self.storage.put(&acceptance_key, "1".to_string());

                                let mut records = self.user_records.lock().unwrap();
                                let user_record = records
                                    .entry(invitee_pubkey)
                                    .or_insert_with(|| UserRecord::new(hex::encode(invitee_pubkey.bytes())));
                                user_record.upsert_session(Some(dev_id), sess);
                                drop(records);

                                let _ = self.store_user_record(&invitee_pubkey);
                            }
                        }
                    }
                }
            }
        } else if event.kind.as_u16() == crate::INVITE_EVENT_KIND as u16 {
            if let Ok(invite) = Invite::from_event(&event) {
                if let Some(ref dev_id) = invite.device_id {
                    let inviter = invite.inviter;

                    // Check if we already have a session with this user/device
                    let mut records = self.user_records.lock().unwrap();
                    let user_record = records
                        .entry(inviter)
                        .or_insert_with(|| UserRecord::new(hex::encode(inviter.bytes())));

                    // Only accept if we don't already have a session for this device
                    if !user_record.device_records.contains_key(dev_id) {
                        drop(records);

                        match invite.accept(self.our_public_key, self.our_identity_key, Some(self.device_id.clone())) {
                            Ok((session, event)) => {
                                let _ = self.event_tx.send(SessionManagerEvent::Publish(event));

                                let mut records = self.user_records.lock().unwrap();
                                let user_record = records
                                    .entry(inviter)
                                    .or_insert_with(|| UserRecord::new(hex::encode(inviter.bytes())));
                                user_record.upsert_session(Some(dev_id), session);
                                drop(records);

                                let _ = self.store_user_record(&inviter);
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        } else if event.kind.as_u16() == crate::MESSAGE_EVENT_KIND as u16 {
            // Handle encrypted message
            // NOTE: event.pubkey is random (for privacy), so we must try all sessions
            let event_id = event.id.map(|id| id.to_string());
            let mut user_records = self.user_records.lock().unwrap();

            // Try to decrypt with ALL sessions (active + inactive) from all users
            for (user_pubkey, user_record) in user_records.iter_mut() {
                let mut all_sessions = user_record.get_all_sessions_mut();

                for session in all_sessions.iter_mut() {
                    if let Ok(Some(plaintext)) = session.receive(&event) {
                        // Message decrypted successfully - emit it
                        let sender = *user_pubkey;
                        drop(user_records);
                        let _ = self.event_tx.send(SessionManagerEvent::DecryptedMessage {
                            sender,
                            content: plaintext,
                            event_id,
                        });
                        let _ = self.store_user_record(&sender);
                        return;
                    }
                }
            }

            drop(user_records);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::Keys;

    #[test]
    fn test_session_manager_new() {
        let keys = Keys::generate();
        let pubkey = Pubkey::new(keys.public_key().to_bytes());
        let identity_key = keys.secret_key().to_secret_bytes();
        let device_id = "test-device".to_string();

        let (tx, _rx) = crossbeam_channel::unbounded();

        let manager = SessionManager::new(
            pubkey,
            identity_key,
            device_id.clone(),
            tx,
            None,
        );

        assert_eq!(manager.get_device_id(), device_id);
    }

    #[test]
    fn test_send_text_no_sessions() {
        let keys = Keys::generate();
        let pubkey = Pubkey::new(keys.public_key().to_bytes());
        let identity_key = keys.secret_key().to_secret_bytes();
        let device_id = "test-device".to_string();

        let (tx, _rx) = crossbeam_channel::unbounded();

        let manager = SessionManager::new(
            pubkey,
            identity_key,
            device_id,
            tx,
            None,
        );

        let recipient = Pubkey::new(Keys::generate().public_key().to_bytes());
        let result = manager.send_text(recipient, "test".to_string());

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
