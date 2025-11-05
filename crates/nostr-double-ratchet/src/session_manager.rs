use crate::{
    InMemoryStorage, Invite, Result, StorageAdapter, Unsubscribe, UserRecord,
};
use enostr::{Filter, Pubkey};
use nostr::UnsignedEvent;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type NostrSubscribe = Arc<
    dyn Fn(Filter, Box<dyn Fn(UnsignedEvent) + Send>) -> Unsubscribe + Send + Sync,
>;
type NostrPublish = Arc<dyn Fn(UnsignedEvent) -> Result<()> + Send + Sync>;

pub struct SessionManager {
    user_records: Arc<Mutex<HashMap<Pubkey, UserRecord>>>,
    our_public_key: Pubkey,
    our_identity_key: [u8; 32],
    device_id: String,
    storage: Arc<dyn StorageAdapter>,
    nostr_subscribe: NostrSubscribe,
    nostr_publish: NostrPublish,
    our_device_invite_subscription: Arc<Mutex<Option<Unsubscribe>>>,
    invite_subscriptions: Arc<Mutex<HashMap<String, Unsubscribe>>>,
    session_subscriptions: Arc<Mutex<HashMap<String, Unsubscribe>>>,
    initialized: Arc<Mutex<bool>>,
}

impl SessionManager {
    pub fn new<S, P>(
        our_public_key: Pubkey,
        our_identity_key: [u8; 32],
        device_id: String,
        nostr_subscribe: S,
        nostr_publish: P,
        storage: Option<Arc<dyn StorageAdapter>>,
    ) -> Self
    where
        S: Fn(Filter, Box<dyn Fn(UnsignedEvent) + Send>) -> Unsubscribe + Send + Sync + 'static,
        P: Fn(UnsignedEvent) -> Result<()> + Send + Sync + 'static,
    {
        Self {
            user_records: Arc::new(Mutex::new(HashMap::new())),
            our_public_key,
            our_identity_key,
            device_id,
            storage: storage.unwrap_or_else(|| Arc::new(InMemoryStorage::new())),
            nostr_subscribe: Arc::new(nostr_subscribe),
            nostr_publish: Arc::new(nostr_publish),
            our_device_invite_subscription: Arc::new(Mutex::new(None)),
            invite_subscriptions: Arc::new(Mutex::new(HashMap::new())),
            session_subscriptions: Arc::new(Mutex::new(HashMap::new())),
            initialized: Arc::new(Mutex::new(false)),
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

        let nostr_subscribe = self.nostr_subscribe.clone();
        let our_identity_key = self.our_identity_key;
        let device_id = self.device_id.clone();
        let storage = self.storage.clone();
        let user_records = self.user_records.clone();

        let unsub = invite.listen(
            our_identity_key,
            move |filter, callback| nostr_subscribe(filter, callback),
            move |session, invitee_pubkey, device_id_opt| {
                if let Some(dev_id) = device_id_opt {
                    if dev_id == device_id {
                        return;
                    }

                    let acceptance_key = format!("invite-accept/{}/{}", hex::encode(invitee_pubkey.bytes()), dev_id);
                    if storage.get(&acceptance_key).ok().flatten().is_some() {
                        return;
                    }

                    let _ = storage.put(&acceptance_key, "1".to_string());

                    let mut records = user_records.lock().unwrap();
                    let user_record = records
                        .entry(invitee_pubkey)
                        .or_insert_with(|| UserRecord::new(hex::encode(invitee_pubkey.bytes())));
                    user_record.upsert_session(Some(&dev_id), session);
                }
            },
        )?;

        *self.our_device_invite_subscription.lock().unwrap() = Some(unsub);

        let event = invite.get_event()?;
        (self.nostr_publish)(event)?;

        Ok(())
    }

    pub fn send_text(&self, recipient: Pubkey, text: String) -> Result<Vec<String>> {
        let mut user_records = self.user_records.lock().unwrap();
        let user_record = user_records
            .entry(recipient)
            .or_insert_with(|| UserRecord::new(hex::encode(recipient.bytes())));

        let active_sessions = user_record.get_active_sessions_mut();

        if active_sessions.is_empty() {
            return Ok(vec![]);
        }

        let mut event_ids = Vec::new();

        for session in active_sessions {
            match session.send(text.clone()) {
                Ok(unsigned_event) => {
                    if let Some(id) = unsigned_event.id {
                        event_ids.push(id.to_string());
                    }
                    let _ = (self.nostr_publish)(unsigned_event);
                }
                Err(_) => continue,
            }
        }

        drop(user_records);
        let _ = self.store_user_record(&recipient);

        Ok(event_ids)
    }

    pub fn get_device_id(&self) -> &str {
        &self.device_id
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
        let nostr_subscribe = self.nostr_subscribe.clone();
        let user_records = self.user_records.clone();
        let our_public_key = self.our_public_key;
        let our_identity_key = self.our_identity_key;
        let device_id = self.device_id.clone();
        let nostr_publish = self.nostr_publish.clone();

        let _unsub = Invite::from_user(
            user_pubkey,
            move |filter, callback| nostr_subscribe(filter, callback),
            move |invite| {
                if let Some(ref dev_id) = invite.device_id {
                    let mut records = user_records.lock().unwrap();
                    let user_record = records
                        .entry(user_pubkey)
                        .or_insert_with(|| UserRecord::new(hex::encode(user_pubkey.bytes())));

                    if user_record.device_records.contains_key(dev_id) {
                        return;
                    }

                    drop(records);

                    match invite.accept(our_public_key, our_identity_key, Some(device_id.clone())) {
                        Ok((session, event)) => {
                            let _ = nostr_publish(event);

                            let mut records = user_records.lock().unwrap();
                            let user_record = records
                                .entry(user_pubkey)
                                .or_insert_with(|| UserRecord::new(hex::encode(user_pubkey.bytes())));
                            user_record.upsert_session(Some(dev_id), session);
                        }
                        Err(_) => {}
                    }
                }
            },
        );

        Ok(())
    }

    pub fn close(&self) {
        if let Some(unsub) = self.our_device_invite_subscription.lock().unwrap().take() {
            unsub();
        }

        let invite_subs = std::mem::take(&mut *self.invite_subscriptions.lock().unwrap());
        for (_, unsub) in invite_subs {
            unsub();
        }

        let session_subs = std::mem::take(&mut *self.session_subscriptions.lock().unwrap());
        for (_, unsub) in session_subs {
            unsub();
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

        let subscribe = |_filter: Filter, _callback: Box<dyn Fn(UnsignedEvent) + Send>| {
            Box::new(|| {}) as Unsubscribe
        };

        let publish = |_event: UnsignedEvent| Ok(());

        let manager = SessionManager::new(
            pubkey,
            identity_key,
            device_id.clone(),
            subscribe,
            publish,
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

        let subscribe = |_filter: Filter, _callback: Box<dyn Fn(UnsignedEvent) + Send>| {
            Box::new(|| {}) as Unsubscribe
        };

        let publish = |_event: UnsignedEvent| Ok(());

        let manager = SessionManager::new(
            pubkey,
            identity_key,
            device_id,
            subscribe,
            publish,
            None,
        );

        let recipient = Pubkey::new(Keys::generate().public_key().to_bytes());
        let result = manager.send_text(recipient, "test".to_string());

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
