use crate::{InMemoryStorage, Result, StorageAdapter, UserRecord};
use enostr::Pubkey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct SessionManager {
    user_records: Arc<Mutex<HashMap<Pubkey, UserRecord>>>,
    our_identity_key: [u8; 32],
    device_id: String,
    storage: Arc<dyn StorageAdapter>,
}

impl SessionManager {
    pub fn new(
        our_identity_key: [u8; 32],
        device_id: String,
        storage: Option<Arc<dyn StorageAdapter>>,
    ) -> Self {
        Self {
            user_records: Arc::new(Mutex::new(HashMap::new())),
            our_identity_key,
            device_id,
            storage: storage.unwrap_or_else(|| Arc::new(InMemoryStorage::new())),
        }
    }

    pub fn send_text(&self, _recipient: Pubkey, _text: String) -> Result<Vec<String>> {
        Ok(vec![])
    }

    pub fn get_device_id(&self) -> &str {
        &self.device_id
    }
}
