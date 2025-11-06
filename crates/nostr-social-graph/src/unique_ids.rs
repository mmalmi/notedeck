use std::collections::HashMap;
use std::sync::RwLock;

pub type UID = u64;

pub struct UniqueIds {
    bytes_to_id: RwLock<HashMap<[u8; 32], UID>>,
    id_to_bytes: RwLock<HashMap<UID, [u8; 32]>>,
    current_id: RwLock<UID>,
}

impl UniqueIds {
    pub fn new() -> Self {
        Self {
            bytes_to_id: RwLock::new(HashMap::new()),
            id_to_bytes: RwLock::new(HashMap::new()),
            current_id: RwLock::new(0),
        }
    }

    pub fn id(&self, pk: &[u8; 32]) -> Option<UID> {
        self.bytes_to_id.read().unwrap().get(pk).copied()
    }

    pub fn get_or_create_id(&self, pk: &[u8; 32]) -> Result<UID, crate::error::SocialGraphError> {
        if let Some(id) = self.id(pk) {
            return Ok(id);
        }

        let new_id = {
            let mut current = self.current_id.write().unwrap();
            let id = *current;
            *current += 1;
            id
        };

        {
            let mut bytes_map = self.bytes_to_id.write().unwrap();
            if let Some(&existing_id) = bytes_map.get(pk) {
                return Ok(existing_id);
            }
            bytes_map.insert(*pk, new_id);
        }

        {
            let mut id_map = self.id_to_bytes.write().unwrap();
            id_map.insert(new_id, *pk);
        }

        Ok(new_id)
    }

    pub fn bytes(&self, id: UID) -> Result<[u8; 32], crate::error::SocialGraphError> {
        self.id_to_bytes.read().unwrap()
            .get(&id)
            .copied()
            .ok_or_else(|| crate::error::SocialGraphError::NotFound(format!("UID {}", id)))
    }
}

impl Default for UniqueIds {
    fn default() -> Self {
        Self::new()
    }
}
