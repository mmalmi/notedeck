use std::collections::HashMap;
use std::sync::RwLock;

pub type UID = u64;

pub struct UniqueIds {
    str_to_id: RwLock<HashMap<String, UID>>,
    id_to_str: RwLock<HashMap<UID, String>>,
    current_id: RwLock<UID>,
}

impl UniqueIds {
    pub fn new() -> Self {
        Self {
            str_to_id: RwLock::new(HashMap::new()),
            id_to_str: RwLock::new(HashMap::new()),
            current_id: RwLock::new(0),
        }
    }

    pub fn id(&self, s: &str) -> Option<UID> {
        self.str_to_id.read().unwrap().get(s).copied()
    }

    pub fn get_or_create_id(&self, s: &str) -> Result<UID, crate::error::SocialGraphError> {
        if let Some(id) = self.id(s) {
            return Ok(id);
        }

        let new_id = {
            let mut current = self.current_id.write().unwrap();
            let id = *current;
            *current += 1;
            id
        };

        {
            let mut str_map = self.str_to_id.write().unwrap();
            if let Some(&existing_id) = str_map.get(s) {
                return Ok(existing_id);
            }
            str_map.insert(s.to_string(), new_id);
        }

        {
            let mut id_map = self.id_to_str.write().unwrap();
            id_map.insert(new_id, s.to_string());
        }

        Ok(new_id)
    }

    pub fn str(&self, id: UID) -> Result<String, crate::error::SocialGraphError> {
        self.id_to_str.read().unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| crate::error::SocialGraphError::NotFound(format!("UID {}", id)))
    }
}

impl Default for UniqueIds {
    fn default() -> Self {
        Self::new()
    }
}
