use enostr::Pubkey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const MESSAGE_EVENT_KIND: u32 = 1060;
pub const INVITE_EVENT_KIND: u32 = 30078;
pub const INVITE_RESPONSE_KIND: u32 = 1059;
pub const CHAT_MESSAGE_KIND: u32 = 14;
pub const MAX_SKIP: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub number: u32,
    pub previous_chain_length: u32,
    pub next_public_key: String,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_key: Pubkey,
    pub private_key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    #[serde(with = "serde_bytes_array")]
    pub root_key: [u8; 32],

    pub their_current_nostr_public_key: Option<Pubkey>,
    pub their_next_nostr_public_key: Option<Pubkey>,

    pub our_current_nostr_key: Option<SerializableKeyPair>,
    pub our_next_nostr_key: SerializableKeyPair,

    #[serde(with = "serde_option_bytes_array", default)]
    pub receiving_chain_key: Option<[u8; 32]>,

    #[serde(with = "serde_option_bytes_array", default)]
    pub sending_chain_key: Option<[u8; 32]>,

    pub sending_chain_message_number: u32,
    pub receiving_chain_message_number: u32,
    pub previous_sending_chain_message_count: u32,

    pub skipped_keys: HashMap<Pubkey, SkippedKeysEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableKeyPair {
    pub public_key: Pubkey,
    #[serde(with = "serde_bytes_array")]
    pub private_key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedKeysEntry {
    #[serde(with = "serde_vec_bytes_array")]
    pub header_keys: Vec<[u8; 32]>,

    #[serde(with = "serde_hashmap_u32_bytes")]
    pub message_keys: HashMap<u32, [u8; 32]>,
}

pub type Unsubscribe = Box<dyn FnOnce() + Send>;

pub type EventCallback = Box<dyn Fn(nostrdb::Note, nostrdb::Note) + Send>;

mod serde_bytes_array {
    use serde::{Deserialize, Deserializer, Serializer};
    use hex;

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}

mod serde_option_bytes_array {
    use serde::{Deserialize, Deserializer, Serializer};
    use hex;

    pub fn serialize<S>(bytes: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_str(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                Ok(Some(array))
            }
            None => Ok(None),
        }
    }
}

mod serde_vec_bytes_array {
    use serde::{Deserialize, Deserializer, Serializer};
    use hex;

    pub fn serialize<S>(vec: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for bytes in vec {
            seq.serialize_element(&hex::encode(bytes))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<String> = Vec::deserialize(deserializer)?;
        vec.into_iter()
            .map(|s| {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                Ok(array)
            })
            .collect()
    }
}

mod serde_hashmap_u32_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::collections::HashMap;
    use hex;

    pub fn serialize<S>(map: &HashMap<u32, [u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map_serializer = serializer.serialize_map(Some(map.len()))?;
        for (k, v) in map {
            map_serializer.serialize_entry(k, &hex::encode(v))?;
        }
        map_serializer.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<u32, [u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: HashMap<u32, String> = HashMap::deserialize(deserializer)?;
        map.into_iter()
            .map(|(k, v)| {
                let bytes = hex::decode(&v).map_err(serde::de::Error::custom)?;
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                Ok((k, array))
            })
            .collect()
    }
}
