use nostrdb::Filter;
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Simple hash of a filter for tracking negentropy sessions
pub fn hash_filter(filter: &Filter) -> u64 {
    let mut hasher = DefaultHasher::new();

    // Hash filter JSON representation for uniqueness
    if let Ok(json) = filter.json() {
        json.hash(&mut hasher);
    }

    hasher.finish()
}

/// Hash multiple filters
pub fn hash_filters(filters: &[Filter]) -> u64 {
    let mut hasher = DefaultHasher::new();

    for filter in filters {
        if let Ok(json) = filter.json() {
            json.hash(&mut hasher);
        }
    }

    hasher.finish()
}

/// SHA256 hash for cryptographic requirements (e.g., subscription IDs)
pub fn sha256_filter(filter: &Filter) -> Option<[u8; 32]> {
    let json = filter.json().ok()?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Some(hasher.finalize().into())
}
