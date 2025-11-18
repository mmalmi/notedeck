use crate::{Error, Result};
use negentropy::{Id, Negentropy as NegentropyCore, NegentropyStorageVector, Storage};
use nostrdb::Note;
use std::collections::HashMap;
use tracing::debug;

/// State of a negentropy sync session
#[derive(Debug)]
pub struct NegentropySync {
    storage: NegentropyStorageVector,
    filter_hash: u64,
    last_sync: std::time::Instant,
    sealed: bool,
}

impl NegentropySync {
    pub fn new(filter_hash: u64) -> Self {
        Self {
            storage: NegentropyStorageVector::new(),
            filter_hash,
            last_sync: std::time::Instant::now(),
            sealed: false,
        }
    }

    /// Add a note to the storage
    pub fn add_note(&mut self, note: &Note) -> Result<()> {
        let timestamp = note.created_at();
        let id_bytes = note.id();
        let id = Id::from_byte_array(*id_bytes);

        self.storage.insert(timestamp, id)
            .map_err(|e| Error::Generic(e.to_string()))?;
        Ok(())
    }

    /// Seal the storage
    pub fn seal(&mut self) -> Result<()> {
        if !self.sealed {
            self.storage.seal()
                .map_err(|e| Error::Generic(e.to_string()))?;
            self.sealed = true;
        }
        Ok(())
    }

    /// Check if sealed
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Initialize a negentropy sync
    pub fn initiate(&mut self) -> Result<Vec<u8>> {
        if !self.is_sealed() {
            self.seal()?;
        }

        let mut neg = NegentropyCore::owned(self.storage.clone(), 0)
            .map_err(|e| Error::Generic(e.to_string()))?;
        neg.initiate()
            .map_err(|e| Error::Generic(e.to_string()))
    }

    /// Reconcile with a message from the relay (client side)
    pub fn reconcile_client(&mut self, msg: &[u8]) -> Result<(Option<Vec<u8>>, Vec<String>, Vec<String>)> {
        if !self.is_sealed() {
            self.seal()?;
        }

        let storage = Storage::Borrowed(&self.storage);
        let mut neg = NegentropyCore::new(storage, 0)
            .map_err(|e| Error::Generic(e.to_string()))?;
        neg.set_initiator();

        let mut have_ids = Vec::new();
        let mut need_ids = Vec::new();
        let next_msg = neg.reconcile_with_ids(msg, &mut have_ids, &mut need_ids)
            .map_err(|e| Error::Generic(e.to_string()))?;

        self.last_sync = std::time::Instant::now();

        let have_hex: Vec<String> = have_ids.iter().map(|id| hex::encode(id.as_bytes())).collect();
        let need_hex: Vec<String> = need_ids.iter().map(|id| hex::encode(id.as_bytes())).collect();

        Ok((next_msg, have_hex, need_hex))
    }

    /// Check if this sync is stale (older than 5 minutes)
    pub fn is_stale(&self) -> bool {
        self.last_sync.elapsed() > std::time::Duration::from_secs(300)
    }

    /// Get filter hash
    pub fn filter_hash(&self) -> u64 {
        self.filter_hash
    }
}

/// Manager for negentropy sync sessions per relay
#[derive(Debug, Default)]
pub struct NegentropyManager {
    syncs: HashMap<String, NegentropySync>, // sub_id -> sync
}

impl NegentropyManager {
    pub fn new() -> Self {
        Self {
            syncs: HashMap::new(),
        }
    }

    /// Start a new sync for a subscription
    pub fn start_sync(&mut self, sub_id: String, filter_hash: u64) -> Result<()> {
        debug!("starting negentropy sync for sub {}", sub_id);
        self.syncs.insert(sub_id, NegentropySync::new(filter_hash));
        Ok(())
    }

    /// Add notes to a sync
    pub fn add_notes(&mut self, sub_id: &str, notes: &[Note]) -> Result<()> {
        if let Some(sync) = self.syncs.get_mut(sub_id) {
            for note in notes {
                sync.add_note(note)?;
            }
        }
        Ok(())
    }

    /// Initiate a sync
    pub fn initiate(&mut self, sub_id: &str) -> Result<Vec<u8>> {
        let sync = self.syncs.get_mut(sub_id)
            .ok_or_else(|| Error::Generic(format!("no sync for sub {}", sub_id)))?;
        sync.initiate()
    }

    /// Reconcile a sync (client side)
    pub fn reconcile(&mut self, sub_id: &str, msg: &[u8]) -> Result<(Option<Vec<u8>>, Vec<String>, Vec<String>)> {
        let sync = self.syncs.get_mut(sub_id)
            .ok_or_else(|| Error::Generic(format!("no sync for sub {}", sub_id)))?;
        sync.reconcile_client(msg)
    }

    /// Close a sync
    pub fn close_sync(&mut self, sub_id: &str) {
        debug!("closing negentropy sync for sub {}", sub_id);
        self.syncs.remove(sub_id);
    }

    /// Clean up stale syncs
    pub fn cleanup_stale(&mut self) {
        self.syncs.retain(|sub_id, sync| {
            if sync.is_stale() {
                debug!("removing stale negentropy sync for sub {}", sub_id);
                false
            } else {
                true
            }
        });
    }
}
