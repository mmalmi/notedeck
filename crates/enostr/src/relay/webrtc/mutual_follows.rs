use nostrdb::{Ndb, Transaction};
use std::collections::HashSet;

/// Helper for detecting mutual follows using nostrdb socialgraph
/// This implementation uses nostrdb's built-in socialgraph API for efficiency
pub struct MutualFollowDetector {
    ndb: Ndb,
}

impl MutualFollowDetector {
    pub fn new(ndb: Ndb) -> Self {
        Self { ndb }
    }

    /// Check if two pubkeys are mutual follows
    /// Returns true if pubkey1 follows pubkey2 AND pubkey2 follows pubkey1
    pub fn are_mutual_follows(&self, txn: &Transaction, pubkey1: &[u8; 32], pubkey2: &[u8; 32]) -> bool {
        // Use socialgraph API to get follows efficiently
        let followed_by_1 = nostrdb::socialgraph::get_followed(txn, &self.ndb, pubkey1, 10000);
        let followed_by_1_set: HashSet<[u8; 32]> = followed_by_1.into_iter().collect();

        let followed_by_2 = nostrdb::socialgraph::get_followed(txn, &self.ndb, pubkey2, 10000);
        let followed_by_2_set: HashSet<[u8; 32]> = followed_by_2.into_iter().collect();

        followed_by_1_set.contains(pubkey2) && followed_by_2_set.contains(pubkey1)
    }

    /// Get all mutual follows for a given pubkey
    /// Uses nostrdb socialgraph API for efficient intersection
    ///
    /// Includes self-connections to allow syncing between multiple
    /// instances/devices running with the same key
    pub fn get_mutual_follows(&self, txn: &Transaction, pubkey: &[u8; 32]) -> Vec<[u8; 32]> {
        // Get people we follow
        let followed = nostrdb::socialgraph::get_followed(txn, &self.ndb, pubkey, 10000);

        // Get people who follow us
        let followers = nostrdb::socialgraph::get_followers(txn, &self.ndb, pubkey, 10000);

        // Find intersection - people we follow who also follow us back
        let followed_set: HashSet<[u8; 32]> = followed.into_iter().collect();
        let mut mutual_follows: Vec<[u8; 32]> = followers
            .into_iter()
            .filter(|pk| followed_set.contains(pk))
            .collect();

        // Include self for connecting to other instances/devices
        // This allows you to sync data between multiple devices using the same key
        mutual_follows.push(*pubkey);

        mutual_follows
    }

    /// Get follow distance between two pubkeys
    /// Uses nostrdb's built-in socialgraph distance calculation
    /// Returns None if no path exists, Some(distance) otherwise
    /// Distance 0 = same pubkey, 1 = direct follow, 2 = follow of follow, etc.
    pub fn get_follow_distance(&self, txn: &Transaction, from: &[u8; 32], to: &[u8; 32]) -> Option<usize> {
        if from == to {
            return Some(0);
        }

        // Use nostrdb's built-in follow distance calculation
        let distance = nostrdb::socialgraph::get_follow_distance(txn, &self.ndb, to);

        // nostrdb returns 0 for no connection, 1 for direct follow, 2 for follow-of-follow, etc.
        // We need to return None for no connection, Some(1) for direct follow, etc.
        if distance == 0 {
            None
        } else {
            Some(distance as usize)
        }
    }

    /// Check if a pubkey should be connected via WebRTC
    /// Criteria:
    /// - Self-connections always allowed (for device-to-device sync)
    /// - Must be mutual follows (bidirectional)
    /// - Follow distance <= 2
    pub fn should_connect(&self, txn: &Transaction, our_pubkey: &[u8; 32], peer_pubkey: &[u8; 32]) -> bool {
        // Always allow self-connections (other instances/devices)
        if our_pubkey == peer_pubkey {
            return true;
        }

        // Check if mutual follows
        if !self.are_mutual_follows(txn, our_pubkey, peer_pubkey) {
            return false;
        }

        // Check follow distance
        if let Some(distance) = self.get_follow_distance(txn, our_pubkey, peer_pubkey) {
            if distance <= 2 {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests would require a mock Ndb instance
    // For now, they're placeholders to show the intended API
}
