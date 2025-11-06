use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use crate::unique_ids::{UniqueIds, UID};
use crate::error::SocialGraphError;
use log::debug;

pub struct SocialGraph {
    root: RwLock<UID>,
    follow_distance_by_user: RwLock<HashMap<UID, u32>>,
    followed_by_user: RwLock<HashMap<UID, HashSet<UID>>>,
    followers_by_user: RwLock<HashMap<UID, HashSet<UID>>>,
    follow_list_created_at: RwLock<HashMap<UID, u64>>,
    muted_by_user: RwLock<HashMap<UID, HashSet<UID>>>,
    user_muted_by: RwLock<HashMap<UID, HashSet<UID>>>,
    mute_list_created_at: RwLock<HashMap<UID, u64>>,
    users_by_follow_distance: RwLock<HashMap<u32, HashSet<UID>>>,
    ids: UniqueIds,
}

impl SocialGraph {
    pub fn new(root: &str) -> Result<Self, SocialGraphError> {
        let ids = UniqueIds::new();
        let root_id = ids.get_or_create_id(root)?;

        let mut follow_distance = HashMap::new();
        follow_distance.insert(root_id, 0);

        let mut users_by_distance = HashMap::new();
        let mut root_set = HashSet::new();
        root_set.insert(root_id);
        users_by_distance.insert(0, root_set);

        Ok(Self {
            root: RwLock::new(root_id),
            follow_distance_by_user: RwLock::new(follow_distance),
            followed_by_user: RwLock::new(HashMap::new()),
            followers_by_user: RwLock::new(HashMap::new()),
            follow_list_created_at: RwLock::new(HashMap::new()),
            muted_by_user: RwLock::new(HashMap::new()),
            user_muted_by: RwLock::new(HashMap::new()),
            mute_list_created_at: RwLock::new(HashMap::new()),
            users_by_follow_distance: RwLock::new(users_by_distance),
            ids,
        })
    }

    pub fn get_root(&self) -> Result<String, SocialGraphError> {
        let root = *self.root.read().unwrap();
        self.ids.str(root)
    }

    pub fn set_root(&self, root: &str) -> Result<(), SocialGraphError> {
        let root_id = self.ids.get_or_create_id(root)?;
        *self.root.write().unwrap() = root_id;
        self.recalculate_follow_distances()?;
        Ok(())
    }

    pub fn recalculate_follow_distances(&self) -> Result<(), SocialGraphError> {
        let root = *self.root.read().unwrap();
        let mut distances: HashMap<UID, u32> = HashMap::new();
        let mut users_by_distance: HashMap<u32, HashSet<UID>> = HashMap::new();

        distances.insert(root, 0);
        users_by_distance.entry(0).or_default().insert(root);

        let mut queue = VecDeque::new();
        queue.push_back(root);

        let followed = self.followed_by_user.read().unwrap();
        while let Some(user) = queue.pop_front() {
            let distance = distances[&user];
            if let Some(followed_users) = followed.get(&user) {
                for &followed_id in followed_users.iter() {
                    if !distances.contains_key(&followed_id) {
                        let new_distance = distance + 1;
                        distances.insert(followed_id, new_distance);
                        users_by_distance.entry(new_distance).or_default().insert(followed_id);
                        queue.push_back(followed_id);
                    }
                }
            }
        }

        *self.follow_distance_by_user.write().unwrap() = distances;
        *self.users_by_follow_distance.write().unwrap() = users_by_distance;
        Ok(())
    }

    pub fn handle_contact_list(&self, pubkey: &str, tags: &[(String, Vec<String>)], created_at: u64) -> Result<(), SocialGraphError> {
        let author = self.ids.get_or_create_id(pubkey)?;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if created_at > (current_time + 10 * 60) {
            return Ok(());
        }

        {
            let created_at_map = self.follow_list_created_at.read().unwrap();
            if let Some(&existing_created_at) = created_at_map.get(&author) {
                if created_at <= existing_created_at {
                    return Ok(());
                }
            }
        }

        let mut followed_in_event = HashSet::new();
        for (tag_name, values) in tags {
            if tag_name == "p" {
                if let Some(pubkey) = values.first() {
                    if pubkey.len() == 64 && pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
                        let followed_user = self.ids.get_or_create_id(pubkey)?;
                        if followed_user != author {
                            followed_in_event.insert(followed_user);
                        }
                    }
                }
            }
        }

        let current_follows = {
            let followed = self.followed_by_user.read().unwrap();
            followed.get(&author).cloned().unwrap_or_default()
        };

        if current_follows == followed_in_event {
            return Ok(());
        }

        {
            let mut created_at_map = self.follow_list_created_at.write().unwrap();
            created_at_map.insert(author, created_at);
        }

        {
            let mut followers = self.followers_by_user.write().unwrap();
            for unfollowed in current_follows.difference(&followed_in_event) {
                if let Some(follower_set) = followers.get_mut(unfollowed) {
                    follower_set.remove(&author);
                    if follower_set.is_empty() {
                        followers.remove(unfollowed);
                    }
                }
            }

            for &followed in followed_in_event.difference(&current_follows) {
                followers.entry(followed).or_default().insert(author);
            }
        }

        {
            let mut followed = self.followed_by_user.write().unwrap();
            if !followed_in_event.is_empty() {
                followed.insert(author, followed_in_event);
            } else {
                followed.remove(&author);
            }
        }

        self.recalculate_follow_distances()?;
        Ok(())
    }

    pub fn handle_mute_list(&self, pubkey: &str, tags: &[(String, Vec<String>)], created_at: u64) -> Result<(), SocialGraphError> {
        let author = self.ids.get_or_create_id(pubkey)?;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if created_at > (current_time + 10 * 60) {
            return Ok(());
        }

        {
            let created_at_map = self.mute_list_created_at.read().unwrap();
            if let Some(&existing_created_at) = created_at_map.get(&author) {
                if created_at <= existing_created_at {
                    return Ok(());
                }
            }
        }

        let mut muted_in_event = HashSet::new();
        for (tag_name, values) in tags {
            if tag_name == "p" {
                if let Some(pubkey) = values.first() {
                    if pubkey.len() == 64 && pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
                        let muted_user = self.ids.get_or_create_id(pubkey)?;
                        if muted_user != author {
                            muted_in_event.insert(muted_user);
                        }
                    }
                }
            }
        }

        let currently_muted = {
            let muted = self.muted_by_user.read().unwrap();
            muted.get(&author).cloned().unwrap_or_default()
        };

        {
            let mut created_at_map = self.mute_list_created_at.write().unwrap();
            created_at_map.insert(author, created_at);
        }

        {
            let mut muted_by = self.muted_by_user.write().unwrap();
            let mut user_muted = self.user_muted_by.write().unwrap();

            for unmuted in currently_muted.difference(&muted_in_event) {
                if let Some(muter_set) = muted_by.get_mut(&author) {
                    muter_set.remove(unmuted);
                }
                if let Some(mutee_set) = user_muted.get_mut(unmuted) {
                    mutee_set.remove(&author);
                }
            }

            for &muted in muted_in_event.iter() {
                muted_by.entry(author).or_default().insert(muted);
                user_muted.entry(muted).or_default().insert(author);
            }
        }

        Ok(())
    }

    pub fn is_following(&self, follower: &str, followed_user: &str) -> Result<bool, SocialGraphError> {
        let followed_user_id = match self.ids.id(followed_user) {
            Some(id) => id,
            None => return Ok(false),
        };
        let follower_id = match self.ids.id(follower) {
            Some(id) => id,
            None => return Ok(false),
        };

        let followed = self.followed_by_user.read().unwrap();
        Ok(followed.get(&follower_id)
            .map(|set| set.contains(&followed_user_id))
            .unwrap_or(false))
    }

    pub fn get_follow_distance(&self, user: &str) -> Result<u32, SocialGraphError> {
        let user_id = match self.ids.id(user) {
            Some(id) => id,
            None => return Ok(1000),
        };

        let distances = self.follow_distance_by_user.read().unwrap();
        Ok(distances.get(&user_id).copied().unwrap_or(1000))
    }

    pub fn follower_count(&self, address: &str) -> Result<usize, SocialGraphError> {
        let id = match self.ids.id(address) {
            Some(id) => id,
            None => return Ok(0),
        };

        let followers = self.followers_by_user.read().unwrap();
        Ok(followers.get(&id).map_or(0, |s| s.len()))
    }

    pub fn followed_by_friends_count(&self, address: &str) -> Result<usize, SocialGraphError> {
        let id = match self.ids.id(address) {
            Some(id) => id,
            None => return Ok(0),
        };

        let followers = self.followers_by_user.read().unwrap();
        let followed = self.followed_by_user.read().unwrap();

        let root = *self.root.read().unwrap();
        let count = if let Some(follower_set) = followers.get(&id) {
            if let Some(root_follows) = followed.get(&root) {
                follower_set.iter()
                    .filter(|&follower| root_follows.contains(follower))
                    .count()
            } else {
                0
            }
        } else {
            0
        };

        Ok(count)
    }

    pub fn followed_by_friends(&self, address: &str) -> Result<HashSet<String>, SocialGraphError> {
        let id = match self.ids.id(address) {
            Some(id) => id,
            None => return Ok(HashSet::new()),
        };

        let root = *self.root.read().unwrap();
        let mut set = HashSet::new();
        let followers = self.followers_by_user.read().unwrap();
        let followed = self.followed_by_user.read().unwrap();

        if let Some(follower_set) = followers.get(&id) {
            if let Some(root_follows) = followed.get(&root) {
                for &follower in follower_set {
                    if root_follows.contains(&follower) {
                        if let Ok(str_id) = self.ids.str(follower) {
                            set.insert(str_id);
                        }
                    }
                }
            }
        }

        Ok(set)
    }

    pub fn get_followed_by_user(&self, user: &str, include_self: bool) -> Result<HashSet<String>, SocialGraphError> {
        let user_id = match self.ids.id(user) {
            Some(id) => id,
            None => return Ok(HashSet::new()),
        };

        let mut set = HashSet::new();
        let followed = self.followed_by_user.read().unwrap();

        if let Some(followed_set) = followed.get(&user_id) {
            for &id in followed_set {
                if let Ok(str_id) = self.ids.str(id) {
                    set.insert(str_id);
                }
            }
        }

        if include_self {
            set.insert(user.to_string());
        }
        Ok(set)
    }

    pub fn get_followers_by_user(&self, address: &str) -> Result<HashSet<String>, SocialGraphError> {
        let user_id = match self.ids.id(address) {
            Some(id) => id,
            None => return Ok(HashSet::new()),
        };

        let mut set = HashSet::new();
        let followers = self.followers_by_user.read().unwrap();

        if let Some(follower_set) = followers.get(&user_id) {
            for &id in follower_set {
                if let Ok(str_id) = self.ids.str(id) {
                    set.insert(str_id);
                }
            }
        }
        Ok(set)
    }

    pub fn get_users_by_follow_distance(&self, distance: u32) -> Result<HashSet<String>, SocialGraphError> {
        let mut result = HashSet::new();
        let users_by_distance = self.users_by_follow_distance.read().unwrap();

        if let Some(users) = users_by_distance.get(&distance) {
            for &user_id in users {
                if let Ok(str_id) = self.ids.str(user_id) {
                    result.insert(str_id);
                }
            }
        }

        Ok(result)
    }

    pub fn is_muted(&self, muter: &str, muted_user: &str) -> Result<bool, SocialGraphError> {
        let muted_user_id = match self.ids.id(muted_user) {
            Some(id) => id,
            None => return Ok(false),
        };
        let muter_id = match self.ids.id(muter) {
            Some(id) => id,
            None => return Ok(false),
        };

        let muted_by = self.muted_by_user.read().unwrap();
        Ok(muted_by.get(&muter_id)
            .map(|set| set.contains(&muted_user_id))
            .unwrap_or(false))
    }

    pub fn muted_by_friends_count(&self, address: &str) -> Result<usize, SocialGraphError> {
        let id = match self.ids.id(address) {
            Some(id) => id,
            None => return Ok(0),
        };

        let root = *self.root.read().unwrap();
        let user_muted = self.user_muted_by.read().unwrap();
        let followed = self.followed_by_user.read().unwrap();

        let count = if let Some(muter_set) = user_muted.get(&id) {
            if let Some(root_follows) = followed.get(&root) {
                muter_set.iter()
                    .filter(|&muter| root_follows.contains(muter))
                    .count()
            } else {
                0
            }
        } else {
            0
        };

        Ok(count)
    }

    pub fn get_muted_by_user(&self, user: &str) -> Result<HashSet<String>, SocialGraphError> {
        let user_id = match self.ids.id(user) {
            Some(id) => id,
            None => return Ok(HashSet::new()),
        };

        let mut set = HashSet::new();
        let muted_by = self.muted_by_user.read().unwrap();

        if let Some(muted_set) = muted_by.get(&user_id) {
            for &id in muted_set {
                if let Ok(str_id) = self.ids.str(id) {
                    set.insert(str_id);
                }
            }
        }

        Ok(set)
    }

    pub fn size(&self) -> (usize, usize, usize) {
        let distances = self.follow_distance_by_user.read().unwrap();
        let followed = self.followed_by_user.read().unwrap();
        let muted = self.muted_by_user.read().unwrap();

        let follows: usize = followed.values().map(|s| s.len()).sum();
        let mutes: usize = muted.values().map(|s| s.len()).sum();

        (distances.len(), follows, mutes)
    }

    pub fn populate_from_ndb(&self, ndb: &nostrdb::Ndb, txn: &nostrdb::Transaction) -> Result<(), SocialGraphError> {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), SocialGraphError> {

            let contact_filter = nostrdb::Filter::new()
                .kinds(vec![3])
                .build();

            let mute_filter = nostrdb::Filter::new()
                .kinds(vec![10000])
                .build();

            let filters = vec![contact_filter, mute_filter];
            let results = ndb.query(txn, &filters, 100000)
                .map_err(|e| SocialGraphError::Serialization(e.to_string()))?;

            debug!("Populating social graph from {} events", results.len());

            let root_hex = {
                let root_id = *self.root.read().unwrap();
                self.ids.str(root_id).ok()
            };

            // Process root's contact list first
            if let Some(root_pk) = &root_hex {
                for result in &results {
                    if let Ok(note) = ndb.get_note_by_key(txn, result.note_key) {
                        let pubkey = hex::encode(note.pubkey());
                        if &pubkey == root_pk && note.kind() == 3 {
                            let mut tags = Vec::new();
                            for tag in note.tags().iter() {
                                if tag.count() < 2 {
                                    continue;
                                }
                                if let Some("p") = tag.get_str(0) {
                                    if let Some(pk_bytes) = tag.get_id(1) {
                                        let pk_hex = hex::encode(pk_bytes);
                                        tags.push(("p".to_string(), vec![pk_hex]));
                                    }
                                }
                            }
                            debug!("Processing root contact list with {} p tags", tags.len());
                            if let Err(e) = self.handle_contact_list(&pubkey, &tags, note.created_at()) {
                                debug!("Error processing root contact list: {:?}", e);
                            }
                            break;
                        }
                    }
                }
            }

            // Process all other events
            for result in results {
                if let Ok(note) = ndb.get_note_by_key(txn, result.note_key) {
                    let pubkey = hex::encode(note.pubkey());
                    let created_at = note.created_at();
                    let kind = note.kind();

                    // Skip root's contact list (already processed)
                    if let Some(root_pk) = &root_hex {
                        if &pubkey == root_pk && kind == 3 {
                            continue;
                        }
                    }

                    let mut tags = Vec::new();
                    for tag in note.tags().iter() {
                        if tag.count() >= 2 {
                            if let Some("p") = tag.get_str(0) {
                                if let Some(pk_bytes) = tag.get_id(1) {
                                    let pk_hex = hex::encode(pk_bytes);
                                    tags.push(("p".to_string(), vec![pk_hex]));
                                }
                            }
                        }
                    }

                    if kind == 3 {
                        if let Err(e) = self.handle_contact_list(&pubkey, &tags, created_at) {
                            debug!("Error processing contact list for {}: {:?}", &pubkey[..8], e);
                        }
                    } else if kind == 10000 {
                        if let Err(e) = self.handle_mute_list(&pubkey, &tags, created_at) {
                            debug!("Error processing mute list for {}: {:?}", &pubkey[..8], e);
                        }
                    }
                }
            }

            let (users, follows, mutes) = self.size();
            debug!("Social graph populated: {} users, {} follows, {} mutes", users, follows, mutes);
            Ok(())
        }));

        match result {
            Ok(r) => r,
            Err(_) => {
                debug!("Panic during social graph population");
                Err(SocialGraphError::Serialization("Panic during population".to_string()))
            }
        }
    }
}
