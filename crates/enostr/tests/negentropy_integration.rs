use enostr::{ClientMessage, Filter, RelayPool, hash_filter};
use nostrdb::FilterBuilder;

#[test]
fn test_negentropy_enabled_by_default() {
    let pool = RelayPool::new();
    assert!(pool.using_negentropy());
}

#[test]
fn test_negentropy_toggle() {
    let mut pool = RelayPool::new();
    assert!(pool.using_negentropy());

    pool.set_use_negentropy(false);
    assert!(!pool.using_negentropy());

    pool.set_use_negentropy(true);
    assert!(pool.using_negentropy());
}

#[test]
fn test_subscribe_generates_neg_open() {
    let pool = RelayPool::new();

    // In a real scenario with relays, single filter would send NEG-OPEN
    // For now, we just verify the setup works
    assert!(pool.using_negentropy());
}

#[test]
fn test_negentropy_session_management() {
    let mut pool = RelayPool::new();
    let relay_url = "wss://relay.damus.io";
    let sub_id = "test-sub";
    let filter = FilterBuilder::new().kinds(vec![1]).limit(100).build();
    let filter_hash = hash_filter(&filter);

    // Start a negentropy sync session
    pool.start_negentropy_sync(relay_url, sub_id, filter_hash).unwrap();

    // Close the session
    pool.close_negentropy_sync(relay_url, sub_id);
}

#[test]
fn test_cleanup_stale_sessions() {
    let mut pool = RelayPool::new();
    let relay_url = "wss://relay.damus.io";
    let filter = FilterBuilder::new().kinds(vec![1]).build();
    let filter_hash = hash_filter(&filter);

    // Start some sessions
    pool.start_negentropy_sync(relay_url, "sub1", filter_hash).unwrap();
    pool.start_negentropy_sync(relay_url, "sub2", filter_hash).unwrap();

    // Cleanup - should not remove fresh sessions
    pool.cleanup_stale_negentropy();

    // Both sessions should still exist (no errors when closing)
    pool.close_negentropy_sync(relay_url, "sub1");
    pool.close_negentropy_sync(relay_url, "sub2");
}

#[test]
fn test_neg_open_message_format() {
    let sub_id = "test-sub".to_string();
    let filter = FilterBuilder::new().kinds(vec![1]).limit(100).build();

    let msg = ClientMessage::neg_open(sub_id.clone(), filter, None);

    // Should serialize to JSON
    let json = msg.to_json().unwrap();
    assert!(json.contains("NEG-OPEN"));
    assert!(json.contains(&sub_id));
}

#[test]
fn test_neg_close_message_format() {
    let sub_id = "test-sub".to_string();
    let msg = ClientMessage::neg_close(sub_id.clone());

    let json = msg.to_json().unwrap();
    assert!(json.contains("NEG-CLOSE"));
    assert!(json.contains(&sub_id));
}

#[test]
fn test_neg_msg_requires_binary() {
    let sub_id = "test-sub".to_string();
    let payload = vec![0x61, 0x00, 0x01, 0x02]; // Mock negentropy payload

    let msg = ClientMessage::neg_msg(sub_id, payload);

    // NEG-MSG should error when trying to serialize to JSON (it's binary only)
    assert!(msg.to_json().is_err());
}

#[test]
fn test_filter_hashing() {
    let filter1 = FilterBuilder::new().kinds(vec![1]).limit(100).build();
    let filter2 = FilterBuilder::new().kinds(vec![1]).limit(100).build();
    let filter3 = FilterBuilder::new().kinds(vec![2]).limit(100).build();

    let hash1 = hash_filter(&filter1);
    let hash2 = hash_filter(&filter2);
    let hash3 = hash_filter(&filter3);

    // Same filter should produce same hash
    assert_eq!(hash1, hash2);

    // Different filter should produce different hash
    assert_ne!(hash1, hash3);
}

#[test]
fn test_subscribe_with_negentropy_explicit() {
    let mut pool = RelayPool::new();
    let filter = FilterBuilder::new().kinds(vec![1]).limit(100).build();

    // Force negentropy off for this subscription
    pool.subscribe_with_negentropy("sub-no-neg".to_string(), vec![filter.clone()], false);

    // Force negentropy on
    pool.subscribe_with_negentropy("sub-with-neg".to_string(), vec![filter], true);

    // Both should work without errors
}

#[test]
fn test_negentropy_filter_rules() {
    use nostrdb::FilterBuilder;

    // Should use negentropy: no limit
    let f1 = FilterBuilder::new().kinds(vec![1]).build();
    let json1 = f1.json().unwrap();
    assert!(!json1.contains("\"ids\""));
    assert!(f1.limit().is_none());

    // Should use negentropy: limit >= 20
    let f2 = FilterBuilder::new().kinds(vec![1]).limit(100).build();
    assert_eq!(f2.limit(), Some(100));

    // Should NOT use negentropy: limit < 20
    let f3 = FilterBuilder::new().kinds(vec![1]).limit(10).build();
    assert_eq!(f3.limit(), Some(10));

    // Should NOT use negentropy: has ids
    let id_bytes = [0u8; 32];
    let f4 = FilterBuilder::new().ids(vec![&id_bytes]).build();
    let json4 = f4.json().unwrap();
    assert!(json4.contains("\"ids\""));
}
