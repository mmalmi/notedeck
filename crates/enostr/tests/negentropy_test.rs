use enostr::{NegentropyManager, NegentropySync};

#[test]
fn test_negentropy_sync_creation() {
    let mut sync = NegentropySync::new(12345);
    assert_eq!(sync.filter_hash(), 12345);
    assert!(!sync.is_sealed());
}

#[test]
fn test_negentropy_manager() {
    let mut manager = NegentropyManager::new();

    // Start a sync
    manager.start_sync("sub1".to_string(), 12345).unwrap();

    // Initiate sync (seal and create initial message)
    let init_msg = manager.initiate("sub1").unwrap();

    // Should have protocol version byte
    assert!(!init_msg.is_empty());
    assert_eq!(init_msg[0], 0x61); // Protocol version 1

    // Close sync
    manager.close_sync("sub1");
}

#[test]
fn test_negentropy_stale_cleanup() {
    let mut manager = NegentropyManager::new();

    manager.start_sync("sub1".to_string(), 123).unwrap();
    manager.start_sync("sub2".to_string(), 456).unwrap();

    // Cleanup should not remove fresh syncs
    manager.cleanup_stale();

    // Both should still exist (we can initiate them)
    assert!(manager.initiate("sub1").is_ok());
    assert!(manager.initiate("sub2").is_ok());
}
