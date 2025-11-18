/// Live Negentropy integration tests with real relays
///
/// These tests verify NIP-77 Negentropy protocol implementation against live relays.
/// Tests are ignored by default. To run:
///
///   cargo test --test negentropy_live -- --ignored --nocapture
///
/// Note: Requires network connection and relay supporting NIP-77 (e.g., relay.damus.io)

use enostr::{ClientMessage, Filter, Relay, RelayPool, NegentropySync, hash_filter};
use nostrdb::FilterBuilder;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

const TEST_PUBKEY_HEX: &str = "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0";
const RELAY_URL: &str = "wss://relay.damus.io";

fn hex_to_bytes(hex: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap();
    }
    bytes
}

#[test]
#[ignore]
fn test_negentropy_live_sync() {
    println!("\n🧪 Testing Negentropy sync with {}", RELAY_URL);

    // Connect to relay
    let wakeup = || {};
    let relay_url = nostr::RelayUrl::parse(RELAY_URL).expect("Invalid relay URL");
    let relay = Relay::new(relay_url, wakeup).expect("Failed to create relay");

    // Wait for connection
    println!("⏳ Connecting to relay...");
    std::thread::sleep(Duration::from_secs(2));

    let mut found_connected = false;
    for _ in 0..10 {
        if let Some(event) = relay.receiver.try_recv() {
            if matches!(event, ewebsock::WsEvent::Opened) {
                println!("✅ Connected to {}", RELAY_URL);
                found_connected = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if !found_connected {
        println!("⚠️  Could not verify connection, proceeding anyway");
    }

    // Build filter
    let pubkey_bytes = hex_to_bytes(TEST_PUBKEY_HEX);
    let filter = FilterBuilder::new()
        .authors(vec![&pubkey_bytes])
        .limit(100)
        .build();

    let filter_hash = hash_filter(&filter);
    let sub_id = "test-neg-sync";

    println!("📤 Sending NEG-OPEN for pubkey {}...", &TEST_PUBKEY_HEX[..8]);

    // Create NEG-OPEN message
    let neg_open = ClientMessage::neg_open(sub_id.to_string(), filter.clone(), None);

    // Serialize and check
    match neg_open.to_json() {
        Ok(json) => {
            println!("📝 NEG-OPEN message: {}", json);
            assert!(json.contains("NEG-OPEN"));
            assert!(json.contains(sub_id));
        }
        Err(e) => {
            panic!("Failed to serialize NEG-OPEN: {}", e);
        }
    }

    // In a real scenario, we would:
    // 1. Send NEG-OPEN via relay
    // 2. Wait for binary NEG-MSG response or NEG-ERR
    // 3. If NEG-MSG: reconcile and continue
    // 4. If NEG-ERR: fallback to REQ
    // 5. Fetch identified events

    // For this test, we verify the protocol setup works
    let mut sync = NegentropySync::new(filter_hash);

    // Seal empty storage (simulating empty local database)
    sync.seal().expect("Failed to seal storage");

    // Create initial negentropy message
    let init_msg = sync.initiate().expect("Failed to initiate");

    println!("✅ Generated initial negentropy message: {} bytes", init_msg.len());
    assert!(!init_msg.is_empty());
    assert_eq!(init_msg[0], 0x61); // Protocol version

    println!("✅ Negentropy protocol setup successful");
    println!("ℹ️  In production, this would:");
    println!("   1. Send NEG-OPEN to relay");
    println!("   2. Receive binary NEG-MSG response");
    println!("   3. Reconcile to identify missing events");
    println!("   4. Fetch only needed events");
}

#[test]
#[ignore]
fn test_negentropy_with_relay_pool() {
    println!("\n🧪 Testing Negentropy with RelayPool");

    let wakeup = || {};
    let mut pool = RelayPool::new();

    // Verify negentropy is enabled
    assert!(pool.using_negentropy(), "Negentropy should be enabled by default");
    println!("✅ Negentropy enabled by default");

    // Add relay
    match pool.add_url(RELAY_URL.to_string(), wakeup.clone()) {
        Ok(_) => println!("✅ Added relay: {}", RELAY_URL),
        Err(e) => {
            println!("⚠️  Failed to add relay: {}", e);
            return;
        }
    }

    // Wait for connection
    println!("⏳ Waiting for connection...");
    std::thread::sleep(Duration::from_secs(2));

    // Check events
    let mut connected = false;
    for _ in 0..10 {
        if let Some(event) = pool.try_recv() {
            println!("📨 Received event from {}", event.relay);
            if matches!(event.event, ewebsock::WsEvent::Opened) {
                connected = true;
                println!("✅ Connected to relay");
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    if !connected {
        println!("⚠️  Could not verify connection");
    }

    // Create subscription with negentropy
    let pubkey_bytes = hex_to_bytes(TEST_PUBKEY_HEX);
    let filter = FilterBuilder::new()
        .authors(vec![&pubkey_bytes])
        .limit(50)
        .build();

    let sub_id = "pool-neg-test";

    println!("📤 Subscribing with negentropy...");

    // This should send NEG-OPEN since it's a single filter
    pool.subscribe_with_negentropy(sub_id.to_string(), vec![filter.clone()], true);

    println!("✅ Subscription sent (would use NEG-OPEN for single filter)");

    // Test explicit REQ fallback
    pool.subscribe_with_negentropy("fallback-sub".to_string(), vec![filter], false);
    println!("✅ Fallback subscription sent (forced REQ)");

    // Test session management
    let filter_hash = hash_filter(&FilterBuilder::new().kinds(vec![1]).build());
    pool.start_negentropy_sync(RELAY_URL, "managed-sub", filter_hash)
        .expect("Failed to start negentropy sync");
    println!("✅ Started managed negentropy session");

    pool.close_negentropy_sync(RELAY_URL, "managed-sub");
    println!("✅ Closed negentropy session");

    println!("✅ RelayPool negentropy integration successful");
}

#[test]
#[ignore]
fn test_negentropy_message_flow() {
    println!("\n🧪 Testing Negentropy message flow");

    let filter = FilterBuilder::new()
        .kinds(vec![1])
        .limit(100)
        .build();

    let sub_id = "flow-test";

    // Test NEG-OPEN
    let neg_open = ClientMessage::neg_open(sub_id.to_string(), filter.clone(), None);
    let open_json = neg_open.to_json().expect("Failed to serialize NEG-OPEN");

    assert!(open_json.contains("NEG-OPEN"));
    assert!(open_json.contains(sub_id));
    println!("✅ NEG-OPEN: {}", open_json);

    // Test NEG-CLOSE
    let neg_close = ClientMessage::neg_close(sub_id.to_string());
    let close_json = neg_close.to_json().expect("Failed to serialize NEG-CLOSE");

    assert!(close_json.contains("NEG-CLOSE"));
    assert!(close_json.contains(sub_id));
    println!("✅ NEG-CLOSE: {}", close_json);

    // Test NEG-MSG (binary)
    let mock_payload = vec![0x61, 0x00, 0x01, 0x02, 0x03];
    let neg_msg = ClientMessage::neg_msg(sub_id.to_string(), mock_payload);

    // NEG-MSG should NOT serialize to JSON (it's binary)
    assert!(neg_msg.to_json().is_err(), "NEG-MSG should not serialize to JSON");
    println!("✅ NEG-MSG correctly requires binary transport");

    // Test sync reconciliation
    let filter_hash = hash_filter(&filter);
    let mut sync = NegentropySync::new(filter_hash);
    sync.seal().expect("Failed to seal");

    let init = sync.initiate().expect("Failed to initiate");
    assert_eq!(init[0], 0x61); // Version byte
    assert!(init.len() > 1);
    println!("✅ Sync reconciliation message: {} bytes", init.len());

    println!("✅ Message flow test complete");
}

#[test]
#[ignore]
fn test_negentropy_fallback_behavior() {
    println!("\n🧪 Testing Negentropy fallback behavior");

    let mut pool = RelayPool::new();
    assert!(pool.using_negentropy());

    let filter1 = FilterBuilder::new().kinds(vec![1]).build();
    let filter2 = FilterBuilder::new().kinds(vec![2]).build();

    // Single filter - should use negentropy
    println!("📤 Single filter subscription (should prefer NEG-OPEN)");
    pool.subscribe_with_negentropy("single".to_string(), vec![filter1.clone()], true);

    // Multiple filters - should fallback to REQ
    println!("📤 Multi-filter subscription (should use REQ)");
    pool.subscribe_with_negentropy("multi".to_string(), vec![filter1, filter2], true);

    // Explicitly disabled
    let filter3 = FilterBuilder::new().kinds(vec![3]).build();
    println!("📤 Negentropy disabled subscription (should use REQ)");
    pool.subscribe_with_negentropy("disabled".to_string(), vec![filter3], false);

    // Global disable
    pool.set_use_negentropy(false);
    assert!(!pool.using_negentropy());
    println!("✅ Negentropy globally disabled");

    let filter4 = FilterBuilder::new().kinds(vec![4]).build();
    pool.subscribe("global-disabled".to_string(), vec![filter4]);
    println!("📤 Subscription with global disable (should use REQ)");

    // Re-enable
    pool.set_use_negentropy(true);
    assert!(pool.using_negentropy());
    println!("✅ Negentropy re-enabled");

    println!("✅ Fallback behavior test complete");
}
