/// Dual instance test with REAL multicast
///
/// Tests 2 instances communicating over real UDP multicast:
/// - Both join multicast group 239.19.88.1:9797
/// - SO_REUSEPORT allows both to bind same port
/// - Instance A sends event
/// - Both instances receive via multicast (including A via loopback)
/// - Proves real multicast works for dual instances
use enostr::RelayPool;
use std::thread;
use std::time::Duration;

#[test]
fn test_dual_instance_real_multicast() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Dual Instance Real Multicast Test ===\n");

    // Instance A
    let mut pool_a = RelayPool::new();
    let wakeup_a = || {};
    pool_a.add_multicast_relay(wakeup_a)?;
    println!("[A] Joined multicast (with SO_REUSEPORT)");

    // Instance B
    let mut pool_b = RelayPool::new();
    let wakeup_b = || {};
    pool_b.add_multicast_relay(wakeup_b)?;
    println!("[B] Joined multicast (with SO_REUSEPORT)\n");

    // Wait for setup
    thread::sleep(Duration::from_millis(200));

    // A sends event
    use enostr::ClientMessage;
    let event_json = r#"{"id":"dual_test_001","pubkey":"deadbeef","created_at":1234567890,"kind":1,"tags":[],"content":"dual instance test","sig":"cafebabe"}"#;
    let msg = ClientMessage::event_json(event_json.to_string())?;
    pool_a.send(&msg);
    println!("[A] Sent event to multicast\n");

    // Wait for multicast delivery
    thread::sleep(Duration::from_millis(300));

    // Poll both instances
    let mut a_count = 0;
    let mut b_count = 0;
    let mut b_found_test_event = false;

    for round in 0..5 {
        // Instance A polls
        while let Some(pool_event) = pool_a.try_recv() {
            use ewebsock::{WsEvent, WsMessage};
            if let WsEvent::Message(WsMessage::Text(ref text)) = pool_event.event {
                println!("[A] Received from {}: {}...", pool_event.relay, &text[..60.min(text.len())]);
                a_count += 1;
            }
        }

        // Instance B polls
        while let Some(pool_event) = pool_b.try_recv() {
            use ewebsock::{WsEvent, WsMessage};
            if let WsEvent::Message(WsMessage::Text(ref text)) = pool_event.event {
                println!("[B] Received from {}: {}...", pool_event.relay, &text[..60.min(text.len())]);

                if text.contains("dual instance test") {
                    println!("  ✓ Found test event!");
                    b_found_test_event = true;
                }

                b_count += 1;
            }
        }

        thread::sleep(Duration::from_millis(100));
    }

    println!("\n=== Results ===");
    println!("[A] Received: {} messages", a_count);
    println!("[B] Received: {} messages", b_count);
    println!("[B] Found test event: {}", b_found_test_event);

    // Assertions
    assert!(a_count > 0, "Instance A should receive own event via loopback");
    assert!(b_count > 0, "Instance B should receive event from A");
    assert!(b_found_test_event, "Instance B should receive the test event content");

    println!("\n✅ Real dual-instance multicast works!\n");
    println!("What this proves:");
    println!("  - SO_REUSEPORT allows 2 instances on same port");
    println!("  - Both instances join multicast group 239.19.88.1:9797");
    println!("  - Events broadcast via real UDP multicast");
    println!("  - Both instances receive (including loopback)");
    println!("  - No mocks - actual network stack");

    Ok(())
}
