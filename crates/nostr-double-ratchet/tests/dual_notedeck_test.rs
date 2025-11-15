use nostr_double_ratchet::{SessionManager, SessionManagerEvent};
use nostr::Keys;
use enostr::{Pubkey, RelayPool};
use nostrdb::{Config, Ndb};
use std::sync::Arc;
use std::time::Duration;
use std::thread;
use std::collections::{VecDeque, HashMap};

/// Test two SessionManagers with SEPARATE notedeck systems communicating through simulated relays.
/// This mirrors the actual UI scenario where each user has their own Ndb and RelayPool.
#[test]
fn test_two_separate_notedeck_systems_via_relay_bridge() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n=== Testing two separate Notedeck systems ===\n");

    // Create separate temp directories for each user's database
    let alice_tmp = tempfile::tempdir()?;
    let bob_tmp = tempfile::tempdir()?;
    let alice_db_path = alice_tmp.path().join("alice_db");
    let bob_db_path = bob_tmp.path().join("bob_db");

    // Alice's notedeck system
    let config = Config::new();
    let mut alice_ndb = Ndb::new(alice_db_path.to_str().unwrap(), &config).expect("alice ndb");
    let _alice_pool = RelayPool::new();

    // Bob's notedeck system
    let mut bob_ndb = Ndb::new(bob_db_path.to_str().unwrap(), &config).expect("bob ndb");
    let _bob_pool = RelayPool::new();

    // Simulated relay bridge - stores events and routes to subscribers
    let mut relay_event_store: Vec<nostr::Event> = Vec::new(); // All published events
    let mut relay_bridge: VecDeque<(String, nostr::Event)> = VecDeque::new(); // Pending delivery

    // Track active subscriptions per client
    let mut active_subscriptions: HashMap<String, Vec<String>> = HashMap::new(); // client -> Vec<filter_json>

    // Setup Alice's session manager
    let alice_keys = Keys::generate();
    let alice_pk = Pubkey::new(alice_keys.public_key().to_bytes());
    let alice_identity = alice_keys.secret_key().to_secret_bytes();

    let (alice_event_tx, alice_event_rx) = crossbeam_channel::unbounded::<SessionManagerEvent>();
    let alice_manager = Arc::new(SessionManager::new(
        alice_pk,
        alice_identity,
        "alice-device".to_string(),
        alice_event_tx.clone(),
        None,
    ));

    // Setup Bob's session manager
    let bob_keys = Keys::generate();
    let bob_pk = Pubkey::new(bob_keys.public_key().to_bytes());
    let bob_identity = bob_keys.secret_key().to_secret_bytes();

    let (bob_event_tx, bob_event_rx) = crossbeam_channel::unbounded::<SessionManagerEvent>();
    let bob_manager = Arc::new(SessionManager::new(
        bob_pk,
        bob_identity,
        "bob-device".to_string(),
        bob_event_tx.clone(),
        None,
    ));

    println!("Alice pubkey: {}", hex::encode(alice_pk.bytes()));
    println!("Bob pubkey: {}", hex::encode(bob_pk.bytes()));

    // Initialize both
    alice_manager.init()?;
    bob_manager.init()?;

    // Event processing function for separate systems
    fn process_events(
        manager: &Arc<SessionManager>,
        event_rx: &crossbeam_channel::Receiver<SessionManagerEvent>,
        ndb: &mut Ndb,
        keys: &Keys,
        relay_event_store: &mut Vec<nostr::Event>,
        relay_bridge: &mut VecDeque<(String, nostr::Event)>,
        active_subscriptions: &mut HashMap<String, Vec<String>>,
        label: &str,
    ) -> (usize, usize) {
        let mut published_count = 0;
        let mut decrypted_count = 0;

        while let Ok(event) = event_rx.try_recv() {
            match event {
                SessionManagerEvent::Publish(unsigned_event) => {
                    let kind = unsigned_event.kind.as_u16();
                    println!("{} publishing event kind {}", label, kind);

                    // Sign the event
                    if let Ok(secret_key) = nostr::SecretKey::from_slice(keys.secret_key().as_secret_bytes()) {
                        let signer_keys = nostr::Keys::new(secret_key);
                        if let Ok(signed) = unsigned_event.sign_with_keys(&signer_keys) {
                            use nostr::JsonUtil;
                            let json = signed.as_json();

                            // Process into own ndb
                            let _ = ndb.process_event(&json);

                            // Store in relay (simulates persistence)
                            relay_event_store.push(signed.clone());

                            // Publish to relay bridge for immediate delivery
                            relay_bridge.push_back((label.to_string(), signed.clone()));
                            println!("  → Sent to relay (now {} events stored)", relay_event_store.len());

                            published_count += 1;
                        }
                    }
                }
                SessionManagerEvent::Subscribe(filter_json) => {
                    println!("{} subscribing to: {}", label, filter_json);

                    // Store active subscription
                    active_subscriptions
                        .entry(label.to_string())
                        .or_insert_with(Vec::new)
                        .push(filter_json.clone());

                    // Parse filter to find matching historical events
                    if let Ok(filter) = nostrdb::Filter::from_json(&filter_json) {
                        // Check stored events against filter
                        let matching_events: Vec<_> = relay_event_store.iter()
                            .filter(|event| {
                                // Check kinds
                                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&filter_json) {
                                    if let Some(kinds) = value.get("kinds").and_then(|k| k.as_array()) {
                                        let kind_matches = kinds.iter().any(|k| k.as_u64() == Some(event.kind.as_u16() as u64));
                                        if !kind_matches {
                                            return false;
                                        }
                                    }

                                    // Check authors
                                    if let Some(authors) = value.get("authors").and_then(|a| a.as_array()) {
                                        let author_hex = hex::encode(event.pubkey.to_bytes());
                                        let author_matches = authors.iter().any(|a| a.as_str() == Some(&author_hex));
                                        if !author_matches {
                                            return false;
                                        }
                                    }
                                }
                                true
                            })
                            .cloned()
                            .collect();

                        if !matching_events.is_empty() {
                            println!("  → Found {} historical events matching subscription", matching_events.len());
                            // Deliver historical events TO THE SUBSCRIBER (not from them)
                            for event in matching_events {
                                relay_bridge.push_back((format!("relay-to-{}", label), event));
                            }
                        }
                    }
                }
                SessionManagerEvent::ReceivedEvent(unsigned_event) => {
                    println!("{} processing received event kind {}", label, unsigned_event.kind);
                    // ReceivedEvent contains UnsignedEvent but process_received_event expects Event
                    // Since we're in a test and events are already validated, we'll skip this path
                    // In production, events come signed from relays and are processed directly
                }
                SessionManagerEvent::PublishSigned(signed_event) => {
                    let kind = signed_event.kind.as_u16();
                    println!("{} publishing pre-signed event kind {}", label, kind);

                    use nostr::JsonUtil;
                    let json = signed_event.as_json();

                    // Process into ndb
                    let _ = ndb.process_event(&json);

                    // Store in relay
                    relay_event_store.push(signed_event.clone());

                    // Publish to relay bridge for delivery
                    relay_bridge.push_back((label.to_string(), signed_event));
                    println!("  → Sent to relay (now {} events stored)", relay_event_store.len());

                    published_count += 1;
                }
                SessionManagerEvent::DecryptedMessage { sender, content, event_id: _ } => {
                    println!("🔓 {} DECRYPTED: '{}' from {}",
                        label, content, hex::encode(sender.bytes())[..8].to_string());
                    decrypted_count += 1;
                }
                SessionManagerEvent::Unsubscribe(subid) => {
                    println!("{} unsubscribing from {}", label, subid);
                    // Remove from active subscriptions if needed
                }
            }
        }

        (published_count, decrypted_count)
    }

    // Check if an event matches any of the client's subscriptions
    fn event_matches_subscriptions(
        event: &nostr::Event,
        client_name: &str,
        active_subscriptions: &HashMap<String, Vec<String>>,
    ) -> bool {
        let Some(filters) = active_subscriptions.get(client_name) else {
            return false;
        };

        for filter_json in filters {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(filter_json) {
                // Check kinds
                if let Some(kinds) = value.get("kinds").and_then(|k| k.as_array()) {
                    let kind_matches = kinds.iter().any(|k| k.as_u64() == Some(event.kind.as_u16() as u64));
                    if !kind_matches {
                        continue; // Try next filter
                    }
                } else {
                    continue; // No kinds specified, try next filter
                }

                // Check authors if present
                if let Some(authors) = value.get("authors").and_then(|a| a.as_array()) {
                    let author_hex = hex::encode(event.pubkey.to_bytes());
                    let author_matches = authors.iter().any(|a| a.as_str() == Some(&author_hex));
                    if !author_matches {
                        continue; // Try next filter
                    }
                }

                // If we got here, this filter matches
                return true;
            }
        }

        false
    }

    // Process relay bridge - delivers messages from one system to the other
    fn process_relay_bridge(
        relay_bridge: &mut VecDeque<(String, nostr::Event)>,
        alice_manager: &Arc<SessionManager>,
        bob_manager: &Arc<SessionManager>,
        alice_ndb: &mut Ndb,
        bob_ndb: &mut Ndb,
        alice_pk: Pubkey,
        bob_pk: Pubkey,
        active_subscriptions: &HashMap<String, Vec<String>>,
    ) {
        while let Some((origin, signed_event)) = relay_bridge.pop_front() {
            use nostr::JsonUtil;
            let event_json = signed_event.as_json();
            let kind = signed_event.kind.as_u16();

            println!("  Relay bridge: routing kind {} (origin: {})", kind, origin);

            // Determine delivery based on origin
            if origin == "relay-to-Alice" {
                // Subscription response for Alice
                let _ = alice_ndb.process_event(&event_json);
                if kind == 30078 || kind == 1059 || kind == 1060 {
                    alice_manager.process_received_event(signed_event.clone());
                }
            } else if origin == "relay-to-Bob" {
                // Subscription response for Bob
                let _ = bob_ndb.process_event(&event_json);
                if kind == 30078 || kind == 1059 || kind == 1060 {
                    bob_manager.process_received_event(signed_event.clone());
                }
            } else if origin == "Alice" {
                // Alice published, check if Bob has subscription match before delivering
                if event_matches_subscriptions(&signed_event, "Bob", active_subscriptions) {
                    println!("    → Bob has matching subscription, delivering");
                    let _ = bob_ndb.process_event(&event_json);
                    if kind == 30078 || kind == 1059 || kind == 1060 {
                        bob_manager.process_received_event(signed_event.clone());
                    }
                } else {
                    let author_hex = hex::encode(signed_event.pubkey.to_bytes());
                    println!("    → No matching subscription for Bob (message author: {}), dropping", &author_hex[..16]);
                    if let Some(bob_subs) = active_subscriptions.get("Bob") {
                        println!("       Bob's subscriptions: {} active", bob_subs.len());
                        for sub in bob_subs {
                            if sub.contains("1060") {
                                println!("       kind 1060 sub: {}", sub);
                            }
                        }
                    }
                }
            } else if origin == "Bob" {
                // Bob published, check if Alice has subscription match before delivering
                if event_matches_subscriptions(&signed_event, "Alice", active_subscriptions) {
                    println!("    → Alice has matching subscription, delivering");
                    let _ = alice_ndb.process_event(&event_json);
                    if kind == 30078 || kind == 1059 || kind == 1060 {
                        alice_manager.process_received_event(signed_event.clone());
                    }
                } else {
                    let author_hex = hex::encode(signed_event.pubkey.to_bytes());
                    println!("    → No matching subscription for Alice (message author: {}), dropping", &author_hex[..16]);
                    if let Some(alice_subs) = active_subscriptions.get("Alice") {
                        println!("       Alice's subscriptions: {} active", alice_subs.len());
                        for sub in alice_subs {
                            if sub.contains("1060") {
                                println!("       kind 1060 sub: {}", sub);
                            }
                        }
                    }
                }
            }
        }
    }

    // Track stats
    let mut alice_published = 0;
    let mut alice_decrypted = 0;
    let mut bob_published = 0;
    let mut bob_decrypted = 0;

    // Initial setup
    println!("\n=== Initial setup ===");
    let (a_pub, a_dec) = process_events(
        &alice_manager,
        &alice_event_rx,
        &mut alice_ndb,
        &alice_keys,
        &mut relay_event_store,
        &mut relay_bridge,
        &mut active_subscriptions,
        "Alice",
    );
    alice_published += a_pub;
    alice_decrypted += a_dec;

    let (b_pub, b_dec) = process_events(
        &bob_manager,
        &bob_event_rx,
        &mut bob_ndb,
        &bob_keys,
        &mut relay_event_store,
        &mut relay_bridge,
        &mut active_subscriptions,
        "Bob",
    );
    bob_published += b_pub;
    bob_decrypted += b_dec;

    // Process relay bridge
    process_relay_bridge(&mut relay_bridge, &alice_manager, &bob_manager,
                        &mut alice_ndb, &mut bob_ndb, alice_pk, bob_pk, &active_subscriptions);

    // Setup users
    println!("\n=== Setting up peer discovery ===");
    alice_manager.setup_user(bob_pk)?;
    bob_manager.setup_user(alice_pk)?;

    let (a_pub, a_dec) = process_events(
        &alice_manager,
        &alice_event_rx,
        &mut alice_ndb,
        &alice_keys,
        &mut relay_event_store,
        &mut relay_bridge,
        &mut active_subscriptions,
        "Alice",
    );
    alice_published += a_pub;
    alice_decrypted += a_dec;

    let (b_pub, b_dec) = process_events(
        &bob_manager,
        &bob_event_rx,
        &mut bob_ndb,
        &bob_keys,
        &mut relay_event_store,
        &mut relay_bridge,
        &mut active_subscriptions,
        "Bob",
    );
    bob_published += b_pub;
    bob_decrypted += b_dec;

    process_relay_bridge(&mut relay_bridge, &alice_manager, &bob_manager,
                        &mut alice_ndb, &mut bob_ndb, alice_pk, bob_pk, &active_subscriptions);

    // Handshake rounds
    println!("\n=== Handshake negotiation ===");
    for round in 0..15 {
        let (a_pub, a_dec) = process_events(
            &alice_manager,
            &alice_event_rx,
            &mut alice_ndb,
            &alice_keys,
            &mut relay_event_store,
            &mut relay_bridge,
            &mut active_subscriptions,
            "Alice",
        );
        alice_published += a_pub;
        alice_decrypted += a_dec;

        let (b_pub, b_dec) = process_events(
            &bob_manager,
            &bob_event_rx,
            &mut bob_ndb,
            &bob_keys,
            &mut relay_event_store,
            &mut relay_bridge,
            &mut active_subscriptions,
            "Bob",
        );
        bob_published += b_pub;
        bob_decrypted += b_dec;

        process_relay_bridge(&mut relay_bridge, &alice_manager, &bob_manager,
                            &mut alice_ndb, &mut bob_ndb, alice_pk, bob_pk, &active_subscriptions);

        if a_pub == 0 && b_pub == 0 && relay_bridge.is_empty() {
            println!("Handshake complete after {} rounds", round + 1);
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    // Check session state
    println!("\n=== Session state ===");
    println!("Alice: {} users, {} sessions",
        alice_manager.get_user_pubkeys().len(),
        alice_manager.get_total_sessions());
    println!("Bob: {} users, {} sessions",
        bob_manager.get_user_pubkeys().len(),
        bob_manager.get_total_sessions());

    // Send messages
    println!("\n=== Sending messages ===");

    // Debug: show actual session keys
    println!("Alice's session keys:");
    println!("{}", alice_manager.debug_session_keys());
    println!("Bob's session keys:");
    println!("{}", bob_manager.debug_session_keys());

    let bob_msg_ids = bob_manager.send_text(alice_pk, "Hello Alice from Bob!".to_string())?;
    println!("Bob sent message: {:?}", bob_msg_ids);

    // Process Bob's outgoing
    let (b_pub, b_dec) = process_events(
        &bob_manager,
        &bob_event_rx,
        &mut bob_ndb,
        &bob_keys,
        &mut relay_event_store,
        &mut relay_bridge,
        &mut active_subscriptions,
        "Bob",
    );
    bob_published += b_pub;
    bob_decrypted += b_dec;

    // Deliver to Alice
    process_relay_bridge(&mut relay_bridge, &alice_manager, &bob_manager,
                        &mut alice_ndb, &mut bob_ndb, alice_pk, bob_pk, &active_subscriptions);

    // Process Alice's incoming
    let (a_pub, a_dec) = process_events(
        &alice_manager,
        &alice_event_rx,
        &mut alice_ndb,
        &alice_keys,
        &mut relay_event_store,
        &mut relay_bridge,
        &mut active_subscriptions,
        "Alice",
    );
    alice_published += a_pub;
    alice_decrypted += a_dec;

    // Alice replies
    let alice_msg_ids = alice_manager.send_text(bob_pk, "Hi Bob from Alice!".to_string())?;
    println!("Alice sent reply: {:?}", alice_msg_ids);

    // Process Alice's outgoing
    let (a_pub, a_dec) = process_events(
        &alice_manager,
        &alice_event_rx,
        &mut alice_ndb,
        &alice_keys,
        &mut relay_event_store,
        &mut relay_bridge,
        &mut active_subscriptions,
        "Alice",
    );
    alice_published += a_pub;
    alice_decrypted += a_dec;

    // Deliver to Bob
    process_relay_bridge(&mut relay_bridge, &alice_manager, &bob_manager,
                        &mut alice_ndb, &mut bob_ndb, alice_pk, bob_pk, &active_subscriptions);

    // Process Bob's incoming
    let (b_pub, b_dec) = process_events(
        &bob_manager,
        &bob_event_rx,
        &mut bob_ndb,
        &bob_keys,
        &mut relay_event_store,
        &mut relay_bridge,
        &mut active_subscriptions,
        "Bob",
    );
    bob_published += b_pub;
    bob_decrypted += b_dec;

    // Final processing rounds - may need multiple rounds for decryption
    println!("\n=== Final message processing ===");
    for round in 0..20 {
        let (a_pub, a_dec) = process_events(
            &alice_manager,
            &alice_event_rx,
            &mut alice_ndb,
            &alice_keys,
            &mut relay_event_store,
            &mut relay_bridge,
            &mut active_subscriptions,
            "Alice",
        );
        alice_published += a_pub;
        alice_decrypted += a_dec;

        let (b_pub, b_dec) = process_events(
            &bob_manager,
            &bob_event_rx,
            &mut bob_ndb,
            &bob_keys,
            &mut relay_event_store,
            &mut relay_bridge,
            &mut active_subscriptions,
            "Bob",
        );
        bob_published += b_pub;
        bob_decrypted += b_dec;

        process_relay_bridge(&mut relay_bridge, &alice_manager, &bob_manager,
                            &mut alice_ndb, &mut bob_ndb, alice_pk, bob_pk, &active_subscriptions);

        if a_pub == 0 && b_pub == 0 && relay_bridge.is_empty() {
            println!("No more events after {} rounds", round + 1);
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    // Results
    println!("\n=== Test results ===");
    println!("Alice: published={}, decrypted={}", alice_published, alice_decrypted);
    println!("Bob: published={}, decrypted={}", bob_published, bob_decrypted);

    // Assertions
    assert!(alice_published > 0, "Alice should publish events");
    assert!(bob_published > 0, "Bob should publish events");
    assert_eq!(alice_decrypted, 1, "Alice should decrypt Bob's message");
    assert_eq!(bob_decrypted, 1, "Bob should decrypt Alice's message");

    println!("\n✅ Test passed - separate Notedeck systems communicated successfully!\n");

    Ok(())
}
