//! Real relay integration test for double-ratchet messaging
//!
//! Tests two users (Alice and Bob) exchanging encrypted DMs through
//! wss://relay.damus.io using nostrdb + enostr + nostr-double-ratchet.
//!
//! Run with: cargo test -p nostr-double-ratchet --test real_relay_test -- --nocapture

use nostr_double_ratchet::{SessionManager, SessionEvent};
use nostr_double_ratchet::pubsub::test_utils::SessionEventReceiver;
use nostr::{Keys, JsonUtil};
use enostr::{Pubkey, RelayPool, RelayMessage, ClientMessage, Filter as EnostrFilter};
use enostr::ewebsock::{WsEvent, WsMessage};
use nostrdb::{Config, Ndb};
use std::sync::Arc;
use std::collections::HashMap;

const REAL_RELAY: &str = "wss://temp.iris.to";

/// Process session manager events - sign, publish to relay, track subscriptions
fn process_session_events(
    event_receiver: &SessionEventReceiver,
    pool: &mut RelayPool,
    ndb: &mut Ndb,
    keys: &Keys,
    subscriptions: &mut HashMap<String, String>,
    label: &str,
) -> (usize, usize) {
    let mut published_count = 0;
    let mut decrypted_count = 0;

    while let Some(event) = event_receiver.try_recv() {
        match event {
            SessionEvent::Publish(unsigned_event) => {
                let kind = unsigned_event.kind.as_u16();
                println!("[{}] Publishing event kind {}", label, kind);

                let json_str = unsigned_event.as_json();
                let is_signed = json_str.contains("\"sig\":");

                let signed = if is_signed {
                    nostr::Event::from_json(&json_str).ok()
                } else {
                    if let Ok(secret_key) = nostr::SecretKey::from_slice(keys.secret_key().as_secret_bytes()) {
                        let signer_keys = nostr::Keys::new(secret_key);
                        unsigned_event.sign_with_keys(&signer_keys).ok()
                    } else {
                        None
                    }
                };

                if let Some(signed) = signed {
                    if signed.verify().is_err() {
                        eprintln!("[{}] Event signature INVALID for kind {}", label, kind);
                        continue;
                    }

                    let signed_json = signed.as_json();
                    if let Ok(msg) = ClientMessage::event_json(signed_json.clone()) {
                        pool.send(&msg);
                    }
                    let _ = ndb.process_event(&signed_json);
                    published_count += 1;
                    println!("[{}] Sent kind {} to relay", label, kind);
                }
            }
            SessionEvent::PublishSigned(signed_event) => {
                let kind = signed_event.kind.as_u16();
                let author = hex::encode(signed_event.pubkey.to_bytes());
                println!("[{}] Publishing pre-signed event kind {} from author {}", label, kind, &author[..16]);

                let signed_json = signed_event.as_json();
                if let Ok(msg) = ClientMessage::event_json(signed_json.clone()) {
                    pool.send(&msg);
                }
                let _ = ndb.process_event(&signed_json);
                published_count += 1;
            }
            SessionEvent::Subscribe(filter_json) => {
                if let Ok(filter_val) = serde_json::from_str::<serde_json::Value>(&filter_json) {
                    // Build enostr filter directly from JSON
                    let mut enostr_filter = EnostrFilter::new();

                    if let Some(kinds) = filter_val["kinds"].as_array() {
                        let kinds_u64: Vec<u64> = kinds.iter().filter_map(|k| k.as_u64()).collect();
                        enostr_filter = enostr_filter.kinds(kinds_u64.clone());

                        // Debug: show full filter for kind 1060
                        if kinds_u64.contains(&1060) {
                            println!("[{}] Subscribing to kinds: {:?} with filter: {}", label, kinds_u64, filter_json);
                        } else {
                            println!("[{}] Subscribing to kinds: {:?}", label, kinds_u64);
                        }
                    }

                    if let Some(authors) = filter_val["authors"].as_array() {
                        let author_bytes: Vec<[u8; 32]> = authors.iter()
                            .filter_map(|a| {
                                let hex_str = a.as_str()?;
                                hex::decode(hex_str).ok().and_then(|bytes| {
                                    if bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        Some(arr)
                                    } else {
                                        None
                                    }
                                })
                            })
                            .collect();
                        let author_refs: Vec<&[u8; 32]> = author_bytes.iter().collect();
                        enostr_filter = enostr_filter.authors(author_refs);
                    }

                    if let Some(p_tags) = filter_val["#p"].as_array() {
                        let p_bytes: Vec<[u8; 32]> = p_tags.iter()
                            .filter_map(|p| {
                                let hex_str = p.as_str()?;
                                hex::decode(hex_str).ok().and_then(|bytes| {
                                    if bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        Some(arr)
                                    } else {
                                        None
                                    }
                                })
                            })
                            .collect();
                        let p_refs: Vec<&[u8; 32]> = p_bytes.iter().collect();
                        enostr_filter = enostr_filter.pubkeys(p_refs);
                    }

                    let filter = enostr_filter.build();
                    let sub_id = format!("{}-{}", label.to_lowercase(), uuid::Uuid::new_v4());
                    let msg = ClientMessage::req(sub_id.clone(), vec![filter]);
                    pool.send(&msg);
                    subscriptions.insert(sub_id.clone(), filter_json.clone());
                    println!("[{}] Created subscription: {}", label, &sub_id[..20]);
                }
            }
            SessionEvent::DecryptedMessage { sender, content, event_id } => {
                println!("[{}] DECRYPTED from {}: '{}' (event: {:?})",
                    label, &hex::encode(sender.bytes())[..16], &content[..content.len().min(80)], event_id);
                decrypted_count += 1;
            }
            SessionEvent::Unsubscribe(sub_id) => {
                println!("[{}] Unsubscribing: {}", label, sub_id);
            }
            SessionEvent::ReceivedEvent(_) => {}
        }
    }

    (published_count, decrypted_count)
}

/// Poll relay for events and route to appropriate session manager
fn poll_relay_events(
    pool: &mut RelayPool,
    ndb: &mut Ndb,
    alice_manager: &Arc<SessionManager>,
    bob_manager: &Arc<SessionManager>,
    alice_pk: &Pubkey,
    bob_pk: &Pubkey,
) -> usize {
    let mut received = 0;

    while let Some(pool_event) = pool.try_recv() {
        if let WsEvent::Message(WsMessage::Text(relay_msg_str)) = pool_event.event {
            if let Ok(relay_msg) = RelayMessage::from_json(&relay_msg_str) {
                match relay_msg {
                    RelayMessage::Event(_subid, ev) => {
                        if let Ok(event) = nostr::Event::from_json(&ev) {
                            let kind = event.kind.as_u16();
                            received += 1;

                            // Process into ndb
                            let _ = ndb.process_event(&ev);

                            let author = hex::encode(event.pubkey.to_bytes());

                            // Route events carefully to avoid both sides accepting invites
                            if kind == 30078 {
                                // Kind 30078 (invite): only route to the party who subscribed
                                // Alice subscribed to Bob's invites, so only Alice should process Bob's invites
                                let is_from_bob = author == hex::encode(bob_pk.bytes());
                                println!("  Received kind {} from {}, routing to {}", kind, &author[..16],
                                    if is_from_bob { "Alice" } else { "Bob" });
                                if is_from_bob {
                                    alice_manager.process_received_event(event.clone());
                                } else {
                                    // Bob shouldn't process Alice's invite - he's the inviter
                                    // (but we need to process our own invite to set up invite_state)
                                    bob_manager.process_received_event(event.clone());
                                }
                            } else if kind == 1059 {
                                // Kind 1059 (invite response): route to both, they'll decrypt what's for them
                                println!("  Received kind {} from {}, routing to both", kind, &author[..16]);
                                alice_manager.process_received_event(event.clone());
                                bob_manager.process_received_event(event.clone());
                            } else if kind == 1060 {
                                // Kind 1060 (message): route to both, they'll decrypt what's for them
                                println!("  Received kind {} from {}, routing to both", kind, &author[..16]);
                                alice_manager.process_received_event(event.clone());
                                bob_manager.process_received_event(event.clone());
                            }
                        }
                    }
                    RelayMessage::OK(result) => {
                        println!("Relay OK: {:?}", result);
                    }
                    RelayMessage::Notice(msg) => {
                        println!("Relay notice: {}", msg);
                    }
                    _ => {}
                }
            }
        }
    }

    received
}

/// Full integration test using real relay (wss://relay.damus.io)
#[tokio::test]
async fn test_two_users_real_relay() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n============================================================");
    println!("  Double Ratchet Real Relay Test");
    println!("  Relay: {}", REAL_RELAY);
    println!("============================================================\n");

    // Create shared database (like the working test)
    let tmp_dir = tempfile::tempdir()?;
    let db_path = tmp_dir.path().join("test_db");

    let config = Config::new();
    let mut ndb = Ndb::new(db_path.to_str().unwrap(), &config)?;

    // Create separate relay pools (each user has their own connection)
    let mut alice_pool = RelayPool::new();
    let mut bob_pool = RelayPool::new();

    println!("Connecting to {}...", REAL_RELAY);
    let wakeup = || {};
    alice_pool.add_url(REAL_RELAY.to_string(), wakeup)?;
    bob_pool.add_url(REAL_RELAY.to_string(), wakeup)?;

    // Wait for connections
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Generate fresh keys for this test
    let alice_keys = Keys::generate();
    let bob_keys = Keys::generate();

    let alice_pk = Pubkey::new(alice_keys.public_key().to_bytes());
    let bob_pk = Pubkey::new(bob_keys.public_key().to_bytes());

    println!("\nTest participants:");
    println!("  Alice: {}...", &hex::encode(alice_pk.bytes())[..16]);
    println!("  Bob:   {}...", &hex::encode(bob_pk.bytes())[..16]);

    // Create session managers
    let (alice_event_tx, alice_event_rx) = crossbeam_channel::unbounded();
    let alice_receiver = SessionEventReceiver::new(alice_event_rx);
    let alice_manager = Arc::new(SessionManager::new(
        alice_pk,
        alice_keys.secret_key().to_secret_bytes(),
        format!("alice-test-{}", uuid::Uuid::new_v4()),
        alice_event_tx,
        None,
    ));

    let (bob_event_tx, bob_event_rx) = crossbeam_channel::unbounded();
    let bob_receiver = SessionEventReceiver::new(bob_event_rx);
    let bob_manager = Arc::new(SessionManager::new(
        bob_pk,
        bob_keys.secret_key().to_secret_bytes(),
        format!("bob-test-{}", uuid::Uuid::new_v4()),
        bob_event_tx,
        None,
    ));

    let mut alice_subs: HashMap<String, String> = HashMap::new();
    let mut bob_subs: HashMap<String, String> = HashMap::new();

    // Track stats
    let mut alice_published = 0;
    let mut alice_decrypted = 0;
    let mut bob_published = 0;
    let mut bob_decrypted = 0;

    // Initialize both managers (publishes invites)
    println!("\nInitializing session managers...");
    alice_manager.init()?;
    bob_manager.init()?;

    // Process initial events (invites)
    let (a_pub, a_dec) = process_session_events(
        &alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice"
    );
    alice_published += a_pub;
    alice_decrypted += a_dec;

    let (b_pub, b_dec) = process_session_events(
        &bob_receiver, &mut bob_pool, &mut ndb, &bob_keys, &mut bob_subs, "Bob"
    );
    bob_published += b_pub;
    bob_decrypted += b_dec;

    // Alice sets up to discover Bob (subscribes to his invite)
    println!("\nAlice discovering Bob...");
    alice_manager.setup_user(bob_pk)?;

    let (a_pub, a_dec) = process_session_events(
        &alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice"
    );
    alice_published += a_pub;
    alice_decrypted += a_dec;

    // Wait a bit then start polling
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Handshake loop - poll BOTH pools in every iteration
    println!("\nWaiting for session establishment...");
    for round in 0..60 {
        // Poll both relay pools
        poll_relay_events(&mut alice_pool, &mut ndb, &alice_manager, &bob_manager, &alice_pk, &bob_pk);
        poll_relay_events(&mut bob_pool, &mut ndb, &alice_manager, &bob_manager, &alice_pk, &bob_pk);

        // Process any generated events from both
        let (a_pub, a_dec) = process_session_events(
            &alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice"
        );
        alice_published += a_pub;
        alice_decrypted += a_dec;

        let (b_pub, b_dec) = process_session_events(
            &bob_receiver, &mut bob_pool, &mut ndb, &bob_keys, &mut bob_subs, "Bob"
        );
        bob_published += b_pub;
        bob_decrypted += b_dec;

        // Check if sessions established
        if alice_manager.get_total_sessions() > 0 && bob_manager.get_total_sessions() > 0 {
            println!("Sessions established after {} rounds!", round + 1);
            break;
        }

        if round % 10 == 9 {
            println!("  Round {}: Alice {} sessions, Bob {} sessions",
                round + 1, alice_manager.get_total_sessions(), bob_manager.get_total_sessions());
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    // Verify session state
    println!("\nSession state:");
    println!("  Alice: {} sessions", alice_manager.get_total_sessions());
    println!("  Bob:   {} sessions", bob_manager.get_total_sessions());

    if alice_manager.get_total_sessions() == 0 {
        println!("WARNING: Alice has no sessions - handshake may have failed");
        // Don't fail yet, continue to see what happens
    }

    // Alice sends message to Bob
    println!("\nAlice sending message to Bob...");
    let test_message = format!("Hello Bob! Test at {}", chrono::Utc::now().format("%H:%M:%S"));
    let alice_msg_ids = alice_manager.send_text(bob_pk, test_message.clone())?;
    println!("  Message sent, event_ids: {:?}", alice_msg_ids);

    let (a_pub, _) = process_session_events(
        &alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice"
    );
    alice_published += a_pub;

    // Wait for Bob to receive and reply
    println!("\nWaiting for message exchange...");
    for round in 0..40 {
        // Poll both pools
        poll_relay_events(&mut alice_pool, &mut ndb, &alice_manager, &bob_manager, &alice_pk, &bob_pk);
        poll_relay_events(&mut bob_pool, &mut ndb, &alice_manager, &bob_manager, &alice_pk, &bob_pk);

        // Process both
        let (a_pub, a_dec) = process_session_events(
            &alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice"
        );
        alice_published += a_pub;
        alice_decrypted += a_dec;

        let (b_pub, b_dec) = process_session_events(
            &bob_receiver, &mut bob_pool, &mut ndb, &bob_keys, &mut bob_subs, "Bob"
        );
        bob_published += b_pub;
        bob_decrypted += b_dec;

        // Once Bob decrypts, have him reply
        if bob_decrypted > 0 && bob_published < 4 {
            println!("\nBob replying to Alice...");
            let reply = format!("Hi Alice! Reply at {}", chrono::Utc::now().format("%H:%M:%S"));
            let _ = bob_manager.send_text(alice_pk, reply)?;

            let (b_pub, _) = process_session_events(
                &bob_receiver, &mut bob_pool, &mut ndb, &bob_keys, &mut bob_subs, "Bob"
            );
            bob_published += b_pub;
        }

        // Check if both exchanged messages
        if alice_decrypted > 0 && bob_decrypted > 0 {
            println!("Both parties exchanged messages after {} rounds!", round + 1);
            break;
        }

        if round % 10 == 9 {
            println!("  Round {}: Alice decrypted={}, Bob decrypted={}",
                round + 1, alice_decrypted, bob_decrypted);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    // Final results
    println!("\n============================================================");
    println!("  Test Results");
    println!("============================================================");
    println!("  Alice: published={}, decrypted={}", alice_published, alice_decrypted);
    println!("  Bob:   published={}, decrypted={}", bob_published, bob_decrypted);

    // Assertions
    assert!(alice_published > 0, "Alice should have published events");
    assert!(bob_published > 0, "Bob should have published events");
    assert!(bob_decrypted > 0, "Bob should have decrypted Alice's message");
    assert!(alice_decrypted > 0, "Alice should have decrypted Bob's reply");

    println!("\n  SUCCESS: Messages exchanged over real relay!");
    println!("============================================================\n");

    Ok(())
}

/// Simple test - verify we can connect and publish to real relay
#[tokio::test]
async fn test_relay_connection() -> Result<(), Box<dyn std::error::Error>> {
    println!("\nTesting connection to {}...", REAL_RELAY);

    let mut pool = RelayPool::new();
    let wakeup = || {};
    pool.add_url(REAL_RELAY.to_string(), wakeup)?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Generate test key and publish a simple event
    let keys = Keys::generate();
    let event = nostr::EventBuilder::new(nostr::Kind::from(1), "notedeck double-ratchet test")
        .sign_with_keys(&keys)?;

    let msg = ClientMessage::event_json(event.as_json())?;
    pool.send(&msg);

    // Wait for OK response
    let mut got_ok = false;
    for _ in 0..20 {
        while let Some(pool_event) = pool.try_recv() {
            if let WsEvent::Message(WsMessage::Text(relay_msg_str)) = pool_event.event {
                if let Ok(relay_msg) = RelayMessage::from_json(&relay_msg_str) {
                    if let RelayMessage::OK(_) = relay_msg {
                        got_ok = true;
                        println!("Received OK from relay");
                    }
                }
            }
        }
        if got_ok { break; }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    assert!(got_ok, "Should receive OK from relay");
    println!("Connection test passed!\n");

    Ok(())
}

/// Helper to route events to both managers (no special routing)
fn poll_relay_events_both(
    pool: &mut RelayPool,
    ndb: &mut Ndb,
    alice_manager: &Arc<SessionManager>,
    bob_manager: &Arc<SessionManager>,
) -> usize {
    let mut received = 0;

    while let Some(pool_event) = pool.try_recv() {
        if let WsEvent::Message(WsMessage::Text(relay_msg_str)) = pool_event.event {
            if let Ok(relay_msg) = RelayMessage::from_json(&relay_msg_str) {
                match relay_msg {
                    RelayMessage::Event(_subid, ev) => {
                        if let Ok(event) = nostr::Event::from_json(&ev) {
                            let kind = event.kind.as_u16();
                            received += 1;

                            let _ = ndb.process_event(&ev);

                            let author = hex::encode(event.pubkey.to_bytes());
                            println!("  Received kind {} from {}", kind, &author[..16]);

                            // Route to both - SessionManager handles deduplication
                            alice_manager.process_received_event(event.clone());
                            bob_manager.process_received_event(event.clone());
                        }
                    }
                    RelayMessage::OK(result) => {
                        println!("Relay OK: {:?}", result);
                    }
                    RelayMessage::Notice(msg) => {
                        println!("Relay notice: {}", msg);
                    }
                    _ => {}
                }
            }
        }
    }

    received
}

/// Test bidirectional session establishment - both parties discover each other
/// SessionManager should handle this and converge on one session per direction
#[tokio::test]
async fn test_bidirectional_discovery() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n============================================================");
    println!("  Bidirectional Discovery Test");
    println!("  Relay: {}", REAL_RELAY);
    println!("============================================================\n");

    let tmp_dir = tempfile::tempdir()?;
    let db_path = tmp_dir.path().join("test_db");
    let config = Config::new();
    let mut ndb = Ndb::new(db_path.to_str().unwrap(), &config)?;

    let mut alice_pool = RelayPool::new();
    let mut bob_pool = RelayPool::new();

    println!("Connecting to {}...", REAL_RELAY);
    let wakeup = || {};
    alice_pool.add_url(REAL_RELAY.to_string(), wakeup)?;
    bob_pool.add_url(REAL_RELAY.to_string(), wakeup)?;

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let alice_keys = Keys::generate();
    let bob_keys = Keys::generate();

    let alice_pk = Pubkey::new(alice_keys.public_key().to_bytes());
    let bob_pk = Pubkey::new(bob_keys.public_key().to_bytes());

    println!("\nTest participants:");
    println!("  Alice: {}...", &hex::encode(alice_pk.bytes())[..16]);
    println!("  Bob:   {}...", &hex::encode(bob_pk.bytes())[..16]);

    let (alice_event_tx, alice_event_rx) = crossbeam_channel::unbounded();
    let alice_receiver = SessionEventReceiver::new(alice_event_rx);
    let alice_manager = Arc::new(SessionManager::new(
        alice_pk,
        alice_keys.secret_key().to_secret_bytes(),
        format!("alice-bidir-{}", uuid::Uuid::new_v4()),
        alice_event_tx,
        None,
    ));

    let (bob_event_tx, bob_event_rx) = crossbeam_channel::unbounded();
    let bob_receiver = SessionEventReceiver::new(bob_event_rx);
    let bob_manager = Arc::new(SessionManager::new(
        bob_pk,
        bob_keys.secret_key().to_secret_bytes(),
        format!("bob-bidir-{}", uuid::Uuid::new_v4()),
        bob_event_tx,
        None,
    ));

    let mut alice_subs: HashMap<String, String> = HashMap::new();
    let mut bob_subs: HashMap<String, String> = HashMap::new();

    let mut alice_decrypted = 0;
    let mut bob_decrypted = 0;

    // Initialize both managers
    println!("\nInitializing session managers...");
    alice_manager.init()?;
    bob_manager.init()?;

    process_session_events(&alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice");
    process_session_events(&bob_receiver, &mut bob_pool, &mut ndb, &bob_keys, &mut bob_subs, "Bob");

    // BOTH Alice and Bob discover each other simultaneously
    println!("\nBoth parties discovering each other...");
    alice_manager.setup_user(bob_pk)?;
    bob_manager.setup_user(alice_pk)?;

    process_session_events(&alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice");
    process_session_events(&bob_receiver, &mut bob_pool, &mut ndb, &bob_keys, &mut bob_subs, "Bob");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Handshake loop - route ALL events to BOTH managers
    println!("\nWaiting for session establishment...");
    for round in 0..60 {
        poll_relay_events_both(&mut alice_pool, &mut ndb, &alice_manager, &bob_manager);
        poll_relay_events_both(&mut bob_pool, &mut ndb, &alice_manager, &bob_manager);

        let (_, a_dec) = process_session_events(&alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice");
        alice_decrypted += a_dec;

        let (_, b_dec) = process_session_events(&bob_receiver, &mut bob_pool, &mut ndb, &bob_keys, &mut bob_subs, "Bob");
        bob_decrypted += b_dec;

        let alice_sessions = alice_manager.get_total_sessions();
        let bob_sessions = bob_manager.get_total_sessions();

        // With bidirectional discovery, each should have sessions
        if alice_sessions > 0 && bob_sessions > 0 {
            println!("Sessions established after {} rounds!", round + 1);
            println!("  Alice: {} sessions with Bob", alice_sessions);
            println!("  Bob:   {} sessions with Alice", bob_sessions);
            break;
        }

        if round % 10 == 9 {
            println!("  Round {}: Alice {} sessions, Bob {} sessions", round + 1, alice_sessions, bob_sessions);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    println!("\nSession state after handshake:");
    println!("  Alice: {} sessions", alice_manager.get_total_sessions());
    println!("  Bob:   {} sessions", bob_manager.get_total_sessions());

    // Alice sends first message
    println!("\nAlice sending message to Bob...");
    let msg1 = format!("Hello Bob! From Alice at {}", chrono::Utc::now().format("%H:%M:%S"));
    let _ = alice_manager.send_text(bob_pk, msg1.clone())?;
    process_session_events(&alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice");

    // Wait for delivery and reply
    let mut bob_replied = false;
    for _round in 0..30 {
        poll_relay_events_both(&mut alice_pool, &mut ndb, &alice_manager, &bob_manager);
        poll_relay_events_both(&mut bob_pool, &mut ndb, &alice_manager, &bob_manager);

        let (_, a_dec) = process_session_events(&alice_receiver, &mut alice_pool, &mut ndb, &alice_keys, &mut alice_subs, "Alice");
        alice_decrypted += a_dec;

        let (_, b_dec) = process_session_events(&bob_receiver, &mut bob_pool, &mut ndb, &bob_keys, &mut bob_subs, "Bob");
        bob_decrypted += b_dec;

        // Bob replies after receiving (once)
        if bob_decrypted > 0 && !bob_replied {
            println!("\nBob replying to Alice...");
            let reply = format!("Hi Alice! From Bob at {}", chrono::Utc::now().format("%H:%M:%S"));
            let _ = bob_manager.send_text(alice_pk, reply)?;
            process_session_events(&bob_receiver, &mut bob_pool, &mut ndb, &bob_keys, &mut bob_subs, "Bob");
            bob_replied = true;
        }

        if alice_decrypted > 0 && bob_decrypted > 0 {
            println!("Both parties exchanged messages!");
            break;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    println!("\n============================================================");
    println!("  Bidirectional Test Results");
    println!("============================================================");
    println!("  Alice decrypted: {}", alice_decrypted);
    println!("  Bob decrypted:   {}", bob_decrypted);

    assert!(bob_decrypted > 0, "Bob should have decrypted Alice's message");
    assert!(alice_decrypted > 0, "Alice should have decrypted Bob's reply");

    println!("\n  SUCCESS: Bidirectional messaging works!");
    println!("============================================================\n");

    Ok(())
}
