use nostr_double_ratchet::{SessionManager, SessionEvent};
use nostr_double_ratchet::pubsub::test_utils::SessionEventReceiver;
use nostr::{Keys, JsonUtil};
use enostr::{Pubkey, RelayPool, RelayMessage, ClientMessage};
use enostr::ewebsock::{WsEvent, WsMessage};
use nostrdb::{Config, Ndb};
use std::sync::Arc;
use std::collections::HashMap;

mod test_relay;

// Helper function for processing session events through relays
fn process_session_events_with_relays(
    _manager: &Arc<SessionManager>,
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
                println!("📤 {} publishing event kind {} to relays", label, kind);

                use nostr::JsonUtil;

                let json_str = unsigned_event.as_json();
                let is_signed = json_str.contains("\"sig\":");

                if kind == 1059 || kind == 1060 {
                    eprintln!("🔍 {} kind {} JSON check: is_signed={}, json preview: {}",
                        label, kind, is_signed, &json_str[..json_str.len().min(150)]);
                }

                let signed = if is_signed {
                    nostr::Event::from_json(&json_str)
                        .map_err(|e| {
                            eprintln!("❌ {} Failed to parse pre-signed event: {:?}", label, e);
                            e
                        })
                        .ok()
                } else {
                    if let Ok(secret_key) = nostr::SecretKey::from_slice(keys.secret_key().as_secret_bytes()) {
                        let signer_keys = nostr::Keys::new(secret_key);
                        unsigned_event.sign_with_keys(&signer_keys).ok()
                    } else {
                        None
                    }
                };

                if let Some(signed) = signed {
                    if let Err(e) = signed.verify() {
                        eprintln!("❌ {} Event signature INVALID for kind {}: {:?}", label, kind, e);
                        return (published_count, decrypted_count);
                    }

                    if kind == 1059 {
                        let p_tags: Vec<_> = signed.tags.iter()
                            .filter(|tag| tag.kind() == nostr::TagKind::p())
                            .collect();
                        if p_tags.is_empty() {
                            eprintln!("❌ {} Kind 1059 event missing p tag", label);
                            return (published_count, decrypted_count);
                        }
                        eprintln!("✅ {} Kind 1059 event is VALID, author: {}", label,
                            &hex::encode(signed.pubkey.to_bytes())[..16]);
                    }

                    if kind == 1060 {
                        eprintln!("✅ {} Kind 1060 event is VALID, author: {}", label,
                            &hex::encode(signed.pubkey.to_bytes())[..16]);
                    }

                    let signed_json = signed.as_json();
                    if let Ok(msg) = ClientMessage::event_json(signed_json.clone()) {
                        pool.send(&msg);
                    }
                    let _ = ndb.process_event(&signed_json);
                    published_count += 1;
                    println!("  ✓ Sent to relays");
                } else {
                    eprintln!("❌ {} Failed to sign event kind {}", label, kind);
                }
            }
            SessionEvent::Subscribe(filter_json) => {
                if let Ok(filter_val) = serde_json::from_str::<serde_json::Value>(&filter_json) {
                    let mut filter_builder = nostrdb::FilterBuilder::new();

                    if let Some(kinds) = filter_val["kinds"].as_array() {
                        let kinds_u64: Vec<u64> = kinds.iter().filter_map(|k| k.as_u64()).collect();
                        filter_builder = filter_builder.kinds(kinds_u64.clone());
                        println!("🔍 {} subscribing to kinds: {:?}", label, kinds_u64);
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
                        filter_builder = filter_builder.authors(author_refs);
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
                        filter_builder = filter_builder.pubkeys(p_refs);
                    }

                    let filter = filter_builder.build();
                    let sub_id = format!("{}-session-{}", label.to_lowercase(), uuid::Uuid::new_v4().as_u128());
                    let msg = ClientMessage::req(sub_id.clone(), vec![filter]);
                    pool.send(&msg);
                    subscriptions.insert(sub_id.clone(), filter_json.clone());

                    println!("  ✅ Created relay subscription: {}", sub_id);
                    println!("     Filter JSON: {}", filter_json);
                }
            }
            SessionEvent::DecryptedMessage { sender, content, event_id } => {
                println!("🔓 {} DECRYPTED message from {}: {} (event_id: {:?})",
                    label, hex::encode(sender.bytes()), content, event_id);
                decrypted_count += 1;
            }
            SessionEvent::Unsubscribe(sub_id) => {
                println!("🔴 {} unsubscribing from: {}", label, sub_id);
            }
            SessionEvent::PublishSigned(event) => {
                let kind = event.kind.as_u16();
                println!("📤 {} publishing pre-signed event kind {}", label, kind);
                let signed_json = event.as_json();
                if let Ok(msg) = ClientMessage::event_json(signed_json.clone()) {
                    pool.send(&msg);
                }
                let _ = ndb.process_event(&signed_json);
                published_count += 1;
            }
            SessionEvent::ReceivedEvent(signed_event) => {
                let kind = signed_event.kind.as_u16();
                println!("📬 {} received event kind {}", label, kind);
            }
        }
    }

    (published_count, decrypted_count)
}

/// Test using LOCAL relay for full diagnostic visibility
#[tokio::test]
async fn test_session_managers_local_relay() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  SessionManager LOCAL Relay Test                        ║");
    println!("║  Full diagnostic control                                ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // Start local relay
    let relay = test_relay::LocalRelay::new().await;
    relay.reset();
    println!("🚀 Local relay: {}", relay.url());

    run_relay_test(vec![relay.url()]).await
}

/// Full integration test using LOCAL RELAY.
/// Tests two SessionManagers communicating through a local relay server.
/// This verifies the complete flow including subscription filters for all required kinds.
#[tokio::test]
async fn test_session_managers_integration() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  SessionManager Integration Test (Local Relay)          ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // Start local relay for testing
    let relay = test_relay::LocalRelay::new().await;
    relay.reset();
    println!("🚀 Local relay: {}", relay.url());

    run_relay_test(vec![relay.url()]).await
}

async fn run_relay_test(test_relays: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = tempfile::tempdir()?;
    let db_path = tmp_dir.path().join("test_db");

    let config = Config::new();
    let mut ndb = Ndb::new(db_path.to_str().unwrap(), &config).expect("ndb");

    // Create SEPARATE relay pools
    let mut alice_pool = RelayPool::new();
    let mut bob_pool = RelayPool::new();

    println!("📡 Connecting to relays...");
    let wakeup = || {};
    for relay_url in &test_relays {
        let _ = alice_pool.add_url(relay_url.clone(), wakeup);
        let _ = bob_pool.add_url(relay_url.clone(), wakeup);
        println!("  • {}", relay_url);
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Setup Alice's session manager
    let alice_keys = Keys::generate();
    let alice_pk = Pubkey::new(alice_keys.public_key().to_bytes());
    let alice_identity = alice_keys.secret_key().to_secret_bytes();

    let (alice_event_tx, alice_event_rx) = crossbeam_channel::unbounded();
    let alice_event_receiver = SessionEventReceiver::new(alice_event_rx);
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

    let (bob_event_tx, bob_event_rx) = crossbeam_channel::unbounded();
    let bob_event_receiver = SessionEventReceiver::new(bob_event_rx);
    let bob_manager = Arc::new(SessionManager::new(
        bob_pk,
        bob_identity,
        "bob-device".to_string(),
        bob_event_tx.clone(),
        None,
    ));

    println!("\n👥 Test participants:");
    println!("  Alice: {}", hex::encode(alice_pk.bytes())[..16].to_string() + "...");
    println!("  Bob:   {}", hex::encode(bob_pk.bytes())[..16].to_string() + "...");

    // Initialize both managers - this triggers subscription to kinds 1059 and 1060
    println!("\n🔧 Initializing SessionManagers...");
    alice_manager.init()?;
    bob_manager.init()?;

    // Track subscriptions per manager
    let mut alice_subscriptions: HashMap<String, String> = HashMap::new();
    let mut bob_subscriptions: HashMap<String, String> = HashMap::new();


    // Process initial events (invites and subscriptions)
    println!("\n🔄 Processing initial setup...");
    let (mut alice_published, mut alice_decrypted) = process_session_events_with_relays(
        &alice_manager,
        &alice_event_receiver,
        &mut alice_pool,
        &mut ndb,
        &alice_keys,
        &mut alice_subscriptions,
        "Alice",
    );

    let (mut bob_published, mut bob_decrypted) = process_session_events_with_relays(
        &bob_manager,
        &bob_event_receiver,
        &mut bob_pool,
        &mut ndb,
        &bob_keys,
        &mut bob_subscriptions,
        "Bob",
    );

    // Alice (first message sender) sets up to listen for Bob's invite
    // This subscribes to kind 30078 events and will auto-accept Bob's invite
    println!("\n👂 Alice setting up to discover Bob's invite...");
    alice_manager.setup_user(bob_pk)?;
    // Bob does NOT call setup_user - he will process Alice's 1059 response with his invite_state

    // Process Alice's subscription (she will subscribe to Bob's invite and auto-accept)
    let (a_pub, a_dec) = process_session_events_with_relays(
        &alice_manager,
        &alice_event_receiver,
        &mut alice_pool,
        &mut ndb,
        &alice_keys,
        &mut alice_subscriptions,
        "Alice",
    );
    alice_published += a_pub;
    alice_decrypted += a_dec;

    // Process Bob's events (he doesn't subscribe to Alice, will only process her 1059 response)
    let (b_pub, b_dec) = process_session_events_with_relays(
        &bob_manager,
        &bob_event_receiver,
        &mut bob_pool,
        &mut ndb,
        &bob_keys,
        &mut bob_subscriptions,
        "Bob",
    );
    bob_published += b_pub;
    bob_decrypted += b_dec;

    // Poll relays for incoming events
    println!("\n⏳ Waiting for relay responses (handshake)...");
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    for round in 0..50 {
        // Poll Alice's relay pool for new messages
        let mut alice_received = 0;
        while let Some(pool_event) = alice_pool.try_recv() {
            alice_received += 1;
            if let WsEvent::Message(WsMessage::Text(relay_msg_str)) = pool_event.event {
                if let Ok(relay_msg) = RelayMessage::from_json(&relay_msg_str) {
                    match relay_msg {
                        RelayMessage::Event(_subid, ev) => {
                            if let Ok(event) = nostr::Event::from_json(&ev) {
                            let kind = event.kind.as_u16();

                            if kind == 1059 {
                                eprintln!("📨 Received kind 1059 from relay! author: {}", &hex::encode(event.pubkey.to_bytes())[..16]);
                            }

                            // Process into ndb
                            let _ = ndb.process_event(&ev);

                            // Route session events to appropriate manager
                            if kind == 30078 || kind == 1059 || kind == 1060 {
                                if kind == 1060 {
                                    // Kind 1060 uses ratchet keys, not identity keys
                                    // Send to both managers and let them figure out if it's for them
                                    eprintln!("📬 Routing kind 1060 with author: {}", &hex::encode(event.pubkey.to_bytes())[..16]);
                                    alice_manager.process_received_event(event.clone());
                                    bob_manager.process_received_event(event.clone());
                                } else if kind == 1059 {
                                    // Kind 1059: gift-wrapped invite responses
                                    // Send to both managers, they'll decrypt if it's for them
                                    alice_manager.process_received_event(event.clone());
                                    bob_manager.process_received_event(event.clone());
                                } else {
                                    // Kind 30078: authored by Bob means it's for Alice (she subscribed to Bob's invites)
                                    let is_for_alice = hex::encode(event.pubkey.to_bytes()) == hex::encode(bob_pk.bytes());
                                    if is_for_alice {
                                        alice_manager.process_received_event(event.clone());
                                    } else {
                                        bob_manager.process_received_event(event.clone());
                                    }
                                }
                                }
                            }
                        }
                        RelayMessage::Notice(msg) => {
                            println!("📢 Relay notice: {}", msg);
                        }
                        RelayMessage::OK(result) => {
                            println!("📝 Relay OK response: {:?}", result);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Poll Bob's relay pool for new messages
        while let Some(pool_event) = bob_pool.try_recv() {
            if let WsEvent::Message(WsMessage::Text(relay_msg_str)) = pool_event.event {
                if let Ok(relay_msg) = RelayMessage::from_json(&relay_msg_str) {
                    match relay_msg {
                        RelayMessage::Event(_subid, ev) => {
                            if let Ok(event) = nostr::Event::from_json(&ev) {
                            let kind = event.kind.as_u16();

                            if kind == 1059 {
                                eprintln!("📨 Received kind 1059 from relay! author: {}", &hex::encode(event.pubkey.to_bytes())[..16]);
                            }

                            // Process into ndb
                            let _ = ndb.process_event(&ev);

                            // Route session events to appropriate manager
                            if kind == 30078 || kind == 1059 || kind == 1060 {
                                if kind == 1060 {
                                    // Kind 1060 uses ratchet keys, not identity keys
                                    // Send to both managers and let them figure out if it's for them
                                    eprintln!("📬 Routing kind 1060 with author: {}", &hex::encode(event.pubkey.to_bytes())[..16]);
                                    alice_manager.process_received_event(event.clone());
                                    bob_manager.process_received_event(event.clone());
                                } else if kind == 1059 {
                                    // Kind 1059: gift-wrapped invite responses
                                    // Send to both managers, they'll decrypt if it's for them
                                    alice_manager.process_received_event(event.clone());
                                    bob_manager.process_received_event(event.clone());
                                } else {
                                    // Kind 30078: authored by Bob means it's for Alice (she subscribed to Bob's invites)
                                    let is_for_alice = hex::encode(event.pubkey.to_bytes()) == hex::encode(bob_pk.bytes());
                                    if is_for_alice {
                                        alice_manager.process_received_event(event.clone());
                                    } else {
                                        bob_manager.process_received_event(event.clone());
                                    }
                                }
                                }
                            }
                        }
                        RelayMessage::Notice(msg) => {
                            println!("📢 Relay notice: {}", msg);
                        }
                        RelayMessage::OK(result) => {
                            println!("📝 Relay OK response: {:?}", result);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Process any events generated by managers
        let (a_pub, a_dec) = process_session_events_with_relays(
            &alice_manager,
            &alice_event_receiver,
            &mut alice_pool,
            &mut ndb,
            &alice_keys,
            &mut alice_subscriptions,
            "Alice",
        );
        alice_published += a_pub;
        alice_decrypted += a_dec;

        let (b_pub, b_dec) = process_session_events_with_relays(
            &bob_manager,
            &bob_event_receiver,
            &mut bob_pool,
            &mut ndb,
            &bob_keys,
            &mut bob_subscriptions,
            "Bob",
        );
        bob_published += b_pub;
        bob_decrypted += b_dec;

        if round % 10 == 9 {
            println!("  Round {}: Alice {} sessions, Bob {} sessions, received {} msgs",
                round + 1, alice_manager.get_total_sessions(), bob_manager.get_total_sessions(), alice_received);
        }

        if round == 0 && alice_received == 0 {
            eprintln!("⚠️  Round 0: No messages received from relay - checking connection...");
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        // Check if sessions are established
        if alice_manager.get_total_sessions() > 0 && bob_manager.get_total_sessions() > 0 {
            println!("✓ Sessions established after {} rounds!", round + 1);
            break;
        }
    }

    // Check session establishment
    let alice_users = alice_manager.get_user_pubkeys();
    let bob_users = bob_manager.get_user_pubkeys();

    println!("\n📊 Session state:");
    println!("  Alice knows {} users, {} sessions", alice_users.len(), alice_manager.get_total_sessions());
    println!("  Bob knows {} users, {} sessions", bob_users.len(), bob_manager.get_total_sessions());

    // Verify both have established sessions
    if alice_manager.get_total_sessions() == 0 {
        println!("⚠️  WARNING: Alice has no sessions! Cannot send/receive messages.");
        println!("   This usually means Alice didn't receive Bob's invite from relays.");
    }
    if bob_manager.get_total_sessions() == 0 {
        println!("⚠️  WARNING: Bob has no sessions! Cannot send/receive messages.");
        println!("   This usually means Bob didn't receive Alice's invite from relays.");
    }

    // Send test messages
    println!("\n💬 Sending test messages...");

    // Alice sends first (she's the initiator, is_initiator=true)
    let alice_msg_ids = alice_manager.send_text(bob_pk, "Hi Bob from Alice via local relay!".to_string())?;
    println!("📤 Alice sent message, event_ids: {:?}", alice_msg_ids);

    // Process and publish Alice's message
    let (a_pub, a_dec) = process_session_events_with_relays(
        &alice_manager,
        &alice_event_receiver,
        &mut alice_pool,
        &mut ndb,
        &alice_keys,
        &mut alice_subscriptions,
        "Alice",
    );
    alice_published += a_pub;
    alice_decrypted += a_dec;

    // Wait for Bob to receive Alice's message
    // (Bob is non-initiator, must receive first message to initialize his sending ratchet)
    println!("\n⏳ Waiting for Bob to receive Alice's message...");
    for round in 0..20 {
        // Poll relay pool for Alice's message
        while let Some(pool_event) = bob_pool.try_recv() {
            if let WsEvent::Message(WsMessage::Text(relay_msg_str)) = pool_event.event {
                if let Ok(relay_msg) = RelayMessage::from_json(&relay_msg_str) {
                    if let RelayMessage::Event(_subid, ev) = relay_msg {
                        if let Ok(event) = nostr::Event::from_json(&ev) {
                            let kind = event.kind.as_u16();

                            // Process Alice's kind 1060 message to Bob
                            if kind == 1060 {
                                alice_manager.process_received_event(event.clone());
                                bob_manager.process_received_event(event.clone());
                            }
                        }
                    }
                }
            }
        }

        // Process Bob's events (including decryption)
        let (b_pub, b_dec) = process_session_events_with_relays(
            &bob_manager,
            &bob_event_receiver,
            &mut bob_pool,
            &mut ndb,
            &bob_keys,
            &mut bob_subscriptions,
            "Bob",
        );
        bob_published += b_pub;
        bob_decrypted += b_dec;

        // Once Bob has decrypted Alice's message, he can reply
        if bob_decrypted > 0 {
            println!("✅ Bob received Alice's message after {} rounds", round + 1);
            break;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    // Bob replies now that his ratchet is initialized
    let bob_msg_ids = bob_manager.send_text(alice_pk, "Hello Alice from Bob via local relay!".to_string())?;
    println!("📤 Bob sent reply message, event_ids: {:?}", bob_msg_ids);

    // Process and publish Bob's message
    let (b_pub, b_dec) = process_session_events_with_relays(
        &bob_manager,
        &bob_event_receiver,
        &mut bob_pool,
        &mut ndb,
        &bob_keys,
        &mut bob_subscriptions,
        "Bob",
    );
    bob_published += b_pub;
    bob_decrypted += b_dec;

    // Poll for message delivery
    println!("\n⏳ Waiting for message delivery from relays...");
    for round in 0..30 {
        // Poll Alice's relay pool for incoming messages
        while let Some(pool_event) = alice_pool.try_recv() {
            if let WsEvent::Message(WsMessage::Text(relay_msg_str)) = pool_event.event {
                if let Ok(relay_msg) = RelayMessage::from_json(&relay_msg_str) {
                    if let RelayMessage::Event(_subid, ev) = relay_msg {
                        if let Ok(event) = nostr::Event::from_json(&ev) {
                        let kind = event.kind.as_u16();

                        if kind == 1060 {
                            println!("📬 Received kind 1060 message from relay!");
                        }

                        // Route to appropriate manager
                        if kind == 30078 || kind == 1059 || kind == 1060 {
                            if kind == 1060 {
                                // Kind 1060 uses ratchet keys, not identity keys
                                // Send to both managers and let them figure out if it's for them
                                alice_manager.process_received_event(event.clone());
                                bob_manager.process_received_event(event.clone());
                            } else if kind == 1059 {
                                // Kind 1059: gift-wrapped with ephemeral key as pubkey (recipient)
                                let is_for_alice = hex::encode(event.pubkey.to_bytes()) == hex::encode(alice_pk.bytes());
                                if is_for_alice {
                                    alice_manager.process_received_event(event.clone());
                                } else {
                                    bob_manager.process_received_event(event.clone());
                                }
                            } else {
                                // Kind 30078: authored by Bob means it's for Alice
                                let is_for_alice = hex::encode(event.pubkey.to_bytes()) == hex::encode(bob_pk.bytes());
                                if is_for_alice {
                                    alice_manager.process_received_event(event.clone());
                                } else {
                                    bob_manager.process_received_event(event.clone());
                                }
                            }
                        }
                    }
                    }
                }
            }
        }

        // Process decrypted messages
        let (a_pub, a_dec) = process_session_events_with_relays(
            &alice_manager,
            &alice_event_receiver,
            &mut alice_pool,
            &mut ndb,
            &alice_keys,
            &mut alice_subscriptions,
            "Alice",
        );
        alice_published += a_pub;
        alice_decrypted += a_dec;

        let (b_pub, b_dec) = process_session_events_with_relays(
            &bob_manager,
            &bob_event_receiver,
            &mut bob_pool,
            &mut ndb,
            &bob_keys,
            &mut bob_subscriptions,
            "Bob",
        );
        bob_published += b_pub;
        bob_decrypted += b_dec;

        // Check if both received messages
        if alice_decrypted > 0 && bob_decrypted > 0 {
            println!("✅ Both parties received messages after {} rounds!", round + 1);
            break;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    // Final statistics
    println!("\n📈 Test results:");
    println!("  Alice published {} events, decrypted {} messages", alice_published, alice_decrypted);
    println!("  Bob published {} events, decrypted {} messages", bob_published, bob_decrypted);
    println!("  Alice subscriptions: {:?}", alice_subscriptions.keys().collect::<Vec<_>>());
    println!("  Bob subscriptions: {:?}", bob_subscriptions.keys().collect::<Vec<_>>());

    // Assertions
    assert!(alice_published > 0, "Alice should have published events");
    assert!(bob_published > 0, "Bob should have published events");

    // The critical test: both should have received and decrypted messages
    assert!(alice_decrypted > 0, "Alice should have decrypted Bob's message (this tests kind 1060 subscription!)");
    assert!(bob_decrypted > 0, "Bob should have decrypted Alice's message (this tests kind 1060 subscription!)");

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  ✅ RELAY INTEGRATION TEST PASSED                       ║");
    println!("║  Messages successfully exchanged over real relays!      ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    Ok(())
}

