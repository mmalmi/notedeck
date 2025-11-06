use nostr_double_ratchet::{SessionManager, SessionManagerEvent};
use nostr::Keys;
use enostr::{Pubkey, RelayPool};
use nostrdb::{Config, Ndb};
use std::sync::Arc;
use std::time::Duration;
use std::thread;

/// Integration test using real notedeck components (RelayPool + Ndb + SessionManager).
/// Tests two session managers communicating through a single shared notedeck event system.
#[test]
fn test_two_session_managers_via_notedeck_event_system() -> Result<(), Box<dyn std::error::Error>> {
    let tmp_dir = tempfile::tempdir()?;
    let db_path = tmp_dir.path().join("test_db");

    // Shared notedeck infrastructure
    let config = Config::new();
    let mut ndb = Ndb::new(db_path.to_str().unwrap(), &config).expect("ndb");
    let mut pool = RelayPool::new();

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

    // Initialize both to test multi-session scenario
    alice_manager.init()?;
    bob_manager.init()?;

    // Event processing loop - routes published events to the other manager
    fn process_session_events(
        manager: &Arc<SessionManager>,
        event_rx: &crossbeam_channel::Receiver<SessionManagerEvent>,
        _pool: &mut RelayPool,
        ndb: &mut Ndb,
        keys: &Keys,
        other_manager: &Arc<SessionManager>,
        label: &str,
    ) -> usize {
        let mut published_count = 0;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                SessionManagerEvent::Publish(unsigned_event) => {
                    let kind = unsigned_event.kind;
                    println!("{} publishing event kind {}", label, kind);

                    // Sign and send through notedeck system
                    if let Ok(secret_key) = nostr::SecretKey::from_slice(keys.secret_key().as_secret_bytes()) {
                        let signer_keys = nostr::Keys::new(secret_key);
                        if let Ok(signed) = unsigned_event.sign_with_keys(&signer_keys) {
                            use nostr::JsonUtil;
                            let json = signed.as_json();

                            // Process into ndb (simulating relay receipt)
                            let _ = ndb.process_event(&json);

                            // Route session-related events to other manager (like notedeck does)
                            // Include invite (30078), invite response (1059), and messages (1060)
                            if kind.as_u16() == 30078 || kind.as_u16() == 1059 || kind.as_u16() == 1060 {
                                let unsigned_for_other = nostr::UnsignedEvent::from(signed.clone());
                                other_manager.process_received_event(unsigned_for_other);
                            }

                            published_count += 1;
                        }
                    }
                }
                SessionManagerEvent::Subscribe(_filter_json) => {
                    println!("{} subscribing to filter", label);
                }
                SessionManagerEvent::ReceivedEvent(event) => {
                    println!("{} processing received event kind {}", label, event.kind);
                    manager.process_received_event(event);
                }
                SessionManagerEvent::DecryptedMessage { sender, content, event_id } => {
                    println!("{} decrypted message from {}: '{}' (event_id: {:?})",
                        label, hex::encode(sender.bytes()), content, event_id);
                }
            }
        }
        published_count
    }

    // Process initial events (invites)
    println!("\n=== Initial invite exchange ===");
    let mut alice_published = process_session_events(
        &alice_manager,
        &alice_event_rx,
        &mut pool,
        &mut ndb,
        &alice_keys,
        &bob_manager,
        "Alice",
    );

    let mut bob_published = process_session_events(
        &bob_manager,
        &bob_event_rx,
        &mut pool,
        &mut ndb,
        &bob_keys,
        &alice_manager,
        "Bob",
    );

    // Setup users to listen for each other
    println!("\n=== Setting up peer subscriptions ===");
    alice_manager.setup_user(bob_pk)?;
    bob_manager.setup_user(alice_pk)?;

    // Process subscriptions
    alice_published += process_session_events(
        &alice_manager,
        &alice_event_rx,
        &mut pool,
        &mut ndb,
        &alice_keys,
        &bob_manager,
        "Alice",
    );

    bob_published += process_session_events(
        &bob_manager,
        &bob_event_rx,
        &mut pool,
        &mut ndb,
        &bob_keys,
        &alice_manager,
        "Bob",
    );

    // Process invite responses (multiple rounds for handshake)
    println!("\n=== Processing invite responses ===");
    for round in 0..10 {
        let alice_events = process_session_events(
            &alice_manager,
            &alice_event_rx,
            &mut pool,
            &mut ndb,
            &alice_keys,
            &bob_manager,
            "Alice",
        );

        let bob_events = process_session_events(
            &bob_manager,
            &bob_event_rx,
            &mut pool,
            &mut ndb,
            &bob_keys,
            &alice_manager,
            "Bob",
        );

        alice_published += alice_events;
        bob_published += bob_events;

        if alice_events == 0 && bob_events == 0 {
            println!("No more events after round {}", round);
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    // Check session establishment
    let alice_users = alice_manager.get_user_pubkeys();
    let bob_users = bob_manager.get_user_pubkeys();

    println!("\n=== Session state ===");
    println!("Alice pubkey: {}", hex::encode(alice_manager.get_our_pubkey().bytes()));
    println!("Alice knows {} users: {:?}", alice_users.len(), alice_users.iter().map(|pk| hex::encode(pk.bytes())).collect::<Vec<_>>());
    println!("Alice has {} total sessions", alice_manager.get_total_sessions());
    println!("Bob pubkey: {}", hex::encode(bob_manager.get_our_pubkey().bytes()));
    println!("Bob knows {} users: {:?}", bob_users.len(), bob_users.iter().map(|pk| hex::encode(pk.bytes())).collect::<Vec<_>>());
    println!("Bob has {} total sessions", bob_manager.get_total_sessions());
    println!("Alice published {} events", alice_published);
    println!("Bob published {} events", bob_published);

    // Try to send messages
    // Both have sessions now (each accepted the other's invite)
    println!("\n=== Sending messages ===");

    let bob_msg_ids = bob_manager.send_text(alice_pk, "Hi Alice from Bob!".to_string())?;
    println!("Bob sent message (as initiator), event_ids: {:?}", bob_msg_ids);

    // Process Bob's outgoing message events immediately
    process_session_events(
        &bob_manager,
        &bob_event_rx,
        &mut pool,
        &mut ndb,
        &bob_keys,
        &alice_manager,
        "Bob",
    );

    // Now Alice can reply (her ratchet should be initialized)
    let alice_msg_ids = alice_manager.send_text(bob_pk, "Hello Bob from Alice!".to_string())?;
    println!("Alice sent reply, event_ids: {:?}", alice_msg_ids);

    // Process Alice's outgoing message events immediately
    process_session_events(
        &alice_manager,
        &alice_event_rx,
        &mut pool,
        &mut ndb,
        &alice_keys,
        &bob_manager,
        "Alice",
    );

    // Process any remaining message events - messages need to be routed and decrypted
    println!("\n=== Processing encrypted messages ===");
    for round in 0..5 {
        let alice_events = process_session_events(
            &alice_manager,
            &alice_event_rx,
            &mut pool,
            &mut ndb,
            &alice_keys,
            &bob_manager,
            "Alice",
        );

        let bob_events = process_session_events(
            &bob_manager,
            &bob_event_rx,
            &mut pool,
            &mut ndb,
            &bob_keys,
            &alice_manager,
            "Bob",
        );

        if alice_events == 0 && bob_events == 0 {
            println!("No more message events after round {}", round);
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    // Verify events were published
    assert!(alice_published > 0, "Alice should have published events");
    assert!(bob_published > 0, "Bob should have published events");

    println!("\n=== Test completed ===");

    Ok(())
}
