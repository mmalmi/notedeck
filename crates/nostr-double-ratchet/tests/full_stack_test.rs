//! Full stack integration test - simulates complete notedeck DM flow
//!
//! This test mirrors what happens in notedeck's app.rs:
//! 1. SessionManager sends events via channel
//! 2. App receives events, signs them, publishes to relay
//! 3. Relay delivers events to subscribers
//! 4. App routes received events back to SessionManager
//!
//! Run with: cargo test -p nostr-double-ratchet --test full_stack_test -- --nocapture

use nostr_double_ratchet::{SessionManager, SessionManagerEvent};
use nostr::{Keys, JsonUtil};
use enostr::{Pubkey, RelayPool, RelayMessage, ClientMessage};
use enostr::ewebsock::{WsEvent, WsMessage};
use nostrdb::{Config, Ndb, Filter as NdbFilter};
use std::sync::Arc;
use std::collections::{HashMap, HashSet};

const RELAY: &str = "wss://temp.iris.to";

/// Simulates notedeck's app event processing loop
struct NotedeckSimulator {
    name: String,
    keys: Keys,
    pubkey: Pubkey,
    ndb: Ndb,
    pool: RelayPool,
    session_manager: Arc<SessionManager>,
    event_rx: crossbeam_channel::Receiver<SessionManagerEvent>,
    session_subscriptions: HashSet<String>,
    published: usize,
    decrypted: usize,
}

impl NotedeckSimulator {
    fn new(name: &str, relay: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let tmp_dir = tempfile::tempdir()?;
        let db_path = tmp_dir.path().join(format!("{}_db", name));

        let config = Config::new();
        let ndb = Ndb::new(db_path.to_str().unwrap(), &config)?;

        let mut pool = RelayPool::new();
        // Negentropy is now automatically disabled for DM kinds (1059, 1060, 30078) in pool.rs
        let wakeup = || {};
        pool.add_url(relay.to_string(), wakeup)?;

        let keys = Keys::generate();
        let pubkey = Pubkey::new(keys.public_key().to_bytes());

        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let session_manager = Arc::new(SessionManager::new(
            pubkey,
            keys.secret_key().to_secret_bytes(),
            format!("{}-device-{}", name, uuid::Uuid::new_v4()),
            event_tx,
            None,
        ));

        // Leak the tmp_dir to keep it alive
        std::mem::forget(tmp_dir);

        Ok(Self {
            name: name.to_string(),
            keys,
            pubkey,
            ndb,
            pool,
            session_manager,
            event_rx,
            session_subscriptions: HashSet::new(),
            published: 0,
            decrypted: 0,
        })
    }

    /// Process outgoing SessionManager events (like app.rs frame loop)
    fn process_session_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                SessionManagerEvent::Publish(unsigned_event) => {
                    let kind = unsigned_event.kind.as_u16();
                    println!("[{}] Publishing unsigned kind {}", self.name, kind);

                    if let Ok(secret_key) = nostr::SecretKey::from_slice(self.keys.secret_key().as_secret_bytes()) {
                        let signer_keys = nostr::Keys::new(secret_key);
                        if let Ok(signed) = unsigned_event.sign_with_keys(&signer_keys) {
                            let json = signed.as_json();
                            if let Ok(msg) = ClientMessage::event_json(json.clone()) {
                                self.pool.send(&msg);
                                let _ = self.ndb.process_event(&json);
                                self.published += 1;
                                println!("[{}] Sent kind {} to relay", self.name, kind);
                            }
                        }
                    }
                }
                SessionManagerEvent::PublishSigned(signed_event) => {
                    let kind = signed_event.kind.as_u16();
                    let json = signed_event.as_json();
                    println!("[{}] Publishing pre-signed kind {} from {}",
                        self.name, kind, &hex::encode(signed_event.pubkey.to_bytes())[..16]);

                    if let Ok(msg) = ClientMessage::event_json(json.clone()) {
                        self.pool.send(&msg);
                        let _ = self.ndb.process_event(&json);
                        self.published += 1;
                    }
                }
                SessionManagerEvent::Subscribe(filter_json) => {
                    println!("[{}] Subscribing: {}", self.name, &filter_json[..filter_json.len().min(80)]);

                    if let Ok(filter) = NdbFilter::from_json(&filter_json) {
                        let subid = format!("session-{}", uuid::Uuid::new_v4());
                        self.pool.subscribe(subid.clone(), vec![filter]);
                        self.session_subscriptions.insert(subid);
                    }
                }
                SessionManagerEvent::Unsubscribe(subid) => {
                    if self.session_subscriptions.remove(&subid) {
                        self.pool.unsubscribe(subid);
                    }
                }
                SessionManagerEvent::ReceivedEvent(event) => {
                    // This shouldn't happen in normal flow - events come from relay
                    println!("[{}] ReceivedEvent (unusual path) kind {}", self.name, event.kind.as_u16());
                    self.session_manager.process_received_event(event);
                }
                SessionManagerEvent::DecryptedMessage { sender, content, event_id } => {
                    // Parse inner content if JSON
                    let display_content = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                        parsed["content"].as_str().unwrap_or(&content).to_string()
                    } else {
                        content.clone()
                    };

                    println!("[{}] DECRYPTED from {}: '{}' (event: {:?})",
                        self.name, &hex::encode(sender.bytes())[..16], display_content, event_id);
                    self.decrypted += 1;
                }
            }
        }
    }

    /// Poll relay and route events (like app.rs handle_relay_message)
    fn poll_relay(&mut self) -> usize {
        let mut received = 0;

        while let Some(pool_event) = self.pool.try_recv() {
            // Log ALL websocket messages
            match &pool_event.event {
                WsEvent::Message(WsMessage::Text(text)) => {
                    if !text.contains("\"OK\"") && !text.contains("\"EOSE\"") {
                        println!("[{}] WS Message: {}", self.name, &text[..text.len().min(100)]);
                    }
                }
                other => {
                    println!("[{}] WS Event: {:?}", self.name, other);
                }
            }

            if let WsEvent::Message(WsMessage::Text(relay_msg_str)) = pool_event.event {
                if let Ok(relay_msg) = RelayMessage::from_json(&relay_msg_str) {
                    match relay_msg {
                        RelayMessage::Event(_subid, ev) => {
                            if let Ok(event) = nostr::Event::from_json(&ev) {
                                let kind = event.kind.as_u16();
                                received += 1;

                                // Process into ndb first
                                let _ = self.ndb.process_event(&ev);

                                // Route DM-related events to SessionManager (like EventBroker)
                                if kind == 30078 || kind == 1059 || kind == 1060 {
                                    println!("[{}] Received kind {} from relay, routing to SessionManager",
                                        self.name, kind);
                                    self.session_manager.process_received_event(event);
                                }
                            }
                        }
                        RelayMessage::OK(result) => {
                            println!("[{}] Relay OK: {:?}", self.name, result);
                        }
                        RelayMessage::Notice(msg) => {
                            println!("[{}] Relay notice: {}", self.name, msg);
                        }
                        _ => {}
                    }
                }
            }
        }

        received
    }
}

#[tokio::test]
async fn test_full_notedeck_stack() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n============================================================");
    println!("  Full Notedeck Stack Integration Test");
    println!("  Relay: {}", RELAY);
    println!("============================================================\n");

    // Create two simulated notedeck instances
    let mut alice = NotedeckSimulator::new("Alice", RELAY)?;
    let mut bob = NotedeckSimulator::new("Bob", RELAY)?;

    println!("Test participants:");
    println!("  Alice: {}...", &hex::encode(alice.pubkey.bytes())[..16]);
    println!("  Bob:   {}...", &hex::encode(bob.pubkey.bytes())[..16]);

    // Wait for relay connections and verify they're open
    println!("\nWaiting for relay connections...");
    for _ in 0..30 {
        alice.poll_relay();
        bob.poll_relay();
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }
    println!("Connections should be open now.");

    // Initialize session managers (publishes invites)
    println!("\nInitializing session managers...");
    alice.session_manager.init()?;
    bob.session_manager.init()?;

    // IMPORTANT: Setup user FIRST to subscribe to invites BEFORE they're published
    // This mirrors what happens in notedeck when you open a chat before the other
    // person has published their invite
    println!("\nAlice setting up chat with Bob (subscribing to Bob's invites)...");
    alice.session_manager.setup_user(bob.pubkey)?;

    // Process events from init + setup_user (subscriptions and invite publish)
    alice.process_session_events();
    bob.process_session_events();

    // Give relay time to process subscriptions before checking for events
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Handshake loop
    println!("\nWaiting for session establishment...");
    for round in 0..60 {
        alice.poll_relay();
        bob.poll_relay();

        alice.process_session_events();
        bob.process_session_events();

        if alice.session_manager.get_total_sessions() > 0 &&
           bob.session_manager.get_total_sessions() > 0 {
            println!("Sessions established after {} rounds!", round + 1);
            break;
        }

        if round % 10 == 9 {
            println!("  Round {}: Alice {} sessions, Bob {} sessions",
                round + 1, alice.session_manager.get_total_sessions(),
                bob.session_manager.get_total_sessions());
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    println!("\nSession state:");
    println!("  Alice: {} sessions", alice.session_manager.get_total_sessions());
    println!("  Bob:   {} sessions", bob.session_manager.get_total_sessions());

    // Alice sends message
    println!("\nAlice sending message to Bob...");
    let msg = format!("Hello Bob! Test at {}", chrono::Utc::now().format("%H:%M:%S"));
    alice.session_manager.send_text(bob.pubkey, msg)?;
    alice.process_session_events();

    // Message exchange loop
    let mut bob_replied = false;
    for round in 0..40 {
        alice.poll_relay();
        bob.poll_relay();

        alice.process_session_events();
        bob.process_session_events();

        // Bob replies once he decrypts
        if bob.decrypted > 0 && !bob_replied {
            println!("\nBob replying to Alice...");
            let reply = format!("Hi Alice! Reply at {}", chrono::Utc::now().format("%H:%M:%S"));
            bob.session_manager.send_text(alice.pubkey, reply)?;
            bob.process_session_events();
            bob_replied = true;
        }

        if alice.decrypted > 0 && bob.decrypted > 0 {
            println!("Both parties exchanged messages after {} rounds!", round + 1);
            break;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    // Results
    println!("\n============================================================");
    println!("  Test Results");
    println!("============================================================");
    println!("  Alice: published={}, decrypted={}", alice.published, alice.decrypted);
    println!("  Bob:   published={}, decrypted={}", bob.published, bob.decrypted);

    assert!(alice.published > 0, "Alice should have published events");
    assert!(bob.published > 0, "Bob should have published events");
    assert!(bob.decrypted > 0, "Bob should have decrypted Alice's message");
    assert!(alice.decrypted > 0, "Alice should have decrypted Bob's reply");

    println!("\n  SUCCESS: Full notedeck stack messaging works!");
    println!("============================================================\n");

    Ok(())
}
