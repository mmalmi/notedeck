/// Event Broker for distributing relay events and handling SessionManager actions.
///
/// Unified pub/sub system where SessionManager publishes events and subscribes to filters
/// through EventBroker, eliminating the need for channels and intermediary processing loops.

use nostr::JsonUtil;

/// Trait for handlers that process received relay events (incoming)
pub trait EventHandler: Send {
    fn handle_event(&mut self, relay: &str, event_json: &str);
}

/// Trait for handlers that process outgoing actions from SessionManager
pub trait ActionHandler: Send {
    fn handle_publish(&mut self, event_json: &str);
    fn handle_subscribe(&mut self, filter_json: &str);
    fn handle_unsubscribe(&mut self, subid: &str);
    fn handle_decrypted_message(&mut self, sender_hex: &str, content: &str, event_id: Option<&str>);
}

/// Handler for receiving relay events destined for SessionManager (kinds 1059, 1060, 30078)
pub struct SessionManagerHandler {
    event_tx: crossbeam_channel::Sender<nostr_double_ratchet::SessionManagerEvent>,
}

impl SessionManagerHandler {
    pub fn new(event_tx: crossbeam_channel::Sender<nostr_double_ratchet::SessionManagerEvent>) -> Self {
        Self { event_tx }
    }
}

impl EventHandler for SessionManagerHandler {
    fn handle_event(&mut self, relay: &str, event_json: &str) {
        if let Ok(nostr_event) = nostr::Event::from_json(event_json) {
            eprintln!("📤 EventBroker routing kind {} event from {} to SessionManager", nostr_event.kind.as_u16(), relay);
            if let Err(e) = self.event_tx.send(nostr_double_ratchet::SessionManagerEvent::ReceivedEvent(nostr_event)) {
                tracing::error!("Failed to send event to SessionManager: {}", e);
            }
        }
    }
}

pub struct EventBroker {
    handlers: Vec<(String, Vec<u64>, Box<dyn EventHandler>)>,
    action_handlers: Vec<Box<dyn ActionHandler>>,
}

impl EventBroker {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            action_handlers: Vec::new(),
        }
    }

    pub fn subscribe_events(
        &mut self,
        name: impl Into<String>,
        kinds: Vec<u64>,
        handler: impl EventHandler + 'static,
    ) {
        self.handlers.push((name.into(), kinds, Box::new(handler)));
    }

    pub fn subscribe_actions(&mut self, handler: impl ActionHandler + 'static) {
        self.action_handlers.push(Box::new(handler));
    }

    /// Route received relay event to matching handlers
    pub fn process_event(&mut self, relay: &str, event_json: &str) {
        if let Ok(event) = nostr::Event::from_json(event_json) {
            let kind = event.kind.as_u16() as u64;
            for (name, kinds, handler) in &mut self.handlers {
                if kinds.contains(&kind) {
                    tracing::debug!("Event kind {} matched handler: {}", kind, name);
                    handler.handle_event(relay, event_json);
                }
            }
        }
    }

    /// SessionManager publishes an event to the relay
    pub fn publish(&mut self, event_json: &str) {
        eprintln!("📤 EventBroker publishing event to relays");
        for handler in &mut self.action_handlers {
            handler.handle_publish(event_json);
        }
    }

    /// SessionManager subscribes to a filter
    pub fn subscribe(&mut self, filter_json: &str) {
        eprintln!("📡 EventBroker subscribing to filter");
        for handler in &mut self.action_handlers {
            handler.handle_subscribe(filter_json);
        }
    }

    /// SessionManager unsubscribes from a subscription
    pub fn unsubscribe(&mut self, subid: &str) {
        eprintln!("🔌 EventBroker unsubscribing from {}", subid);
        for handler in &mut self.action_handlers {
            handler.handle_unsubscribe(subid);
        }
    }

    /// SessionManager delivers a decrypted message
    pub fn emit_decrypted_message(&mut self, sender_hex: &str, content: &str, event_id: Option<&str>) {
        eprintln!("💬 EventBroker emitting decrypted message from {}", sender_hex);
        for handler in &mut self.action_handlers {
            handler.handle_decrypted_message(sender_hex, content, event_id);
        }
    }
}

impl Default for EventBroker {
    fn default() -> Self {
        Self::new()
    }
}
