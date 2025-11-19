use crate::relay::{setup_multicast_relay, MulticastRelay, Relay, RelayStatus};
use crate::relay::webrtc::WebRTCRelay;
use crate::relay::negentropy::NegentropyManager;
use crate::{ClientMessage, Error, Result};
use nostrdb::{Filter, Note};

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use url::Url;

use ewebsock::{WsEvent, WsMessage};
use tracing::{debug, error, trace, warn};

use super::subs_debug::SubsDebug;

/// Tracks relay negentropy protocol support state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegentropySupport {
    /// Unknown - initial state, not yet determined
    Unknown,
    /// Confirmed supported - received NEG-MSG response
    Supported,
    /// Confirmed unsupported - received NOTICE/NEG-ERR or timeout
    Unsupported,
}

/// Check if a filter is suitable for negentropy sync (matches NDK logic)
fn should_use_negentropy(filter: &Filter) -> bool {
    // Get filter JSON for inspection
    let json = match filter.json() {
        Ok(j) => j,
        Err(_) => return false,
    };

    // Skip if has ids filter
    if json.contains("\"ids\"") {
        return false;
    }

    // Check for single author
    let has_single_author = json.contains("\"authors\"") && json.matches("\"authors\"").count() == 1;

    if has_single_author {
        // Skip if all kinds are replaceable (10000-19999 or 0, 3)
        // Relays only keep latest, negentropy pointless
        if json.contains("\"kinds\"") {
            // Parse kinds to check if all replaceable
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json) {
                if let Some(kinds) = parsed.get("kinds").and_then(|k| k.as_array()) {
                    let all_replaceable = kinds.iter().all(|k| {
                        if let Some(kind) = k.as_u64() {
                            kind == 0 || kind == 3 || (10000..=19999).contains(&kind)
                        } else {
                            false
                        }
                    });
                    if all_replaceable {
                        return false;
                    }

                    // Skip if addressable/parameterized (30000-39999) with "d" tag filter
                    let has_addressable = kinds.iter().any(|k| {
                        if let Some(kind) = k.as_u64() {
                            (30000..=39999).contains(&kind)
                        } else {
                            false
                        }
                    });
                    if has_addressable && json.contains("\"#d\"") {
                        return false;
                    }
                }
            }
        }
    }

    // Use negentropy if no limit or limit >= 20
    filter.limit().map_or(true, |limit| limit >= 20)
}

/// Negentropy sync events emitted by the pool
#[derive(Debug, Clone)]
pub enum NegentropyEvent {
    /// Pool needs local events for a filter to seed negentropy sync
    /// App should query ndb and call pool.add_negentropy_notes()
    NeedLocalEvents {
        relay_url: String,
        sub_id: String,
        filter: Filter,
    },
    /// Reconciliation complete, these are event IDs we need to fetch
    NeedEvents {
        relay_url: String,
        sub_id: String,
        event_ids: Vec<String>,
    },
    /// Reconciliation complete, these are event IDs the relay needs (we have)
    HaveEvents {
        relay_url: String,
        sub_id: String,
        event_ids: Vec<String>,
    },
    /// Negentropy sync completed successfully
    SyncComplete {
        relay_url: String,
        sub_id: String,
    },
    /// Negentropy error occurred
    Error {
        relay_url: String,
        sub_id: String,
        error: String,
    },
}

#[derive(Debug)]
pub struct PoolEvent {
    pub relay: String,
    pub event: ewebsock::WsEvent,
    /// Optional negentropy event that needs app-level handling
    pub negentropy_event: Option<NegentropyEvent>,
}

impl PoolEvent {
    /// No-op for backwards compat - PoolEvent is already owned
    pub fn into_owned(self) -> Self {
        self
    }
}

// Deprecated, keeping for backwards compat
#[allow(dead_code)]
pub type PoolEventBuf = PoolEvent;

pub enum PoolRelay {
    Websocket(WebsocketRelay),
    Multicast(MulticastRelay),
    WebRTC(WebRTCRelay),
}

pub struct WebsocketRelay {
    pub relay: Relay,
    pub last_ping: Instant,
    pub last_connect_attempt: Instant,
    pub retry_connect_after: Duration,
}

impl PoolRelay {
    pub fn url(&self) -> &str {
        match self {
            Self::Websocket(wsr) => wsr.relay.url.as_str(),
            Self::Multicast(_wsr) => "multicast",
            Self::WebRTC(rtc) => rtc.url(),
        }
    }

    pub fn set_status(&mut self, status: RelayStatus) {
        match self {
            Self::Websocket(wsr) => {
                wsr.relay.status = status;
            }
            Self::Multicast(_mcr) => {}
            Self::WebRTC(rtc) => {
                rtc.status = status;
            }
        }
    }

    pub fn try_recv(&self) -> Option<WsEvent> {
        match self {
            Self::Websocket(recvr) => recvr.relay.receiver.try_recv(),
            Self::Multicast(recvr) => recvr.try_recv(),
            Self::WebRTC(_rtc) => None, // WebRTC uses async channels
        }
    }

    pub fn status(&self) -> RelayStatus {
        match self {
            Self::Websocket(wsr) => wsr.relay.status,
            Self::Multicast(mcr) => mcr.status,
            Self::WebRTC(rtc) => rtc.status,
        }
    }

    pub fn send(&mut self, msg: &ClientMessage) -> Result<()> {
        match self {
            Self::Websocket(wsr) => {
                wsr.relay.send(msg);
                Ok(())
            }

            Self::Multicast(mcr) => {
                // we only send event client messages at the moment
                if let ClientMessage::Event(ecm) = msg {
                    mcr.send(ecm)?;
                }
                Ok(())
            }

            Self::WebRTC(_rtc) => {
                // WebRTC send will be implemented async
                // For now, this is a placeholder
                Ok(())
            }
        }
    }

    pub fn subscribe(&mut self, subid: String, filter: Vec<Filter>) -> Result<()> {
        self.send(&ClientMessage::req(subid, filter))
    }

    pub fn websocket(relay: Relay) -> Self {
        Self::Websocket(WebsocketRelay::new(relay))
    }

    pub fn multicast(wakeup: impl Fn() + Send + Sync + Clone + 'static) -> Result<Self> {
        Ok(Self::Multicast(setup_multicast_relay(wakeup)?))
    }

    pub fn webrtc(enable_stun_server: bool) -> Result<Self> {
        Ok(Self::WebRTC(WebRTCRelay::new(enable_stun_server)?))
    }
}

impl WebsocketRelay {
    pub fn new(relay: Relay) -> Self {
        Self {
            relay,
            last_ping: Instant::now(),
            last_connect_attempt: Instant::now(),
            retry_connect_after: Self::initial_reconnect_duration(),
        }
    }

    pub fn initial_reconnect_duration() -> Duration {
        Duration::from_secs(5)
    }
}

pub struct RelayPool {
    pub relays: Vec<PoolRelay>,
    pub ping_rate: Duration,
    pub debug: Option<SubsDebug>,
    negentropy_managers: HashMap<String, NegentropyManager>, // relay_url -> manager
    use_negentropy: bool,
    /// Pending negentropy events to be consumed by app
    negentropy_events: Vec<NegentropyEvent>,
    /// Track active negentropy subscriptions per relay: relay_url -> sub_id
    active_neg_subs: HashMap<String, String>,
    /// Track negentropy support state per relay: relay_url -> (support_state, last_attempt_time)
    /// Unknown: initial state
    /// Supported: confirmed via NEG-MSG receipt
    /// Unsupported: confirmed via NOTICE/NEG-ERR or 10s timeout
    negentropy_support: HashMap<String, (NegentropySupport, Instant)>,
}

impl Default for RelayPool {
    fn default() -> Self {
        RelayPool::new()
    }
}

impl RelayPool {
    // Constructs a new, empty RelayPool.
    pub fn new() -> RelayPool {
        RelayPool {
            relays: vec![],
            ping_rate: Duration::from_secs(45),
            debug: None,
            negentropy_managers: HashMap::new(),
            use_negentropy: true,
            negentropy_events: Vec::new(),
            active_neg_subs: HashMap::new(),
            negentropy_support: HashMap::new(),
        }
    }

    /// Enable or disable negentropy protocol
    pub fn set_use_negentropy(&mut self, enabled: bool) {
        self.use_negentropy = enabled;
    }

    /// Check if negentropy is enabled
    pub fn using_negentropy(&self) -> bool {
        self.use_negentropy
    }

    /// Get or create negentropy manager for a relay
    fn get_neg_manager(&mut self, relay_url: &str) -> &mut NegentropyManager {
        self.negentropy_managers
            .entry(relay_url.to_owned())
            .or_insert_with(NegentropyManager::new)
    }

    /// Start negentropy sync for a subscription on a relay
    pub fn start_negentropy_sync(&mut self, relay_url: &str, sub_id: &str, filter_hash: u64) -> Result<()> {
        let manager = self.get_neg_manager(relay_url);
        manager.start_sync(sub_id.to_string(), filter_hash)
    }

    /// Add local notes to a negentropy sync session and send NEG-OPEN
    /// Call this after receiving NeedLocalEvents
    pub fn add_negentropy_notes(&mut self, relay_url: &str, sub_id: &str, filter: Filter, notes: &[Note]) -> Result<()> {
        let manager = self.get_neg_manager(relay_url);
        manager.add_notes(sub_id, notes)?;

        // Seal and initiate sync to get initial message
        let init_msg = manager.initiate(sub_id)?;

        // Send NEG-OPEN with initial message (NIP-77 format)
        if let Some(relay) = self.relays.iter_mut().find(|r| r.url() == relay_url) {
            debug!("sending NEG-OPEN with {} byte init msg for sub {} to {}", init_msg.len(), sub_id, relay_url);
            let neg_open = ClientMessage::neg_open(sub_id.to_string(), filter, None, init_msg);
            relay.send(&neg_open)?;
        } else {
            return Err(Error::Generic(format!("relay {} not found", relay_url)));
        }

        Ok(())
    }

    /// Add local events as (timestamp, id) pairs (lightweight, no Note clone)
    pub fn add_negentropy_events(&mut self, relay_url: &str, sub_id: &str, filter: Filter, events: &[(u64, [u8; 32])]) -> Result<()> {
        let manager = self.get_neg_manager(relay_url);
        manager.add_events(sub_id, events)?;

        // Seal and initiate sync
        let init_msg = manager.initiate(sub_id)?;

        // Send NEG-OPEN
        if let Some(relay) = self.relays.iter_mut().find(|r| r.url() == relay_url) {
            debug!("sending NEG-OPEN with {} byte init msg ({} events) for sub {} to {}", init_msg.len(), events.len(), sub_id, relay_url);

            // Mark relay as Unknown with timestamp if not already tracked
            self.negentropy_support.entry(relay_url.to_string())
                .or_insert((NegentropySupport::Unknown, Instant::now()));

            let neg_open = ClientMessage::neg_open(sub_id.to_string(), filter, None, init_msg);
            relay.send(&neg_open)?;
        } else {
            return Err(Error::Generic(format!("relay {} not found", relay_url)));
        }

        Ok(())
    }

    /// Close negentropy sync for a subscription on a relay
    pub fn close_negentropy_sync(&mut self, relay_url: &str, sub_id: &str) {
        if let Some(manager) = self.negentropy_managers.get_mut(relay_url) {
            manager.close_sync(sub_id);
        }
    }

    /// Process NEG-MSG response (hex-decoded payload)
    /// Returns (next_msg, have_ids, need_ids)
    pub fn handle_negentropy_message(
        &mut self,
        relay_url: &str,
        sub_id: &str,
        msg: &[u8],
    ) -> Result<(Option<Vec<u8>>, Vec<String>, Vec<String>)> {
        let manager = self.get_neg_manager(relay_url);
        manager.reconcile(sub_id, msg)
    }

    /// Cleanup stale negentropy sessions across all relays
    pub fn cleanup_stale_negentropy(&mut self) {
        for manager in self.negentropy_managers.values_mut() {
            manager.cleanup_stale();
        }
    }

    /// Mark a relay as not supporting negentropy
    /// Future subscriptions to this relay will use REQ instead of NEG-OPEN
    pub fn mark_negentropy_unsupported(&mut self, relay_url: &str) {
        debug!("marking relay {} as not supporting negentropy", relay_url);
        self.negentropy_support.insert(relay_url.to_string(), (NegentropySupport::Unsupported, Instant::now()));
        // Clean up any active negentropy state for this relay
        self.active_neg_subs.retain(|url, _| url != relay_url);
        self.negentropy_managers.remove(relay_url);
    }

    /// Mark a relay as supporting negentropy (confirmed via NEG-MSG)
    fn mark_negentropy_supported(&mut self, relay_url: &str) {
        if let Some((state, _)) = self.negentropy_support.get(relay_url) {
            if *state == NegentropySupport::Unknown {
                debug!("relay {} confirmed negentropy support", relay_url);
                self.negentropy_support.insert(relay_url.to_string(), (NegentropySupport::Supported, Instant::now()));
            }
        }
    }

    /// Check if a relay supports negentropy (true if Unknown or Supported)
    pub fn supports_negentropy(&self, relay_url: &str) -> bool {
        self.negentropy_support
            .get(relay_url)
            .map_or(true, |(state, _)| *state != NegentropySupport::Unsupported)
    }

    /// Get the number of connected WebRTC peers across all WebRTC relays (synchronous)
    pub fn webrtc_peer_count(&self) -> usize {
        let mut count = 0;
        for relay in &self.relays {
            if let PoolRelay::WebRTC(rtc) = relay {
                count += rtc.connected_peer_count();
            }
        }
        count
    }

    /// Get all connected WebRTC peer pubkeys (synchronous, cached)
    pub fn webrtc_peer_pubkeys(&self) -> Vec<String> {
        let mut peers = Vec::new();
        for relay in &self.relays {
            if let PoolRelay::WebRTC(rtc) = relay {
                peers.extend(rtc.get_peer_pubkeys());
            }
        }
        peers
    }

    /// Get all online WebRTC peer pubkeys (synchronous, cached)
    pub fn webrtc_online_peers(&self) -> Vec<String> {
        let mut peers = Vec::new();
        for relay in &self.relays {
            if let PoolRelay::WebRTC(rtc) = relay {
                peers.extend(rtc.get_online_peers());
            }
        }
        peers
    }

    /// Check if a peer is online across all WebRTC relays
    pub fn is_webrtc_peer_online(&self, pubkey: &str) -> bool {
        for relay in &self.relays {
            if let PoolRelay::WebRTC(rtc) = relay {
                if rtc.is_peer_online(pubkey) {
                    return true;
                }
            }
        }
        false
    }

    pub fn add_multicast_relay(
        &mut self,
        wakeup: impl Fn() + Send + Sync + Clone + 'static,
    ) -> Result<()> {
        let multicast_relay = PoolRelay::multicast(wakeup)?;
        self.relays.push(multicast_relay);
        Ok(())
    }

    pub fn use_debug(&mut self) {
        self.debug = Some(SubsDebug::default());
    }

    pub fn ping_rate(&mut self, duration: Duration) -> &mut Self {
        self.ping_rate = duration;
        self
    }

    pub fn has(&self, url: &str) -> bool {
        for relay in &self.relays {
            if relay.url() == url {
                return true;
            }
        }

        false
    }

    pub fn urls(&self) -> BTreeSet<String> {
        self.relays
            .iter()
            .map(|pool_relay| pool_relay.url().to_string())
            .collect()
    }

    pub fn send(&mut self, cmd: &ClientMessage) {
        for relay in &mut self.relays {
            if let Some(debug) = &mut self.debug {
                debug.send_cmd(relay.url().to_owned(), cmd);
            }
            if let Err(err) = relay.send(cmd) {
                error!("error sending {:?} to {}: {err}", cmd, relay.url());
            }
        }
    }

    pub fn unsubscribe(&mut self, subid: String) {
        for relay in &mut self.relays {
            let cmd = ClientMessage::close(subid.clone());
            if let Some(debug) = &mut self.debug {
                debug.send_cmd(relay.url().to_owned(), &cmd);
            }
            if let Err(err) = relay.send(&cmd) {
                error!(
                    "error unsubscribing from {} on {}: {err}",
                    &subid,
                    relay.url()
                );
            }
        }
    }

    pub fn subscribe(&mut self, subid: String, filter: Vec<Filter>) {
        self.subscribe_with_negentropy(subid, filter, self.use_negentropy);
    }

    /// Subscribe with explicit negentropy control
    pub fn subscribe_with_negentropy(&mut self, subid: String, filter: Vec<Filter>, try_negentropy: bool) {
        // Collect relay operations to avoid borrow checker issues
        let mut neg_operations = Vec::new();

        // Cache negentropy support status to avoid borrow conflicts
        let neg_support: HashMap<String, bool> = self.relays.iter()
            .map(|r| (r.url().to_owned(), self.supports_negentropy(r.url())))
            .collect();

        for relay in &mut self.relays {
            let relay_url = relay.url().to_owned();

            // Try negentropy if enabled and this is a websocket relay and relay supports it
            let relay_supports_neg = neg_support.get(&relay_url).copied().unwrap_or(true);
            let use_neg = try_negentropy
                && matches!(relay, PoolRelay::Websocket(_))
                && relay_supports_neg;

            let msg = if use_neg && !filter.is_empty() {
                // Check if suitable for negentropy:
                // - Single filter only
                // - No ids filter (negentropy is for discovery, not fetching specific events)
                // - No limit or limit >= 20 (small limits are faster with REQ)
                if filter.len() == 1 && should_use_negentropy(&filter[0]) {
                    debug!("using negentropy for subscription {} on {}", subid, relay_url);

                    // Defer negentropy setup - will send NEG-OPEN after we have initial message
                    let filter_hash = crate::filter_hash::hash_filter(&filter[0]);
                    neg_operations.push((relay_url.clone(), subid.clone(), filter_hash, filter[0].clone()));

                    // Don't send anything yet - wait for app to provide local events
                    continue;
                } else {
                    if filter.len() > 1 {
                        debug!("falling back to REQ for multi-filter subscription {} on {}", subid, relay_url);
                    } else if !filter.is_empty() {
                        debug!("falling back to REQ for subscription {} (ids filter or small limit) on {}", subid, relay_url);
                    }
                    ClientMessage::req(subid.clone(), filter.clone())
                }
            } else {
                if !relay_supports_neg {
                    debug!("relay {} doesn't support negentropy, using REQ for subscription {}", relay_url, subid);
                }
                ClientMessage::req(subid.clone(), filter.clone())
            };

            if let Some(debug) = &mut self.debug {
                debug.send_cmd(relay_url.clone(), &msg);
            }

            if let Err(err) = relay.send(&msg) {
                error!("error subscribing to {}: {err}", relay_url);
            }
        }

        // Now perform negentropy setup without conflicting borrows
        for (relay_url, sub_id, filter_hash, filter) in neg_operations {
            if let Err(e) = self.start_negentropy_sync(&relay_url, &sub_id, filter_hash) {
                warn!("failed to start negentropy sync: {}", e);
            } else {
                // Track active negentropy subscription
                self.active_neg_subs.insert(relay_url.clone(), sub_id.clone());

                // Queue event for app to provide local events
                self.negentropy_events.push(NegentropyEvent::NeedLocalEvents {
                    relay_url,
                    sub_id,
                    filter,
                });
            }
        }
    }

    /// Keep relay connectiongs alive by pinging relays that haven't been
    /// pinged in awhile. Adjust ping rate with [`ping_rate`].
    pub fn keepalive_ping(&mut self, wakeup: impl Fn() + Send + Sync + Clone + 'static) {
        for relay in &mut self.relays {
            let now = std::time::Instant::now();

            match relay {
                PoolRelay::Multicast(_) => {}
                PoolRelay::WebRTC(_) => {
                    // WebRTC connections don't need pinging
                }
                PoolRelay::Websocket(relay) => {
                    match relay.relay.status {
                        RelayStatus::Disconnected => {
                            let reconnect_at =
                                relay.last_connect_attempt + relay.retry_connect_after;
                            if now > reconnect_at {
                                relay.last_connect_attempt = now;
                                let next_duration = Duration::from_millis(3000);
                                debug!(
                                    "bumping reconnect duration from {:?} to {:?} and retrying connect",
                                    relay.retry_connect_after, next_duration
                                );
                                relay.retry_connect_after = next_duration;
                                if let Err(err) = relay.relay.connect(wakeup.clone()) {
                                    error!("error connecting to relay: {}", err);
                                }
                            } else {
                                // let's wait a bit before we try again
                            }
                        }

                        RelayStatus::Connected => {
                            relay.retry_connect_after =
                                WebsocketRelay::initial_reconnect_duration();

                            let should_ping = now - relay.last_ping > self.ping_rate;
                            if should_ping {
                                trace!("pinging {}", relay.relay.url);
                                relay.relay.ping();
                                relay.last_ping = Instant::now();
                            }
                        }

                        RelayStatus::Connecting => {
                            // cool story bro
                        }
                    }
                }
            }
        }
    }

    pub fn send_to(&mut self, cmd: &ClientMessage, relay_url: &str) {
        for relay in &mut self.relays {
            if relay.url() == relay_url {
                if let Some(debug) = &mut self.debug {
                    debug.send_cmd(relay.url().to_owned(), cmd);
                }
                if let Err(err) = relay.send(cmd) {
                    error!("send_to err: {err}");
                }
                return;
            }
        }
    }

    /// check whether a relay url is valid to add
    pub fn is_valid_url(&self, url: &str) -> bool {
        if url.is_empty() {
            return false;
        }
        let url = match Url::parse(url) {
            Ok(parsed_url) => parsed_url.to_string(),
            Err(_err) => {
                // debug!("bad relay url \"{}\": {:?}", url, err);
                return false;
            }
        };
        if self.has(&url) {
            return false;
        }
        true
    }

    // Adds a websocket url to the RelayPool.
    pub fn add_url(
        &mut self,
        url: String,
        wakeup: impl Fn() + Send + Sync + Clone + 'static,
    ) -> Result<()> {
        let url = Self::canonicalize_url(url);
        // Check if the URL already exists in the pool.
        if self.has(&url) {
            return Ok(());
        }
        let relay = Relay::new(
            nostr::RelayUrl::parse(url).map_err(|_| Error::InvalidRelayUrl)?,
            wakeup,
        )?;
        let pool_relay = PoolRelay::websocket(relay);

        self.relays.push(pool_relay);

        Ok(())
    }

    pub fn add_urls(
        &mut self,
        urls: BTreeSet<String>,
        wakeup: impl Fn() + Send + Sync + Clone + 'static,
    ) -> Result<()> {
        for url in urls {
            self.add_url(url, wakeup.clone())?;
        }
        Ok(())
    }

    pub fn remove_urls(&mut self, urls: &BTreeSet<String>) {
        self.relays
            .retain(|pool_relay| !urls.contains(pool_relay.url()));
    }

    // standardize the format (ie, trailing slashes)
    fn canonicalize_url(url: String) -> String {
        match Url::parse(&url) {
            Ok(parsed_url) => parsed_url.to_string(),
            Err(_) => url, // If parsing fails, return the original URL.
        }
    }

    /// Attempts to receive a pool event from a list of relays. The
    /// function searches each relay in the list in order, attempting to
    /// receive a message from each. If a message is received, return it.
    /// If no message is received from any relays, None is returned.
    pub fn try_recv(&mut self) -> Option<PoolEvent> {
        // First pass: collect events without processing
        let mut relay_events: Vec<(String, WsEvent)> = Vec::new();

        for relay in &mut self.relays {
            if let PoolRelay::Multicast(mcr) = relay {
                if mcr.should_rejoin() {
                    if let Err(err) = mcr.rejoin() {
                        error!("multicast: rejoin error: {err}");
                    }
                }
            }

            if let Some(event) = relay.try_recv() {
                let relay_url = relay.url().to_string();

                // Handle status changes immediately (needs mutable relay)
                match &event {
                    WsEvent::Opened => {
                        relay.set_status(RelayStatus::Connected);
                    }
                    WsEvent::Closed => {
                        relay.set_status(RelayStatus::Disconnected);
                    }
                    WsEvent::Error(err) => {
                        error!("{:?}", err);
                        relay.set_status(RelayStatus::Disconnected);
                    }
                    WsEvent::Message(ev) => {
                        #[cfg(not(target_arch = "wasm32"))]
                        if let WsMessage::Ping(ref bs) = ev {
                            trace!("pong {}", relay_url);
                            match relay {
                                PoolRelay::Websocket(wsr) => {
                                    wsr.relay.sender.send(WsMessage::Pong(bs.to_owned()));
                                }
                                PoolRelay::Multicast(_mcr) => {}
                                PoolRelay::WebRTC(_) => {}
                            }
                        }
                    }
                }

                // Collect event for processing
                relay_events.push((relay_url, event));
                break; // Process one event at a time
            }
        }

        // Second pass: process collected events (no borrow conflicts)
        if let Some((relay_url, event)) = relay_events.pop() {
            // Handle NEG-MSG responses
            if let WsEvent::Message(WsMessage::Text(ref text)) = &event {
                if text.contains("\"NEG-MSG\"") {
                    use crate::relay::message::RelayMessage;
                    if let Ok(RelayMessage::NegMsg(sub_id, payload)) = RelayMessage::from_json(text) {
                        debug!("processing NEG-MSG ({} bytes) for sub {} from {}", payload.len(), sub_id, relay_url);

                        // Mark relay as supporting negentropy on first NEG-MSG receipt
                        self.mark_negentropy_supported(&relay_url);

                        match self.handle_negentropy_message(&relay_url, sub_id, payload) {
                            Ok((next_msg, have_ids, need_ids)) => {
                                if let Some(next) = next_msg {
                                    // Send next NEG-MSG
                                    debug!("sending next NEG-MSG ({} bytes) for sub {} to {}", next.len(), sub_id, relay_url);
                                    if let Some(r) = self.relays.iter_mut().find(|r| r.url() == &relay_url) {
                                        if let Err(e) = r.send(&ClientMessage::neg_msg(sub_id.to_string(), next)) {
                                            error!("failed to send NEG-MSG: {}", e);
                                        }
                                    }
                                    return self.try_recv(); // Recurse to get next event
                                } else {
                                    // Sync complete - emit NeedEvents for caller to fetch
                                    debug!("negentropy sync complete for {}: have={}, need={}", sub_id, have_ids.len(), need_ids.len());

                                    if !need_ids.is_empty() {
                                        self.negentropy_events.push(NegentropyEvent::NeedEvents {
                                            relay_url: relay_url.clone(),
                                            sub_id: sub_id.to_string(),
                                            event_ids: need_ids,
                                        });
                                    }
                                    if !have_ids.is_empty() {
                                        self.negentropy_events.push(NegentropyEvent::HaveEvents {
                                            relay_url: relay_url.clone(),
                                            sub_id: sub_id.to_string(),
                                            event_ids: have_ids,
                                        });
                                    }

                                    self.negentropy_events.push(NegentropyEvent::SyncComplete {
                                        relay_url: relay_url.clone(),
                                        sub_id: sub_id.to_string(),
                                    });

                                    self.active_neg_subs.remove(&relay_url);
                                    return self.try_recv(); // Recurse to emit queued events
                                }
                            }
                            Err(e) => {
                                error!("negentropy reconciliation failed for {}: {}", relay_url, e);
                                self.negentropy_events.push(NegentropyEvent::Error {
                                    relay_url: relay_url.clone(),
                                    sub_id: sub_id.to_string(),
                                    error: e.to_string(),
                                });
                                self.active_neg_subs.remove(&relay_url);
                            }
                        }
                    }
                }
            }

            // Return event to caller
            if let Some(debug) = &mut self.debug {
                debug.receive_cmd(relay_url.clone(), (&event).into());
            }

            let neg_event = self.negentropy_events.pop();

            return Some(PoolEvent {
                event,
                relay: relay_url,
                negentropy_event: neg_event,
            });
        }

        // If no WS events but we have queued negentropy events, emit them
        // Note: We return them piggybacked on a synthetic EOSE event to avoid
        // "empty message" errors from dummy events
        if !self.negentropy_events.is_empty() {
            if let Some(neg_event) = self.negentropy_events.pop() {
                let relay_url = match &neg_event {
                    NegentropyEvent::NeedLocalEvents { relay_url, .. }
                    | NegentropyEvent::NeedEvents { relay_url, .. }
                    | NegentropyEvent::HaveEvents { relay_url, .. }
                    | NegentropyEvent::SyncComplete { relay_url, .. }
                    | NegentropyEvent::Error { relay_url, .. } => relay_url,
                };

                // Find the relay
                if self.relays.iter().any(|r| r.url() == relay_url) {
                    // Use a synthetic EOSE with special ID to avoid empty message errors
                    // App can ignore EOSE for "_negentropy_event" subscription
                    let event = WsEvent::Message(WsMessage::Text(
                        r#"["EOSE","_negentropy_event"]"#.to_string()
                    ));
                    return Some(PoolEvent {
                        event,
                        relay: relay_url.to_string(),
                        negentropy_event: Some(neg_event),
                    });
                }
            }
        }

        // Check for negentropy timeouts (10s without response)
        let now = Instant::now();
        let timeout_duration = Duration::from_secs(10);
        let mut timed_out_relays = Vec::new();

        for (relay_url, (state, timestamp)) in &self.negentropy_support {
            if *state == NegentropySupport::Unknown && now.duration_since(*timestamp) > timeout_duration {
                timed_out_relays.push(relay_url.clone());
            }
        }

        for relay_url in timed_out_relays {
            debug!("relay {} negentropy timeout - marking unsupported", relay_url);
            self.mark_negentropy_unsupported(&relay_url);
        }

        None
    }
}
