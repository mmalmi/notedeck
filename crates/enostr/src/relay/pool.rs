use crate::relay::{setup_multicast_relay, MulticastRelay, Relay, RelayStatus};
use crate::relay::webrtc::WebRTCRelay;
use crate::relay::negentropy::NegentropyManager;
use crate::{ClientMessage, Error, Result};
use nostrdb::Filter;

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use url::Url;

use ewebsock::{WsEvent, WsMessage};
use tracing::{debug, error, trace};

use super::subs_debug::SubsDebug;

/// Check if a filter is suitable for negentropy sync
fn should_use_negentropy(filter: &Filter) -> bool {
    // Check if has ids filter (only called once per subscription, minimal overhead)
    if let Ok(json) = filter.json() {
        if json.contains("\"ids\"") {
            return false;
        }
    }

    // Use negentropy if no limit or limit >= 20
    // Small limits are faster with traditional REQ
    filter.limit().map_or(true, |limit| limit >= 20)
}

#[derive(Debug)]
pub struct PoolEvent<'a> {
    pub relay: &'a str,
    pub event: ewebsock::WsEvent,
}

impl PoolEvent<'_> {
    pub fn into_owned(self) -> PoolEventBuf {
        PoolEventBuf {
            relay: self.relay.to_owned(),
            event: self.event,
        }
    }
}

pub struct PoolEventBuf {
    pub relay: String,
    pub event: ewebsock::WsEvent,
}

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
    #[allow(dead_code)] // Will be used for handling NEG-MSG responses
    negentropy_managers: HashMap<String, NegentropyManager>, // relay_url -> manager
    use_negentropy: bool,
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

    /// Close negentropy sync for a subscription on a relay
    pub fn close_negentropy_sync(&mut self, relay_url: &str, sub_id: &str) {
        if let Some(manager) = self.negentropy_managers.get_mut(relay_url) {
            manager.close_sync(sub_id);
        }
    }

    /// Process binary NEG-MSG response
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
        for relay in &mut self.relays {
            let relay_url = relay.url().to_owned();

            // Try negentropy if enabled and this is a websocket relay
            let use_neg = try_negentropy && matches!(relay, PoolRelay::Websocket(_));

            let msg = if use_neg && !filter.is_empty() {
                // Check if suitable for negentropy:
                // - Single filter only
                // - No ids filter (negentropy is for discovery, not fetching specific events)
                // - No limit or limit >= 20 (small limits are faster with REQ)
                if filter.len() == 1 && should_use_negentropy(&filter[0]) {
                    debug!("using negentropy for subscription {} on {}", subid, relay_url);
                    ClientMessage::neg_open(subid.clone(), filter[0].clone(), None)
                } else {
                    if filter.len() > 1 {
                        debug!("falling back to REQ for multi-filter subscription {} on {}", subid, relay_url);
                    } else if !filter.is_empty() {
                        debug!("falling back to REQ for subscription {} (ids filter or small limit) on {}", subid, relay_url);
                    }
                    ClientMessage::req(subid.clone(), filter.clone())
                }
            } else {
                ClientMessage::req(subid.clone(), filter.clone())
            };

            if let Some(debug) = &mut self.debug {
                debug.send_cmd(relay_url.clone(), &msg);
            }

            if let Err(err) = relay.send(&msg) {
                error!("error subscribing to {}: {err}", relay_url);
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
    pub fn try_recv(&mut self) -> Option<PoolEvent<'_>> {
        for relay in &mut self.relays {
            if let PoolRelay::Multicast(mcr) = relay {
                // try rejoin on multicast
                if mcr.should_rejoin() {
                    if let Err(err) = mcr.rejoin() {
                        error!("multicast: rejoin error: {err}");
                    }
                }
            }

            if let Some(event) = relay.try_recv() {
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
                        // Handle pings
                        #[cfg(not(target_arch = "wasm32"))]
                        if let WsMessage::Ping(ref bs) = ev {
                            trace!("pong {}", relay.url());
                            match relay {
                                PoolRelay::Websocket(wsr) => {
                                    wsr.relay.sender.send(WsMessage::Pong(bs.to_owned()));
                                }
                                PoolRelay::Multicast(_mcr) => {}
                                PoolRelay::WebRTC(_) => {}
                            }
                        }

                        // Handle binary negentropy messages
                        if let WsMessage::Binary(ref data) = ev {
                            if self.use_negentropy {
                                debug!("received binary NEG-MSG ({} bytes) from {}", data.len(), relay.url());
                                // Binary NEG-MSG responses are passed through to the application
                                // The application layer will need to:
                                // 1. Match this to the active subscription
                                // 2. Call negentropy_manager.reconcile()
                                // 3. Send next NEG-MSG or fetch missing events
                            }
                        }
                    }
                }

                if let Some(debug) = &mut self.debug {
                    debug.receive_cmd(relay.url().to_owned(), (&event).into());
                }

                let pool_event = PoolEvent {
                    event,
                    relay: relay.url(),
                };

                return Some(pool_event);
            }
        }

        None
    }
}
