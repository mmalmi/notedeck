use crate::account::FALLBACK_PUBKEY;
use crate::i18n::Localization;
use crate::persist::{AppSizeHandler, SettingsHandler};
use crate::wallet::GlobalWallet;
use crate::zaps::Zaps;
use crate::Error;
use crate::JobPool;
use crate::NotedeckOptions;
use crate::{
    frame_history::FrameHistory, AccountStorage, Accounts, AppContext, Args, DataPath,
    DataPathType, Directory, Images, NoteAction, NoteCache, RelayDebugView, UnknownIds,
};
use egui::Margin;
use egui::ThemePreference;
use egui_winit::clipboard::Clipboard;
use enostr::{RelayPool, Pubkey};
use nostrdb::{Config, Ndb, Transaction};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use tracing::{error, info};
use unic_langid::{LanguageIdentifier, LanguageIdentifierError};
use nostr_double_ratchet::{SessionManager, DebouncedFileStorage, SessionManagerEvent};
use crossbeam_channel::Receiver;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChatMessage {
    #[serde(serialize_with = "serialize_pubkey", deserialize_with = "deserialize_pubkey")]
    pub sender: Pubkey,
    pub content: String,
    pub timestamp: u64,
    pub event_id: Option<String>,
}

fn serialize_pubkey<S>(pubkey: &Pubkey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(pubkey.bytes()))
}

fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<Pubkey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let s = String::deserialize(deserializer)?;
    let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
    if bytes.len() != 32 {
        return Err(serde::de::Error::custom("Invalid pubkey length"));
    }
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&bytes);
    Ok(Pubkey::new(pk_bytes))
}

pub type ChatMessages = Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>;

pub fn get_chat_key(user_pk: &Pubkey) -> String {
    hex::encode(user_pk.bytes())
}

fn chat_messages_path(data_path: &DataPath, account_pubkey: &Pubkey) -> std::path::PathBuf {
    let account_hex = hex::encode(account_pubkey.bytes());
    data_path.path(DataPathType::Cache)
        .join("chat-messages")
        .join(format!("{}.json", account_hex))
}

fn save_chat_messages(
    chat_messages: &ChatMessages,
    data_path: &DataPath,
    account_pubkey: &Pubkey,
) {
    let path = chat_messages_path(data_path, account_pubkey);

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let messages = chat_messages.lock().unwrap().clone();

    match serde_json::to_string_pretty(&messages) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                error!("Failed to save chat messages: {}", e);
            }
        }
        Err(e) => {
            error!("Failed to serialize chat messages: {}", e);
        }
    }
}

fn load_chat_messages(
    data_path: &DataPath,
    account_pubkey: &Pubkey,
) -> HashMap<String, Vec<ChatMessage>> {
    let path = chat_messages_path(data_path, account_pubkey);

    match std::fs::read_to_string(&path) {
        Ok(json) => {
            match serde_json::from_str(&json) {
                Ok(messages) => messages,
                Err(e) => {
                    error!("Failed to deserialize chat messages: {}", e);
                    HashMap::new()
                }
            }
        }
        Err(_) => HashMap::new(), // File doesn't exist yet
    }
}

#[cfg(target_os = "android")]
use android_activity::AndroidApp;

pub enum AppAction {
    Note(NoteAction),
    ToggleChrome,
    SwitchToDave,
}

pub trait App {
    fn update(&mut self, ctx: &mut AppContext<'_>, ui: &mut egui::Ui) -> AppResponse;
}

/// Setup WebRTC signaling subscription for mutual follows + self
pub fn setup_webrtc_signaling_subscription(
    pool: &mut RelayPool,
    ndb: &Ndb,
    txn: &Transaction,
    our_pubkey: &[u8; 32],
) {
    use enostr::MutualFollowDetector;

    info!("Setting up WebRTC signaling subscription");

    // Get mutual follows
    let detector = MutualFollowDetector::new(ndb.clone());
    let mut mutual_follows = detector.get_mutual_follows(txn, our_pubkey);

    // Add self to receive own messages from other devices (iris-compatible)
    mutual_follows.push(*our_pubkey);

    info!("Subscribing to WebRTC signaling for {} peers (including self)", mutual_follows.len());

    // Create filter for kind 30078 with #l="webrtc" from mutual follows + self
    // iris-client subscribes with: kinds: [30078], "#l": ["webrtc"], authors: [mutual_follows + self], since: now - 15s
    let filter = enostr::Filter::new()
        .kinds(vec![30078])
        .authors(mutual_follows.iter())
        .tags(["webrtc"], 'l') // #l="webrtc" tag
        .since(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 15) // Last 15 seconds like iris
        .build();

    let subid = "webrtc-signaling".to_string();

    // Subscribe to all relays
    pool.subscribe(subid, vec![filter]);

    info!("WebRTC signaling subscription active");
}

/// Publish a WebRTC signaling message
/// iris-client compatible: kind 30078, #l="webrtc", with d and expiration tags
///
/// Hello messages are always plaintext (broadcast)
/// Signaling messages (offer/answer/candidate) are encrypted with NIP-44 to recipient
pub fn publish_webrtc_signaling<'a>(
    pool: &mut RelayPool,
    keypair: &enostr::FilledKeypair<'a>,
    message: &enostr::SignalingMessage,
    recipient_pubkey: Option<&[u8; 32]>,
) -> Result<(), String> {
    use uuid::Uuid;
    use enostr::SignalingType;

    // Serialize message to JSON
    let plaintext_content = message.to_json().map_err(|e| format!("Failed to serialize message: {}", e))?;

    tracing::info!("WebRTC signaling JSON: {}", plaintext_content);

    // Determine if encryption is needed
    // Hello messages are always plaintext (broadcast)
    // Signaling messages (offer/answer/candidate) are encrypted with NIP-44
    let should_encrypt = matches!(message.msg_type,
        SignalingType::Offer { .. } |
        SignalingType::Answer { .. } |
        SignalingType::Candidate { .. }
    );

    // Encrypt content if needed
    let content = if should_encrypt {
        if let Some(recipient) = recipient_pubkey {
            // Encrypt with NIP-44
            let secret_key = nostr::SecretKey::from_slice(keypair.secret_key.as_secret_bytes())
                .map_err(|e| format!("Invalid secret key: {}", e))?;
            let recipient_pk = nostr::PublicKey::from_slice(recipient)
                .map_err(|e| format!("Invalid recipient pubkey: {}", e))?;

            nostr::nips::nip44::encrypt(&secret_key, &recipient_pk, &plaintext_content, nostr::nips::nip44::Version::V2)
                .map_err(|e| format!("Failed to encrypt message: {}", e))?
        } else {
            return Err("Signaling messages require recipient pubkey for encryption".to_string());
        }
    } else {
        plaintext_content
    };

    // Create nostr event
    let secret_key = nostr::SecretKey::from_slice(keypair.secret_key.as_secret_bytes())
        .map_err(|e| format!("Invalid secret key: {}", e))?;
    let keys = nostr::Keys::new(secret_key);

    // Build event with iris-compatible tags
    // Note: No 'p' tag even for encrypted messages to preserve privacy
    // Recipients try to decrypt all messages to see if they're for them
    let event_builder = nostr::EventBuilder::new(
        nostr::Kind::from(30078), // APP_DATA
        content,
    )
    .tag(nostr::Tag::custom(
        nostr::TagKind::Custom(std::borrow::Cow::Borrowed("l")),
        vec!["webrtc"],
    ))
    .tag(nostr::Tag::custom(
        nostr::TagKind::Custom(std::borrow::Cow::Borrowed("d")),
        vec![&Uuid::new_v4().to_string()],
    ))
    .tag(nostr::Tag::custom(
        nostr::TagKind::Custom(std::borrow::Cow::Borrowed("expiration")),
        vec![&(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 15).to_string()], // 15s expiration like iris
    ));

    let event = event_builder.sign_with_keys(&keys)
        .map_err(|e| format!("Failed to sign event: {}", e))?;

    // Publish to all relays
    use nostr::JsonUtil;
    let json = event.as_json();
    tracing::info!("WebRTC event JSON: {}", json);
    let msg = enostr::ClientMessage::event_json(json)
        .map_err(|e| format!("Failed to create client message: {}", e))?;
    pool.send(&msg);

    info!("Published WebRTC signaling message: {:?}", message.msg_type);
    Ok(())
}

#[derive(Default)]
pub struct AppResponse {
    pub action: Option<AppAction>,
    pub can_take_drag_from: Vec<egui::Id>,
}

impl AppResponse {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn action(action: Option<AppAction>) -> Self {
        Self {
            action,
            can_take_drag_from: Vec::new(),
        }
    }

    pub fn drag(mut self, can_take_drag_from: Vec<egui::Id>) -> Self {
        self.can_take_drag_from.extend(can_take_drag_from);
        self
    }
}

/// Main notedeck app framework
pub struct Notedeck {
    ndb: Ndb,
    img_cache: Images,
    unknown_ids: UnknownIds,
    pool: RelayPool,
    note_cache: NoteCache,
    accounts: Accounts,
    global_wallet: GlobalWallet,
    path: DataPath,
    args: Args,
    settings: SettingsHandler,
    app: Option<Rc<RefCell<dyn App>>>,
    app_size: AppSizeHandler,
    unrecognized_args: BTreeSet<String>,
    clipboard: Clipboard,
    zaps: Zaps,
    frame_history: FrameHistory,
    job_pool: JobPool,
    i18n: Localization,
    session_manager: Option<Arc<SessionManager>>,
    session_event_rx: Option<Receiver<SessionManagerEvent>>,
    session_event_tx: Option<crossbeam_channel::Sender<SessionManagerEvent>>,
    chat_messages: ChatMessages,
    session_subscriptions: HashSet<String>,
    test_dm_sent: bool,
    event_broker: crate::event_broker::EventBroker,
    #[cfg(target_os = "android")]
    android_app: Option<AndroidApp>,
}

/// Our chrome, which is basically nothing
fn main_panel(style: &egui::Style) -> egui::CentralPanel {
    egui::CentralPanel::default().frame(egui::Frame {
        inner_margin: Margin::ZERO,
        fill: style.visuals.panel_fill,
        ..Default::default()
    })
}

fn render_notedeck(notedeck: &mut Notedeck, ctx: &egui::Context) {
    main_panel(&ctx.style()).show(ctx, |ui| {
        // render app
        let Some(app) = &notedeck.app else {
            return;
        };

        let app = app.clone();
        app.borrow_mut().update(&mut notedeck.app_context(), ui);

        // Move the screen up when we have a virtual keyboard
        // NOTE: actually, we only want to do this if the keyboard is covering the focused element?
        /*
        let keyboard_height = crate::platform::virtual_keyboard_height() as f32;
        if keyboard_height > 0.0 {
            ui.ctx().transform_layer_shapes(
                ui.layer_id(),
                egui::emath::TSTransform::from_translation(egui::Vec2::new(0.0, -(keyboard_height/2.0))),
            );
        }
        */
    });
}

impl eframe::App for Notedeck {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        profiling::finish_frame!();
        self.frame_history
            .on_new_frame(ctx.input(|i| i.time), frame.info().cpu_usage);

        // handle account updates
        self.accounts.update(&mut self.ndb, &mut self.pool, ctx);

        self.zaps
            .process(&mut self.accounts, &mut self.global_wallet, &self.ndb);

        // Send test DM if requested
        if !self.test_dm_sent {
            if let Some(recipient) = self.args.test_dm_recipient {
                if let Some(manager) = &self.session_manager {
                    info!("Sending test DM to {}", hex::encode(recipient.bytes()));
                    match manager.send_text(recipient, "Test DM from --test-dm flag".to_string()) {
                        Ok(event_ids) => {
                            info!("Test DM sent: {} events", event_ids.len());
                            self.test_dm_sent = true;
                        }
                        Err(e) => {
                            error!("Failed to send test DM: {}", e);
                            self.test_dm_sent = true; // Don't retry
                        }
                    }
                }
            }
        }

        // process session manager events
        if let Some(rx) = &self.session_event_rx {
            if let Some(manager) = &self.session_manager {
                while let Ok(event) = rx.try_recv() {
                    match event {
                        SessionManagerEvent::Publish(unsigned_event) => {
                            if let Some(kp) = self.accounts.get_selected_account().key.to_full() {
                                if let Ok(secret_key) = nostr::SecretKey::from_slice(kp.secret_key.as_secret_bytes()) {
                                    let keys = nostr::Keys::new(secret_key);
                                    if let Ok(signed) = unsigned_event.sign_with_keys(&keys) {
                                        use nostr::JsonUtil;
                                        let json = signed.as_json();
                                        if let Ok(msg) = enostr::ClientMessage::event_json(json) {
                                            self.pool.send(&msg);
                                            info!("Published session event: kind {}", signed.kind);
                                        }
                                    }
                                }
                            }
                        }
                        SessionManagerEvent::Subscribe(filter_json) => {
                            info!("SessionManager Subscribe request with filter JSON: {}", filter_json);
                            if let Ok(filter) = nostrdb::Filter::from_json(&filter_json) {
                                let subid = format!("session-{}", uuid::Uuid::new_v4());
                                self.pool.subscribe(subid.clone(), vec![filter]);
                                self.session_subscriptions.insert(subid.clone());
                                info!("Subscribed to session filter: {} with filter: {}", subid, filter_json);
                            } else {
                                error!("Failed to parse session filter JSON: {}", filter_json);
                            }
                        }
                        SessionManagerEvent::Unsubscribe(subid) => {
                            info!("SessionManager Unsubscribe request: {}", subid);
                            if self.session_subscriptions.remove(&subid) {
                                self.pool.unsubscribe(subid.clone());
                                info!("Unsubscribed from session filter: {}", subid);
                            }
                        }
                        SessionManagerEvent::ReceivedEvent(event) => {
                            eprintln!("🔄 App processing ReceivedEvent kind {}", event.kind.as_u16());
                            manager.process_received_event(event);
                        }
                        SessionManagerEvent::PublishSigned(signed_event) => {
                            use nostr::JsonUtil;
                            let json = signed_event.as_json();
                            if let Ok(msg) = enostr::ClientMessage::event_json(json) {
                                self.pool.send(&msg);
                                info!("Published signed session event: kind {}", signed_event.kind);
                            }
                        }
                        SessionManagerEvent::DecryptedMessage { sender, content, event_id } => {
                            info!("Decrypted message from {}: {} (event_id: {:?})",
                                hex::encode(sender.bytes()), content, event_id);

                            // Store message in chat_messages
                            let chat_key = get_chat_key(&sender);
                            let msg = ChatMessage {
                                sender,
                                content,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                event_id,
                            };

                            self.chat_messages
                                .lock()
                                .unwrap()
                                .entry(chat_key)
                                .or_insert_with(Vec::new)
                                .push(msg);
                        }
                    }
                }
            }
        }

        // Process relay events through EventBroker
        loop {
            let pool_event = if let Some(ev) = self.pool.try_recv() {
                ev.into_owned()
            } else {
                break;
            };

            use enostr::RelayEvent;
            match (&pool_event.event).into() {
                RelayEvent::Opened => {
                    tracing::info!("Relay opened: {}", pool_event.relay);
                }
                RelayEvent::Closed => {
                    tracing::warn!("{} connection closed", pool_event.relay);
                }
                RelayEvent::Error(e) => {
                    tracing::error!("{}: {}", pool_event.relay, e);
                }
                RelayEvent::Other(_msg) => {
                    // Ignore other events
                }
                RelayEvent::Message(msg) => {
                    self.process_relay_message(&pool_event.relay, &msg);
                }
            }
        }

        render_notedeck(self, ctx);

        self.settings.update_batch(|settings| {
            settings.zoom_factor = ctx.zoom_factor();
            settings.locale = self.i18n.get_current_locale().to_string();
            settings.theme = if ctx.style().visuals.dark_mode {
                ThemePreference::Dark
            } else {
                ThemePreference::Light
            };
        });
        self.app_size.try_save_app_size(ctx);

        if self.args.options.contains(NotedeckOptions::RelayDebug) {
            if self.pool.debug.is_none() {
                self.pool.use_debug();
            }

            if let Some(debug) = &mut self.pool.debug {
                RelayDebugView::window(ctx, debug);
            }
        }

        #[cfg(feature = "puffin")]
        puffin_egui::profiler_window(ctx);
    }

    /// Called by the framework to save state before shutdown.
    fn save(&mut self, _storage: &mut dyn eframe::Storage) {
        //eframe::set_value(storage, eframe::APP_KEY, self);

        // Save chat messages for current account
        let selected_pubkey = self.accounts.get_selected_account().key.pubkey;
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(selected_pubkey.bytes());
        save_chat_messages(&self.chat_messages, &self.path, &Pubkey::new(pk_bytes));
    }
}

#[cfg(feature = "puffin")]
fn setup_puffin() {
    info!("setting up puffin");
    puffin::set_scopes_on(true); // tell puffin to collect data
}

impl Notedeck {
    #[cfg(target_os = "android")]
    pub fn set_android_context(&mut self, context: AndroidApp) {
        self.android_app = Some(context);
    }

    pub fn new<P: AsRef<Path>>(ctx: &egui::Context, data_path: P, args: &[String]) -> Self {
        #[cfg(feature = "puffin")]
        setup_puffin();

        // Skip the first argument, which is the program name.
        let (parsed_args, unrecognized_args) = Args::parse(&args[1..]);

        let data_path = parsed_args
            .datapath
            .clone()
            .unwrap_or(data_path.as_ref().to_str().expect("db path ok").to_string());
        let path = DataPath::new(&data_path);
        let dbpath_str = parsed_args
            .dbpath
            .clone()
            .unwrap_or_else(|| path.path(DataPathType::Db).to_str().unwrap().to_string());

        let _ = std::fs::create_dir_all(&dbpath_str);

        let img_cache_dir = path.path(DataPathType::Cache);
        let _ = std::fs::create_dir_all(img_cache_dir.clone());

        let map_size = if cfg!(target_os = "windows") {
            // 16 Gib on windows because it actually creates the file
            1024usize * 1024usize * 1024usize * 16usize
        } else {
            // 1 TiB for everything else since its just virtually mapped
            1024usize * 1024usize * 1024usize * 1024usize
        };

        let settings = SettingsHandler::new(&path).load();

        let config = Config::new().set_ingester_threads(2).set_mapsize(map_size);

        let keystore = if parsed_args.options.contains(NotedeckOptions::UseKeystore) {
            let keys_path = path.path(DataPathType::Keys);
            let selected_key_path = path.path(DataPathType::SelectedKey);
            Some(AccountStorage::new(
                Directory::new(keys_path),
                Directory::new(selected_key_path),
            ))
        } else {
            None
        };

        // AccountManager will setup the pool on first update
        let mut pool = RelayPool::new();
        {
            let ctx = ctx.clone();
            if let Err(err) = pool.add_multicast_relay(move || ctx.request_repaint()) {
                error!("error setting up multicast relay: {err}");
            }
        }

        // Add WebRTC relay for peer-to-peer connections
        {
            if let Ok(webrtc_relay) = enostr::PoolRelay::webrtc(true) {
                // Clone the relay before pushing to pool for async start
                let relay_to_start = if let enostr::PoolRelay::WebRTC(ref relay) = webrtc_relay {
                    Some(relay.clone())
                } else {
                    None
                };

                pool.relays.push(webrtc_relay);
                info!("WebRTC relay initialized with STUN server");

                // Start the WebRTC relay asynchronously
                if let Some(relay) = relay_to_start {
                    tokio::spawn(async move {
                        let mut relay_mut = relay;
                        if let Err(e) = relay_mut.start().await {
                            error!("Failed to start WebRTC relay: {}", e);
                        } else {
                            info!("WebRTC relay started successfully");
                        }
                    });
                }
            } else {
                error!("Failed to initialize WebRTC relay");
            }
        }

        let mut unknown_ids = UnknownIds::default();
        let mut ndb = Ndb::new(&dbpath_str, &config).expect("ndb");
        let txn = Transaction::new(&ndb).expect("txn");

        let mut accounts = Accounts::new(
            keystore,
            parsed_args.relays.clone(),
            FALLBACK_PUBKEY(),
            &mut ndb,
            &txn,
            &mut pool,
            ctx,
            &mut unknown_ids,
        );

        {
            for key in &parsed_args.keys {
                info!("adding account: {}", &key.pubkey);
                if let Some(resp) = accounts.add_account(key.clone()) {
                    resp.unk_id_action
                        .process_action(&mut unknown_ids, &ndb, &txn);
                }
            }
        }

        if let Some(first) = parsed_args.keys.first() {
            accounts.select_account(&first.pubkey, &mut ndb, &txn, &mut pool, ctx);
        }

        // Set social graph root to selected account
        let selected_pubkey = accounts.get_selected_account().key.pubkey;
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(selected_pubkey.bytes());
        nostrdb::socialgraph::set_root(&ndb, &pk_bytes);

        // Subscribe to WebRTC signaling events for mutual follows
        setup_webrtc_signaling_subscription(&mut pool, &ndb, &txn, &pk_bytes);

        let img_cache = Images::new(img_cache_dir);
        let note_cache = NoteCache::default();

        let app_size = AppSizeHandler::new(&path);

        // migrate
        if let Err(e) = img_cache.migrate_v0() {
            error!("error migrating image cache: {e}");
        }

        let global_wallet = GlobalWallet::new(&path);
        let zaps = Zaps::default();
        let job_pool = JobPool::default();

        // Initialize localization
        let mut i18n = Localization::new();

        let setting_locale: Result<LanguageIdentifier, LanguageIdentifierError> =
            settings.locale().parse();

        if let Ok(setting_locale) = setting_locale {
            if let Err(err) = i18n.set_locale(setting_locale) {
                error!("{err}");
            }
        }

        if let Some(locale) = &parsed_args.locale {
            if let Err(err) = i18n.set_locale(locale.to_owned()) {
                error!("{err}");
            }
        }

        let (session_event_tx, session_event_rx) = crossbeam_channel::unbounded();
        let session_manager = Self::init_session_manager(&path, &accounts, session_event_tx.clone());

        // Load chat messages for the selected account
        let selected_pubkey = accounts.get_selected_account().key.pubkey;
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(selected_pubkey.bytes());
        let loaded_messages = load_chat_messages(&path, &Pubkey::new(pk_bytes));
        let chat_messages = Arc::new(Mutex::new(loaded_messages));

        // Initialize EventBroker
        let mut event_broker = crate::event_broker::EventBroker::new();
        // SessionManagerHandler will be created in notedeck_columns when ready
        // For now, register it for kinds 1059, 1060, 30078
        let session_handler = crate::event_broker::SessionManagerHandler::new(session_event_tx.clone());
        event_broker.subscribe_events("SessionManager", vec![1059, 1060, 30078], session_handler);

        Self {
            ndb,
            img_cache,
            unknown_ids,
            pool,
            note_cache,
            accounts,
            global_wallet,
            path,
            args: parsed_args,
            settings,
            app: None,
            app_size,
            unrecognized_args,
            clipboard: Clipboard::new(None),
            zaps,
            frame_history: FrameHistory::default(),
            job_pool,
            i18n,
            session_manager,
            session_event_rx: Some(session_event_rx),
            session_event_tx: Some(session_event_tx),
            chat_messages,
            session_subscriptions: HashSet::new(),
            test_dm_sent: false,
            event_broker,
            #[cfg(target_os = "android")]
            android_app: None,
        }
    }

    fn init_session_manager(
        path: &DataPath,
        accounts: &Accounts,
        event_tx: crossbeam_channel::Sender<SessionManagerEvent>,
    ) -> Option<Arc<SessionManager>> {
        let selected_account = accounts.get_selected_account();
        let keypair = selected_account.key.to_full()?;
        let pubkey = enostr::Pubkey::new(*keypair.pubkey.bytes());
        let identity_key_bytes = keypair.secret_key.as_secret_bytes();
        let mut identity_key = [0u8; 32];
        identity_key.copy_from_slice(identity_key_bytes);

        let device_id = Self::get_or_create_device_id(path, &pubkey);

        let storage_path = path.path(DataPathType::Cache).join("double-ratchet");
        let storage = match DebouncedFileStorage::new(storage_path, 5000) {
            Ok(s) => Arc::new(s) as Arc<dyn nostr_double_ratchet::StorageAdapter>,
            Err(e) => {
                error!("Failed to create session storage: {}", e);
                return None;
            }
        };

        let manager = SessionManager::new(
            pubkey,
            identity_key,
            device_id,
            event_tx,
            Some(storage),
        );

        if let Err(e) = manager.init() {
            error!("Failed to initialize session manager: {}", e);
            return None;
        }

        Some(Arc::new(manager))
    }

    #[allow(dead_code)]


    fn get_or_create_device_id(path: &DataPath, pubkey: &enostr::Pubkey) -> String {
        let pubkey_hex = hex::encode(pubkey.bytes());
        let device_id_path = path.path(DataPathType::Cache)
            .join("device-ids")
            .join(&pubkey_hex);

        if let Ok(existing_id) = std::fs::read_to_string(&device_id_path) {
            if !existing_id.trim().is_empty() {
                return existing_id.trim().to_string();
            }
        }

        let device_id = uuid::Uuid::new_v4().to_string();

        if let Some(parent) = device_id_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&device_id_path, &device_id);

        device_id
    }

    /// Setup egui context
    pub fn setup(&self, ctx: &egui::Context) {
        // Initialize global i18n context
        //crate::i18n::init_global_i18n(i18n.clone());
        crate::setup::setup_egui_context(
            ctx,
            self.args.options,
            self.theme(),
            self.note_body_font_size(),
            self.zoom_factor(),
        );
    }

    /// ensure we recognized all the arguments
    pub fn check_args(&self, other_app_args: &BTreeSet<String>) -> Result<(), Error> {
        let completely_unrecognized: Vec<String> = self
            .unrecognized_args()
            .intersection(other_app_args)
            .cloned()
            .collect();
        if !completely_unrecognized.is_empty() {
            let err = format!("Unrecognized arguments: {completely_unrecognized:?}");
            tracing::error!("{}", &err);
            return Err(Error::Generic(err));
        }

        Ok(())
    }

    #[inline]
    pub fn options(&self) -> NotedeckOptions {
        self.args.options
    }

    pub fn has_option(&self, option: NotedeckOptions) -> bool {
        self.options().contains(option)
    }

    pub fn app<A: App + 'static>(mut self, app: A) -> Self {
        self.set_app(app);
        self
    }

    pub fn app_context(&mut self) -> AppContext<'_> {
        AppContext {
            ndb: &mut self.ndb,
            img_cache: &mut self.img_cache,
            unknown_ids: &mut self.unknown_ids,
            pool: &mut self.pool,
            note_cache: &mut self.note_cache,
            accounts: &mut self.accounts,
            global_wallet: &mut self.global_wallet,
            path: &self.path,
            args: &self.args,
            settings: &mut self.settings,
            clipboard: &mut self.clipboard,
            zaps: &mut self.zaps,
            frame_history: &mut self.frame_history,
            job_pool: &mut self.job_pool,
            i18n: &mut self.i18n,
            session_manager: &self.session_manager,
            session_event_tx: &self.session_event_tx,
            chat_messages: &self.chat_messages,
            subscriptions: None,
            event_broker: &mut self.event_broker,
            #[cfg(target_os = "android")]
            android: self.android_app.as_ref().unwrap().clone(),
        }
    }

    fn process_relay_message(&mut self, relay: &str, msg: &enostr::RelayMessage) {
        use enostr::RelayMessage;
        use nostr::JsonUtil;

        match msg {
            RelayMessage::Event(_subid, ev) => {
                // Validate event can be parsed before processing
                if nostr::Event::from_json(ev).is_err() {
                    return;
                }

                // Route to EventBroker handlers BEFORE processing into ndb
                let event_json = ev.to_string();
                self.event_broker.process_event(relay, &event_json);

                // Process event into nostrdb
                let relay_obj = if let Some(r) = self.pool.relays.iter().find(|r| r.url() == relay) {
                    r
                } else {
                    tracing::error!("couldn't find relay {} for note processing", relay);
                    return;
                };

                match relay_obj {
                    enostr::PoolRelay::Websocket(_) => {
                        if let Err(err) = self.ndb.process_event_with(
                            ev,
                            nostrdb::IngestMetadata::new()
                                .client(false)
                                .relay(relay),
                        ) {
                            tracing::error!("error processing event {}: {}", ev, err);
                        }
                    }
                    enostr::PoolRelay::Multicast(_) | enostr::PoolRelay::WebRTC(_) => {
                        if let Err(err) = self.ndb.process_event_with(
                            ev,
                            nostrdb::IngestMetadata::new()
                                .client(true)
                                .relay(relay),
                        ) {
                            tracing::error!("error processing client event {}: {}", ev, err);
                        }
                    }
                }
            }
            RelayMessage::Notice(msg) => {
                tracing::warn!("Notice from {}: {}", relay, msg);
            }
            RelayMessage::OK(cr) => {
                tracing::info!("OK from {}: {:?}", relay, cr);
            }
            RelayMessage::Eose(subid) => {
                tracing::trace!("EOSE from {} for subscription {}", relay, subid);
                // Check if this is a session subscription
                if self.session_subscriptions.contains(&subid.to_string()) {
                    tracing::trace!("EOSE for session subscription: {}", subid);
                }
            }
        }
    }

    pub fn set_app<T: App + 'static>(&mut self, app: T) {
        self.app = Some(Rc::new(RefCell::new(app)));
    }

    pub fn args(&self) -> &Args {
        &self.args
    }

    pub fn theme(&self) -> ThemePreference {
        self.settings.theme()
    }

    pub fn note_body_font_size(&self) -> f32 {
        self.settings.note_body_font_size()
    }

    pub fn zoom_factor(&self) -> f32 {
        self.settings.zoom_factor()
    }

    pub fn unrecognized_args(&self) -> &BTreeSet<String> {
        &self.unrecognized_args
    }
}
