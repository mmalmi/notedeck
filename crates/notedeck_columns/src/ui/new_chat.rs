use egui::{RichText, Vec2};
use notedeck::{Localization, Images};
use nostr_double_ratchet::SessionManager;
use nostrdb::Ndb;
use std::sync::Arc;
use crate::ui::profile_search_dropdown::ProfileSearchDropdown;

pub struct NewChatView<'a> {
    #[allow(dead_code)]
    i18n: &'a mut Localization,
    session_manager: &'a Option<Arc<SessionManager>>,
    ndb: &'a Ndb,
    img_cache: &'a mut Images,
    accounts: &'a notedeck::Accounts,
}

impl<'a> NewChatView<'a> {
    pub fn new(
        i18n: &'a mut Localization,
        session_manager: &'a Option<Arc<SessionManager>>,
        ndb: &'a Ndb,
        img_cache: &'a mut Images,
        accounts: &'a notedeck::Accounts,
    ) -> Self {
        Self {
            i18n,
            session_manager,
            ndb,
            img_cache,
            accounts,
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<NewChatAction> {
        let mut action = None;

        ui.vertical_centered(|ui| {
            ui.add_space(40.0);

            ui.label(
                RichText::new("Start New Chat")
                    .size(24.0)
                    .strong(),
            );

            ui.add_space(20.0);

            ui.label(
                RichText::new("Search")
                    .size(14.0)
                    .color(ui.visuals().weak_text_color()),
            );

            ui.add_space(12.0);

            let input_id = ui.id().with("new_chat_input");
            let mut input_text = ui.ctx().data_mut(|d| {
                d.get_temp::<String>(input_id).unwrap_or_default()
            });

            let bg_color = if ui.visuals().dark_mode {
                egui::Color32::from_rgb(40, 40, 45)
            } else {
                egui::Color32::from_rgb(245, 245, 250)
            };

            let input_frame = egui::Frame::new()
                .fill(bg_color)
                .corner_radius(8.0)
                .inner_margin(12.0);

            let focus_id = ui.id().with("new_chat_focus_state");
            let mut focus_state = ui.ctx().data(|d| {
                d.get_temp::<crate::ui::search::FocusState>(focus_id)
                    .unwrap_or(crate::ui::search::FocusState::ShouldRequestFocus)
            });

            let text_resp = input_frame.show(ui, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut input_text)
                        .hint_text("Search")
                        .desired_width(ui.available_width().min(400.0))
                        .font(egui::TextStyle::Body)
                )
            }).inner;

            if focus_state == crate::ui::search::FocusState::ShouldRequestFocus {
                text_resp.request_focus();
                focus_state = crate::ui::search::FocusState::RequestedFocus;
            } else if focus_state == crate::ui::search::FocusState::RequestedFocus {
                focus_state = crate::ui::search::FocusState::Navigating;
            }

            ui.ctx().data_mut(|d| {
                d.insert_temp(focus_id, focus_state);
                d.insert_temp(input_id, input_text.clone());
            });

            // Show search dropdown if typing and not a valid pubkey
            if !input_text.trim().is_empty() && parse_pubkey(&input_text).is_none() {
                ui.add_space(8.0);
                let our_pubkey = self.accounts.selected_account_pubkey();
                let selected_index_id = ui.id().with("new_chat_selected_index");
                let mut selected_index = ui.ctx().data(|d| d.get_temp::<i32>(selected_index_id).unwrap_or(0));

                // Handle arrow key navigation
                if ui.input(|i| i.key_pressed(egui::Key::ArrowDown) || i.key_pressed(egui::Key::ArrowUp)) {
                    text_resp.surrender_focus();
                }

                let mut dropdown = ProfileSearchDropdown::new(self.ndb, self.img_cache, our_pubkey, self.accounts);
                if let Some(pubkey_hex) = dropdown.show(ui, &input_text, &mut selected_index, 400.0) {
                    action = Some(NewChatAction::ChatStarted(pubkey_hex));
                }

                ui.ctx().data_mut(|d| d.insert_temp(selected_index_id, selected_index));
            }

            ui.add_space(16.0);

            let button_enabled = !input_text.trim().is_empty();
            let button_color = if button_enabled {
                notedeck::theme::PURPLE
            } else {
                if ui.visuals().dark_mode {
                    egui::Color32::from_rgb(60, 60, 65)
                } else {
                    egui::Color32::from_rgb(200, 200, 205)
                }
            };

            let button_resp = ui.add_enabled(
                button_enabled,
                egui::Button::new(
                    RichText::new("Start Chat")
                        .size(16.0)
                        .color(egui::Color32::WHITE)
                )
                .fill(button_color)
                .min_size(Vec2::new(120.0, 40.0))
                .corner_radius(8.0)
            );

            let should_start = (text_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                || button_resp.clicked();

            if should_start && button_enabled {
                if let Some(pubkey_hex) = parse_pubkey(&input_text) {
                    if let Some(manager) = self.session_manager {
                        if let Ok(pubkey_bytes) = hex::decode(&pubkey_hex) {
                            if pubkey_bytes.len() == 32 {
                                let mut bytes = [0u8; 32];
                                bytes.copy_from_slice(&pubkey_bytes);
                                let recipient = enostr::Pubkey::new(bytes);

                                match manager.setup_user(recipient) {
                                    Ok(_) => {
                                        tracing::info!("Started chat setup with {}", pubkey_hex);
                                        // Try to send empty message to create user record
                                        let _ = manager.send_text(recipient, "".to_string());
                                        action = Some(NewChatAction::ChatStarted(pubkey_hex));
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to setup chat: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            ui.add_space(20.0);

            if let Some(error_msg) = validate_input(&input_text) {
                ui.label(
                    RichText::new(error_msg)
                        .size(12.0)
                        .color(egui::Color32::from_rgb(220, 80, 80)),
                );
            }
        });

        action
    }
}

pub enum NewChatAction {
    ChatStarted(String),
}

fn parse_pubkey(input: &str) -> Option<String> {
    let trimmed = input.trim();

    if trimmed.starts_with("npub1") {
        if let Ok((_, pubkey_bytes)) = bech32::decode(trimmed) {
            return Some(hex::encode(pubkey_bytes));
        }
    }

    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(trimmed.to_lowercase());
    }

    None
}

fn validate_input(input: &str) -> Option<&'static str> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return None;
    }

    if trimmed.starts_with("npub1") {
        if bech32::decode(trimmed).is_err() {
            return Some("Invalid npub format");
        }
    }

    None
}
