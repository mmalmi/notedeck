use egui::{RichText, ScrollArea, Vec2};
use notedeck::{tr, Localization, get_chat_key, ChatMessages};
use notedeck_ui::ProfilePic;
use nostrdb::{Ndb, Transaction};
use nostr_double_ratchet::SessionManager;
use std::sync::Arc;

pub struct ChatView<'a> {
    i18n: &'a mut Localization,
    img_cache: &'a mut notedeck::Images,
    ndb: &'a Ndb,
    chat_id: String,
    session_manager: &'a Option<Arc<SessionManager>>,
    chat_messages: &'a ChatMessages,
}

impl<'a> ChatView<'a> {
    pub fn new(
        i18n: &'a mut Localization,
        img_cache: &'a mut notedeck::Images,
        ndb: &'a Ndb,
        chat_id: String,
        session_manager: &'a Option<Arc<SessionManager>>,
        chat_messages: &'a ChatMessages,
    ) -> Self {
        Self {
            i18n,
            img_cache,
            ndb,
            chat_id,
            session_manager,
            chat_messages,
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            self.render_header(ui);

            let input_height = 60.0;
            let remaining = ui.available_height();
            let messages_height = remaining - input_height;

            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), messages_height),
                egui::Layout::bottom_up(egui::Align::Min),
                |ui| {
                    ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                                ui.add_space(8.0);

                                // Get messages for this chat
                                let chat_pk = hex::decode(&self.chat_id)
                                    .ok()
                                    .and_then(|bytes| {
                                        if bytes.len() == 32 {
                                            let mut arr = [0u8; 32];
                                            arr.copy_from_slice(&bytes);
                                            Some(enostr::Pubkey::new(arr))
                                        } else {
                                            None
                                        }
                                    });

                                if let Some(pk) = chat_pk {
                                    let chat_key = get_chat_key(&pk);
                                    let messages = self.chat_messages
                                        .lock()
                                        .unwrap()
                                        .get(&chat_key)
                                        .cloned()
                                        .unwrap_or_default();

                                    if messages.is_empty() {
                                        ui.centered_and_justified(|ui| {
                                            ui.label(
                                                egui::RichText::new("No messages yet")
                                                    .size(14.0)
                                                    .color(ui.visuals().weak_text_color()),
                                            );
                                        });
                                    } else {
                                        let our_pubkey = self.session_manager.as_ref().map(|m| m.get_our_pubkey());
                                        for msg in &messages {
                                            let is_sent = our_pubkey.map_or(false, |our_pk| msg.sender == our_pk);

                                            // Try to parse as JSON rumor first, fallback to plain text
                                            let content = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&msg.content) {
                                                parsed["content"].as_str().unwrap_or(&msg.content).to_string()
                                            } else {
                                                msg.content.clone()
                                            };

                                            self.render_message(ui, &content, is_sent);
                                            ui.add_space(8.0);
                                        }
                                    }
                                } else {
                                    ui.centered_and_justified(|ui| {
                                        ui.label(
                                            egui::RichText::new("Invalid chat ID")
                                                .size(14.0)
                                                .color(ui.visuals().weak_text_color()),
                                        );
                                    });
                                }
                            });
                        });
                },
            );

            self.render_input(ui);
        });
    }

    fn render_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(8.0);

            let pfp_size = 36.0;

            let (profile_url, display_name): (String, String) = match hex::decode(&self.chat_id) {
                Ok(pubkey_bytes) if pubkey_bytes.len() == 32 => {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&pubkey_bytes);
                    match Transaction::new(self.ndb) {
                        Ok(txn) => {
                            match self.ndb.get_profile_by_pubkey(&txn, &bytes) {
                                Ok(profile) => {
                                    let url = notedeck::profile::get_profile_url(Some(&profile)).to_string();
                                    let name = notedeck::name::get_display_name(Some(&profile));
                                    (url, name.name().to_string())
                                }
                                Err(_) => {
                                    (notedeck::profile::no_pfp_url().to_string(), format!("{}...", &self.chat_id[..16]))
                                }
                            }
                        }
                        Err(_) => {
                            (notedeck::profile::no_pfp_url().to_string(), format!("{}...", &self.chat_id[..16]))
                        }
                    }
                }
                _ => {
                    (notedeck::profile::no_pfp_url().to_string(), self.chat_id.clone())
                }
            };

            ui.add(&mut ProfilePic::new(self.img_cache, &profile_url).size(pfp_size));

            ui.add_space(8.0);

            ui.vertical(|ui| {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(display_name)
                        .size(16.0)
                        .strong(),
                );
            });
        });

        ui.add_space(8.0);
    }

    fn render_message(&mut self, ui: &mut egui::Ui, content: &str, is_sent: bool) {
        let margin = 16.0;
        let max_width = (ui.available_width() - margin * 2.0) * 0.7;

        if is_sent {
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                    ui.add_space(margin);
                    self.render_message_bubble(ui, content, max_width, true);
                });
            });
        } else {
            ui.horizontal(|ui| {
                ui.add_space(margin);
                self.render_message_bubble(ui, content, max_width, false);
                ui.add_space(margin);
            });
        }
    }

    fn render_message_bubble(&self, ui: &mut egui::Ui, content: &str, max_width: f32, is_sent: bool) {
        let bg_color = if is_sent {
            egui::Color32::from_rgb(88, 86, 214)
        } else {
            if ui.visuals().dark_mode {
                egui::Color32::from_rgb(40, 40, 45)
            } else {
                egui::Color32::from_rgb(240, 240, 245)
            }
        };

        let text_color = if is_sent {
            egui::Color32::WHITE
        } else {
            ui.visuals().text_color()
        };

        egui::Frame::new()
            .fill(bg_color)
            .corner_radius(12.0)
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.set_max_width(max_width);
                ui.label(RichText::new(content).size(14.0).color(text_color));
            });
    }

    fn render_input(&mut self, ui: &mut egui::Ui) {
        let margin = 16;
        let frame = egui::Frame::new()
            .inner_margin(egui::Margin {
                left: margin,
                right: margin,
                top: 0,
                bottom: margin,
            });

        frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                let input_id = ui.id().with(("chat_input", &self.chat_id));
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
                    .corner_radius(20.0)
                    .inner_margin(egui::Margin {
                        left: 16,
                        right: 16,
                        top: 10,
                        bottom: 10,
                    });

                let focus_id = ui.id().with(("chat_input_focus_state", &self.chat_id));
                let mut focus_state = ui.ctx().data(|d| {
                    d.get_temp::<crate::ui::search::FocusState>(focus_id)
                        .unwrap_or(crate::ui::search::FocusState::ShouldRequestFocus)
                });

                let text_resp = input_frame.show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut input_text)
                            .hint_text(tr!(
                                self.i18n,
                                "Type a message...",
                                "Placeholder for chat input"
                            ))
                            .desired_width(ui.available_width())
                            .frame(false)
                    )
                }).inner;

                if focus_state == crate::ui::search::FocusState::ShouldRequestFocus {
                    text_resp.request_focus();
                    focus_state = crate::ui::search::FocusState::RequestedFocus;
                } else if focus_state == crate::ui::search::FocusState::RequestedFocus {
                    focus_state = crate::ui::search::FocusState::Navigating;
                }

                ui.ctx().data_mut(|d| d.insert_temp(focus_id, focus_state));

                ui.ctx().data_mut(|d| {
                    d.insert_temp(input_id, input_text.clone());
                });

                ui.add_space(8.0);

                let send_button_size = 32.0;
                let (rect, send_resp) = ui.allocate_exact_size(
                    Vec2::splat(send_button_size),
                    egui::Sense::click()
                );

                let circle_color = if input_text.trim().is_empty() {
                    if ui.visuals().dark_mode {
                        egui::Color32::from_rgb(60, 60, 65)
                    } else {
                        egui::Color32::from_rgb(200, 200, 205)
                    }
                } else {
                    egui::Color32::from_rgb(88, 86, 214)
                };

                ui.painter().circle_filled(rect.center(), send_button_size / 2.0, circle_color);

                let arrow_size = 12.0;
                let arrow_center = rect.center();
                let arrow_points = [
                    egui::pos2(arrow_center.x - arrow_size / 3.0, arrow_center.y + arrow_size / 2.5),
                    egui::pos2(arrow_center.x, arrow_center.y - arrow_size / 2.5),
                    egui::pos2(arrow_center.x + arrow_size / 3.0, arrow_center.y + arrow_size / 2.5),
                ];

                ui.painter().line_segment(
                    [arrow_points[0], arrow_points[1]],
                    egui::Stroke::new(2.0, egui::Color32::WHITE),
                );
                ui.painter().line_segment(
                    [arrow_points[1], arrow_points[2]],
                    egui::Stroke::new(2.0, egui::Color32::WHITE),
                );
                ui.painter().line_segment(
                    [arrow_points[1], egui::pos2(arrow_points[1].x, arrow_center.y + arrow_size / 3.0)],
                    egui::Stroke::new(2.0, egui::Color32::WHITE),
                );

                let should_send = (text_resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    || send_resp.clicked();

                if should_send && !input_text.trim().is_empty() {
                    if let Some(manager) = self.session_manager {
                        if let Ok(pubkey_bytes) = hex::decode(&self.chat_id) {
                            if pubkey_bytes.len() == 32 {
                                let mut bytes = [0u8; 32];
                                bytes.copy_from_slice(&pubkey_bytes);
                                let recipient = enostr::Pubkey::new(bytes);

                                // Optimistically store the message locally
                                let our_pubkey = manager.get_our_pubkey();
                                let chat_key = get_chat_key(&recipient);
                                let msg = notedeck::ChatMessage {
                                    sender: our_pubkey,
                                    content: input_text.clone(),
                                    timestamp: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs(),
                                    event_id: None,
                                };

                                self.chat_messages
                                    .lock()
                                    .unwrap()
                                    .entry(chat_key)
                                    .or_insert_with(Vec::new)
                                    .push(msg);

                                match manager.send_text(recipient, input_text.clone()) {
                                    Ok(event_ids) => {
                                        if event_ids.is_empty() {
                                            tracing::warn!("No active sessions with {}. Message queued for when session establishes.", &self.chat_id);
                                        } else {
                                            tracing::info!("Sent {} messages to {}", event_ids.len(), &self.chat_id);
                                        }
                                        ui.ctx().data_mut(|d| {
                                            d.insert_temp(input_id, String::new());
                                        });
                                        // Keep focus in input after send
                                        let focus_id = ui.id().with(("chat_input_focus_state", &self.chat_id));
                                        ui.ctx().data_mut(|d| d.insert_temp(focus_id, crate::ui::search::FocusState::ShouldRequestFocus));
                                    }
                                    Err(e) => {
                                        tracing::error!("Failed to send message: {}", e);
                                    }
                                }
                            }
                        }
                    } else {
                        tracing::warn!("SessionManager not initialized, cannot send message");
                    }
                }
            });
        });
    }
}

