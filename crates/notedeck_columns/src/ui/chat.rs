use egui::{RichText, ScrollArea, Vec2};
use notedeck::{tr, Localization};
use notedeck_ui::ProfilePic;
use nostr_double_ratchet::SessionManager;
use std::sync::Arc;
use nostrdb::{Ndb, Transaction};

pub struct ChatView<'a> {
    i18n: &'a mut Localization,
    img_cache: &'a mut notedeck::Images,
    ndb: &'a Ndb,
    chat_id: String,
    session_manager: &'a Option<Arc<SessionManager>>,
}

impl<'a> ChatView<'a> {
    pub fn new(
        i18n: &'a mut Localization,
        img_cache: &'a mut notedeck::Images,
        ndb: &'a Ndb,
        chat_id: String,
        session_manager: &'a Option<Arc<SessionManager>>,
    ) -> Self {
        Self {
            i18n,
            img_cache,
            ndb,
            chat_id,
            session_manager,
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

                                // TODO: get actual messages from SessionManager
                                // For now, show empty state
                                ui.centered_and_justified(|ui| {
                                    ui.label(
                                        egui::RichText::new("No messages yet")
                                            .size(14.0)
                                            .color(ui.visuals().weak_text_color()),
                                    );
                                });
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
                                match manager.send_text(recipient, input_text.clone()) {
                                    Ok(event_ids) => {
                                        if event_ids.is_empty() {
                                            tracing::warn!("No active sessions with {}. Waiting for handshake.", &self.chat_id);
                                        } else {
                                            tracing::info!("Sent {} messages to {}", event_ids.len(), &self.chat_id);
                                            ui.ctx().data_mut(|d| {
                                                d.insert_temp(input_id, String::new());
                                            });
                                        }
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

