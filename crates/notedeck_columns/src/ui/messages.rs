use egui::{Label, RichText, Stroke, Vec2};
use notedeck::theme::PURPLE;
use notedeck_ui::ProfilePic;
use nostr_double_ratchet::SessionManager;
use std::sync::Arc;
use nostrdb::{Ndb, Transaction};

pub struct MessagesView<'a> {
    img_cache: &'a mut notedeck::Images,
    ndb: &'a Ndb,
    session_manager: &'a Option<Arc<SessionManager>>,
}

impl<'a> MessagesView<'a> {
    pub fn new(
        _i18n: &'a mut notedeck::Localization,
        img_cache: &'a mut notedeck::Images,
        ndb: &'a Ndb,
        session_manager: &'a Option<Arc<SessionManager>>,
    ) -> Self {
        Self {
            img_cache,
            ndb,
            session_manager,
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<MessageAction> {
        let mut action = None;

        ui.add_space(8.0);

        if self.session_manager.is_some() {
            let new_chat_resp = self.render_new_chat_button(ui);
            if new_chat_resp.clicked() {
                return Some(MessageAction::NewChat);
            }
            ui.add_space(8.0);
        }

        let conversations = if let Some(manager) = self.session_manager {
            let Ok(txn) = Transaction::new(self.ndb) else {
                return None;
            };

            manager.get_user_pubkeys()
                .iter()
                .map(|pubkey| {
                    let pubkey_hex = hex::encode(pubkey.bytes());

                    let (display_name, profile_pic) = match self.ndb.get_profile_by_pubkey(&txn, pubkey.bytes()) {
                        Ok(profile) => {
                            let name = notedeck::name::get_display_name(Some(&profile)).name().to_string();
                            let pic = notedeck::profile::get_profile_url(Some(&profile)).to_string();
                            (name, pic)
                        }
                        Err(_) => {
                            (format!("{}...", &pubkey_hex[..16]), notedeck::profile::no_pfp_url().to_string())
                        }
                    };

                    MockConversation {
                        pubkey: pubkey_hex,
                        display_name,
                        profile_pic,
                        last_message: "No messages yet".to_string(),
                        timestamp: "".to_string(),
                        unread: false,
                    }
                })
                .collect()
        } else {
            vec![]
        };

        for conversation in conversations {
            let resp = self.render_conversation_item(ui, &conversation)
                .on_hover_cursor(egui::CursorIcon::PointingHand);
            if resp.clicked() {
                action = Some(MessageAction::OpenConversation(conversation.pubkey));
            }
        }

        action
    }

    fn render_conversation_item(
        &mut self,
        ui: &mut egui::Ui,
        conversation: &MockConversation,
    ) -> egui::Response {
        let (rect, resp) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), 72.0),
            egui::Sense::click(),
        );

        if ui.is_rect_visible(rect) {
            let fg_stroke_color = ui.style().interact(&resp).fg_stroke.color;

            let bg_color = if resp.hovered() {
                ui.visuals().widgets.hovered.bg_fill
            } else if conversation.unread {
                if ui.visuals().dark_mode {
                    egui::Color32::from_rgb(30, 30, 35)
                } else {
                    egui::Color32::from_rgb(245, 245, 250)
                }
            } else {
                ui.visuals().window_fill()
            };

            ui.painter().rect_filled(rect, 4.0, bg_color);

            let content_rect = rect.shrink2(Vec2::new(16.0, 12.0));

            let pfp_size = 48.0;
            let pfp_rect = egui::Rect::from_min_size(
                content_rect.left_top(),
                Vec2::new(pfp_size, pfp_size),
            );

            ui.put(pfp_rect, &mut ProfilePic::new(self.img_cache, &conversation.profile_pic)
                .size(pfp_size));

            let text_left = pfp_rect.right() + 12.0;
            let text_rect = egui::Rect::from_min_max(
                egui::pos2(text_left, content_rect.top()),
                content_rect.right_bottom(),
            );

            let mut text_ui = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(text_rect)
                    .layout(*ui.layout())
            );

            text_ui.horizontal(|ui| {
                let name_color = if conversation.unread {
                    ui.visuals().strong_text_color()
                } else {
                    ui.visuals().text_color()
                };

                ui.label(
                    RichText::new(&conversation.display_name)
                        .size(15.0)
                        .color(name_color)
                        .strong(),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(&conversation.timestamp)
                            .size(12.0)
                            .color(ui.visuals().weak_text_color()),
                    );
                });
            });

            text_ui.add_space(4.0);

            text_ui.horizontal(|ui| {
                let preview_color = if conversation.unread {
                    ui.visuals().text_color()
                } else {
                    ui.visuals().weak_text_color()
                };

                let preview_text = if conversation.unread {
                    RichText::new(&conversation.last_message)
                        .size(13.0)
                        .color(preview_color)
                        .strong()
                } else {
                    RichText::new(&conversation.last_message)
                        .size(13.0)
                        .color(preview_color)
                };

                ui.add(Label::new(preview_text).truncate());

                if conversation.unread {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let badge_size = 8.0;
                        let badge_pos = ui.cursor().left_top();
                        ui.painter().circle_filled(
                            egui::pos2(badge_pos.x + badge_size / 2.0, badge_pos.y + 8.0),
                            badge_size / 2.0,
                            PURPLE,
                        );
                    });
                }
            });

            if resp.hovered() {
                ui.painter()
                    .rect_stroke(rect, 4.0, Stroke::new(1.0, fg_stroke_color), egui::StrokeKind::Outside);
            }
        }

        resp
    }

    fn render_new_chat_button(&mut self, ui: &mut egui::Ui) -> egui::Response {
        let (rect, resp) = ui.allocate_exact_size(
            Vec2::new(ui.available_width() - 32.0, 48.0),
            egui::Sense::click(),
        );

        if ui.is_rect_visible(rect) {
            let bg_color = if resp.hovered() {
                ui.visuals().widgets.hovered.bg_fill
            } else {
                PURPLE
            };

            ui.painter().rect_filled(rect, 8.0, bg_color);

            let icon_size = 24.0;
            let text_left = rect.left() + 16.0;

            ui.painter().text(
                egui::pos2(text_left, rect.center().y),
                egui::Align2::LEFT_CENTER,
                "+",
                egui::FontId::proportional(icon_size),
                egui::Color32::WHITE,
            );

            ui.painter().text(
                egui::pos2(text_left + icon_size + 8.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                "New Chat",
                egui::FontId::proportional(15.0),
                egui::Color32::WHITE,
            );
        }

        resp.on_hover_cursor(egui::CursorIcon::PointingHand)
    }
}

pub enum MessageAction {
    OpenConversation(String),
    NewChat,
}

struct MockConversation {
    pubkey: String,
    display_name: String,
    profile_pic: String,
    last_message: String,
    timestamp: String,
    unread: bool,
}

