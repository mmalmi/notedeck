use egui::{Label, RichText, Stroke, Vec2};
use notedeck::theme::PURPLE;
use notedeck_ui::ProfilePic;

pub struct MessagesView<'a> {
    img_cache: &'a mut notedeck::Images,
}

impl<'a> MessagesView<'a> {
    pub fn new(_i18n: &'a mut notedeck::Localization, img_cache: &'a mut notedeck::Images) -> Self {
        Self { img_cache }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<MessageAction> {
        let mut action = None;

        ui.add_space(8.0);

        let mock_conversations = get_mock_conversations();

        for conversation in mock_conversations {
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

            ui.put(pfp_rect, &mut ProfilePic::new(self.img_cache, conversation.profile_pic)
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
}

pub enum MessageAction {
    OpenConversation(String),
}

struct MockConversation {
    pubkey: String,
    display_name: String,
    profile_pic: &'static str,
    last_message: String,
    timestamp: String,
    unread: bool,
}

fn get_mock_conversations() -> Vec<MockConversation> {
    vec![
        MockConversation {
            pubkey: "alice".to_string(),
            display_name: "Alice".to_string(),
            profile_pic: "https://i.pravatar.cc/150?img=1",
            last_message: "Hey, are we still meeting tomorrow?".to_string(),
            timestamp: "2m".to_string(),
            unread: true,
        },
        MockConversation {
            pubkey: "bob".to_string(),
            display_name: "Bob".to_string(),
            profile_pic: "https://i.pravatar.cc/150?img=12",
            last_message: "Thanks for the help!".to_string(),
            timestamp: "1h".to_string(),
            unread: false,
        },
        MockConversation {
            pubkey: "carol".to_string(),
            display_name: "Carol".to_string(),
            profile_pic: "https://i.pravatar.cc/150?img=5",
            last_message: "Did you see the new update?".to_string(),
            timestamp: "3h".to_string(),
            unread: true,
        },
        MockConversation {
            pubkey: "dave".to_string(),
            display_name: "Dave".to_string(),
            profile_pic: "https://i.pravatar.cc/150?img=13",
            last_message: "Let me know when you're free".to_string(),
            timestamp: "1d".to_string(),
            unread: false,
        },
        MockConversation {
            pubkey: "eve".to_string(),
            display_name: "Eve".to_string(),
            profile_pic: "https://i.pravatar.cc/150?img=9",
            last_message: "Check out this article I found".to_string(),
            timestamp: "2d".to_string(),
            unread: false,
        },
        MockConversation {
            pubkey: "frank".to_string(),
            display_name: "Frank".to_string(),
            profile_pic: "https://i.pravatar.cc/150?img=33",
            last_message: "Great work on the project!".to_string(),
            timestamp: "3d".to_string(),
            unread: false,
        },
    ]
}
