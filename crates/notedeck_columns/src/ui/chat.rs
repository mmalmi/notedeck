use egui::{RichText, ScrollArea, Vec2};
use notedeck::{tr, Localization};
use notedeck_ui::ProfilePic;

pub struct ChatView<'a> {
    i18n: &'a mut Localization,
    img_cache: &'a mut notedeck::Images,
    chat_id: String,
}

impl<'a> ChatView<'a> {
    pub fn new(
        i18n: &'a mut Localization,
        img_cache: &'a mut notedeck::Images,
        chat_id: String,
    ) -> Self {
        Self {
            i18n,
            img_cache,
            chat_id,
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
                                let messages = get_mock_messages(&self.chat_id);

                                ui.add_space(8.0);

                                for message in messages {
                                    self.render_message(ui, &message);
                                    ui.add_space(8.0);
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
            let profile_pic = get_profile_pic(&self.chat_id);
            ui.add(&mut ProfilePic::new(self.img_cache, profile_pic).size(pfp_size));

            ui.add_space(8.0);

            ui.vertical(|ui| {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(get_display_name(&self.chat_id))
                        .size(16.0)
                        .strong(),
                );
            });
        });

        ui.add_space(8.0);
    }

    fn render_message(&mut self, ui: &mut egui::Ui, message: &MockMessage) {
        let margin = 16.0;
        let max_width = (ui.available_width() - margin * 2.0) * 0.7;

        if message.is_sent {
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                    ui.add_space(margin);
                    self.render_message_bubble(ui, message, max_width, true);
                });
            });
        } else {
            ui.horizontal(|ui| {
                ui.add_space(margin);
                self.render_message_bubble(ui, message, max_width, false);
                ui.add_space(margin);
            });
        }
    }

    fn render_message_bubble(
        &self,
        ui: &mut egui::Ui,
        message: &MockMessage,
        max_width: f32,
        is_sent: bool,
    ) {
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

                ui.label(RichText::new(&message.content).size(14.0).color(text_color));

                ui.add_space(2.0);

                ui.with_layout(egui::Layout::right_to_left(egui::Align::BOTTOM), |ui| {
                    ui.label(
                        RichText::new(&message.timestamp)
                            .size(11.0)
                            .color(if is_sent {
                                egui::Color32::from_white_alpha(180)
                            } else {
                                ui.visuals().weak_text_color()
                            }),
                    );
                });
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
                    tracing::info!("Sending message to {}: {}", self.chat_id, input_text);
                    ui.ctx().data_mut(|d| {
                        d.insert_temp(input_id, String::new());
                    });
                }
            });
        });
    }
}

struct MockMessage {
    content: String,
    timestamp: String,
    is_sent: bool,
}

fn get_mock_messages(chat_id: &str) -> Vec<MockMessage> {
    match chat_id {
        "alice" => vec![
            MockMessage {
                content: "Hey! How are you doing?".to_string(),
                timestamp: "10:32 AM".to_string(),
                is_sent: false,
            },
            MockMessage {
                content: "I'm good! Just working on some code.".to_string(),
                timestamp: "10:33 AM".to_string(),
                is_sent: true,
            },
            MockMessage {
                content: "Nice! What are you building?".to_string(),
                timestamp: "10:34 AM".to_string(),
                is_sent: false,
            },
            MockMessage {
                content: "A messaging interface for a Nostr client".to_string(),
                timestamp: "10:35 AM".to_string(),
                is_sent: true,
            },
            MockMessage {
                content: "That sounds exciting! Are we still meeting tomorrow?".to_string(),
                timestamp: "10:36 AM".to_string(),
                is_sent: false,
            },
            MockMessage {
                content: "Yes! Let's meet at 3pm".to_string(),
                timestamp: "10:37 AM".to_string(),
                is_sent: true,
            },
        ],
        "bob" => vec![
            MockMessage {
                content: "Thanks for the help earlier!".to_string(),
                timestamp: "9:15 AM".to_string(),
                is_sent: false,
            },
            MockMessage {
                content: "No problem! Happy to help.".to_string(),
                timestamp: "9:16 AM".to_string(),
                is_sent: true,
            },
            MockMessage {
                content: "The code is working perfectly now".to_string(),
                timestamp: "9:17 AM".to_string(),
                is_sent: false,
            },
        ],
        "carol" => vec![
            MockMessage {
                content: "Did you see the new update?".to_string(),
                timestamp: "Yesterday".to_string(),
                is_sent: false,
            },
            MockMessage {
                content: "Not yet, what changed?".to_string(),
                timestamp: "Yesterday".to_string(),
                is_sent: true,
            },
            MockMessage {
                content: "They added a bunch of new features!".to_string(),
                timestamp: "Yesterday".to_string(),
                is_sent: false,
            },
        ],
        _ => vec![
            MockMessage {
                content: "Hello!".to_string(),
                timestamp: "Just now".to_string(),
                is_sent: false,
            },
        ],
    }
}

fn get_display_name(chat_id: &str) -> &str {
    match chat_id {
        "alice" => "Alice",
        "bob" => "Bob",
        "carol" => "Carol",
        "dave" => "Dave",
        "eve" => "Eve",
        "frank" => "Frank",
        _ => "Unknown",
    }
}

fn get_profile_pic(chat_id: &str) -> &'static str {
    match chat_id {
        "alice" => "https://i.pravatar.cc/150?img=1",
        "bob" => "https://i.pravatar.cc/150?img=12",
        "carol" => "https://i.pravatar.cc/150?img=5",
        "dave" => "https://i.pravatar.cc/150?img=13",
        "eve" => "https://i.pravatar.cc/150?img=9",
        "frank" => "https://i.pravatar.cc/150?img=33",
        _ => "https://i.pravatar.cc/150?img=0",
    }
}
