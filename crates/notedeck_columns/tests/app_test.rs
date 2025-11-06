#[cfg(test)]
mod tests {
    use egui_kittest::Harness;
    use notedeck::ui::richtext_small;

    #[test]
    fn test_settings_menu_screenshot() {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(600.0, 800.0))
            .build_ui(|ui| {
                egui::Frame::group(ui.style())
                    .fill(ui.style().visuals.widgets.open.bg_fill)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.label("Settings");
                        ui.separator();

                        ui.horizontal_wrapped(|ui| {
                            ui.label(richtext_small("Theme:"));
                            ui.selectable_value(&mut "Dark", "Dark", richtext_small("Dark"));
                            ui.selectable_value(&mut "Light", "Light", richtext_small("Light"));
                        });

                        ui.horizontal_wrapped(|ui| {
                            ui.label(richtext_small("Language:"));
                            ui.label(richtext_small("English"));
                        });

                        ui.horizontal_wrapped(|ui| {
                            ui.label(richtext_small("Zoom:"));
                            ui.button("-");
                            ui.label("100%");
                            ui.button("+");
                        });
                    });
            });

        harness.run();
        harness.snapshot("/tmp/settings_menu");
    }
}
