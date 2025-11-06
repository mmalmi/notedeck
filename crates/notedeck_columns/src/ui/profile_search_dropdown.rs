use egui::Key;
use notedeck::{Images, Accounts};
use nostrdb::{Ndb, Transaction};
use enostr::Pubkey;
use crate::ui::widgets::UserRow;

pub struct ProfileSearchResult {
    pub pubkey_hex: String,
    pub pubkey: Pubkey,
}

pub struct ProfileSearchDropdown<'a> {
    ndb: &'a Ndb,
    img_cache: &'a mut Images,
    #[allow(dead_code)]
    our_pubkey: &'a Pubkey,
    accounts: &'a Accounts,
}

impl<'a> ProfileSearchDropdown<'a> {
    pub fn new(ndb: &'a Ndb, img_cache: &'a mut Images, our_pubkey: &'a Pubkey, accounts: &'a Accounts) -> Self {
        Self { ndb, img_cache, our_pubkey, accounts }
    }

    /// Renders profile search dropdown with keyboard navigation
    /// Returns Some(pubkey_hex) if a profile was selected
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        query: &str,
        selected_index: &mut i32,
        max_width: f32,
    ) -> Option<String> {
        let Ok(txn) = Transaction::new(self.ndb) else {
            return None;
        };

        let search_results = self.search_profiles(&txn, query);
        if search_results.is_empty() {
            *selected_index = 0;
            return None;
        }

        let mut selected_pubkey = None;

        // Handle keyboard navigation
        let max_index = search_results.len() as i32 - 1;
        if ui.input(|i| i.key_pressed(Key::ArrowDown)) {
            *selected_index = (*selected_index + 1).min(max_index);
        } else if ui.input(|i| i.key_pressed(Key::ArrowUp)) {
            *selected_index = (*selected_index - 1).max(0);
        }

        let enter_pressed = ui.input(|i| i.key_pressed(Key::Enter));
        if enter_pressed && *selected_index >= 0 && (*selected_index as usize) < search_results.len() {
            selected_pubkey = Some(search_results[*selected_index as usize].pubkey_hex.clone());
        }

        ui.set_max_width(max_width);
        for (idx, result) in search_results.iter().enumerate() {
            let is_selected = idx as i32 == *selected_index;
            let profile = self.ndb.get_profile_by_pubkey(&txn, result.pubkey.bytes()).ok();

            if ui.add(UserRow::new(profile.as_ref(), &result.pubkey, self.img_cache, max_width)
                .with_accounts(self.accounts)
                .with_selection(is_selected)).clicked() {
                selected_pubkey = Some(result.pubkey_hex.clone());
            }
        }

        selected_pubkey
    }

    fn search_profiles(&self, txn: &Transaction, query: &str) -> Vec<ProfileSearchResult> {
        let query_lower = query.trim().to_lowercase();
        if query_lower.is_empty() {
            return vec![];
        }

        let mut results = Vec::new();

        let filter = nostrdb::Filter::new()
            .kinds([0])
            .limit(1000)
            .build();

        if let Ok(query_results) = self.ndb.query(txn, &[filter], 1000) {
            for qr in query_results {
                if let Ok(note) = self.ndb.get_note_by_key(txn, qr.note_key) {
                    let pubkey_bytes = note.pubkey();

                    if let Ok(profile) = self.ndb.get_profile_by_pubkey(txn, pubkey_bytes) {
                        let name = notedeck::name::get_display_name(Some(&profile)).name().to_lowercase();
                        let pubkey_hex_full = hex::encode(pubkey_bytes);

                        // Match on name or pubkey
                        if name.contains(&query_lower) || pubkey_hex_full.contains(&query_lower) {
                            let mut pk_bytes = [0u8; 32];
                            pk_bytes.copy_from_slice(pubkey_bytes);
                            let pubkey = Pubkey::new(pk_bytes);

                            results.push(ProfileSearchResult {
                                pubkey_hex: pubkey_hex_full,
                                pubkey,
                            });

                            if results.len() >= 10 {
                                break;
                            }
                        }
                    }
                }
            }
        }

        results
    }
}
