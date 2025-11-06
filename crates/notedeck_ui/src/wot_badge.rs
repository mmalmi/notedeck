use egui::{Color32, Pos2};
use enostr::Pubkey;
use nostrdb::{Ndb, Transaction};

#[derive(Clone, Copy, Debug)]
pub enum BadgeColor {
    Purple,  // Self or following (distance 0 or 1)
    Orange,  // 2nd degree, followed by 10+ friends
    Gray,    // 2nd degree, followed by < 10 friends
}

impl BadgeColor {
    pub fn to_color32(self) -> Color32 {
        match self {
            BadgeColor::Purple => Color32::from_rgb(139, 92, 246),
            BadgeColor::Orange => Color32::from_rgb(251, 146, 60),
            BadgeColor::Gray => Color32::from_rgb(156, 163, 175),
        }
    }
}

pub fn get_wot_badge(
    pubkey: &Pubkey,
    logged_in_pubkey: Option<&Pubkey>,
    ndb: &Ndb,
    txn: &Transaction,
) -> Option<BadgeColor> {
    let logged_in = logged_in_pubkey?;

    let mut logged_in_bytes = [0u8; 32];
    logged_in_bytes.copy_from_slice(logged_in.bytes());
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(pubkey.bytes());

    // Check if muted
    if nostrdb::socialgraph::is_muting(txn, ndb, &logged_in_bytes, &pubkey_bytes) {
        return None;
    }

    let distance = nostrdb::socialgraph::get_follow_distance(txn, ndb, &pubkey_bytes);

    match distance {
        0 => Some(BadgeColor::Purple),  // Self
        1 => Some(BadgeColor::Purple),  // Following
        2 => {
            // Check how many friends follow this user
            let followers = nostrdb::socialgraph::get_followers(txn, ndb, &pubkey_bytes, 100);
            let friends_count = followers.iter().filter(|follower| {
                nostrdb::socialgraph::get_follow_distance(txn, ndb, follower) == 1
            }).count();

            if friends_count >= 10 {
                Some(BadgeColor::Orange)
            } else if friends_count > 0 {
                Some(BadgeColor::Gray)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn paint_wot_badge(
    painter: &egui::Painter,
    badge_pos: Pos2,
    badge_size: f32,
    color: BadgeColor,
) {
    painter.circle_filled(badge_pos, badge_size / 2.0, color.to_color32());

    painter.text(
        badge_pos,
        egui::Align2::CENTER_CENTER,
        "✓",
        egui::FontId::proportional(badge_size * 0.6),
        Color32::WHITE,
    );
}
