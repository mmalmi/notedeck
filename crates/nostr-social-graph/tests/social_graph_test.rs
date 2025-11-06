use nostr_social_graph::SocialGraph;

const ADAM: &str = "020f2d21ae09bf35fcdfb65decf1478b846f5f728ab30c5eaabcd6d081a81c3e";
const FIATJAF: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const SNOWDEN: &str = "84dee6e676e5bb67b4ad4e042cf70cbd8681155db535942fcc6a0533858a7240";
const SIRIUS: &str = "4523be58d395b1b196a9b8c82b038b6895cb02b683d0c253a955068dba1facd0";

fn create_contact_list_tags(followed: &[&str]) -> Vec<(String, Vec<String>)> {
    followed
        .iter()
        .map(|pubkey| ("p".to_string(), vec![pubkey.to_string()]))
        .collect()
}

#[test]
fn test_initialize_with_root_user() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");
    assert_eq!(graph.get_follow_distance(ADAM).unwrap(), 0);
}

#[test]
fn test_handle_contact_list() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");
    let tags = create_contact_list_tags(&[FIATJAF]);

    graph
        .handle_contact_list(ADAM, &tags, 1234567890)
        .expect("Failed to handle contact list");
    assert!(graph.is_following(ADAM, FIATJAF).unwrap());
}

#[test]
fn test_update_follow_distances() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let tags1 = create_contact_list_tags(&[FIATJAF]);
    let tags2 = create_contact_list_tags(&[SNOWDEN]);

    graph
        .handle_contact_list(ADAM, &tags1, 1234567890)
        .expect("Failed to handle contact list");
    graph
        .handle_contact_list(FIATJAF, &tags2, 1234567890)
        .expect("Failed to handle contact list");

    assert_eq!(graph.get_follow_distance(SNOWDEN).unwrap(), 2);
}

#[test]
fn test_update_follow_distances_when_root_changed() {
    let mut graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let tags1 = create_contact_list_tags(&[FIATJAF]);
    let tags2 = create_contact_list_tags(&[SNOWDEN]);

    graph
        .handle_contact_list(ADAM, &tags1, 1234567890)
        .expect("Failed to handle contact list");
    graph
        .handle_contact_list(FIATJAF, &tags2, 1234567890)
        .expect("Failed to handle contact list");

    assert_eq!(graph.get_follow_distance(ADAM).unwrap(), 0);
    assert_eq!(graph.get_follow_distance(FIATJAF).unwrap(), 1);
    assert_eq!(graph.get_follow_distance(SNOWDEN).unwrap(), 2);

    graph.set_root(SNOWDEN).expect("Failed to set root");
    assert_eq!(graph.get_follow_distance(SNOWDEN).unwrap(), 0);
    assert_eq!(graph.get_follow_distance(FIATJAF).unwrap(), 1000);
    assert_eq!(graph.get_follow_distance(ADAM).unwrap(), 1000);

    graph.set_root(FIATJAF).expect("Failed to set root");
    assert_eq!(graph.get_follow_distance(SNOWDEN).unwrap(), 1);
    assert_eq!(graph.get_follow_distance(FIATJAF).unwrap(), 0);
    assert_eq!(graph.get_follow_distance(ADAM).unwrap(), 1000);
}

#[test]
fn test_follower_counts() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let tags1 = create_contact_list_tags(&[FIATJAF]);
    let tags2 = create_contact_list_tags(&[FIATJAF]);
    let tags3 = create_contact_list_tags(&[FIATJAF]);

    graph
        .handle_contact_list(ADAM, &tags1, 1234567890)
        .expect("Failed to handle contact list");
    graph
        .handle_contact_list(SNOWDEN, &tags2, 1234567890)
        .expect("Failed to handle contact list");
    graph
        .handle_contact_list(SIRIUS, &tags3, 1234567890)
        .expect("Failed to handle contact list");

    assert_eq!(graph.follower_count(FIATJAF).unwrap(), 3);
    assert_eq!(graph.follower_count(ADAM).unwrap(), 0);
    assert_eq!(graph.followed_by_friends_count(FIATJAF).unwrap(), 0);
}

#[test]
fn test_followed_by_friends() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let tags1 = create_contact_list_tags(&[FIATJAF]);
    let tags2 = create_contact_list_tags(&[SNOWDEN]);

    graph
        .handle_contact_list(ADAM, &tags1, 1234567890)
        .expect("Failed to handle contact list");
    graph
        .handle_contact_list(FIATJAF, &tags2, 1234567890)
        .expect("Failed to handle contact list");

    let friends = graph.followed_by_friends(SNOWDEN).unwrap();
    assert!(friends.contains(FIATJAF));
    assert_eq!(friends.len(), 1);
}

#[test]
fn test_get_users_by_follow_distance() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let tags1 = create_contact_list_tags(&[FIATJAF]);
    let tags2 = create_contact_list_tags(&[SNOWDEN]);

    graph
        .handle_contact_list(ADAM, &tags1, 1234567890)
        .expect("Failed to handle contact list");
    graph
        .handle_contact_list(FIATJAF, &tags2, 1234567890)
        .expect("Failed to handle contact list");

    let distance_1_users = graph.get_users_by_follow_distance(1).unwrap();
    let distance_2_users = graph.get_users_by_follow_distance(2).unwrap();

    assert_eq!(distance_1_users.len(), 1);
    assert!(distance_1_users.contains(&FIATJAF.to_string()));

    assert_eq!(distance_2_users.len(), 1);
    assert!(distance_2_users.contains(&SNOWDEN.to_string()));
}

#[test]
fn test_reuse_existing_follow_lists() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create initial graph");

    let tags1 = create_contact_list_tags(&[FIATJAF]);
    let tags2 = create_contact_list_tags(&[SNOWDEN]);

    graph
        .handle_contact_list(ADAM, &tags1, 1234567890)
        .expect("Failed to handle contact list");
    graph
        .handle_contact_list(FIATJAF, &tags2, 1234567890)
        .expect("Failed to handle contact list");

    assert_eq!(graph.get_follow_distance(ADAM).unwrap(), 0);
    assert_eq!(graph.get_follow_distance(FIATJAF).unwrap(), 1);
    assert_eq!(graph.get_follow_distance(SNOWDEN).unwrap(), 2);
    assert!(graph.is_following(ADAM, FIATJAF).unwrap());
    assert!(graph.is_following(FIATJAF, SNOWDEN).unwrap());

    let new_graph = SocialGraph::new(SIRIUS).expect("Failed to create new graph");

    assert_eq!(new_graph.get_follow_distance(SIRIUS).unwrap(), 0);
    assert_eq!(new_graph.get_follow_distance(ADAM).unwrap(), 1000);
    assert_eq!(new_graph.get_follow_distance(FIATJAF).unwrap(), 1000);
    assert_eq!(new_graph.get_follow_distance(SNOWDEN).unwrap(), 1000);

    let tags3 = create_contact_list_tags(&[ADAM]);
    new_graph
        .handle_contact_list(SIRIUS, &tags3, 1234567890)
        .expect("Failed to handle contact list");

    new_graph
        .recalculate_follow_distances()
        .expect("Failed to recalculate distances");

    assert!(new_graph.is_following(SIRIUS, ADAM).unwrap());
    assert_eq!(new_graph.get_follow_distance(SIRIUS).unwrap(), 0);
    assert_eq!(new_graph.get_follow_distance(ADAM).unwrap(), 1);
}

#[test]
fn test_timestamp_filtering() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let tags1 = create_contact_list_tags(&[FIATJAF]);
    let tags2 = create_contact_list_tags(&[SNOWDEN]);

    graph
        .handle_contact_list(ADAM, &tags1, 1000)
        .expect("Failed to handle contact list");
    assert!(graph.is_following(ADAM, FIATJAF).unwrap());

    graph
        .handle_contact_list(ADAM, &tags2, 999)
        .expect("Failed to handle contact list");
    assert!(graph.is_following(ADAM, FIATJAF).unwrap());
    assert!(!graph.is_following(ADAM, SNOWDEN).unwrap());

    graph
        .handle_contact_list(ADAM, &tags2, 1001)
        .expect("Failed to handle contact list");
    assert!(!graph.is_following(ADAM, FIATJAF).unwrap());
    assert!(graph.is_following(ADAM, SNOWDEN).unwrap());
}

#[test]
fn test_handle_mute_list() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");
    let tags = create_contact_list_tags(&[FIATJAF]);

    graph
        .handle_mute_list(ADAM, &tags, 1234567890)
        .expect("Failed to handle mute list");
    assert!(graph.is_muted(ADAM, FIATJAF).unwrap());
}

#[test]
fn test_mute_list_timestamps() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let tags1 = create_contact_list_tags(&[FIATJAF]);
    let tags2 = create_contact_list_tags(&[SNOWDEN]);

    graph
        .handle_mute_list(ADAM, &tags1, 1000)
        .expect("Failed to handle mute list");
    assert!(graph.is_muted(ADAM, FIATJAF).unwrap());

    graph
        .handle_mute_list(ADAM, &tags2, 999)
        .expect("Failed to handle mute list");
    assert!(graph.is_muted(ADAM, FIATJAF).unwrap());
    assert!(!graph.is_muted(ADAM, SNOWDEN).unwrap());

    graph
        .handle_mute_list(ADAM, &tags2, 1001)
        .expect("Failed to handle mute list");
    assert!(!graph.is_muted(ADAM, FIATJAF).unwrap());
    assert!(graph.is_muted(ADAM, SNOWDEN).unwrap());
}

#[test]
fn test_muted_by_friends_count() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let follow_tags = create_contact_list_tags(&[FIATJAF, SNOWDEN]);
    let mute_tags1 = create_contact_list_tags(&[SIRIUS]);
    let mute_tags2 = create_contact_list_tags(&[SIRIUS]);

    graph
        .handle_contact_list(ADAM, &follow_tags, 1234567890)
        .expect("Failed to handle contact list");
    graph
        .handle_mute_list(FIATJAF, &mute_tags1, 1234567890)
        .expect("Failed to handle mute list");
    graph
        .handle_mute_list(SNOWDEN, &mute_tags2, 1234567890)
        .expect("Failed to handle mute list");

    assert_eq!(graph.muted_by_friends_count(SIRIUS).unwrap(), 2);
}

#[test]
fn test_get_muted_by_user() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let tags = create_contact_list_tags(&[FIATJAF, SNOWDEN]);

    graph
        .handle_mute_list(ADAM, &tags, 1234567890)
        .expect("Failed to handle mute list");

    let muted = graph.get_muted_by_user(ADAM).unwrap();
    assert_eq!(muted.len(), 2);
    assert!(muted.contains(FIATJAF));
    assert!(muted.contains(SNOWDEN));
}

#[test]
fn test_size_with_mutes() {
    let graph = SocialGraph::new(ADAM).expect("Failed to create graph");

    let follow_tags = create_contact_list_tags(&[FIATJAF]);
    let mute_tags = create_contact_list_tags(&[SNOWDEN]);

    graph
        .handle_contact_list(ADAM, &follow_tags, 1234567890)
        .expect("Failed to handle contact list");
    graph
        .handle_mute_list(ADAM, &mute_tags, 1234567890)
        .expect("Failed to handle mute list");

    let (users, follows, mutes) = graph.size();
    assert!(users >= 2);
    assert_eq!(follows, 1);
    assert_eq!(mutes, 1);
}
