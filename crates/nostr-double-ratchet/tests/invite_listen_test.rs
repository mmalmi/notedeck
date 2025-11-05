use nostr_double_ratchet::{Invite, Result};
use nostr::Keys;
use std::sync::{Arc, Mutex};
use enostr::Filter;

#[test]
fn test_invite_listen_and_accept() -> Result<()> {
    let alice_keys = Keys::generate();
    let alice_pk = enostr::Pubkey::new(alice_keys.public_key().to_bytes());
    let alice_sk = alice_keys.secret_key().to_secret_bytes();

    let invite = Invite::create_new(alice_pk, Some("alice-device".to_string()), None)?;

    let bob_keys = Keys::generate();
    let bob_pk = enostr::Pubkey::new(bob_keys.public_key().to_bytes());
    let bob_sk = bob_keys.secret_key().to_secret_bytes();

    let (_bob_session, acceptance_event) = invite.accept(bob_pk, bob_sk, Some("bob-device".to_string()))?;

    let received_sessions = Arc::new(Mutex::new(Vec::new()));
    let received_sessions_clone = Arc::clone(&received_sessions);

    let acceptance_event_clone = acceptance_event.clone();
    let mock_subscribe = move |_filter: Filter, callback: Box<dyn Fn(nostr::UnsignedEvent) + Send>| {
        eprintln!("Subscribe called, calling callback with event");
        callback(acceptance_event_clone.clone());
        eprintln!("Callback executed");
        Box::new(|| {}) as Box<dyn FnOnce() + Send>
    };

    let _unsub = invite.listen(
        alice_sk,
        mock_subscribe,
        move |session, identity, device_id| {
            received_sessions_clone.lock().unwrap().push((session, identity, device_id));
        },
    )?;

    std::thread::sleep(std::time::Duration::from_millis(100));

    let sessions = received_sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);

    let (alice_session, identity, device_id) = &sessions[0];
    assert_eq!(identity.bytes(), bob_pk.bytes());
    assert_eq!(device_id, &Some("bob-device".to_string()));
    assert!(alice_session.state.receiving_chain_key.is_none());
    assert!(alice_session.state.sending_chain_key.is_none());

    Ok(())
}

#[test]
fn test_from_user_subscription() -> Result<()> {
    let alice_keys = Keys::generate();
    let alice_pk = enostr::Pubkey::new(alice_keys.public_key().to_bytes());

    let invite = Invite::create_new(alice_pk, Some("device-1".to_string()), None)?;
    let event = invite.get_event()?;

    let received_invites = Arc::new(Mutex::new(Vec::new()));
    let received_invites_clone = Arc::clone(&received_invites);

    let mock_subscribe = move |_filter: Filter, callback: Box<dyn Fn(nostr::UnsignedEvent) + Send>| {
        callback(event.clone());
        Box::new(|| {}) as Box<dyn FnOnce() + Send>
    };

    let _unsub = Invite::from_user(
        alice_pk,
        mock_subscribe,
        move |invite| {
            received_invites_clone.lock().unwrap().push(invite);
        },
    );

    std::thread::sleep(std::time::Duration::from_millis(100));

    let invites = received_invites.lock().unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].inviter.bytes(), alice_pk.bytes());
    assert_eq!(invites[0].device_id, Some("device-1".to_string()));

    Ok(())
}

#[test]
fn test_listen_without_device_id() -> Result<()> {
    let alice_keys = Keys::generate();
    let alice_pk = enostr::Pubkey::new(alice_keys.public_key().to_bytes());
    let alice_sk = alice_keys.secret_key().to_secret_bytes();

    let invite = Invite::create_new(alice_pk, Some("alice-device".to_string()), None)?;

    let bob_keys = Keys::generate();
    let bob_pk = enostr::Pubkey::new(bob_keys.public_key().to_bytes());
    let bob_sk = bob_keys.secret_key().to_secret_bytes();

    let (_bob_session, acceptance_event) = invite.accept(bob_pk, bob_sk, None)?;

    let received_sessions = Arc::new(Mutex::new(Vec::new()));
    let received_sessions_clone = Arc::clone(&received_sessions);

    let mock_subscribe = move |_filter: Filter, callback: Box<dyn Fn(nostr::UnsignedEvent) + Send>| {
        callback(acceptance_event.clone());
        Box::new(|| {}) as Box<dyn FnOnce() + Send>
    };

    let _unsub = invite.listen(
        alice_sk,
        mock_subscribe,
        move |session, identity, device_id| {
            received_sessions_clone.lock().unwrap().push((session, identity, device_id));
        },
    )?;

    std::thread::sleep(std::time::Duration::from_millis(100));

    let sessions = received_sessions.lock().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].2, None);

    Ok(())
}
