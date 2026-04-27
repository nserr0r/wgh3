use rand_core::OsRng;
use wgh3::wg::Tunnel;
use wgh3::wg::TunnelAction;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

fn keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

fn complete_handshake(alice: &Tunnel, bob: &Tunnel) {
    let initiation = match alice.encapsulate(&[]).unwrap() {
        TunnelAction::WriteToNetwork(data) => data,
        _ => panic!("initiation"),
    };

    let response = match bob.decapsulate(&initiation).unwrap().into_iter().next() {
        Some(TunnelAction::WriteToNetwork(data)) => data,
        _ => panic!("response"),
    };

    let _ = alice.decapsulate(&response).unwrap();
}

#[test]
fn handshake_completes() {
    let (alice_secret, alice_public) = keypair();
    let (bob_secret, bob_public) = keypair();

    let alice = Tunnel::new(alice_secret, bob_public, None, None).unwrap();
    let bob = Tunnel::new(bob_secret, alice_public, None, None).unwrap();

    complete_handshake(&alice, &bob);
}

#[test]
fn data_roundtrip() {
    let (alice_secret, alice_public) = keypair();
    let (bob_secret, bob_public) = keypair();

    let alice = Tunnel::new(alice_secret, bob_public, None, None).unwrap();
    let bob = Tunnel::new(bob_secret, alice_public, None, None).unwrap();

    complete_handshake(&alice, &bob);

    let mut payload = vec![0x45, 0x00, 0x00, 0x28];
    payload.extend_from_slice(&[0u8; 36]);
    assert_eq!(payload.len(), 0x28);

    let encrypted = match alice.encapsulate(&payload).unwrap() {
        TunnelAction::WriteToNetwork(data) => data,
        _ => panic!("ожидался шифрованный пакет"),
    };

    let actions = bob.decapsulate(&encrypted).unwrap();
    let decrypted = actions
        .into_iter()
        .find_map(|action| match action {
            TunnelAction::WriteToTun(data) => Some(data),
            _ => None,
        })
        .expect("должен расшифровать пакет");

    assert_eq!(&decrypted[..], &payload[..]);
}

#[test]
fn data_roundtrip_both_directions() {
    let (alice_secret, alice_public) = keypair();
    let (bob_secret, bob_public) = keypair();

    let alice = Tunnel::new(alice_secret, bob_public, None, None).unwrap();
    let bob = Tunnel::new(bob_secret, alice_public, None, None).unwrap();

    complete_handshake(&alice, &bob);

    let mut from_alice = vec![0x45, 0x00, 0x00, 0x28];
    from_alice.extend_from_slice(&[1u8; 36]);

    let encrypted = match alice.encapsulate(&from_alice).unwrap() {
        TunnelAction::WriteToNetwork(data) => data,
        _ => panic!(),
    };

    let decrypted = bob
        .decapsulate(&encrypted)
        .unwrap()
        .into_iter()
        .find_map(|action| match action {
            TunnelAction::WriteToTun(data) => Some(data),
            _ => None,
        })
        .unwrap();

    assert_eq!(&decrypted[..], &from_alice[..]);

    let mut from_bob = vec![0x45, 0x00, 0x00, 0x28];
    from_bob.extend_from_slice(&[2u8; 36]);

    let encrypted = match bob.encapsulate(&from_bob).unwrap() {
        TunnelAction::WriteToNetwork(data) => data,
        _ => panic!(),
    };

    let decrypted = alice
        .decapsulate(&encrypted)
        .unwrap()
        .into_iter()
        .find_map(|action| match action {
            TunnelAction::WriteToTun(data) => Some(data),
            _ => None,
        })
        .unwrap();

    assert_eq!(&decrypted[..], &from_bob[..]);
}

#[test]
fn preshared_key_works() {
    let (alice_secret, alice_public) = keypair();
    let (bob_secret, bob_public) = keypair();
    let psk = [42u8; 32];

    let alice = Tunnel::new(alice_secret, bob_public, Some(psk), None).unwrap();
    let bob = Tunnel::new(bob_secret, alice_public, Some(psk), None).unwrap();

    complete_handshake(&alice, &bob);

    let mut payload = vec![0x45, 0x00, 0x00, 0x28];
    payload.extend_from_slice(&[7u8; 36]);

    let encrypted = match alice.encapsulate(&payload).unwrap() {
        TunnelAction::WriteToNetwork(data) => data,
        _ => panic!(),
    };

    let decrypted = bob
        .decapsulate(&encrypted)
        .unwrap()
        .into_iter()
        .find_map(|action| match action {
            TunnelAction::WriteToTun(data) => Some(data),
            _ => None,
        })
        .unwrap();

    assert_eq!(&decrypted[..], &payload[..]);
}

#[test]
fn preshared_key_mismatch_breaks_data_transfer() {
    let (alice_secret, alice_public) = keypair();
    let (bob_secret, bob_public) = keypair();

    let alice = Tunnel::new(alice_secret, bob_public, Some([1u8; 32]), None).unwrap();
    let bob = Tunnel::new(bob_secret, alice_public, Some([2u8; 32]), None).unwrap();

    let initiation = match alice.encapsulate(&[]).unwrap() {
        TunnelAction::WriteToNetwork(data) => data,
        _ => panic!(),
    };

    let bob_actions = bob.decapsulate(&initiation).unwrap();

    let response = bob_actions.into_iter().find_map(|action| match action {
        TunnelAction::WriteToNetwork(data) => Some(data),
        _ => None,
    });

    if let Some(response) = response {
        let _ = alice.decapsulate(&response);

        let mut payload = vec![0x45, 0x00, 0x00, 0x28];
        payload.extend_from_slice(&[0u8; 36]);

        let encrypted = match alice.encapsulate(&payload).unwrap() {
            TunnelAction::WriteToNetwork(data) => data,
            _ => return,
        };

        let actions = bob.decapsulate(&encrypted);

        let decrypted_ok = actions.map(|list| list.into_iter().any(|action| matches!(action, TunnelAction::WriteToTun(_)))).unwrap_or(false);

        assert!(!decrypted_ok, "с другим PSK не должен расшифровать данные");
    }
}
