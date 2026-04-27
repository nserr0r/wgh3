use bytes::Bytes;
use rand_core::OsRng;
use std::sync::Arc;
use tokio::sync::mpsc;
use wgh3::wg::Tunnel;
use wgh3::wg::TunnelAction;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

fn keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

async fn complete_handshake(alice: &Tunnel, bob: &Tunnel) {
    let init = match alice.encapsulate(&[]).unwrap() {
        TunnelAction::WriteToNetwork(data) => data,
        _ => panic!(),
    };

    let response = match bob.decapsulate(&init).unwrap().into_iter().next() {
        Some(TunnelAction::WriteToNetwork(data)) => data,
        _ => panic!(),
    };

    let _ = alice.decapsulate(&response).unwrap();
}

#[tokio::test]
async fn pipeline_roundtrip() {
    let (alice_secret, alice_public) = keypair();
    let (bob_secret, bob_public) = keypair();

    let alice = Arc::new(Tunnel::new(alice_secret, bob_public, None, None).unwrap());
    let bob = Arc::new(Tunnel::new(bob_secret, alice_public, None, None).unwrap());

    complete_handshake(&alice, &bob).await;

    let (a_to_b_tx, mut a_to_b_rx) = mpsc::channel::<Bytes>(64);
    let (b_to_a_tx, mut b_to_a_rx) = mpsc::channel::<Bytes>(64);

    let (a_decrypted_tx, mut a_decrypted_rx) = mpsc::channel::<Bytes>(64);
    let (b_decrypted_tx, mut b_decrypted_rx) = mpsc::channel::<Bytes>(64);

    let alice_pump = {
        let alice = alice.clone();
        tokio::spawn(async move {
            while let Some(packet) = b_to_a_rx.recv().await {
                let actions = alice.decapsulate(&packet).unwrap();
                for action in actions {
                    if let TunnelAction::WriteToTun(data) = action {
                        a_decrypted_tx.send(data).await.unwrap();
                    }
                }
            }
        })
    };

    let bob_pump = {
        let bob = bob.clone();
        tokio::spawn(async move {
            while let Some(packet) = a_to_b_rx.recv().await {
                let actions = bob.decapsulate(&packet).unwrap();
                for action in actions {
                    if let TunnelAction::WriteToTun(data) = action {
                        b_decrypted_tx.send(data).await.unwrap();
                    }
                }
            }
        })
    };

    let mut payload = vec![0x45, 0x00, 0x00, 0x28];
    payload.extend_from_slice(&[0xAB; 36]);

    let encrypted = match alice.encapsulate(&payload).unwrap() {
        TunnelAction::WriteToNetwork(data) => data,
        _ => panic!(),
    };
    a_to_b_tx.send(encrypted).await.unwrap();

    let received = b_decrypted_rx.recv().await.expect("bob должен получить пакет");
    assert_eq!(&received[..], &payload[..]);

    let mut reply = vec![0x45, 0x00, 0x00, 0x28];
    reply.extend_from_slice(&[0xCD; 36]);

    let encrypted = match bob.encapsulate(&reply).unwrap() {
        TunnelAction::WriteToNetwork(data) => data,
        _ => panic!(),
    };
    b_to_a_tx.send(encrypted).await.unwrap();

    let received = a_decrypted_rx.recv().await.expect("alice должна получить ответ");
    assert_eq!(&received[..], &reply[..]);

    drop(a_to_b_tx);
    drop(b_to_a_tx);
    let _ = tokio::join!(alice_pump, bob_pump);
}

#[tokio::test]
async fn pipeline_many_packets() {
    let (alice_secret, alice_public) = keypair();
    let (bob_secret, bob_public) = keypair();

    let alice = Arc::new(Tunnel::new(alice_secret, bob_public, None, None).unwrap());
    let bob = Arc::new(Tunnel::new(bob_secret, alice_public, None, None).unwrap());

    complete_handshake(&alice, &bob).await;

    const COUNT: usize = 100;

    for i in 0..COUNT {
        let mut payload = vec![0x45, 0x00, 0x00, 0x28];
        payload.extend_from_slice(&[i as u8; 36]);

        let encrypted = match alice.encapsulate(&payload).unwrap() {
            TunnelAction::WriteToNetwork(data) => data,
            _ => panic!("пакет {i}"),
        };

        let actions = bob.decapsulate(&encrypted).unwrap();
        let decrypted = actions
            .into_iter()
            .find_map(|action| match action {
                TunnelAction::WriteToTun(data) => Some(data),
                _ => None,
            })
            .unwrap_or_else(|| panic!("пакет {i} не расшифровался"));

        assert_eq!(&decrypted[..], &payload[..], "пакет {i}");
    }
}
