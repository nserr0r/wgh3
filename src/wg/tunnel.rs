use crate::mtu;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use boringtun::noise::Tunn;
use boringtun::noise::TunnResult;
use bytes::Bytes;
use std::sync::Mutex;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

pub enum Output {
    Network(Bytes),
    Device(Bytes),
}

struct State {
    tunn: Tunn,
    buffer: Vec<u8>,
}

pub struct Tunnel {
    state: Mutex<State>,
}

impl Tunnel {
    pub fn new(private_key: StaticSecret, peer_public_key: PublicKey, preshared_key: Option<[u8; 32]>, keepalive: Option<u16>, mtu: u16) -> Self {
        let tunn = Tunn::new(private_key, peer_public_key, preshared_key, keepalive, 0, None);
        let buffer = vec![0; mtu::wireguard_packet(mtu)];
        Self { state: Mutex::new(State { tunn, buffer }) }
    }

    pub fn initiate_handshake(&self) -> Result<Option<Bytes>> {
        let mut state = self.lock();
        let State { tunn, buffer } = &mut *state;
        network_packet(tunn.format_handshake_initiation(buffer, false))
    }

    pub fn encapsulate(&self, packet: &[u8]) -> Result<Option<Bytes>> {
        let mut state = self.lock();
        let State { tunn, buffer } = &mut *state;

        if packet.len() + usize::from(mtu::WIREGUARD_OVERHEAD) > buffer.len() {
            bail!("пакет {} байт больше MTU туннеля", packet.len());
        }

        network_packet(tunn.encapsulate(packet, buffer))
    }

    pub fn decapsulate(&self, datagram: &[u8]) -> Result<Vec<Output>> {
        let mut state = self.lock();
        let State { tunn, buffer } = &mut *state;

        let output = match tunn.decapsulate(None, datagram, buffer) {
            TunnResult::Done => return Ok(Vec::new()),
            TunnResult::Err(err) => return Err(anyhow!("decapsulate: {err:?}")),
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => return Ok(vec![Output::Device(Bytes::copy_from_slice(packet))]),
            TunnResult::WriteToNetwork(packet) => Output::Network(Bytes::copy_from_slice(packet)),
        };

        let mut outputs = vec![output];
        while let TunnResult::WriteToNetwork(packet) = tunn.decapsulate(None, &[], buffer) {
            outputs.push(Output::Network(Bytes::copy_from_slice(packet)));
        }

        Ok(outputs)
    }

    pub fn update_timers(&self) -> Result<Option<Bytes>> {
        let mut state = self.lock();
        let State { tunn, buffer } = &mut *state;
        network_packet(tunn.update_timers(buffer))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn network_packet(result: TunnResult<'_>) -> Result<Option<Bytes>> {
    match result {
        TunnResult::WriteToNetwork(packet) => Ok(Some(Bytes::copy_from_slice(packet))),
        TunnResult::Err(err) => Err(anyhow!("{err:?}")),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const MTU: u16 = 1380;

    fn tunnel_pair(alice_psk: Option<[u8; 32]>, bob_psk: Option<[u8; 32]>) -> (Tunnel, Tunnel) {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);

        let alice = Tunnel::new(alice_secret, bob_public, alice_psk, None, MTU);
        let bob = Tunnel::new(bob_secret, alice_public, bob_psk, None, MTU);
        (alice, bob)
    }

    fn network(outputs: Vec<Output>) -> Bytes {
        match outputs.into_iter().next() {
            Some(Output::Network(packet)) => packet,
            _ => panic!("ожидался сетевой пакет"),
        }
    }

    fn device(outputs: Vec<Output>) -> Option<Bytes> {
        outputs.into_iter().find_map(|output| match output {
            Output::Device(packet) => Some(packet),
            Output::Network(_) => None,
        })
    }

    fn handshake(alice: &Tunnel, bob: &Tunnel) {
        let initiation = alice.initiate_handshake().unwrap().expect("initiation");
        let response = network(bob.decapsulate(&initiation).unwrap());
        alice.decapsulate(&response).unwrap();
    }

    fn ip_packet(fill: u8, len: usize) -> Vec<u8> {
        let mut packet = vec![fill; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet
    }

    fn transfer(from: &Tunnel, to: &Tunnel, packet: &[u8]) -> Option<Bytes> {
        let encrypted = from.encapsulate(packet).unwrap().expect("зашифрованный пакет");
        device(to.decapsulate(&encrypted).ok()?)
    }

    #[test]
    fn roundtrip_both_directions() {
        let (alice, bob) = tunnel_pair(None, None);
        handshake(&alice, &bob);

        let request = ip_packet(1, 40);
        assert_eq!(transfer(&alice, &bob, &request).unwrap(), &request[..]);

        let reply = ip_packet(2, 40);
        assert_eq!(transfer(&bob, &alice, &reply).unwrap(), &reply[..]);
    }

    #[test]
    fn full_mtu_packet_fits() {
        let (alice, bob) = tunnel_pair(None, None);
        handshake(&alice, &bob);

        let packet = ip_packet(3, usize::from(MTU));
        let encrypted = alice.encapsulate(&packet).unwrap().unwrap();

        assert_eq!(encrypted.len(), mtu::wireguard_packet(MTU));
        assert_eq!(device(bob.decapsulate(&encrypted).unwrap()).unwrap(), &packet[..]);
    }

    #[test]
    fn oversized_packet_rejected() {
        let (alice, bob) = tunnel_pair(None, None);
        handshake(&alice, &bob);

        assert!(alice.encapsulate(&ip_packet(4, usize::from(MTU) + 1)).is_err());
    }

    #[test]
    fn packet_before_handshake_is_queued() {
        let (alice, bob) = tunnel_pair(None, None);
        let packet = ip_packet(5, 60);

        let initiation = alice.encapsulate(&packet).unwrap().expect("initiation");
        let response = network(bob.decapsulate(&initiation).unwrap());

        let mut delivered = Vec::new();
        for output in alice.decapsulate(&response).unwrap() {
            if let Output::Network(datagram) = output
                && let Some(packet) = device(bob.decapsulate(&datagram).unwrap())
            {
                delivered.push(packet);
            }
        }

        assert_eq!(delivered, vec![Bytes::from(packet)]);
    }

    #[test]
    fn many_packets_in_order() {
        let (alice, bob) = tunnel_pair(None, None);
        handshake(&alice, &bob);

        for fill in 0..100u8 {
            let packet = ip_packet(fill, 64);
            assert_eq!(transfer(&alice, &bob, &packet).unwrap(), &packet[..], "пакет {fill}");
        }
    }

    #[test]
    fn matching_preshared_key_works() {
        let (alice, bob) = tunnel_pair(Some([42; 32]), Some([42; 32]));
        handshake(&alice, &bob);

        let packet = ip_packet(6, 40);
        assert_eq!(transfer(&alice, &bob, &packet).unwrap(), &packet[..]);
    }

    #[test]
    fn mismatched_preshared_key_fails_handshake() {
        let (alice, bob) = tunnel_pair(Some([1; 32]), Some([2; 32]));

        let initiation = alice.initiate_handshake().unwrap().unwrap();
        let response = network(bob.decapsulate(&initiation).unwrap());

        assert!(alice.decapsulate(&response).is_err());
    }
}
