use anyhow::Result;
use anyhow::anyhow;
use boringtun::noise::Tunn;
use boringtun::noise::TunnResult;
use bytes::Bytes;
use std::sync::Mutex;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

const BUF_SIZE: usize = 65535;

pub enum TunnelAction {
    None,
    WriteToNetwork(Bytes),
    WriteToTun(Bytes),
}

pub struct Tunnel {
    inner: Mutex<Tunn>,
}

impl Tunnel {
    pub fn new(private_key: StaticSecret, peer_public_key: PublicKey, preshared_key: Option<[u8; 32]>, persistent_keepalive: Option<u16>) -> Result<Self> {
        let tunn = Tunn::new(private_key, peer_public_key, preshared_key, persistent_keepalive, 0, None);
        Ok(Self { inner: Mutex::new(tunn) })
    }

    pub fn encapsulate(&self, packet: &[u8]) -> Result<TunnelAction> {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut tunn = self.inner.lock().unwrap();

        match tunn.encapsulate(packet, &mut buf) {
            TunnResult::Done => Ok(TunnelAction::None),
            TunnResult::WriteToNetwork(data) => Ok(TunnelAction::WriteToNetwork(Bytes::copy_from_slice(data))),
            TunnResult::Err(err) => Err(anyhow!("encapsulate: {err:?}")),
            _ => Ok(TunnelAction::None),
        }
    }

    pub fn decapsulate(&self, packet: &[u8]) -> Result<Vec<TunnelAction>> {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut actions = Vec::new();
        let mut tunn = self.inner.lock().unwrap();

        match tunn.decapsulate(None, packet, &mut buf) {
            TunnResult::Done => {}
            TunnResult::WriteToNetwork(data) => {
                actions.push(TunnelAction::WriteToNetwork(Bytes::copy_from_slice(data)));

                loop {
                    let mut next = vec![0u8; BUF_SIZE];
                    match tunn.decapsulate(None, &[], &mut next) {
                        TunnResult::WriteToNetwork(data) => {
                            actions.push(TunnelAction::WriteToNetwork(Bytes::copy_from_slice(data)));
                        }
                        _ => break,
                    }
                }
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                actions.push(TunnelAction::WriteToTun(Bytes::copy_from_slice(data)));
            }
            TunnResult::Err(err) => return Err(anyhow!("decapsulate: {err:?}")),
        }

        Ok(actions)
    }

    pub fn update_timers(&self) -> Result<TunnelAction> {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut tunn = self.inner.lock().unwrap();

        match tunn.update_timers(&mut buf) {
            TunnResult::Done => Ok(TunnelAction::None),
            TunnResult::WriteToNetwork(data) => Ok(TunnelAction::WriteToNetwork(Bytes::copy_from_slice(data))),
            TunnResult::Err(err) => Err(anyhow!("timers: {err:?}")),
            _ => Ok(TunnelAction::None),
        }
    }
}
