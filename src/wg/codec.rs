use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use blake2::Blake2s256;
use blake2::Blake2sMac;
use blake2::Digest;
use blake2::digest::KeyInit;
use blake2::digest::Mac;
use blake2::digest::consts::U16;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

const LABEL_MAC1: &[u8] = b"mac1----";
const HANDSHAKE_INIT_MSG_TYPE: u32 = 1;
const HANDSHAKE_INIT_LEN: usize = 148;
const MAC1_OFFSET: usize = 116;
const MAC1_LEN: usize = 16;

pub fn parse_private_key(value: &str) -> Result<StaticSecret> {
    let bytes = decode_b64(value).context("некорректный base64 в private_key")?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("private_key должен быть 32 байта"))?;
    Ok(StaticSecret::from(array))
}

pub fn parse_public_key(value: &str) -> Result<PublicKey> {
    let bytes = decode_b64(value).context("некорректный base64 в public_key")?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("public_key должен быть 32 байта"))?;
    Ok(PublicKey::from(array))
}

pub fn parse_preshared_key(value: &str) -> Result<[u8; 32]> {
    let bytes = decode_b64(value).context("некорректный base64 в preshared_key")?;
    bytes.try_into().map_err(|_| anyhow!("preshared_key должен быть 32 байта"))
}

pub fn decode_b64(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::decode(value.trim())
}

pub fn encode_b64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

pub fn is_handshake_init(packet: &[u8]) -> bool {
    if packet.len() != HANDSHAKE_INIT_LEN {
        return false;
    }
    let msg_type = u32::from_le_bytes([packet[0], packet[1], packet[2], packet[3]]);
    msg_type == HANDSHAKE_INIT_MSG_TYPE
}

pub fn verify_mac1(packet: &[u8], local_private_key: &StaticSecret) -> bool {
    if !is_handshake_init(packet) {
        return false;
    }

    let local_public_key = PublicKey::from(local_private_key);

    let mut hasher = Blake2s256::new();
    Digest::update(&mut hasher, LABEL_MAC1);
    Digest::update(&mut hasher, local_public_key.as_bytes());
    let mac1_key = hasher.finalize();

    type Mac16 = Blake2sMac<U16>;
    let mut mac = match <Mac16 as KeyInit>::new_from_slice(&mac1_key) {
        Ok(value) => value,
        Err(_) => return false,
    };

    Mac::update(&mut mac, &packet[..MAC1_OFFSET]);
    let computed = mac.finalize().into_bytes();

    computed.as_slice() == &packet[MAC1_OFFSET..MAC1_OFFSET + MAC1_LEN]
}
