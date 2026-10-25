use anyhow::Context;
use anyhow::Result;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

pub fn parse_private_key(value: &str) -> Result<StaticSecret> {
    parse_key(value, "private_key").map(StaticSecret::from)
}

pub fn parse_public_key(value: &str) -> Result<PublicKey> {
    parse_key(value, "public_key").map(PublicKey::from)
}

pub fn parse_preshared_key(value: &str) -> Result<[u8; 32]> {
    parse_key(value, "preshared_key")
}

pub fn parse_key(value: &str, name: &str) -> Result<[u8; 32]> {
    let bytes = decode_b64(value).with_context(|| format!("некорректный base64 в {name}"))?;
    bytes.try_into().ok().with_context(|| format!("{name} должен быть 32 байта"))
}

fn decode_b64(value: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    base64::decode(value.trim())
}

pub fn encode_b64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip() {
        let key = [7u8; 32];
        assert_eq!(parse_preshared_key(&encode_b64(&key)).unwrap(), key);
    }

    #[test]
    fn surrounding_whitespace_ignored() {
        let key = [9u8; 32];
        assert_eq!(parse_preshared_key(&format!("  {}\n", encode_b64(&key))).unwrap(), key);
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(parse_public_key(&encode_b64(&[1u8; 31])).is_err());
    }

    #[test]
    fn invalid_base64_rejected() {
        assert!(parse_private_key("не base64").is_err());
    }
}
