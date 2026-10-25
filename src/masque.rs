use anyhow::Result;
use anyhow::bail;
use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use h3::ext::Protocol;
use http::Method;
use http::Request;
use quinn::Connection;
use quinn::ConnectionError;
use quinn::SendDatagramError;

pub const CONNECT_UDP_PATH: &str = "/.well-known/masque/udp/0.0.0.0/0/";

const CONTEXT_ID: u64 = 0;

pub fn is_connect_udp(request: &Request<()>) -> bool {
    request.method() == Method::CONNECT && request.extensions().get::<Protocol>() == Some(&Protocol::CONNECT_UDP)
}

pub fn has_valid_token(request: &Request<()>, token: &str) -> bool {
    let Some(value) = request.headers().get(http::header::AUTHORIZATION) else {
        return false;
    };

    let Some(presented) = value.as_bytes().strip_prefix(b"Bearer ") else {
        return false;
    };

    constant_time_eq(presented, token.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    difference == 0
}

pub struct DatagramChannel {
    connection: Connection,
    quarter_stream_id: u64,
    header: Bytes,
}

impl DatagramChannel {
    pub fn new(connection: Connection, stream_id: u64) -> Self {
        let quarter_stream_id = stream_id / 4;
        let header = encode_header(quarter_stream_id);
        Self { connection, quarter_stream_id, header }
    }

    pub fn max_packet_size(&self) -> usize {
        self.connection.max_datagram_size().unwrap_or(0).saturating_sub(self.header.len())
    }

    pub fn send(&self, packet: &[u8]) -> Result<()> {
        let mut datagram = BytesMut::with_capacity(self.header.len() + packet.len());
        datagram.extend_from_slice(&self.header);
        datagram.extend_from_slice(packet);

        match self.connection.send_datagram(datagram.freeze()) {
            Ok(()) => Ok(()),
            Err(SendDatagramError::TooLarge) => {
                tracing::debug!(size = packet.len(), limit = self.max_packet_size(), "пакет не помещается в датаграмму, дроп");
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    pub async fn recv(&self) -> Result<Bytes, ConnectionError> {
        loop {
            let datagram = self.connection.read_datagram().await?;
            if let Some(packet) = strip_header(datagram, self.quarter_stream_id) {
                return Ok(packet);
            }
        }
    }
}

fn encode_header(quarter_stream_id: u64) -> Bytes {
    let mut header = BytesMut::with_capacity(16);
    put_varint(&mut header, quarter_stream_id);
    put_varint(&mut header, CONTEXT_ID);
    header.freeze()
}

fn strip_header(mut datagram: Bytes, quarter_stream_id: u64) -> Option<Bytes> {
    let stream = decode_varint(&mut datagram).ok()?;
    let context = decode_varint(&mut datagram).ok()?;
    (stream == quarter_stream_id && context == CONTEXT_ID).then_some(datagram)
}

fn put_varint(buffer: &mut BytesMut, value: u64) {
    if value < 1 << 6 {
        buffer.put_u8(value as u8);
    } else if value < 1 << 14 {
        buffer.put_u16(0x4000 | value as u16);
    } else if value < 1 << 30 {
        buffer.put_u32(0x8000_0000 | value as u32);
    } else {
        buffer.put_u64(0xc000_0000_0000_0000 | value);
    }
}

fn decode_varint(data: &mut Bytes) -> Result<u64> {
    if !data.has_remaining() {
        bail!("пустой varint");
    }

    let first = data.get_u8();
    let tail = (1usize << (first >> 6)) - 1;

    if data.remaining() < tail {
        bail!("обрезанный varint");
    }

    let mut value = u64::from(first & 0x3f);
    for _ in 0..tail {
        value = (value << 8) | u64::from(data.get_u8());
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint_roundtrip(value: u64) -> (u64, usize) {
        let mut buffer = BytesMut::new();
        put_varint(&mut buffer, value);
        let len = buffer.len();

        let mut data = buffer.freeze();
        let decoded = decode_varint(&mut data).unwrap();
        assert!(data.is_empty());
        (decoded, len)
    }

    #[test]
    fn varint_boundaries() {
        assert_eq!(varint_roundtrip(0), (0, 1));
        assert_eq!(varint_roundtrip(63), (63, 1));
        assert_eq!(varint_roundtrip(64), (64, 2));
        assert_eq!(varint_roundtrip(16383), (16383, 2));
        assert_eq!(varint_roundtrip(16384), (16384, 4));
        assert_eq!(varint_roundtrip((1 << 30) - 1), ((1 << 30) - 1, 4));
        assert_eq!(varint_roundtrip(1 << 30), (1 << 30, 8));
        assert_eq!(varint_roundtrip((1 << 62) - 1), ((1 << 62) - 1, 8));
    }

    #[test]
    fn varint_truncated_fails() {
        assert!(decode_varint(&mut Bytes::from_static(&[0x40])).is_err());
        assert!(decode_varint(&mut Bytes::new()).is_err());
    }

    #[test]
    fn non_minimal_varint_accepted() {
        let datagram = Bytes::from_static(&[0x40, 0x00, 0x40, 0x00, 0xAA]);
        assert_eq!(strip_header(datagram, 0).unwrap(), &[0xAA][..]);
    }

    #[test]
    fn header_for_first_request_stream_is_two_bytes() {
        assert_eq!(encode_header(0), &[0x00, 0x00][..]);
    }

    #[test]
    fn header_roundtrip() {
        let mut datagram = BytesMut::from(&encode_header(25)[..]);
        datagram.extend_from_slice(b"packet");

        assert_eq!(strip_header(datagram.freeze(), 25).unwrap(), &b"packet"[..]);
    }

    #[test]
    fn foreign_stream_or_context_dropped() {
        let mut datagram = BytesMut::from(&encode_header(1)[..]);
        datagram.extend_from_slice(b"packet");
        assert!(strip_header(datagram.freeze(), 0).is_none());

        let datagram = Bytes::from_static(&[0x00, 0x01, 0xAA]);
        assert!(strip_header(datagram, 0).is_none());
    }

    fn request(method: Method, protocol: Option<Protocol>, authorization: Option<&str>) -> Request<()> {
        let mut builder = Request::builder().method(method).uri(format!("https://example.com{CONNECT_UDP_PATH}"));
        if let Some(protocol) = protocol {
            builder = builder.extension(protocol);
        }
        if let Some(value) = authorization {
            builder = builder.header(http::header::AUTHORIZATION, value);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn connect_udp_detection() {
        assert!(is_connect_udp(&request(Method::CONNECT, Some(Protocol::CONNECT_UDP), None)));
        assert!(!is_connect_udp(&request(Method::CONNECT, None, None)));
        assert!(!is_connect_udp(&request(Method::GET, Some(Protocol::CONNECT_UDP), None)));
    }

    #[test]
    fn token_validation() {
        let valid = request(Method::CONNECT, None, Some("Bearer secret"));
        assert!(has_valid_token(&valid, "secret"));
        assert!(!has_valid_token(&valid, "secreT"));
        assert!(!has_valid_token(&valid, "secret2"));
        assert!(!has_valid_token(&request(Method::CONNECT, None, Some("secret")), "secret"));
        assert!(!has_valid_token(&request(Method::CONNECT, None, None), "secret"));
    }
}
