use anyhow::Result;
use anyhow::anyhow;
use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use h3::ext::Protocol;
use http::Request;
use std::net::IpAddr;
use std::net::SocketAddr;

pub const MAX_PACKET_SIZE: usize = 1500;
pub const CONTEXT_ID: u64 = 0;

pub fn connect_udp_path(addr: SocketAddr) -> String {
    let host = match addr.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_string().replace(':', "%3A"),
    };

    format!("/.well-known/masque/udp/{}/{}/", host, addr.port())
}

pub fn path_to_socketaddr(path: &str) -> Option<SocketAddr> {
    let path = path.trim_end_matches('/');
    let mut parts = path.rsplit('/');

    let port = parts.next()?.parse::<u16>().ok()?;
    let host = parts.next()?.replace("%3A", ":");

    let ip = host.parse::<IpAddr>().ok()?;
    Some(SocketAddr::new(ip, port))
}

pub fn is_connect_udp(request: &Request<()>) -> bool {
    let protocol = request.extensions().get::<Protocol>();

    matches!(
        (request.method(), protocol),
        (&http::Method::CONNECT, Some(protocol)) if protocol == &Protocol::CONNECT_UDP
    )
}

pub fn has_valid_token(request: &Request<()>, token: &str) -> bool {
    let Some(auth) = request.headers().get("authorization") else {
        return false;
    };

    auth.as_bytes() == format!("Bearer {token}").as_bytes()
}

pub fn encode_datagram(packet: &[u8]) -> Bytes {
    let mut data = BytesMut::with_capacity(packet.len() + 8);
    put_varint(&mut data, CONTEXT_ID);
    data.extend_from_slice(packet);
    data.freeze()
}

pub fn decode_datagram(mut data: Bytes) -> Result<Bytes> {
    let context_id = decode_varint(&mut data)?;

    if context_id != CONTEXT_ID {
        return Err(anyhow!("неподдерживаемый context id: {context_id}"));
    }

    Ok(data)
}

pub fn put_varint(buf: &mut BytesMut, value: u64) {
    if value < 0x40 {
        buf.put_u8(value as u8);
    } else if value < 0x4000 {
        buf.put_u16(0x4000 | value as u16);
    } else if value < 0x40000000 {
        buf.put_u32(0x80000000 | value as u32);
    } else {
        buf.put_u64(0xc000000000000000 | value);
    }
}

pub fn encode_varint(value: u64) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(8);
    put_varint(&mut buf, value);
    buf.to_vec()
}

pub fn decode_varint(data: &mut Bytes) -> Result<u64> {
    if !data.has_remaining() {
        return Err(anyhow!("пустой varint"));
    }

    let first = data.get_u8();
    let prefix = first >> 6;
    let len = 1usize << prefix;
    let remaining = len - 1;

    if data.remaining() < remaining {
        return Err(anyhow!("обрезанный varint"));
    }

    let mut value = u64::from(first & 0x3f);

    for _ in 0..remaining {
        value = (value << 8) | u64::from(data.get_u8());
    }

    Ok(value)
}
