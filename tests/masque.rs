use bytes::Bytes;
use wgh3::masque;

#[test]
fn varint_roundtrip_small() {
    let encoded = masque::encode_varint(0);
    let mut data = Bytes::from(encoded);

    assert_eq!(masque::decode_varint(&mut data).unwrap(), 0);
    assert!(data.is_empty());
}

#[test]
fn varint_roundtrip_medium() {
    let encoded = masque::encode_varint(15293);
    let mut data = Bytes::from(encoded);

    assert_eq!(masque::decode_varint(&mut data).unwrap(), 15293);
    assert!(data.is_empty());
}

#[test]
fn varint_roundtrip_large() {
    let encoded = masque::encode_varint(0x3fffffff);
    let mut data = Bytes::from(encoded);

    assert_eq!(masque::decode_varint(&mut data).unwrap(), 0x3fffffff);
    assert!(data.is_empty());
}

#[test]
fn varint_truncated_fails() {
    let mut data = Bytes::from(vec![0x40]);
    assert!(masque::decode_varint(&mut data).is_err());
}

#[test]
fn datagram_roundtrip() {
    let packet = b"hello";
    let data = masque::encode_datagram(packet);
    let decoded = masque::decode_datagram(data).unwrap();

    assert_eq!(&decoded[..], packet);
}

#[test]
fn connect_udp_path_roundtrip_v4() {
    let addr = "127.0.0.1:51820".parse().unwrap();
    let path = masque::connect_udp_path(addr);

    assert_eq!(masque::path_to_socketaddr(&path), Some(addr));
}

#[test]
fn connect_udp_path_roundtrip_v6() {
    let addr = "[fe80::1]:51820".parse().unwrap();
    let path = masque::connect_udp_path(addr);

    assert_eq!(masque::path_to_socketaddr(&path), Some(addr));
}
