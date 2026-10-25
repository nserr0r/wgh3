pub const WIREGUARD_OVERHEAD: u16 = 32;

const HTTP_DATAGRAM_HEADER: u16 = 2;
const QUIC_CONNECTION_ID: u16 = 8;
const QUIC_SHORT_HEADER: u16 = 1 + QUIC_CONNECTION_ID + 4;
const QUIC_AEAD_TAG: u16 = 16;
const QUIC_DATAGRAM_FRAME: u16 = 9;

const IPV4_UDP_HEADER: u16 = 28;
const IPV6_UDP_HEADER: u16 = 48;

pub const TUNNEL_OVERHEAD: u16 = WIREGUARD_OVERHEAD + HTTP_DATAGRAM_HEADER + QUIC_DATAGRAM_FRAME + QUIC_SHORT_HEADER + QUIC_AEAD_TAG;

pub const MIN_UDP_PAYLOAD: u16 = 1200;
pub const MAX_UDP_PAYLOAD: u16 = 65527;

pub const MIN_MTU: u16 = MIN_UDP_PAYLOAD - TUNNEL_OVERHEAD;
pub const MAX_MTU: u16 = MAX_UDP_PAYLOAD - TUNNEL_OVERHEAD;
pub const DEFAULT_MTU: u16 = 1500 - IPV6_UDP_HEADER - TUNNEL_OVERHEAD;

pub fn udp_payload(mtu: u16) -> u16 {
    mtu + TUNNEL_OVERHEAD
}

pub fn ipv4_packet(mtu: u16) -> u16 {
    udp_payload(mtu) + IPV4_UDP_HEADER
}

pub fn ipv6_packet(mtu: u16) -> u16 {
    udp_payload(mtu) + IPV6_UDP_HEADER
}

pub fn wireguard_packet(mtu: u16) -> usize {
    usize::from(mtu + WIREGUARD_OVERHEAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overhead_matches_quinn_datagram_budget() {
        assert_eq!(TUNNEL_OVERHEAD, 72);
    }

    #[test]
    fn default_mtu_fills_ethernet_frame_over_ipv6() {
        assert_eq!(DEFAULT_MTU, 1380);
        assert_eq!(ipv6_packet(DEFAULT_MTU), 1500);
        assert_eq!(ipv4_packet(DEFAULT_MTU), 1480);
    }

    #[test]
    fn bounds_match_quic_limits() {
        assert_eq!(udp_payload(MIN_MTU), MIN_UDP_PAYLOAD);
        assert_eq!(udp_payload(MAX_MTU), MAX_UDP_PAYLOAD);
    }
}
