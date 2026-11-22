//! TCP SYN header parsing and extracted fingerprint features.

use etherparse::SlicedPacket;
use pcap_file::DataLink;
use serde::Serialize;
use std::net::IpAddr;

/// TCP packet direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Client,
    Server,
}

/// Source and transport-independent SYN characteristics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Observation {
    pub source_ip: String,
    pub destination_ip: String,
    pub direction: Direction,
    pub ttl_observed: u8,
    pub initial_ttl: u16,
    pub hop_distance: u16,
    pub df: Option<bool>,
    pub ip_id_nonzero: Option<bool>,
    pub ip_total_length: u16,
    pub tcp_window: u16,
    pub window_scale: Option<u8>,
    pub mss: Option<u16>,
    pub options_layout: String,
    pub sack_permitted: bool,
    pub timestamp_present: bool,
    pub timestamp_echo_zero: bool,
    pub ecn_ece: bool,
    pub ecn_cwr: bool,
    pub reserved_bits: u8,
    pub quirks: Vec<String>,
}

/// Estimate initial TTL and hop distance from an observed IP time-to-live.
pub fn ttl_estimate(observed: u8) -> (u16, u16) {
    let initial = if observed <= 32 {
        32
    } else if observed <= 64 {
        64
    } else if observed <= 128 {
        128
    } else {
        255
    };
    (initial, initial.saturating_sub(u16::from(observed)))
}

/// Parse a captured network frame and return a SYN or SYN+ACK observation.
pub fn parse_packet(data: &[u8], linktype: DataLink) -> Option<Observation> {
    let packet = match linktype {
        DataLink::ETHERNET => SlicedPacket::from_ethernet(data).ok()?,
        DataLink::LINUX_SLL => SlicedPacket::from_linux_sll(data).ok()?,
        DataLink::LINUX_SLL2 => parse_linux_sll2(data)?,
        DataLink::RAW => SlicedPacket::from_ip(data).ok()?,
        DataLink::NULL | DataLink::LOOP => parse_loopback(data)?,
        _ => return None,
    };

    let net = packet.net?;
    let transport = packet.transport?;
    let etherparse::TransportSlice::Tcp(tcp) = transport else {
        return None;
    };

    if !tcp.syn() || !tcp.payload().is_empty() {
        return None;
    }

    let source_ip: IpAddr;
    let destination_ip: IpAddr;
    let ttl_observed;
    let mut df = None;
    let mut ip_id_nonzero = None;
    let ip_total_length: u16;

    match net {
        etherparse::NetSlice::Ipv4(ipv4) => {
            let header = ipv4.header();
            source_ip = IpAddr::V4(header.source_addr());
            destination_ip = IpAddr::V4(header.destination_addr());
            ttl_observed = header.ttl();
            df = Some(header.dont_fragment());
            ip_id_nonzero = Some(header.identification() != 0);
            ip_total_length = header.total_len();
        }
        etherparse::NetSlice::Ipv6(ipv6) => {
            let header = ipv6.header();
            source_ip = IpAddr::V6(header.source_addr());
            destination_ip = IpAddr::V6(header.destination_addr());
            ttl_observed = header.hop_limit();
            ip_total_length =
                u16::try_from(40usize.saturating_add(usize::from(header.payload_length())))
                    .unwrap_or(u16::MAX);
        }
        etherparse::NetSlice::Arp(_) => return None,
    }

    let direction = if tcp.ack() {
        Direction::Server
    } else {
        Direction::Client
    };
    let (initial_ttl, hop_distance) = ttl_estimate(ttl_observed);
    let options = tcp.options();
    let mut layout = Vec::<&str>::new();
    let mut mss = None;
    let mut window_scale = None;
    let mut sack_permitted = false;
    let mut timestamp_present = false;
    let mut timestamp_echo_zero = false;
    let mut quirks = Vec::new();

    let mut i = 0usize;
    let mut saw_eol = false;
    while i < options.len() {
        if saw_eol && i < options.len() {
            quirks.push("options-after-eol".to_string());
        }
        match options[i] {
            0 => {
                if !layout.last().is_some_and(|option| *option == "eol") {
                    layout.push("eol");
                }
                saw_eol = true;
                i += 1;
            }
            1 => {
                layout.push("nop");
                i += 1;
            }
            2 if i + 4 <= options.len() => {
                layout.push("mss");
                mss = Some(u16::from_be_bytes([options[i + 2], options[i + 3]]));
                i += 4;
            }
            3 if i + 3 <= options.len() => {
                layout.push("ws");
                window_scale = Some(options[i + 2]);
                i += 3;
            }
            4 if i + 2 <= options.len() => {
                layout.push("sok");
                sack_permitted = true;
                i += 2;
            }
            5 => {
                layout.push("sack");
                i = i.saturating_add(1);
                if i < options.len() {
                    let len = usize::from(options[i]);
                    i = i.saturating_add(len).min(options.len());
                }
            }
            8 if i + 10 <= options.len() => {
                layout.push("ts");
                timestamp_present = true;
                let echo = u32::from_be_bytes([
                    options[i + 6],
                    options[i + 7],
                    options[i + 8],
                    options[i + 9],
                ]);
                timestamp_echo_zero = echo == 0;
                i += 10;
            }
            kind => {
                layout.push("unknown");
                quirks.push(format!("unknown-tcp-option-{kind}"));
                i = i.saturating_add(if i + 1 < options.len() {
                    usize::from(options[i + 1]).max(2)
                } else {
                    2
                });
                i = i.min(options.len());
            }
        }
    }

    let header = tcp.header_slice();
    let tcp_header_len = tcp.header_len();
    let reserved_bits = (header[12] & 0x0e) >> 1;
    let data_offset = header[12] >> 4;
    if tcp_header_len != usize::from(data_offset) * 4 {
        quirks.push("unusual-data-offset".to_string());
    }
    if tcp.urgent_pointer() != 0 && !tcp.urg() {
        quirks.push("urgent-pointer-without-urg".to_string());
    }
    if tcp.syn() && tcp.ack() && tcp.acknowledgment_number() == 0 {
        quirks.push("synack-zero-ack".to_string());
    }
    if tcp.sequence_number() == 0 {
        quirks.push("sequence-number-zero".to_string());
    }
    if tcp.acknowledgment_number() != 0 && tcp.syn() && !tcp.ack() {
        quirks.push("nonzero-ack-on-syn".to_string());
    }

    Some(Observation {
        source_ip: source_ip.to_string(),
        destination_ip: destination_ip.to_string(),
        direction,
        ttl_observed,
        initial_ttl,
        hop_distance,
        df,
        ip_id_nonzero,
        ip_total_length,
        tcp_window: tcp.window_size(),
        window_scale,
        mss,
        options_layout: layout.join(","),
        sack_permitted,
        timestamp_present,
        timestamp_echo_zero,
        ecn_ece: tcp.ece(),
        ecn_cwr: tcp.cwr(),
        reserved_bits,
        quirks,
    })
}

fn parse_linux_sll2(data: &[u8]) -> Option<SlicedPacket<'_>> {
    if data.len() < 20 {
        return None;
    }
    let ether_type = u16::from_be_bytes([data[0], data[1]]);
    SlicedPacket::from_ether_type(ether_type.into(), &data[20..]).ok()
}

fn parse_loopback(data: &[u8]) -> Option<SlicedPacket<'_>> {
    if data.len() < 4 {
        return None;
    }
    let family = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    match family {
        2 | 0x02000000 => SlicedPacket::from_ip(&data[4..]).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_syn_frame(syn_ack: bool) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 44];
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        frame[14..16].copy_from_slice(&[0x45, 0x00]);
        frame[16..18].copy_from_slice(&64u16.to_be_bytes());
        frame[18..20].copy_from_slice(&0x1234u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[22] = 64;
        frame[23] = 6;
        if syn_ack {
            frame[26..30].copy_from_slice(&[198, 51, 100, 20]);
            frame[30..34].copy_from_slice(&[192, 0, 2, 10]);
        } else {
            frame[26..30].copy_from_slice(&[192, 0, 2, 10]);
            frame[30..34].copy_from_slice(&[198, 51, 100, 20]);
        }

        let tcp = &mut frame[34..];
        tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&49152u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&100u32.to_be_bytes());
        if syn_ack {
            tcp[8..12].copy_from_slice(&101u32.to_be_bytes());
        } else {
            tcp[8..12].copy_from_slice(&[0; 4]);
        }
        tcp[12] = 11 << 4;
        tcp[13] = if syn_ack { 0x12 } else { 0x02 };
        tcp[14..16].copy_from_slice(&14600u16.to_be_bytes());

        tcp[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        tcp[24] = 1;
        tcp[25..28].copy_from_slice(&[3, 3, 7]);
        tcp[28..30].copy_from_slice(&[4, 2]);
        tcp[30..40].copy_from_slice(&[8, 10, 0, 0, 0, 1, 0, 0, 0, 0]);
        if syn_ack {
            tcp[36..40].copy_from_slice(&[0, 0, 0, 1]);
        }
        tcp[40..44].copy_from_slice(&[1, 0, 1, 0]);
        frame
    }

    fn ipv6_syn_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 40 + 40];
        frame[12..14].copy_from_slice(&[0x86, 0xdd]);
        frame[14..18].copy_from_slice(&[0x60, 0, 0, 0]);
        frame[18..20].copy_from_slice(&40u16.to_be_bytes());
        frame[20] = 6;
        frame[21] = 64;
        frame[22..38]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame[38..54]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let tcp = &mut frame[54..];
        tcp[0..2].copy_from_slice(&49152u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&777u32.to_be_bytes());
        tcp[12] = 10 << 4;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        tcp[24..26].copy_from_slice(&[1, 1]);
        tcp[26..29].copy_from_slice(&[3, 3, 7]);
        tcp[29..31].copy_from_slice(&[4, 2]);
        frame
    }

    #[test]
    fn ttl_estimates_boundaries() {
        assert_eq!(ttl_estimate(32), (32, 0));
        assert_eq!(ttl_estimate(33), (64, 31));
        assert_eq!(ttl_estimate(64), (64, 0));
        assert_eq!(ttl_estimate(65), (128, 63));
        assert_eq!(ttl_estimate(129), (255, 126));
    }

    #[test]
    fn arbitrary_bytes_do_not_panic() {
        for len in 0..=128 {
            let mut bytes = vec![0u8; len];
            bytes.fill_with(|| 0xa5);
            let _ = parse_packet(&bytes, DataLink::ETHERNET);
            let _ = parse_packet(&bytes, DataLink::RAW);
            let _ = parse_packet(&bytes, DataLink::LINUX_SLL);
            let _ = parse_packet(&bytes, DataLink::LINUX_SLL2);
            let _ = parse_packet(&bytes, DataLink::NULL);
        }
    }

    #[test]
    fn detects_ipv4_client_syn() {
        let observation = parse_packet(&ipv4_syn_frame(false), DataLink::ETHERNET).unwrap();
        assert_eq!(observation.direction, Direction::Client);
        assert_eq!(observation.source_ip, "192.0.2.10");
        assert_eq!(observation.destination_ip, "198.51.100.20");
        assert_eq!(observation.initial_ttl, 64);
        assert_eq!(observation.df, Some(true));
        assert_eq!(observation.ip_id_nonzero, Some(true));
        assert_eq!(observation.tcp_window, 14600);
        assert_eq!(observation.mss, Some(1460));
        assert_eq!(observation.window_scale, Some(7));
        assert!(observation.sack_permitted);
        assert!(observation.timestamp_present);
        assert_eq!(
            observation.options_layout,
            "mss,nop,ws,sok,ts,nop,eol,nop,eol"
        );
    }

    #[test]
    fn detects_ipv4_server_synack() {
        let observation = parse_packet(&ipv4_syn_frame(true), DataLink::ETHERNET).unwrap();
        assert_eq!(observation.direction, Direction::Server);
        assert_eq!(observation.source_ip, "198.51.100.20");
        assert_eq!(observation.destination_ip, "192.0.2.10");
        assert!(!observation.timestamp_echo_zero);
    }

    #[test]
    fn detects_ipv6_syn_and_hop_limit() {
        let observation = parse_packet(&ipv6_syn_frame(), DataLink::ETHERNET).unwrap();
        assert_eq!(observation.direction, Direction::Client);
        assert_eq!(observation.source_ip, "2001:db8::1");
        assert_eq!(observation.destination_ip, "2001:db8::2");
        assert_eq!(observation.ttl_observed, 64);
        assert_eq!(observation.initial_ttl, 64);
        assert_eq!(observation.df, None);
        assert_eq!(observation.mss, Some(1460));
        assert_eq!(observation.window_scale, Some(7));
    }

    #[test]
    fn ignores_non_syn_and_payload_packets() {
        let mut frame = ipv4_syn_frame(false);
        frame[47] &= 0xfd;
        assert!(parse_packet(&frame, DataLink::ETHERNET).is_none());

        let mut frame = ipv4_syn_frame(false);
        frame[16..18].copy_from_slice(&65u16.to_be_bytes());
        frame.push(1);
        assert!(parse_packet(&frame, DataLink::ETHERNET).is_none());
    }
}
