//! Offline pcap and pcapng reader support.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{bail, Context, Result};
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::blocks::Block;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::DataLink;

use crate::parse::{parse_packet, Observation};

const MAX_STDIN_CAPTURE_BYTES: u64 = 1024 * 1024 * 1024;

/// Read observations from a pcap or pcapng file, or stdin for `-`.
pub fn read_observations(path: &Path) -> Result<Vec<Observation>> {
    read_observations_with_aggregation(path, false)
}

/// Read observations, skipping byte-identical Ethernet/IPv4 SYN retransmissions.
pub fn read_observations_with_aggregation(
    path: &Path,
    aggregate: bool,
) -> Result<Vec<Observation>> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(MAX_STDIN_CAPTURE_BYTES)
            .read_to_end(&mut bytes)
            .context("failed to read capture from stdin")?;
        read_bytes(&bytes, aggregate)
    } else {
        read_file(path, aggregate)
    }
}

fn read_file(path: &Path, aggregate: bool) -> Result<Vec<Observation>> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut header = [0u8; 4];
    if file.read_exact(&mut header).is_err() {
        bail!("capture {} is empty or truncated", path.display());
    }
    file.seek(SeekFrom::Start(0))
        .context("failed to seek capture")?;

    if &header == b"\x0a\x0d\x0d\x0a" {
        read_pcapng(file, aggregate)
    } else {
        read_pcap(file, aggregate)
    }
}

fn read_bytes(bytes: &[u8], aggregate: bool) -> Result<Vec<Observation>> {
    if bytes.len() < 4 {
        bail!("capture from stdin is empty or truncated");
    }
    if &bytes[..4] == b"\x0a\x0d\x0d\x0a" {
        read_pcapng(Cursor::new(bytes), aggregate)
    } else {
        read_pcap(Cursor::new(bytes), aggregate)
    }
}

fn read_pcap<R: Read>(reader: R, aggregate: bool) -> Result<Vec<Observation>> {
    let mut reader = PcapReader::new(reader).context("invalid pcap capture")?;
    let datalink = reader.header().datalink;
    let mut observations = Vec::new();
    let mut seen = HashSet::<Vec<u8>>::new();

    while let Some(packet) = reader.next_packet() {
        let packet = packet.context("invalid pcap packet")?;
        if aggregate && datalink == DataLink::ETHERNET && is_empty_ipv4_syn(&packet.data) {
            if seen.contains(packet.data.as_ref()) {
                continue;
            }
            seen.insert(packet.data.to_vec());
        }
        if let Some(observation) = parse_packet(&packet.data, datalink) {
            observations.push(observation);
        }
    }
    Ok(observations)
}

fn read_pcapng<R: Read>(reader: R, aggregate: bool) -> Result<Vec<Observation>> {
    let mut reader = PcapNgReader::new(reader).context("invalid pcapng capture")?;
    let mut observations = Vec::new();
    let mut linktypes = Vec::<DataLink>::new();
    let mut seen = HashSet::<Vec<u8>>::new();

    while let Some(block) = reader.next_block() {
        let block = block.context("invalid pcapng block")?;
        match block {
            Block::EnhancedPacket(packet) => {
                let linktype = linktypes.get(packet.interface_id as usize).copied();
                if let Some(linktype) = linktype {
                    if aggregate
                        && linktype == DataLink::ETHERNET
                        && is_empty_ipv4_syn(&packet.data)
                    {
                        if seen.contains(packet.data.as_ref()) {
                            continue;
                        }
                        seen.insert(packet.data.to_vec());
                    }
                    if let Some(observation) = parse_packet(&packet.data, linktype) {
                        observations.push(observation);
                    }
                }
            }
            Block::InterfaceDescription(interface) => {
                linktypes.push(interface.linktype);
            }
            _ => {}
        }
    }
    Ok(observations)
}

fn is_empty_ipv4_syn(frame: &[u8]) -> bool {
    if frame.len() < 54 || frame[12..14] != [0x08, 0x00] {
        return false;
    }

    let ip = 14;
    let ip_header_len = usize::from(frame[ip] & 0x0f) * 4;
    if frame[ip] >> 4 != 4
        || ip_header_len < 20
        || frame[ip + 9] != 6
        || frame[ip + 6] & 0x1f != 0
        || frame[ip + 7] != 0
    {
        return false;
    }
    let ip_total_len = usize::from(u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]));
    let tcp = ip + ip_header_len;
    if ip_total_len < ip_header_len + 20
        || frame.len() < ip + ip_total_len
        || frame[tcp + 13] & 0x02 == 0
    {
        return false;
    }
    let tcp_header_len = usize::from(frame[tcp + 12] >> 4) * 4;
    tcp_header_len >= 20 && ip_total_len == ip_header_len + tcp_header_len
}

#[allow(dead_code)]
fn _supported_linktype(linktype: DataLink) -> bool {
    matches!(
        linktype,
        DataLink::ETHERNET
            | DataLink::LINUX_SLL
            | DataLink::LINUX_SLL2
            | DataLink::RAW
            | DataLink::NULL
            | DataLink::LOOP
    )
}
