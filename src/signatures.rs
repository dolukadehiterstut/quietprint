//! Passive OS signature loading and matching.

use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::parse::{Direction, Observation};

#[derive(Debug, Clone, Deserialize)]
pub struct Signature {
    pub name: String,
    pub family: String,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub initial_ttl: Option<u16>,
    #[serde(default)]
    pub tcp_window: Option<u16>,
    #[serde(default)]
    pub mss: Option<u16>,
    #[serde(default)]
    pub window_scale: Option<u8>,
    #[serde(default)]
    pub options_layout: Option<String>,
    #[serde(default)]
    pub df: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignatureFile {
    #[serde(rename = "signature")]
    signatures: Vec<Signature>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Candidate {
    pub name: String,
    pub family: String,
    pub score: u8,
}

impl Signature {
    fn score(&self, observation: &Observation) -> Option<u8> {
        if let Some(direction) = &self.direction {
            let expected = if direction.eq_ignore_ascii_case("client") {
                Direction::Client
            } else if direction.eq_ignore_ascii_case("server") {
                Direction::Server
            } else {
                return None;
            };
            if observation.direction != expected {
                return None;
            }
        }

        let mut weighted = 0u32;
        let mut total = 0u32;
        if let Some(ttl) = self.initial_ttl {
            total += 15;
            if observation.initial_ttl == ttl {
                weighted += 15;
            }
        }
        if let Some(window) = self.tcp_window {
            total += 25;
            if observation.tcp_window == window {
                weighted += 25;
            }
        }
        if let Some(mss) = self.mss {
            total += 15;
            if observation.mss == Some(mss) {
                weighted += 15;
            }
        }
        if let Some(scale) = self.window_scale {
            total += 20;
            if observation.window_scale == Some(scale) {
                weighted += 20;
            }
        }
        if let Some(layout) = &self.options_layout {
            total += 20;
            if observation.options_layout == *layout {
                weighted += 20;
            }
        }
        if let Some(df) = self.df {
            total += 5;
            if observation.df == Some(df) {
                weighted += 5;
            }
        }

        if total == 0 {
            return None;
        }

        let score = ((weighted * 100) / total).min(100) as u8;
        Some(score)
    }
}

fn built_in_signatures() -> Vec<Signature> {
    vec![
        Signature {
            name: "Linux 3.11 and newer".into(),
            family: "Linux".into(),
            direction: Some("client".into()),
            initial_ttl: Some(64),
            tcp_window: Some(29200),
            mss: Some(1460),
            window_scale: Some(7),
            options_layout: Some("mss,sok,ts,nop,ws".into()),
            df: Some(true),
        },
        Signature {
            name: "Linux 2.2-5.x".into(),
            family: "Linux".into(),
            direction: Some("client".into()),
            initial_ttl: Some(64),
            tcp_window: Some(29200),
            mss: Some(1460),
            window_scale: Some(7),
            options_layout: Some("mss,sok,ts,nop,ws,eol".into()),
            df: Some(true),
        },
        Signature {
            name: "Linux modern".into(),
            family: "Linux".into(),
            direction: Some("client".into()),
            initial_ttl: Some(64),
            tcp_window: None,
            mss: Some(1460),
            window_scale: Some(7),
            options_layout: Some("mss,sok,ts,nop,ws,eol".into()),
            df: Some(true),
        },
        Signature {
            name: "Windows 10/11".into(),
            family: "Windows".into(),
            direction: Some("client".into()),
            initial_ttl: Some(128),
            tcp_window: Some(64240),
            mss: Some(1460),
            window_scale: Some(8),
            options_layout: Some("mss,nop,ws,nop,nop,sok,eol".into()),
            df: Some(true),
        },
        Signature {
            name: "macOS".into(),
            family: "macOS".into(),
            direction: Some("client".into()),
            initial_ttl: Some(64),
            tcp_window: Some(65535),
            mss: Some(1460),
            window_scale: Some(6),
            options_layout: Some("mss,nop,ws,nop,nop,ts,sok,eol".into()),
            df: Some(true),
        },
        Signature {
            name: "FreeBSD".into(),
            family: "FreeBSD".into(),
            direction: Some("client".into()),
            initial_ttl: Some(64),
            tcp_window: Some(65535),
            mss: Some(1460),
            window_scale: Some(6),
            options_layout: Some("mss,nop,ws,nop,nop,ts,sok,eol".into()),
            df: Some(true),
        },
    ]
}

pub fn default_signatures() -> Vec<Signature> {
    built_in_signatures()
}

pub fn load_signatures(path: Option<&Path>) -> anyhow::Result<Vec<Signature>> {
    let mut signatures = built_in_signatures();
    let Some(path) = path else {
        return Ok(signatures);
    };

    if path.is_file() {
        signatures.extend(load_signature_file(path)?);
        return Ok(signatures);
    }
    if path.is_dir() {
        let mut paths = fs::read_dir(path)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|file| file.extension().is_some_and(|ext| ext == "toml"))
            .collect::<Vec<_>>();
        paths.sort();
        for file in paths {
            signatures.extend(load_signature_file(&file)?);
        }
        return Ok(signatures);
    }

    anyhow::bail!("signature path does not exist: {}", path.display())
}

pub fn load_signature_file(path: &Path) -> anyhow::Result<Vec<Signature>> {
    let text = fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("failed to read {}: {error}", path.display()))?;
    let file: SignatureFile = toml::from_str(&text)
        .map_err(|error| anyhow::anyhow!("invalid signature file {}: {error}", path.display()))?;
    Ok(file.signatures)
}

pub fn match_observation(
    observation: &Observation,
    signatures: &[Signature],
    min_score: u8,
    top: u8,
) -> Vec<Candidate> {
    let mut candidates = signatures
        .iter()
        .filter_map(|signature| {
            signature.score(observation).map(|score| Candidate {
                name: signature.name.clone(),
                family: signature.family.clone(),
                score,
            })
        })
        .filter(|candidate| candidate.score >= min_score)
        .collect::<Vec<_>>();

    candidates.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.family.cmp(&b.family)));
    candidates.truncate(top as usize);
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Direction;

    #[test]
    fn matches_linux_signature() {
        let observation = Observation {
            source_ip: "192.0.2.1".into(),
            destination_ip: "198.51.100.1".into(),
            direction: Direction::Client,
            ttl_observed: 64,
            initial_ttl: 64,
            hop_distance: 0,
            df: Some(true),
            ip_id_nonzero: Some(true),
            ip_total_length: 60,
            tcp_window: 29200,
            window_scale: Some(7),
            mss: Some(1460),
            options_layout: "mss,nop,ws,nop,nop,ts,sok,eol".into(),
            sack_permitted: true,
            timestamp_present: true,
            timestamp_echo_zero: true,
            ecn_ece: false,
            ecn_cwr: false,
            reserved_bits: 0,
            quirks: vec![],
        };
        let candidates = match_observation(&observation, &default_signatures(), 60, 5);
        assert_eq!(candidates[0].family, "Linux");
    }
}
