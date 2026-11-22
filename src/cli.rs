//! Command-line interface for quietprint.

use std::borrow::Cow;
use std::collections::HashSet;
use std::io::{stdout, BufWriter, Write};
use std::path::PathBuf;

use crate::capture::offline::read_observations_with_aggregation;
use crate::signatures::{load_signatures, match_observation, Candidate};
use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct AnalyzedObservation<'a> {
    #[serde(flatten)]
    observation: &'a crate::parse::Observation,
    candidates: &'a [Candidate],
}

fn displayed_observation(
    observation: &crate::parse::Observation,
    anonymize: bool,
) -> Cow<'_, crate::parse::Observation> {
    if anonymize {
        let mut observation = observation.clone();
        observation.source_ip = "[redacted]".into();
        observation.destination_ip = "[redacted]".into();
        Cow::Owned(observation)
    } else {
        Cow::Borrowed(observation)
    }
}

fn escape_csv_field(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    if value
        .chars()
        .any(|character| matches!(character, ',' | '"' | '\r' | '\n'))
    {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

/// Quietprint passively identifies TCP/IP operating-system families.
#[derive(Debug, Parser)]
#[command(name = "quietprint", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Analyze a pcap or pcapng file (offline support is added in M1).
    Analyze {
        /// Packet capture file, or "-" for stdin.
        file: PathBuf,
        #[arg(long)]
        signatures: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "both")]
        direction: Direction,
        #[arg(long, default_value = "60")]
        min_score: u8,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        ndjson: bool,
        #[arg(long)]
        csv: bool,
        #[arg(long, help = "Redact source and destination IP addresses in output")]
        anonymize: bool,
        /// Maximum number of candidate matches returned (1-50).
        #[arg(long, default_value = "50", value_parser = clap::value_parser!(u8).range(1..=50))]
        top: u8,
        /// Collapse identical SYN observations.
        #[arg(long)]
        aggregate: bool,
    },
    /// Capture live traffic (implemented behind the "live" feature in M5).
    Live {
        #[arg(long)]
        iface: String,
        #[arg(long)]
        signatures: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "both")]
        direction: Direction,
        #[arg(long, default_value = "60")]
        min_score: u8,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        ndjson: bool,
        #[arg(long)]
        csv: bool,
        #[arg(long)]
        anonymize: bool,
        /// Maximum number of candidate matches returned (1-50).
        #[arg(long, default_value = "50", value_parser = clap::value_parser!(u8).range(1..=50))]
        top: u8,
    },
    /// Print a draft signature from a capture (implemented in M6).
    Learn {
        file: PathBuf,
        #[arg(long)]
        label: String,
    },
    /// Validate signature TOML files.
    ValidateSignatures {
        #[arg(long)]
        signatures: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Direction {
    Client,
    Server,
    Both,
}

/// Run the command-line application.
pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Analyze {
            file,
            json,
            ndjson,
            csv,
            top,
            signatures,
            min_score,
            direction,
            anonymize,
            aggregate,
            ..
        } => {
            if top > 50 {
                bail!("--top must be between 1 and 50");
            }
            if [json, ndjson, csv]
                .into_iter()
                .filter(|enabled| *enabled)
                .count()
                > 1
            {
                bail!("choose only one output format: --json, --ndjson, or --csv");
            }
            let observations = read_observations_with_aggregation(&file, aggregate)?;
            let signature_db = load_signatures(signatures.as_deref())?;
            if json || ndjson {
                let mut seen = HashSet::<&crate::parse::Observation>::new();
                let mut last_observation = None;
                let mut stdout = BufWriter::new(stdout().lock());
                for observation in &observations {
                    if direction != Direction::Both
                        && matches!(
                            (direction, observation.direction),
                            (Direction::Client, crate::parse::Direction::Server)
                                | (Direction::Server, crate::parse::Direction::Client)
                        )
                    {
                        continue;
                    }
                    if aggregate {
                        if last_observation.is_some_and(|last| last == observation) {
                            continue;
                        }
                        last_observation = Some(observation);
                        if !seen.insert(observation) {
                            continue;
                        }
                    }
                    let candidates = match_observation(observation, &signature_db, min_score, top);
                    let displayed = displayed_observation(observation, anonymize);
                    serde_json::to_writer(
                        &mut stdout,
                        &AnalyzedObservation {
                            observation: displayed.as_ref(),
                            candidates: &candidates,
                        },
                    )?;
                    stdout.write_all(b"\n")?;
                }
                stdout.flush()?;
            } else if csv {
                println!(
                    "source_ip,direction,initial_ttl,hop_distance,df,tcp_window,mss,window_scale,options_layout,candidates"
                );
                let mut seen = HashSet::<&crate::parse::Observation>::new();
                let mut last_observation = None;
                for observation in &observations {
                    if direction != Direction::Both
                        && matches!(
                            (direction, observation.direction),
                            (Direction::Client, crate::parse::Direction::Server)
                                | (Direction::Server, crate::parse::Direction::Client)
                        )
                    {
                        continue;
                    }
                    if aggregate {
                        if last_observation.is_some_and(|last| last == observation) {
                            continue;
                        }
                        last_observation = Some(observation);
                        if !seen.insert(observation) {
                            continue;
                        }
                    }
                    let candidates = match_observation(observation, &signature_db, min_score, top);
                    let displayed = displayed_observation(observation, anonymize);
                    let fields = [
                        displayed.source_ip.clone(),
                        format!("{:?}", displayed.direction),
                        displayed.initial_ttl.to_string(),
                        displayed.hop_distance.to_string(),
                        displayed
                            .df
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        displayed.tcp_window.to_string(),
                        displayed
                            .mss
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        displayed
                            .window_scale
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        displayed.options_layout.clone(),
                        format!("{candidates:?}"),
                    ];
                    println!(
                        "{}",
                        fields
                            .iter()
                            .map(|field| escape_csv_field(field))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                }
            } else {
                let mut seen = HashSet::<&crate::parse::Observation>::new();
                let mut last_observation = None;
                let mut selected = Vec::new();
                for observation in &observations {
                    if direction != Direction::Both
                        && matches!(
                            (direction, observation.direction),
                            (Direction::Client, crate::parse::Direction::Server)
                                | (Direction::Server, crate::parse::Direction::Client)
                        )
                    {
                        continue;
                    }
                    if aggregate {
                        if last_observation.is_some_and(|last| last == observation) {
                            continue;
                        }
                        last_observation = Some(observation);
                        if !seen.insert(observation) {
                            continue;
                        }
                    }
                    selected.push(observation);
                }
                println!("SYN observations: {}", selected.len());
                for observation in selected {
                    let displayed = displayed_observation(observation, anonymize);
                    println!("{displayed:?}");
                    let candidates = match_observation(observation, &signature_db, min_score, top);
                    if candidates.is_empty() {
                        println!("  OS: unknown (no candidate met --min-score {min_score})");
                    } else {
                        println!("  OS candidates:");
                        for candidate in candidates {
                            println!(
                                "    {} {} ({})",
                                candidate.family, candidate.name, candidate.score
                            );
                        }
                    }
                }
            }
            Ok(())
        }
        Command::Live { .. } => bail!(
            "live capture is not implemented yet (milestone M5); this build is purely offline"
        ),
        Command::Learn { .. } => {
            bail!("signature learning is not implemented yet (milestone M6)")
        }
        Command::ValidateSignatures { signatures } => {
            let signatures = load_signatures(signatures.as_deref())?;
            println!("Validated {} signature(s).", signatures.len());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_analyze() {
        let cli = Cli::try_parse_from([
            "quietprint",
            "analyze",
            "capture.pcap",
            "--direction",
            "client",
            "--json",
        ])
        .unwrap();

        assert!(matches!(cli.command, Command::Analyze { .. }));
    }

    #[test]
    fn cli_rejects_unknown_direction() {
        assert!(Cli::try_parse_from([
            "quietprint",
            "analyze",
            "capture.pcap",
            "--direction",
            "sideways"
        ])
        .is_err());
    }
}
