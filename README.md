<p style=text-align:center; height:50px;><img src=logo.png></p>

# quietprint

Quietprint is a Rust tool for **purely passive** TCP/IP operating-system fingerprinting. It analyzes SYN and SYN+ACK packets in packet capture files and estimates the sending stack's OS family from TCP/IP header characteristics.

Offline pcap/pcapng analysis is available. Live capture and signature learning
are not implemented yet.

## Installation

### Arch Linux

Install the stable Rust toolchain:

```sh
sudo pacman -S --needed rust
```

From a Quietprint source checkout, install the optimized executable into
`~/.cargo/bin`:

```sh
cargo install --path .
```

Or build and run it directly from the checkout:

```sh
cargo build --release
./target/release/quietprint --help
```

Quietprint requires Rust 1.75 or newer and uses the stable toolchain. Offline
pcap/pcapng analysis does not require libpcap. Ensure `~/.cargo/bin` is on your
`PATH` when using `cargo install`.

### Other platforms

Install Rust 1.75+ with [rustup](https://rustup.rs/), obtain a source checkout,
then run `cargo install --path .` or `cargo build --release` from the project
root. Live capture is not available yet.

## CLI

```text
quietprint analyze <file.pcap|-> [--signatures DIR] [--direction client|server|both]
quietprint live --iface <name>
quietprint learn <file.pcap> --label "<OS name>"
quietprint validate-signatures [--signatures DIR]
```

Use `--top N` with `N` from 1 to 50 to control candidate ranking. The default
is 50. A candidate is emitted only from the loaded signature database; the
tool does not invent OS matches or claim verified coverage.

Candidates must match the loaded signature database and meet `--min-score`.

## Acceptable Use and Legal Notice

Use Quietprint only on networks you own or where you have explicit written permission to monitor. Examples include your own home laboratory, approved employer monitoring, and authorized CTF or lab environments. Passive packet capture may still be subject to interception, wiretapping, workplace monitoring, privacy, and data-protection laws. IP addresses and other captured identifiers may be personal data, including under frameworks such as GDPR.

Obtain appropriate authorization and, where uncertain, legal advice before monitoring a network. This notice is not legal advice.

Quietprint never sends packets, scans targets, performs active probes, reads application payloads, or persists observed data by default. In offline analysis, `--anonymize` replaces source and destination IPs with `[redacted]` in output; matching still uses the original observations. MAC omission is planned. The tool is not intended to identify individuals.

## Limitations

NAT, proxies, load balancers, VPNs, middleboxes, packet rewriting, and manually
tuned stacks can change or obscure fingerprint characteristics.

## Accuracy

Quietprint provides heuristic OS candidates from built-in TCP/IP signatures.
It does not claim verified OS identity: candidates can be wrong when NAT,
virtualization, proxies, middleboxes, or manual TCP tuning alter header
values. Verified accuracy evaluation remains future work.

Use `quietprint analyze <capture> --top 5 --min-score 60` to rank candidates.
Use `--aggregate` to collapse repeated SYN fingerprints in JSON, NDJSON, CSV,
and text output.
Custom TOML signatures can be supplied with `--signatures <file-or-directory>`;
see [signatures/README.md](signatures/README.md) and
[docs/signature-format.md](docs/signature-format.md).

## Performance

A local release-build benchmark compared Quietprint with p0f 3.09b on the same
500,000-packet synthetic Ethernet/IPv4 SYN capture. Every captured frame was
74 bytes and repeated the same byte-identical SYN; each tool emitted one
identification result. Each tool was run five times.
Quietprint used `analyze --json --aggregate`; p0f used offline read mode and
wrote its log to a file.

Re-run the comparison on your machine with:

```sh
cargo build --release
python3 scripts/benchmark.py --packets 500000 --runs 5
```

The script reports medians for identical frames and for same-flow SYN
retransmissions whose IP ID and TCP sequence number vary. It generates
synthetic captures in a temporary directory and does not read or capture
network traffic. It prints each tool's result count and reports a throughput
ratio only when those counts match. Quietprint aggregates the varied
retransmissions into a few feature-distinct observations, while p0f records
them as separate events, so that case is a stress test rather than a
like-for-like comparison.

| Tool | Median time | Approximate throughput |
|---|---:|---:|
| Quietprint (`--aggregate --json`) | 0.095 s | 5.24 million packets/s |
| p0f 3.09b | 0.138 s | 3.62 million packets/s |

Both tools emitted one result for these identical packets. On this workload,
Quietprint took about **31% less time** and processed packets at about **1.45x
the rate** of p0f.

The synthetic retransmission stress case took 1.396 s in Quietprint and 12.464 s
in p0f. Quietprint emitted 3 aggregated observations and p0f emitted 500,000
SYN events, so this is not a fair speed comparison.

On the one synthetic SYN used to smoke-test output, Quietprint returned Linux
candidates (top score 80) and p0f returned `os=???`:

| Tool | Output |
|---|---|
| Quietprint | `Linux 3.11 and newer` (80), plus lower-ranked candidates |
| p0f | `os=???` |

That packet has no independently verified OS label, so this is not an accuracy
result. Both tools successfully read the synthetic pcap and pcapng smoke-test
captures.

### Where Quietprint can be a better fit

- `--aggregate` recognizes byte-identical Ethernet/IPv4 SYN packets before
  full parsing, avoiding repeated work for duplicated frames and exact
  retransmissions.
- It reports ranked signature candidates with scores and exposes extracted
  header features in JSON, NDJSON, CSV, or text output.
- Custom TOML signatures can be loaded without modifying the program.
- It is a standalone Rust executable for offline pcap/pcapng analysis and does
  not need libpcap for that workflow.

These are workflow and output advantages, not proof of generally higher
identification accuracy. p0f has a mature, broader fingerprint database and is
the more established choice for OS fingerprint coverage.

### Comparison snapshot

| Area | Result |
|---|---|
| Repeated identical-packet throughput | **Quietprint wins this one local workload** (1.45x measured rate, with 1 result each). |
| Varied retransmission throughput | **No winner declared**; Quietprint emitted 3 results and p0f emitted 500,000. |
| Output sample / accuracy | **Inconclusive**; synthetic packet has no verified ground truth. |
| Offline pcap and pcapng input | Both passed the synthetic smoke test. |
| Ranked JSON/NDJSON/CSV output and custom TOML signatures | Quietprint offers these workflows. |
| Live capture and mature fingerprint coverage | **p0f wins today**; Quietprint's live command is not implemented and its built-in database is small. |

Overall there is no evidence that Quietprint is better in every area. It wins
the tested repeated-frame throughput case and offers flexible structured output;
p0f remains the more complete and established tool. Real accuracy, memory use,
and performance on representative non-synthetic captures have not been
compared.

The speed result is specific to a capture containing byte-identical repeated
SYNs: Quietprint's aggregate mode skips those frames before full parsing and
buffers JSON output. It does **not** show that Quietprint is faster on captures
where packets differ. Results depend on capture shape, hardware, output format,
p0f's host cache, compiler settings, and packet volume. This synthetic test
does not establish real-world accuracy or performance.

## Tests

The test suite uses synthetic Ethernet/IPv4/IPv6 packets and never requires
third-party captures or live network traffic.

```sh
cargo test
```

Detection tests cover:

- IPv4 TCP SYN client packets
- IPv4 TCP SYN+ACK server packets
- IPv6 TCP SYN packets using hop limit as TTL
- TCP option layout and MSS/window-scale extraction
- DF and IP ID behavior
- Rejection of non-SYN and SYN packets with payload
- Arbitrary-byte parser robustness

## License

MIT. See [LICENSE](LICENSE).
