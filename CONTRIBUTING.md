# Contributing

## Setup

```sh
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Use edition 2021 or newer Rust syntax and keep changes focused. Public library functions should have doc comments.

## Test captures

Do not commit third-party captures. Synthetic captures or captures made by the author on their own network are acceptable only after real IP and MAC addresses are scrubbed.

When changing CLI output, test all supported formats, CSV escaping, conflicting format flags, and `--anonymize` redaction.

## Security and privacy

Never add packet transmission, payload capture, decryption, replay, scanning, spoofing, exploitation, or persistent host databases. Do not commit secrets or personal data.
