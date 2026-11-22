# Signature Format

Signature files use TOML and may contain one or more `[[signature]]` tables.
All fields except `name` and `family` are optional.

```toml
[[signature]]
name = "Example Linux"
family = "Linux"
direction = "client"
initial_ttl = 64
tcp_window = 29200
mss = 1460
window_scale = 7
options_layout = "mss,nop,ws,nop,nop,ts,sok,eol"
df = true
```

`direction` is `client` or `server`. `options_layout` contains the TCP option
order recognized by Quietprint. Matching is a weighted similarity score, and
the CLI filters candidates with `--min-score` and limits them with `--top`.
