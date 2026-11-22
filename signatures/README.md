# Signatures

Quietprint includes built-in, clearly labeled heuristic signatures for Linux,
Windows, macOS, and FreeBSD. These are not guaranteed OS identification and
can be affected by NAT, proxies, tuning, virtualization, and middleboxes.

Custom signatures can be loaded with `--signatures <file-or-directory>`.
The file format is:

```toml
[[signature]]
name = "My Linux signature"
family = "Linux"
direction = "client"
initial_ttl = 64
tcp_window = 29200
mss = 1460
window_scale = 7
options_layout = "mss,nop,ws,nop,nop,ts,sok,eol"
df = true
```
