# Vendetta

Vendetta is a cross-platform encrypted TCP proxy written in Rust. It accepts
local SOCKS5 `CONNECT` requests, carries them through a shared client TLS plus
SSH session, and forwards them on the server through SSH `direct-tcpip`
channels.

## Features

- SOCKS5 `CONNECT` proxy support for TCP workloads
- TLS server identity verification on the client
- SSH password authentication over the TLS transport
- Server-side outbound egress filtering for public Internet destinations only
- Cross-platform builds for Linux and Windows
- GitHub Actions CI for formatting, linting, tests, and release builds
- GitHub Releases publishing on every pushed version tag such as `v0.1.0`

## CLI

```bash
vendetta client --config client.json
vendetta server --config server.json
vendetta hash-password --password-stdin
```

## Configuration

Reference configuration files live under [examples/client.json](examples/client.json)
and [examples/server.json](examples/server.json).

Client configuration fields:

- `local_bind`
- `server_addr`
- `server_name`
- `username`
- `password`
- `connect_timeout_ms`
- `idle_timeout_secs`
- `relay_buffer_bytes`

Server configuration fields:

- `listen`
- `tls_cert_path`
- `tls_key_path`
- `ssh_host_key_path`
- `users`
- `max_channels_per_session`
- `connect_timeout_ms`
- `relay_buffer_bytes`

## Development

```bash
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

## Release Flow

Push a semantic version tag such as `v0.1.0` and GitHub Actions will:

1. run the verification suite
2. build release binaries for Linux and Windows
3. attach packaged artifacts to the GitHub Releases tab

See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md),
[SECURITY.md](SECURITY.md), and [RELEASING.md](RELEASING.md) for the operating
docs.
