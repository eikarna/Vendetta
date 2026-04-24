# Changelog

All notable changes to this project will be documented in this file.

The format follows Keep a Changelog and the project uses SemVer-style tags such
as `v0.1.0`.

## [Unreleased]

### Added

- GitHub Actions CI for formatting, linting, unit tests, integration tests, and
  cross-platform release builds.
- GitHub Releases automation that publishes Linux and Windows artifacts whenever
  a new version tag is pushed.
- Baseline project operating documents including contribution, release, and
  security guidance.

## [0.1.0] - 2026-04-23

### Added

- Initial Vendetta release with SOCKS5 `CONNECT` proxying over TLS plus SSH.
- Password hashing support with Argon2id PHC strings.
- Public-Internet-only egress filtering on the server.
- Integration coverage for end-to-end proxy relaying.
