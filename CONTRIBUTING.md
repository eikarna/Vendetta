# Contributing

## Prerequisites

- Rust stable toolchain
- Git
- OpenSSL or another source of PEM-encoded TLS assets for local testing

## Local Development

Clone the repository, create a feature branch, and run the full verification
suite before opening a pull request.

```bash
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

## Configuration and Manual Testing

- Use [examples/client.json](examples/client.json) as the client template.
- Use [examples/server.json](examples/server.json) as the server template.
- Generate password hashes with `vendetta hash-password --password-stdin`.
- Keep plaintext client passwords out of shared logs and screenshots.

## Pull Requests

- Keep changes scoped to one problem.
- Add or update tests when behavior changes.
- Update [CHANGELOG.md](CHANGELOG.md) for user-visible changes.
- Prefer small PRs that are easy to review and revert.

## Commit and Review Expectations

- Use clear commit messages.
- Include setup, migration, or security notes in the PR description when relevant.
- Do not merge if CI is failing.

## Releases

Release steps are documented in [RELEASING.md](RELEASING.md).
