# Releasing

Vendetta publishes releases from Git tags through GitHub Actions.

## Release Checklist

1. Update `version` in [Cargo.toml](Cargo.toml).
2. Move release notes from the `Unreleased` section in [CHANGELOG.md](CHANGELOG.md) into a new versioned section.
3. Run the local verification suite:

```bash
cargo fmt --all --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

4. Commit the release changes.
5. Create and push a version tag:

```bash
git tag v0.1.0
git push origin main --follow-tags
```

## What the Release Workflow Does

When a new tag matching `v*` is pushed, GitHub Actions will:

- re-run the verification suite
- build release binaries on Linux and Windows
- package the binary with `README.md`, `LICENSE`, and `CHANGELOG.md`
- generate `SHA256SUMS.txt`
- publish the assets to the GitHub Releases tab
