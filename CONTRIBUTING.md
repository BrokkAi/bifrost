# Contributing

## Development Setup

Rust build:

```bash
cargo build --lib --bin bifrost
```

Python client build/install:

```bash
maturin develop
```

This repository has a maturin-backed `pyproject.toml` so `uv run python ...` can execute the `bifrost_searchtools` client through the PyO3 native Rust extension.

## Test

Rust:

```bash
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Python:

```bash
scripts/test_python.sh
```

That wrapper provisions a uv-managed Python 3.12 environment, makes `maturin` available, installs the editable native extension, and then runs the unittest suite.

## Python Development

For repo-local development without installing the package, `SearchToolsClient(..., library_path=...)` can load a built debug library such as `target/debug/libbrokk_bifrost.so`.

## Release Process

The crate, the `bifrost` binary, and the Python wheel are versioned **together**
and cut from a **single tag**. `Cargo.toml` is the only place the version lives;
`pyproject.toml` inherits it via maturin's `dynamic = ["version"]`, so the wheel
and the crate can never drift.

To cut a release:

1. Bump `version` in `Cargo.toml` (only there) and merge.
2. Tag the commit and push:

   ```bash
   git tag -a v0.6.4 -m "Release v0.6.4"
   git push origin refs/tags/v0.6.4
   ```

A single `vX.Y.Z` tag fans out to three workflows:

- `release.yml` — builds platform archives + SHA-256 checksums and publishes a
  GitHub Release.
- `publish-crate.yml` — publishes the crate to crates.io.
- `publish-wheels.yml` — builds all platform wheels + sdist and publishes to PyPI.

Each publish workflow refuses to run if the tag does not match `Cargo.toml`, and
`publish-wheels.yml` additionally fails if `pyproject.toml` ever re-introduces a
hardcoded `version` (which would break the single-source invariant) or if a built
artifact does not carry the tagged version.

All three can also be triggered manually from the GitHub Actions UI with a `tag`
input.

## Version Policy

- The crate version in `Cargo.toml` is the single source of truth for both the
  Rust crate and the Python package; never add a `version` to `pyproject.toml`.
- The Tree-sitter grammar crate versions are intentionally not forced to share
  the same numeric version. The policy is documented in `Cargo.toml`.
