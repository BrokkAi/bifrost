# Release crate inventory

Use this list before each Bifrost release. It is the expected crates.io
publication set for the workspace.

| Package | Manifest | Publication order |
| --- | --- | --- |
| `brokk-bifrost-core` | `crates/bifrost-core/Cargo.toml` | 1 |
| `brokk-bifrost-analysis` | `crates/bifrost-analysis/Cargo.toml` | 2 |
| `brokk-bifrost-nlp` | `crates/bifrost-nlp/Cargo.toml` | 3 |
| `brokk-bifrost-policy` | `crates/bifrost-policy/Cargo.toml` | 3 |
| `brokk-bifrost-semantic-packs` | `crates/bifrost-semantic-packs/Cargo.toml` | 3 |
| `brokk-bifrost-runtime` | `crates/bifrost-runtime/Cargo.toml` | 4 |
| `brokk-bifrost-mcp` | `crates/bifrost-mcp/Cargo.toml` | 5 |
| `brokk-bifrost-lsp` | `crates/bifrost-lsp/Cargo.toml` | 5 |
| `brokk-bifrost` | `Cargo.toml` | 6 |

## Pre-release audit

Complete these checks before you create the release tag:

1. Compare this table with the root workspace members and all package names.
2. Confirm that each package exists on crates.io.
3. Confirm that each package has a trusted GitHub publisher for this repository.
4. Confirm that the publisher uses `release.yml` and the `release` environment.
5. Confirm that `release.yml` includes each package in its publication graph.
6. Confirm that each internal dependency uses the release version.

## New crates

Do not add a crate only to move code into a new directory. A new crate must have
a clear dependency, compilation, publication, or ownership boundary.

When a change adds a publishable crate, update this table and the release
workflow in the same change. Publish the crate through a separate bootstrap
change before the next version release. Configure its trusted publisher during
that bootstrap. This process prevents a version release from stopping because
crates.io does not know the new package or does not trust its workflow.
