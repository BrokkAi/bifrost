# Rust standard-library semantic pack

This directory pins the official Rust `rust-docs-json-preview` component for
`nightly-2026-08-24`, whose compiler is `rustc 1.100.0-nightly
(fb6531d55 2026-08-23)`. The pack contains exactly the public rustdoc JSON
documents for `core`, `alloc`, and `std` from that component. Generated
manifests and shards are release assets and are not checked into Git.
The producer accepts exactly rustdoc JSON format 61 from this pin and rejects
other formats before decoding the full documents.

The producer consumes Rustdoc's typed JSON item graph. It does not parse Rust
source text, execute Cargo, or infer declarations from a local toolchain. The
three crate roots remain qualified (`core::`, `alloc::`, and `std::`) so a
declaration from one standard-library crate cannot collide with another.

The workspace-side Rust dependency reader parses only the structured
`[toolchain].channel` field in `rust-toolchain.toml`. The standard-library pack
is selected only for the exact dated channel above. Stable channels, floating
`nightly`, and other dated nightlies produce an attributable mismatch and do
not activate this pack.

## Regeneration

Run `scripts/public/build-pinned-rust-semantic-packs.sh OUTPUT_DIR WORK_DIR`.
The script downloads the official Linux archive for the pinned nightly,
verifies its SHA-256, copies only `core.json`, `alloc.json`, and `std.json`
into the canonical source-set root, and runs generation plus verification.
The specification additionally verifies the canonical digest of those three
selected files, so changes to archive contents fail closed.

The official archive and compiler identity are recorded in the specification
and notice. The release asset must be generated with the pinned
`rust-docs-json-preview` component; do not substitute rustdoc output from a
different nightly or a local source checkout.
