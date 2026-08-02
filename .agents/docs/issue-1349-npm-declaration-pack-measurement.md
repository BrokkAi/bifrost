# Issue 1349 npm declaration-pack measurement

This report records one reproducible smoke measurement for the exact npm declaration-pack path. It is operational evidence, not a machine-independent performance threshold.

## Revision and environment

- Bifrost commit: `c31358c7b` (`Report compiled npm shard bytes`)
- Date: 2026-08-02
- Host: Apple arm64, Darwin 25.5.0
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo: `cargo 1.96.0 (30a34c682 2026-05-25)`
- Catalog mode: ephemeral, reused within one process
- Cargo profile: featureless test profile, unoptimized plus debuginfo

## Command

    cargo test -p brokk-bifrost --test suite_semantic -- js_ts_dependency_semantic_pack::measure_exact_npm_declaration_pack_cold_warm_and_lookup --exact --ignored --nocapture

## Fixture

The ignored test creates one exact npm package at version `1.0.0`, selected by a version-three `package-lock.json` and an installed `package.json` with a root `types` entry. Its declaration artifact contains 250 exported generic interfaces plus one generic base interface. Each generated interface has a property, a method, another typed property, and one extends relation. `node_modules` is ignored by the workspace file listing.

- Declaration bytes: 28,318
- Exact artifacts: 2 (manifest and declaration)
- Total exact artifact bytes: 28,383
- Loaded semantic records: 1,003
- Completeness: complete for discovery, cold production, warm reuse, activation, and lookup

## Observed result

- Cold discovery plus generation: 491,600 us
- Warm discovery plus catalog reuse: 197,333 us
- Warm activation and overlay publication: 253,582 us
- Representative `Widget249` symbol lookup: 10,991 us
- Generated compiled shard raw bytes: 566,590
- Catalog stored bytes: 82,673
- Active-model retained bytes: 778,524

The warm preparation reported one reused pack and no generation. The representative lookup returned `measured.Widget249`. No error, cancellation, partial result, or workspace dependency-file indexing occurred.
