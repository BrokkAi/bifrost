# Vertical split, phase 2: what stage 2 bought us

Evaluation of the `brokk-bifrost-core` extraction (#1549, commits `428c3446` + `8ccc4afa`),
measured 2026-08-03 on the primary dev machine. Baseline is the pre-split commit `1071d78a`;
post-split is `236d94c7`. All cold builds ran in isolated cargo targets
(`scripts/with-isolated-cargo-target.sh`), featureless dev profile, sequentially on an
otherwise idle machine. Warm-loop numbers are single runs; treat +/- 1-2s as noise.

## What moved

13,159 LOC / 30 files into `crates/bifrost-core`: the util family (hash, text_utils,
path_normalization, cancellation, profiling, schema_version, compact_graph, throttled_log),
the cache family (cache_db, cache_gc, gitblob, git_file, the SQL migrations), the analyzer
model layer (model.rs with `Language`, fq_name, identifier, dense_id, source_content,
semantic_diagnostics, config, test_paths, project), and `structural/{kinds,spec}.rs`.
Zero source changes in any downstream crate; analysis re-exports everything at its old paths.
`capabilities.rs`/`pool_memo.rs` stayed behind, blocked on `IAnalyzer` (see stage-3 notes).

## Cold build: a wash, as predicted

| | baseline `1071d78a` | post-split `236d94c7` |
| --- | ---: | ---: |
| workspace wall | 168.4s | 165.7s |
| analysis frontend (rmeta gate for policy/nlp) | 78.0s | 75.8s |
| analysis full unit | 123.8s | 114.9s |
| core unit | - | 5.5s (starts t=34.2; analysis pipelines in at t=38.8) |

Layering serializes almost exactly what it removes: core's 5.5s sits in front of an
analysis frontend that shrank by ~2s, netting ~3s of wall. This was the predicted shape -
a 13k-LOC peel off a 519k-LOC crate cannot move the pole.

## Warm whole-workspace incrementals: a wash

Touch one file, `cargo build --workspace`, warm target:

| edited file | baseline | post-split |
| --- | ---: | ---: |
| model-layer file (text_utils.rs) | 23.9s | 22.7s |
| analysis file (analyzer/common.rs) | 22.8s | 22.6s |

Incremental compilation already made single-file edits cheap; the split neither helps nor
hurts the edit-build loop when the target is the whole workspace.

## The real win: the model-layer test loop

Touch a model-layer file, then build its unit-test target
(`cargo test -p <crate> --lib --no-run`):

| | baseline (target = analysis lib tests) | post-split (target = core lib tests) |
| --- | ---: | ---: |
| first iteration after a dev build | 148.6s | 16.8s |
| steady state (each subsequent edit) | 19.2s | **1.1s** |

Pre-split, iterating on cache_db, gitblob, fq_name, model.rs or text_utils meant
compiling the 519k-LOC crate's `cfg(test)` universe and relinking its giant test binary
on every edit. Post-split that loop is effectively instant. This is the same effect CI
now gets structurally: the "Analysis, policy, and nlp unit tests" job runs core's unit
tests in seconds without waiting on the analysis build.

## Non-timing outcomes

- The seam decisions stage 3 needs are now made and proven: mirror the module tree
  (moved files were near-byte-identical; ~630 insertions total for the extraction),
  module-level re-exports preserve every old path, promote-then-audit for visibility
  (105 promotions, 6 demoted on audit), `test-support` features chain down layers,
  and `#[cfg(test)]` fixture modules must become real modules at a crate boundary.
- The workspace machinery for adding a bottom crate is exercised end to end: member
  registration, dependency-direction checks (core -> analysis edges rejected by
  `check-workspace-dependencies.mjs`), release DAG (core publishes before analysis,
  both promotion-evidence-gated), packaging gate green from the actual archives.
- Flushed out four latent CI/master problems in the process (unbuildable analysis
  archive from `source_ingestion.rs` include_str! vs exclude list; unaudited
  onig_sys/ring native-linking packages; nlp sidecar test needing uv on the runner;
  stale Python client tests from the five-tool removal).

## Stage-3 go/no-go inputs

The cold-build math says per-language crates WILL move the pole where stage 2 could not:
the eleven language units plus their graphs are the bulk of the 519k LOC, and everything
that leaves the analysis crate both shortens its 76s frontend and gains the 18x test-loop
effect above for its own unit tests. The costs, per the seam matrix
(`analysis-crate-seam-matrix-2026-08.md`):

1. `IAnalyzer` must be decomposed (or a language SPI trait introduced) first. It blocked
   even `capabilities.rs` in stage 2 and every language reaches it.
2. Four hand-maintained language dispatch lists (finder, workspace_graph, scan_usages,
   dead_code_smells) must become registries or stay in the top crate.
3. Visibility promotion at ~10x stage-2 scale; scriptable promote-then-audit.
4. `js_ts::cache` relocation (nine languages import it) - cheap, worth doing regardless.
5. The JVM realm ships as one crate; js_ts needs four seams built first; the other seven
   languages are MODERATE with enumerated promotion lists.
6. Publishing: each new crate repeats the crates.io bootstrap ceremony
   (policy/nlp/core are already queued for it before the next release).

Recommendation: stage 3 is justified on the measured locality economics, but only in the
matrix's order - core SPI design first, then jvm-merged or a MODERATE language
(rust or go) as the pilot, js_ts last. Whether to spend that is a product call given the
bootstrap/publishing overhead per crate.
