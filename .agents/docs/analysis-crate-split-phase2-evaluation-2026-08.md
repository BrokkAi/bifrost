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

## Phase 3 gates 1-2 follow-up (2026-08-04, milestone 3 of the registry ExecPlan)

Measured at `5fe542b1` (registry + SPI inversion + CodeUnitIndex split complete), same
methodology, same machine, isolated target, featureless dev profile. Baseline for
comparison is the post-stage-2 column above (`236d94c7`).

| | post-stage-2 `236d94c7` | post-registry `5fe542b1` |
| --- | ---: | ---: |
| workspace wall | 165.7s | 159.3s |
| analysis frontend (rmeta gate) | 75.8s | ~71.8s |
| analysis full unit | 114.9s | 114.4s |
| warm workspace, core-file edit | 22.7s | 21.4s |
| warm workspace, analysis-file edit | 22.6s | 23.5s |
| core test loop, first iteration | 16.8s | 18.1s |
| core test loop, steady state | 1.1s | 1.2s |

Build-time neutral, as the plan required (decision 7) and predicted: the deltas are
within run-to-run variance. The one new locality win is that `capabilities.rs` and
`pool_memo.rs` -- the exact files stage 2 had to abandon -- now iterate in the core
loop (~1.0s measured on a capabilities.rs touch) instead of the 19s analysis loop.

What this stage actually bought is not on the timing table: the six-plus-one dispatch
lists are gone, capability lookup is one enforced contract
(`analyzer/languages.rs`), a syn-based module-tree-aware gate fails the build on any
new framework reach-in, the capability matrix is a reviewed snapshot, behavior was
proven flat by a byte-identical 56k-site reference-differential census, and
`IAnalyzer` is split with `CodeUnitIndex` proven in core. The lockstep-list hazard
class that motivated the plan no longer exists regardless of what happens next.

## Stage 3 (per-language extraction): recommendation

Conditional go: run ONE pilot extraction, and only when the build economics are worth
buying; do not commit to the fleet now.

The correctness argument for extraction is spent -- the registry already delivered it
in place. What remains is pure build economics: ~0.17s of analysis frontend per kLOC
removed, plus the 18x test-loop effect for whatever leaves. Those economics still
favor extraction eventually (the eleven language units and their graphs are the bulk
of the 519k LOC), but the prerequisite relocations are now enumerated and real:

1. Type-level leaks that must be lowered or generalized first: `ScalaExportInfo` in
   `tree_sitter_analyzer.rs`/`store/mod.rs` signatures, `BoundedJavaResolution` in
   `receiver_query.rs`'s Java route (both carry gate-allowlist follow-up notes).
2. Per-language implementation sets living in framework files, which a language crate
   cannot leave behind: `exception_handling.rs` (ten analyze_* bodies),
   `get_definition/mod.rs` + `call_sites.rs`, the `lexical_definitions.rs` node-kind
   tables, dead-code scoring, epoch cells (census doc section 6).
3. The crates.io bootstrap ceremony per new crate.

Dependency structure (the choice this recommendation must name): analysis-owned
shims, not SPI lowering. `LanguageSupport` and its contract traits stay `pub(crate)`
in analysis; each extracted language crate exposes plain functions and types, and
analysis keeps a thin `<Lang>Support` adapter that implements the SPI over them. Two
reasons. First, stability posture: lowering the SPI into a published crate makes the
whole contract public API in a workspace whose supported tier is deliberately the
facade; shims keep the contract internal and freely evolvable. Second, incrementality:
either structure requires the shared scan/product types (`UsageEdges`,
`UsageEdgeWeights`, scan contexts) to sit below both parties, but shims let each pilot
lower only the types it actually consumes, instead of front-loading a wholesale SPI
crate. Revisit full SPI lowering only if shim maintenance across many languages
proves costly in practice.

Pilot choice per the seam matrix ordering: Go (MODERATE seam, enumerated promotion
list, no realm entanglement) or Rust if its heavier graph is wanted as the harder
proof. JVM ships as one crate whenever it goes; js_ts last. Measure the pilot's
actual frontend reduction and test-loop gain against the relocation cost it forced,
then decide the fleet with numbers rather than extrapolation.
