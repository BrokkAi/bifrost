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

## Go extraction pilot: measurements and verdict (2026-08-04, P2 of the pilot ExecPlan)

Measured at the pilot tip (P1.4 wiring commit), isolated targets, featureless dev
profile. The pre-pilot comparison column is the cold run at the master-merge commit
(49a7f535); the xee-xpath dependency removal (6bcd3cdb) sits between them and changed
only the off-pole dependency band.

| | pre-pilot | pilot tip |
| --- | ---: | ---: |
| workspace wall | 152.7s | 154.6s |
| analysis frontend (rmeta gate) | 73.3s | 70.5s |
| analysis full unit | 109.6s | 105.5s |
| brokk-bifrost-go cold | - | 1.9s (starts t=26.8, fully off the critical path) |
| go crate test loop, first / steady | - | 15.5s / 0.44s |
| warm workspace edit of a go-crate file | - | 21.4s |

Behavior: byte-identical reference-differential censuses and full per-site payloads
on the 11-repo corpus (56,506 sites) and on a denser Go pass with tests included
(8,239 sites), between the pre-P0 commit and the pilot tip
(go-extraction-pilot-differential-evidence-2026-08.md).

Scorecard against the plan's PASS bar:

- Behavior flat: PASS (4/4 identical projections).
- Gates green: PASS (fmt, clippy, workspace nextest 8420, dependency graph, ten
  package archives, release-workflow policy tests).
- Frontend reduction in the predicted band: PASS and above it -- 2.8s for ~6.0k LOC
  moved is ~0.47s/kLOC against the 0.17 planning rate, and the steady-state go test
  loop at 0.44s reproduces the core locality win at >40x.
- Shim at or under ~1.3k LOC: FAIL -- the analysis-side residue is ~4.5k LOC. The
  planned forwarding shim is ~1.05k of it; the other ~3.5k is Go language logic the
  census-missed couplings pinned in place: parse_go_file and its visitors write
  ParsedFile, analysis's private indexing accumulator (617 LOC); diagnostics threads
  DefinitionIndexHandle (1,072); extractor/hits need IAnalyzer::enclosing_code_unit,
  which has no CodeUnitIndex equivalent (650); the inverted-edge driver stayed in
  analysis by P0 design (618); the memo shell is intentional (164).

Verdict: CONDITIONAL. The pilot proves the economics (better than predicted) and the
mechanism (shims, behavior-flat, gates enforce the boundary), but a fleet run under
today's contracts would retain roughly a quarter of every language in analysis and
repeat these five couplings eleven times. The retained mass is not shim overhead; it
is three shared, fundable workstreams:

1. Lower the per-file indexing product (ParsedFile and its builders) so language
   declaration walks can leave -- the same workstream that generalizes
   ScalaExportInfo out of tree_sitter_analyzer/store signatures.
2. Lower the inverted-edge driver (EdgeCollector, parse_and_collect) or split its
   IAnalyzer dependency down to CodeUnitIndex plus parsing inputs.
3. Give CodeUnitIndex an enclosing-declaration query (reopens one milestone-2
   adjudication: "answers from a parse tree" was an implementation argument, not a
   semantic one) and a lowered handle for bounded definition lookup.

Recommendation to Jonathan: fund the three workstreams, re-run Go's residual moves
(diagnostics, declarations walk, extractor/hits, inverted) to shrink the shim to the
planned ~1.1k, then fleet with the full pattern. The alternative -- fleet now with
fat shims -- still buys the frontend and test-loop wins but leaves ~25% of each
language's mass in analysis and bakes the couplings in eleven more times before the
workstreams undo them. Fleet execution is on hold for that call.

## Stage-3 fleet: closing measurements (2026-08-06, all eleven languages extracted)

Measured at 249c1121 (js_ts extraction merged, fleet complete), same methodology:
isolated cargo target (`scripts/with-isolated-cargo-target.sh`), featureless dev
profile, cold, sequential on an otherwise idle machine.

| | baseline 1071d78a | pre-pilot 49a7f535 | fleet tip 249c1121 |
| --- | ---: | ---: | ---: |
| workspace wall | 168.4s | 152.7s | 132.0s |
| analysis full unit | 123.8s | 109.6s | 88.0s |
| analysis share of wall | 74% | 72% | 67% |
| analysis rmeta gate (policy/nlp start) | - | t=105.9 | t=90.7 |
| language-crate band | - | - | 9 crates, t=26.4 start, all parallel |

Language crate cold units (all start together at t=26.4 on core's rmeta, all
complete before analysis needs them at t=33.1 -- the entire band is off the
critical path): php 2.1s, ruby 2.1s, go 2.9s, python 3.3s, csharp 3.5s,
js-ts 5.1s, rust 6.6s, cpp 6.9s, jvm 8.5s. Core 5.8s at t=22.1.

Steady-state per-crate test loops (`cargo-nextest -p <crate> --lib`, warm):
js-ts 0.46s, go 0.44s (pilot number reproduced at fleet scale). The
pre-campaign alternative was the 19s analysis edit loop for any language
change.

Against the plan's expectations:

- The ~25-30% wall ceiling was the projection for the FULL split including the
  parked bands (semantic lowerers ~36.8k, semantic_model pack bands ~14.5k+,
  definition/type routes ~15k+). The landed fleet -- ~165k LOC relocated, parks
  retained -- delivers -13.6% wall against the pre-pilot tip and -21.6% against
  the pre-split baseline, with the analysis pole itself down 21.6s (-20%) from
  the pre-pilot 109.6s. Consistent with the ceiling: the remaining pole is
  exactly the parked mass plus the framework (analysis src is now 414.0k LOC,
  from 519k pre-campaign).
- The per-language locality economics (the pilot's headline) held across the
  fleet: every language now has a sub-second steady test loop against the
  pre-campaign 19s, and the 0.47s/kLOC frontend rate held within noise across
  eleven extractions of very different shape.
- The xee-xpath/icu_datetime external band (6bcd3cdb) is gone from the cold
  path; the heaviest remaining externals are libgit2-sys/libsqlite3-sys cc
  builds and rmcp/lsp-types, all fully overlapped.

Remaining known pole-shrinking work, all parked by design with recorded
reasons (census docs + decision log): the per-language semantic lowerers, the
semantic_model pack bands, and the definition/type routes. The routes' js_ts
share shrank 42% during Js-1/1b (3,984 -> 2,314 LOC) as a side effect of the
closure relocations, suggesting the route park is softer than the census
matrix assumed once each language's syntax helpers live crate-side.
