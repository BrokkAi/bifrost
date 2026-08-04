# Stage 3 pilot: extract Go into brokk-bifrost-go on analysis-owned shims

Approved by Jonathan 2026-08-04 ("run the pilot and if it works as expected, finish
stage 3"). This plan executes the milestone-3 recommendation of
`.agents/plans/analysis-language-registry-spi.md`: one pilot extraction, analysis-owned
shims, only the types the pilot consumes lowered, measured before any fleet decision.
The factual basis is the seam census taken at `6bcd3cdb` (recorded in the decision log
below and summarized here); LOC figures and file citations come from it. Line numbers
drift; search.

## Shape

New workspace crate `crates/bifrost-go` (package `brokk-bifrost-go`), sitting between
`brokk-bifrost-core` and `brokk-bifrost-analysis`: it depends only on core (plus
crates.io: tree-sitter, tree-sitter-go, rayon, regex, serde, semver), and analysis
depends on it. It holds Go *language knowledge* as plain functions, data, and types.
Analysis keeps the shim: `GoAnalyzer` (a newtype over `TreeSitterAnalyzer<GoAdapter>`
that CANNOT leave), the `GoAdapter` forwarding shell, the SPI block
(`GoSupport`/edge pass/dead-code bulk), the trait-impl wrappers
(`GoQueryResolver`/`GoEdgeResolver`/`GoUsageGraphStrategy`), the capability-provider
impls, `GoMemoCaches`, and the one-line `impl_program_semantics_provider!` invocation.
Estimated shim ~1,050 LOC, most of it pre-existing forwarding that merely stays.

Moves to `brokk-bifrost-go` (~10.3k LOC): `packages.rs`, `structural.rs` (after the
adapter_helpers promotion), the import-analysis logic from `imports.rs`,
`declarations.rs`, `tests.rs` (Go test detection — production code), `hierarchy.rs`,
`diagnostics.rs`, the 12 pure `GoAdapter` method bodies as free functions +
`GO_COGNITIVE_CONFIG`, `GO_CLONE_SYNTAX`, and all six `go_graph` files (the
whole-workspace inverted pass reshaped per milestone P0's split). The
`resources/treesitter/go/*.scm` queries move with the crate; the store epoch salt path
(`analyzer/store/epoch.rs`, `"treesitter/go/"`) must be updated to the new location and
the Go `lang_epoch!` salt BUMPED, since query-file relocation changes what the salt
hashes.

Stays in analysis, explicitly, with the reason recorded:
- `go/semantic.rs` (3,265 LOC): inseparable from the 36.8k-LOC `analyzer/semantic`
  subsystem; its registration macro textually requires the `TreeSitterAnalyzer` field.
- `go/artifact.rs` + `go/dependency_discovery.rs` (4,353 LOC): gated on
  `semantic_model/` (17k LOC) and `process.rs`. Lowering `semantic_model` is a named
  fleet-phase workstream, not a pilot blocker.
- `get_definition/go.rs` + `get_type/go.rs` (3,479 LOC): gated on
  `SemanticModelOverlay`, `ResolutionSession`, `GlobalUsageDefinitionIndex`. Same
  fleet-phase workstream.
- `go/cache.rs`: `GoMemoCaches` is shim state (keeps moka out of the go crate and out
  of core); it may cache go-crate-defined types (e.g. `GoHierarchyIndex`).

Go-crate functions that today take `&dyn IAnalyzer` take `&dyn CodeUnitIndex` (core)
plus explicit Go side-data instead; every `resolve_analyzer::<GoAnalyzer>` downcast
happens in the shim.

## Milestones

P0 — fleet-reusable lowerings into `brokk-bifrost-core` (no Go crate yet; analysis
re-exports at old paths; every downstream crate compiles unchanged):
1. `analyzer/usages/model.rs` (755 LOC — imports ONLY CodeUnit/ProjectFile/Range/hash;
   the highest-leverage single move) and `outcome.rs` (82).
2. `local_inference.rs` (356), `reference_site.rs` (458; core already has
   tree-sitter), `receiver_analysis.rs` (624), `type_relations.rs` (121),
   `graph_core::{ImportEdge, ImportEdgeKind}`, `reexport_seeds.rs` (147).
3. SPLIT `inverted_edges.rs`: data types (`UsageEdges<K>`, `UsageEdgeWeights<K>`,
   `CallSite`, `UsageNodeKey`, `NodeKey`, `UsageReferenceCounts`) to core; the driver
   (`EdgeCollector`, `parse_and_collect`, `build_edge_output`, `ClassRangeIndex`)
   stays in analysis. `LanguageEdgePass` signatures now traffic in core types.
4. Extract `UsageScanScope` from `traits.rs` (its co-residents `UsageAnalyzer`/
   `GraphUsageAnalyzer` name IAnalyzer and stay).
5. Promote pure helpers: `structural/adapter_helpers.rs` (161),
   `walk_named_tree_preorder`/`try_walk_...`/`WalkControl`/`collect_parse_errors`/
   `expanded_comment_start` (~60), `cognitive_complexity::Config` (the plain data
   struct, not the engine), `canonical_hash.rs` (93). `usages/common` helpers that are
   pure (`same_node`, `node_text`, `namespace_prefixes`) may ride along;
   `analyzed_files_for_language` stays (IAnalyzer).
6. Decide `GO_MODULE_SCOPE_SEGMENT`'s home now (used by symbol_lookup, searchtools):
   it is Go language knowledge -> it will live in the go crate; for P0 it moves to a
   spot the crate can re-export from later, or stays put with a note. Also confirm the
   gate misses `crate::analyzer::`-path imports of Go items (census section 4.3) and
   extend the gate if cheap.
Acceptance: workspace gates green; `cargo test -p brokk-bifrost-core --lib` green;
package + dependency gates green (code moved between published crates); no downstream
source changes.

P1 — the crate and the shim:
1. Create `crates/bifrost-go`, move the ~10.3k LOC, reshape IAnalyzer params to
   CodeUnitIndex + side data, wire the shim in `analyzer/go/` (which shrinks to the
   shim files). Query assets move; epoch salt path updated and salt bumped.
2. Workspace wiring: root Cargo.toml member + analysis dependency (exact `=` version
   like core's); `scripts/check-workspace-dependencies.mjs` gains `brokk-bifrost-go`
   with allowed set `[brokk-bifrost-core]` and analysis's allowed set gains it;
   `scripts/check-workspace-packages.sh` gains the archive (with the .scm files
   asserted present); release workflow publish DAG: core -> go -> analysis, with the
   promotion-evidence gating pattern copied from core's entry;
   `scripts/release-promotion-workflow.test.mjs` updated (run it);
   CLAUDE.md release-bootstrap section gains brokk-bifrost-go (crates.io first-publish
   ceremony). Internal-crate doc stamp on the new crate (registry M2 idiom).
3. The reach-in gate: `analyzer/go/` remains the per-language exemption dir (now shim
   only); the gate's LANGUAGE_MODULES etc. need no removal, but verify the gate still
   passes and that the go crate itself is outside its walk.
Acceptance: full workspace gates green (fmt, clippy featureless + all-features,
nextest, doctests); root Go suites named in the census pass; package + dependency +
release-workflow tests green.

P2 — measurement and verdict (the "works as expected" test):
1. Cold `--timings` featureless build (isolated target): analysis frontend expected to
   shrink ~1.5-2s (10.3k LOC at ~0.17s/kLOC) with the go crate compiling in parallel
   off the critical path; wall neutral or slightly better. Warm loops per the phase-2
   methodology. Go-crate unit-test loop measured (expect core-style locality, seconds
   not tens of seconds).
2. Reference-differential smoke: identical divergence census on the 11-repo corpus
   (includes jellydator/ttlcache for Go) between the pre-P0 commit and P1 tip.
3. Evidence + verdict appended to
   `.agents/docs/analysis-crate-split-phase2-evaluation-2026-08.md`. PASS =
   behavior flat + gates green + frontend reduction in the predicted band + shim at or
   under ~1.3k LOC. On PASS, the fleet proceeds under this plan's sequencing section.
   On FAIL, stop and report to Jonathan with the numbers.

## Fleet sequencing (on pilot PASS)

Per the seam matrix order, each language repeating the P1 pattern (P0's lowerings are
already fleet-shared): Rust, then the remaining MODERATE languages (Python, C#, PHP,
Ruby, C++ — C++ requires generalizing nothing extra per its seam), then the JVM realm
as ONE crate (Java+Scala+Kotlin+jvm shared realm; prerequisite: lower or generalize
`ScalaExportInfo` out of `tree_sitter_analyzer.rs`/`store/mod.rs` signatures, and
`BoundedJavaResolution` out of `receiver_query.rs`), then js_ts last (its four seams
from the matrix). Two shared fleet workstreams scheduled where first needed rather
than up front: (w1) lower `semantic_model/` so artifact/dependency-discovery adapters
and the definition-route files can follow their languages; (w2) the per-language
semantic lowerers stay in analysis until/unless `analyzer/semantic` itself is lowered,
which is NOT in stage-3 scope — record the retained mass per language honestly in the
final evaluation. Each fleet crate updates the same wiring set as P1.2 and lands with
the same gates; the differential smoke runs at each language whose corpus repo exists,
else the language's unit pins are the evidence (Ruby/Kotlin precedent).

## Decision log

- 2026-08-04: Plan created from the seam census (agent-run, verified spot checks; Go
  seam 21,385 LOC total: ~950 (a)-clean, ~11,850 (b) after ~2,600 LOC of (a)-clean
  lowerings, ~7,620 (b') gated on semantic subsystems, 909 shim). Pilot excludes the
  (b') files and the definition routes; they stay behind the shim with named
  fleet-phase workstreams. Lowered product types go to CORE, not a new mid-crate:
  every candidate's import list is already core-clean, and core already carries
  tree-sitter; moka deliberately kept out of core by leaving GoMemoCaches and
  weighted_cache in analysis.
- 2026-08-04: inverted_edges.rs split identified as the SPI-touching prerequisite
  (LanguageEdgePass returns products that must be core types before any language
  crate can produce them) -- it leads P0.
- 2026-08-04: Epoch-salt rule honored: moving the .scm query files changes the salted
  path, so the Go lang_epoch! salt bumps in P1 (worktree-agent-pitfalls memory:
  epoch-salt requirement).
