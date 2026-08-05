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

## Fleet sequencing (amended 2026-08-05 after the Rust census)

The Rust census (.agents/docs/rust-extraction-census-2026-08.md) added two
prerequisites and one deviation before Rust can ship near the shim bar:

- W5 (shared): lower a PreparedSyntaxTree contract to core. Five non-semantic
  Rust files sit on the crate-private analysis struct; Go never did.
- R1 (Rust-only): rewrite the 2,896 LOC of impl-RustAnalyzer inherent language
  logic (73 methods, 303 call sites) as free functions before the crate move.
  The self-recursive memo accessors (usage_index -> declarations ->
  cargo_routes) stay shim-side with the PoolSafeMemo/parallel-flag contract of
  #1416 preserved byte-for-byte in behavior.
- Deviation: moka enters the rust crate with lexical_scope.rs's RUST_TREES
  parse memo. A global parse cache is language-crate state; the pilot's
  moka-stays-in-analysis rule was about GoMemoCaches shim state, not this.

With those, the census projects a ~21.4k move (54%), a ~2.8k shim, and about
-10s of analysis frontend -- the largest single opportunity in the fleet.
Expect the same census-first discipline per language: each fleet language gets
its seam census before its extraction, and new couplings become named
workstreams rather than improvisations.

## Fleet sequencing (original, on pilot PASS)

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

## Progress

- [x] P0: core lowerings (4f913fd9, 4a99644e, 3434d692) -- 3,523 LOC to core;
      inverted_edges split with LanguageEdgePass unchanged; all gates green
- [x] P1 chunk 1: crate + moves (087a0bac, edd0924b, c520ffdb) -- ~6,030 LOC moved,
      five census-missed couplings retained ~3.5k in analysis; epoch salt bumped;
      gates green
- [x] P1 chunk 2: workspace wiring (87625563) -- dependency graph, ten package
      archives with .scm assertions, release DAG core -> go -> analysis, workflow
      policy tests, CONTRIBUTING bootstrap note, stability page
- [x] P2: measurements + differential (evidence docs committed). Frontend -2.8s
      (~0.47s/kLOC), go test loop 0.44s steady, wall neutral; behavior byte-identical
      4/4. Shim ~4.5k vs the ~1.3k bar.
- [x] Verdict: CONDITIONAL; Jonathan chose option 1 (2026-08-05): fund the three
      shared workstreams (W1 ParsedFile/ScalaExportInfo lowering, W2 inverted-edge
      scan contract, W3 CodeUnitIndex enclosing query + bounded-lookup trait), then
      move Go's residual files (W4), then fleet
- [x] W4: Go's four residual blocks moved (declaration walk, diagnostics, forward
      scan, inverted per-file walk) -- 2,445 LOC out of analysis, all four
      couplings cleared by W1/W2/W3 with no new abstractions needed. Analysis Go
      residue 4,529 -> 2,084 (1,598 production shim + 486 retained tests); the
      parked 11,098 (semantic/artifact/dependency-discovery/definition routes)
      untouched, its workstream is semantic_model lowering. Go crate 6,090 ->
      8,544. Fleet note: the pilot tip already carried 1,570 of pure forwarding
      shim, so the plan's ~1.05k per-language shim estimate is low by ~500 LOC
      independently of the blocks -- the floor is the SPI block plus the memo
      shell.
- [x] R2 (Rust extraction, 27153340 5039cfa7 b3feef88 c28e56ff 508912cb):
      `brokk-bifrost-rust` created and wired. 16,375 LOC in the crate -- the
      `analyzer/rust/` band (declarations, imports, structural, test detection,
      field roles, adapter bodies, cargo routes, graph support, usage index,
      hierarchy, lexical scope, diagnostics) plus the usage-graph resolver -- and
      the `.scm` assets ship from the crate with the Rust epoch salt bumped.
      Analysis Rust residue 23,582, of which 17,494 is parked by design
      (semantic 3,235; semantic_model adapters 4,233; definition/type routes
      7,619; and the two scan bodies plus their hit recorder, 5,642 -- newly
      found to route receiver types through `get_definition/rust.rs`, so they
      follow it) and ~2,540 is production shim plus retained analyzer-bound
      tests. Move rate 41% of the 39.9k seam, 68% of the seam outside the parks.
      Three census-missed lowerings were needed; see the decision log.
- [x] Py-2 (Python extraction): `brokk-bifrost-python` created and wired. 10,129
      LOC in the crate -- the whole `analyzer/python/` band minus the three parks
      (bindings, declarations, syntax, structural, test detection, clones tokens,
      adapter answers, imports, graph support with Py-1's two source traits,
      usage index, diagnostics) plus all four `usages/python_graph/` scans -- and
      the `.scm` assets ship from the crate with the Python epoch salt bumped.
      Analysis Python residue 10,445, of which 7,974 is parked by design
      (`semantic.rs` 3,427; `external.rs` 1,795; the definition/type routes
      2,747) and 2,471 is production shim plus the analyzer-bound tests that
      follow it (`mod.rs` 990, `python_graph.rs` 340, `diagnostics.rs` 352 of
      which ~320 is the retained fixture suite, `structural.rs` 214 all tests,
      `cache.rs` 151, `imports.rs` 193, `adapter.rs` 130, `lexical_scope.rs` 43,
      `hierarchy.rs` 28). Move rate 49% of the 20.6k seam, 93% of the seam
      outside the parks -- the highest in the fleet so far, because Py-1 had
      already retired the R1-class inherent block. Three census-missed couplings
      were resolved by lowering; see the decision log.


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
- 2026-08-04: Pilot verdict CONDITIONAL. Economics and behavior criteria passed
  (frontend -2.8s for 6k LOC, 0.44s go test loop, byte-identical differential);
  the shim-size criterion failed 3.5x because five census-missed couplings
  (ParsedFile accumulator, DefinitionIndexHandle, enclosing_code_unit,
  inverted-edge driver, memo shell) retained ~3.5k LOC of Go logic in analysis.
  Fleet execution halted per the plan's FAIL action; the three shared workstreams
  that unlock the residue are enumerated in the evaluation doc, with the
  recommendation to fund them before the fleet rather than repeating the
  couplings eleven times.
- 2026-08-04: Epoch-salt rule honored: moving the .scm query files changes the salted
  path, so the Go lang_epoch! salt bumps in P1 (worktree-agent-pitfalls memory:
  epoch-salt requirement).
- 2026-08-05 (R2): three census-missed couplings resolved by lowering pure code to
  core rather than by leaving Rust logic behind. (1) `parse_symbol_path` and its
  private helper chain moved to `core::analyzer::symbol_path`: the Rust crate
  splits `self::`/`super::` use-paths through it at three sites, cannot depend on
  analysis, and re-deriving the split in the language crate would be the
  source-text mini-parser the design rules forbid. It carries the Go and Rust
  per-segment normalizers with it, which is language knowledge in core and the
  one thing about this move to revisit if the fleet finds a better seam. (2)
  `IdentifierSigil`/`node_ident_text`/`parse_source_region` to `core::analyzer::
  common` -- language-blind mechanism; Rust's sigil constant went to the language
  crate, C#'s stayed in analysis. (3) `cognitive_complexity::is_wildcard_case` to
  core beside the `Config` that stores it. All three are verbatim moves with
  analysis re-exporting the old paths, so no caller changed.
- 2026-08-05 (R2): moka enters `brokk-bifrost-rust` with `lexical_scope`'s
  `RUST_TREES` parse memo, as the amended fleet section anticipated. The pilot's
  moka-stays-in-analysis rule was about `GoMemoCaches` shim state; a global
  source-keyed parse cache is language-crate state. The three facade parse
  counters survive as re-exports through `analyzer/rust/mod.rs`, so `src/lib.rs`
  is unchanged.
- 2026-08-05 (R2): `rust_graph/{extractor,inverted,hits}.rs` (5,642 LOC) do NOT
  move, against the census's "movable-with-reshaping" classification. Both scan
  bodies route Rust receiver types through six items of `get_definition/rust.rs`
  (`RustTypeLookupCache` and the cached type-definition helpers around it), and
  `hits.rs` is written against `extractor::ScanCtx`. They follow the definition
  route's park on `ResolutionSession`/`LimitedQueryRows`/`DefinitionBatchContext`
  and need nothing new of their own once that park lifts. Recorded rather than
  improvised around, per the pilot's own handling of census-missed couplings.
- 2026-08-05 (Py-2): three census-missed couplings resolved by lowering pure code
  to core, the R2 pattern. (1) `analyzer/test_assertions.rs` (the per-language
  assertion-smell shaping) is pure functions over core's own `TestAssertionSmell`
  and `TestAssertionWeights`, and Java and Ruby need it where they are, so it
  moved to `core::analyzer::test_assertions` with analysis re-exporting the old
  path. (2) `tree_walk::subtree_contains` likewise, beside the preorder family
  already in core. (3) `usages::common::enclosing_owner_chain`, used by
  java/csharp/cpp as well. All three are verbatim moves; no caller outside the
  Python seam changed.
- 2026-08-05 (Py-2): `PythonLexicalScopeInventory::collect_bounded` seeded its
  parameter set from `lexical_definitions::formal_parameter_slots_for_owner_bounded`,
  which dispatches through the analysis-side language registry and so cannot be
  lowered. Rather than keep the 993-LOC binding inventory in analysis for one
  call, `collect_bounded` now takes the parameter-name stream, and a 43-LOC
  `analyzer/python/lexical_scope.rs` forwarder computes the layout under the
  caller's own `scope_step` meter. The metering order and the `None`-on-stop
  behaviour are unchanged.
- 2026-08-05 (Py-2): the Python usage-graph scans take a `PythonGraphSource`
  *alongside* the `PythonUsageSource`, not instead of it. The census's
  "all `CodeUnitIndex`" reading of `python_graph/extractor.rs` is right about the
  trait, but the `&dyn IAnalyzer` those scans held is the *dispatching* analyzer:
  in a mixed workspace that is a `MultiAnalyzer`, whose `definitions` merges every
  language's shards and whose `get_ancestors` crosses language boundaries.
  Collapsing it onto the Python analyzer would have silently narrowed
  cross-language resolution. `PythonGraphSource` therefore carries the
  dispatching analyzer's `CodeUnitIndex`, `TypeHierarchyProvider` and
  `ImportAnalysisProvider` -- the `GoGraphSource` shape -- plus a *callback* for
  the global definition index, because that index builds on first access and only
  `resolve_receiver_type`'s last fallback reads it. Recording this because a
  handle would have been the obvious simplification and would have moved a
  workspace-wide index build onto every Python scan, invisibly to the suite: only
  the C# graph and persistence tests assert build counts.
