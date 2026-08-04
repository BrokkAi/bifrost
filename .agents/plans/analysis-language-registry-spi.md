# Language registry and analyzer SPI: dispatch inversion inside brokk-bifrost-analysis

This ExecPlan is the gate-1 design for phase 3 of the analysis-crate vertical split. It is
self-contained: everything needed to implement it is in this file plus the current working
tree. Two checked-in companion documents provide background evidence but are not required
reading to execute the plan: `.agents/docs/analysis-crate-seam-matrix-2026-08.md` (the
measured reference inventory this design is derived from) and
`.agents/docs/analysis-crate-split-phase2-evaluation-2026-08.md` (why wall-clock build time
is not the goal of this stage). File/line citations were verified at commit `999a0d5c` and
re-verified selectively at `09eb52b2` and `7ff7ce33` during two external review rounds;
line numbers drift, so treat them as starting points for a search, not gospel. Census
corrections from those reviews are incorporated and flagged where they appear.

## Purpose

Today the code-intelligence framework inside `crates/bifrost-analysis` reaches each of the
twelve analyzable languages *by name*, from at least six independently hand-maintained
places. When a language gains a capability, a human must remember to update every list;
when they forget, the language silently lacks the capability on one path while having it on
another. This is the same "two copies maintained in lockstep" hazard class that produced
the MCP pre-handshake authorization bypass documented in CLAUDE.md, and it has already
produced real divergence here: the dead-code path's list has only 9 languages (C++ and
Python are handled by separate special cases), Ruby never received a `UsageQueryResolver`
implementation, and JS/TS cannot participate in the shared workspace-edge-weights shape at
all.

After this plan is implemented, the registry (`analyzer/languages.rs`) and the assembly
layer (`analyzer/multi_analyzer.rs`, which owns concrete analyzer storage and
construction) are the only places that enumerate the languages. Every framework consumer
(usage finding, workspace edges, receiver resolution, dead-code analysis, searchtools)
looks capabilities up through the registry. Adding a language becomes three localized
edits — one `LanguageSupport` implementation, one registry match arm, one assembly-enum
variant — instead of a hunt across six lists. A self-policing test fails the build if any
framework file names a language module again.

On extraction: this plan removes the dispatch-census blocker and validates the SPI shape
in place, but per-language crate extraction is *not* thereby reduced to a mechanical file
move. `LanguageSupport` is `pub(crate)` and its methods traffic in analysis-owned
contracts (`GraphUsageAnalyzer`, `LanguageEdgePass`, receiver and edge product types,
`DeadCodeSupport`), so a `RustSupport` living in an extracted Rust crate would need
analysis as a dependency while analysis registers it — a cycle. Extraction therefore
additionally requires either lowering the SPI contracts into a dependency-safe crate or
retaining analysis-owned adapter shims that call into the extracted language crates;
milestone 3's stop/go recommendation must pick one of those structures. What this plan
does guarantee is that all such future work happens against one explicit contract instead
of six scattered lists. Otherwise this plan changes no crate boundaries except one proof
move (milestone 2). Everything happens inside `brokk-bifrost-analysis`, which keeps the
promotion pain out of this stage entirely: registry and languages share a crate, so
`pub(crate)` suffices throughout.

## Orientation: the six language lists and the named reach-ins

A "dispatch list" here means a place where framework code (code that serves all languages)
matches on `Language` or names concrete per-language types in order to route work. As of
`7ff7ce33` there are six, plus a set of scattered single-item reach-ins.

Pre-flight correction (2026-08-04, census at `ec74ddac`, full detail in
`.agents/docs/registry-preflight-census-2026-08.md`): the sweep found a *seventh* list —
`analyzer/global_usage_definition_index.rs:185-208`, a 13-arm `ForwardQueryProvider`
downcast table (plus a package-separator fallback match at `:822`) — a second
bounded-resolver table at `analyzer/usages/get_type/mod.rs:189`, two twelve-arm tables in
`analyzer/mod.rs` (`structural_spec_for` at `:362`, `parser_language_for_flavor` at
`:313`), and additional small reach-ins (C# name normalization in
`common.rs`/`symbol_lookup.rs`, Ruby range helpers in `declaration_range.rs`, Kotlin
syntax helpers in `receiver_query.rs:3013`/`call_sites.rs:419`). No dispatch site changed
since `999a0d5c` — these are census breadth omissions, dispositioned in the census doc
and absorbed into milestones 1b and 1f below. The census doc also records the named
gate-allowlist entries (`summary.rs` Java-specific public API, the `ScalaExportInfo`
type-level leak in `tree_sitter_analyzer.rs`/`store`, the re-export hubs) and the
out-of-scope `match Language` inventory the gate deliberately does not police.

The six lists:

1. `analyzer/usages/finder.rs:726-811` — `graph_find_usages` is a 12-arm `match language`
   (including a `Language::None` arm that returns a terminal failure — see decision 1)
   constructing `&<Lang>UsageGraphStrategy::new()` and passing it to
   `graph_strategy_find_usages(strategy: &dyn GraphUsageAnalyzer, ...)` (`finder.rs:709`).
2. `analyzer/usages/workspace_graph.rs:352-491` — the workspace edge-*weights* path. A
   local macro `record_package_edges` is instantiated ten times against per-language
   `build_<lang>_usage_edge_weights` functions, and JS/TS is a fully hand-written eleventh
   arm (`workspace_graph.rs:434-491`) calling `build_jsts_scoped_usage_edges`, whose
   product is keyed by `UsageNodeKey { file, fqn }` rather than by fqn string.
3. `searchtools/scan_usages.rs:2476-2615` — the edge-*sites* path: an eleven-way sequence
   of `build_<lang>_usage_edges` calls producing location-bearing `UsageEdges`. JS/TS here
   uses the ordinary fqn-keyed `build_jsts_usage_edges` (`scan_usages.rs:2490`), *not* the
   scoped shape list 2 uses. Lists 2 and 3 encode the same per-language registration
   knowledge but consume different finalizations of the underlying scan — see decision 3.
4. `code_quality/dead_code_smells.rs:2387-2416` — `graph_strategy_for` is an if-chain over
   *nine* strategy types (C++ and Python deliberately absent, served by separate
   whole-workspace edge builds at `dead_code_smells.rs:1136` and `:1004`), plus a
   ten-entry per-language edge-build sequence at `:906-1342` with semantics beyond the
   generic passes (see decision 3's dead-code carve-out) and a four-language
   bulk-eligibility block at `:1997-2085`.
5. `analyzer/multi_analyzer.rs` — `AnalyzerDelegate`, a 12-variant enum of concrete
   analyzers, plus `resolve_analyzer<T: Any>` (the sanctioned
   downcast-through-`MultiAnalyzer` helper).
6. `analyzer/workspace.rs` — the sixth list, surfaced by external review after earlier
   revisions attributed construction to `multi_analyzer.rs` alone:
   `WorkspaceAnalyzer::build_language_delegate` (`workspace.rs:406`) is the actual
   twelve-arm construction match (`Language::Rust => build_delegate!(Rust, RustAnalyzer)`
   at `:437`), the file's imports name every concrete analyzer plus
   `PythonDependencyPackAdapter` (`workspace.rs:11`), `warm_rust_usage_analysis`
   (`:460-462`) downcasts to `RustAnalyzer` directly, and
   `activate_python_environment_packs` (`:203`) is Python-specific workspace API.

The scattered reach-ins, all documented item-by-item in the seam matrix sections 4.1-4.7:
`analyzer/usages/receiver_query.rs:16,25` imports nine `resolve_<lang>_bounded` and nine
`resolve_<lang>_type_bounded` functions (correction, milestone 1b: not eleven — Java's
resolvers are session-shaped and separately routed, and no JS/TS bounded resolver
exists) and dispatches them at `:2061` and `:2018`;
`receiver_query.rs:47` downcasts to all twelve analyzer types;
`analyzer/usages/get_definition/mod.rs:78` names nine;
`analyzer/usages/candidates.rs:652,657` call Python/Rust candidate-file hooks;
`analyzer/usages/finder.rs:367-402` calls PHP composer/import-alias candidate expansion;
`receiver_query.rs:31,36` pull six `pub(in crate::analyzer::usages)` items from
`js_ts_graph::receiver_analysis` plus `JsTsReceiverFactProvider` — no other language's
receiver analysis is reached this way; and small `match language` sites at
`workspace_graph.rs:38,57,124` (`UsageEcosystem`), `receiver_query.rs:2097` (unsupported
reason), `:2143,2883,2953`, and `parsed_tree.rs:16`. Census correction (review round 3):
the seam matrix listed `analyzer/semantic/service.rs:707,1235` as production references to
`TypescriptAdapter` and `JsTsSemanticLowerer::typescript`; both sit inside that file's
`#[cfg(test)] mod tests` (opening at `service.rs:697`) — the matrix's stated extraction
limit (section 1.3) misclassified them. The semantic engine's production code is already
fully language-blind; see decision 5.

Relevant existing traits, from `analyzer/usages/traits.rs`: `UsageAnalyzer` (pub, one
method, used as `dyn` only by dead-code), `GraphUsageAnalyzer` (pub(crate), `dyn` in
finder immediately after the hardcoded match, so it currently buys nothing),
`UsageQueryResolver` and `UsageEdgeResolver` (pub(crate), ten and eleven monomorphic impls
respectively, zero polymorphic use — uniformity contracts, not dispatch), and
`CandidateFileProvider` (pub, genuinely polymorphic, language-agnostic, healthy — untouched
by this plan).

## Design decisions

Decision 1: a trait and an exhaustive match — not a table, and not link-time magic. A new
module `analyzer/languages.rs` defines `trait LanguageSupport` (decision 2) and the
registry function:

    pub(crate) fn language_support(language: Language) -> Option<&'static dyn LanguageSupport> {
        match language {
            Language::None => None,
            Language::Rust => Some(&rust::RustSupport),
            Language::Kotlin => Some(&kotlin::KotlinSupport),
            // ... one arm per Language variant; no wildcard arm
        }
    }

The return type is `Option` because `Language::None` is a real, currently handled input:
today's dispatch (for example the finder's 12-arm match) maps it to a terminal
graph-unsupported outcome, not a panic, and the registry must not convert a handled input
into an `unreachable!`. Each consumer maps `None` to its existing fallback semantics,
which the absent-capability inventory (milestone 1) pins. The match remains exhaustive
with no wildcard, so adding a `Language` variant still fails to *compile* until it is
registered — completeness is enforced by the compiler rather than by a unit test, and
there is no lazy initialization, no hashing, and no allocation (the support structs are
ZSTs behind `&'static` borrows). A newtype (`AnalyzableLanguage`) that excludes `None` at
the type level was considered and deferred: it is stronger but forces conversion churn at
every entry point for no milestone-1 benefit. We deliberately do not use
`linkme`/`inventory`-style distributed registration: explicit assembly in one file
preserves greppability and adds no build dependencies. The registry file and the assembly
layer in `multi_analyzer.rs` (which absorbs `workspace.rs`'s construction match in
milestone 1 — see the sixth list) become the only files allowed to name language modules;
the `AnalyzerDelegate` enum stays because concrete per-language analyzer *storage and
construction* is the assembly layer's job, and collapsing it into trait objects would
change the `resolve_analyzer` contract for no benefit at this stage.

Decision 2: `LanguageSupport` is a trait with default methods — one method per capability
the six lists and reach-ins currently encode. A trait rather than a struct of function
pointers, for two reasons. First, optional capabilities become default method bodies, so
the fallback for an unsupported capability is written once in the trait definition instead
of being re-decided at every consumer's `None` branch — divergent per-site fallbacks are
precisely the disease this plan cures. Second, it matches the idiom the analyzers already
use for optional capability accessors (`type_hierarchy_provider() ->
Option<&dyn TypeHierarchyProvider>` and friends), so the result reads native rather than
invented. The initial surface, derived from the census above (names indicative, implementer
may adjust spelling):

    pub(crate) trait LanguageSupport: Send + Sync {
        fn language(&self) -> Language;
        fn ecosystem(&self) -> UsageEcosystem;      // SINGLE owner of ecosystem knowledge
        fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer;    // lists 1 and 4
        fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> { None } // lists 2, 3 (decision 3)
        fn resolve_definition_bounded(&self, ...) -> ...;               // receiver_query.rs:16
        fn resolve_type_bounded(&self, ...) -> ...;                     // receiver_query.rs:25
        fn make_receiver_facts<'a>(&self, ctx: ReceiverFactContext<'a>)
            -> Option<Box<dyn ReceiverFactProvider + 'a>> { None }      // js_ts today
        fn dead_code(&self) -> DeadCodeSupport { ... }                  // list 4, incl. its edge builds
        fn candidate_augmentation(&self, ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> { None }
        fn warm_usage_analysis(&self, analyzer: &dyn IAnalyzer) {}      // workspace.rs:460 (Rust overrides)
        fn graph_unsupported_reason(&self, ...) -> ... { ... }          // receiver_query.rs:2097
    }

`usage_strategy` returns `&'static dyn GraphUsageAnalyzer` rather than `Box<dyn ...>`
because every strategy is a stateless unit struct: a static borrow of a promoted static
states that property structurally and avoids implying an allocation that a boxed ZST would
not even perform. `make_receiver_facts` is a *factory*, not an accessor, because the one
existing provider (`JsTsReceiverFactProvider<'tree, 'a>`,
`analyzer/usages/js_ts_graph/receiver_analysis.rs:38`) borrows the analyzer, bounded
resolution state, file, source, and a tree-sitter node, and owns query-local caches — a
ZST cannot hand out a `&dyn` to per-file state that does not exist yet. The context struct
carries those borrows; the `Box` allocation is once per bounded resolution query, which
decision 7 permits (per-query, never per-node). A callback form
(`with_receiver_facts(ctx, &mut dyn FnMut(...))`) that avoids the allocation, and flat
exposure of the receiver operations directly on `LanguageSupport`, were both considered
and rejected for call-site contortion; revisit only if the allocation ever shows up in a
profile. The governing rule is behavioral, not structural: after milestone 1, no file
outside `analyzer/languages.rs`, `analyzer/multi_analyzer.rs`, and the per-language
directories may name language-specific modules or types (enforced syntactically — see the
milestone 1 gate) — the trait grows exactly the methods needed to delete each such
reference, and no more. Where a reach-in is a single helper function (for example
`cpp::identity::*` used by searchtools), the method is that function's signature.

Candidate augmentation carries semantics that a plain set-returning method would silently
lose, so it is modeled explicitly. Today the Python and Rust additions
(`candidates.rs:652,657`) run inside the default candidate calculation, *before*
`protected_candidates` is cloned, so they survive file-count and source-byte truncation;
the PHP composer/import-alias additions (`finder.rs:367-402`) run after that clone, are
droppable first under a tight budget, and cancellation is checked between augmentations. A
generic method that merged both classes would change result quality under budget pressure
while every unlimited-budget test stayed green. Therefore:

    pub(crate) struct CandidateAugmentation {
        protected: HashSet<ProjectFile>,    // joins the pre-truncation protected set
        supplemental: HashSet<ProjectFile>, // post-clone, first to be dropped under budget
    }

with the cancellation token in `CandidateCtx`, and milestone 1's tests must include
budget-constrained cases that pin the protected/supplemental distinction, not only
unlimited candidate-set comparisons.

Decision 3: workspace edges get an explicit pass identity with separate site and weight
outputs; there is no per-edge indirection and no double scanning. Census corrections drive
this design. First, the two edge consumers want *different products*: `scan_usages`
consumes location-bearing `UsageEdges` (every call-site path and line), while
`workspace_graph` consumes `UsageEdgeWeights` (reference-kind counts). The underlying
per-language scan finalizes into one *or* the other, and neither can be reconstructed from
its counterpart — so a single method returning one value for both consumers would force
every language to either scan twice (violating decision 7) or grow a new, richer
intermediate representation (a large unplanned refactor). Second, edge-pass cardinality is
not one-per-`Language`: JavaScript and TypeScript are served by one combined JS/TS pass,
while Java, Scala, and Kotlin share one candidate ecosystem but run three distinct
resolver passes. Iterating twelve `LanguageSupport` objects naively would run JS/TS twice,
and deduplicating by `UsageEcosystem` would wrongly collapse the three JVM passes. The
design models both facts:

    pub(crate) trait LanguageEdgePass: Send + Sync {
        fn id(&self) -> EdgePassId;                 // dedup key: JS and TS return the SAME pass
        fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites>;
        fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights>;
    }

    pub(crate) enum LanguageEdgeWeights {
        Fqn(UsageEdgeWeights),
        Scoped(JsTsScopedUsageEdges),   // js_ts's {file, fqn}-keyed weights product
    }

`LanguageEdgeSites` wraps fqn-keyed, location-bearing `UsageEdges` (every language,
including JS/TS via `build_jsts_usage_edges`, already produces this shape on the sites
path, so no enum is needed there today). Ecosystem knowledge has exactly one owner —
`LanguageSupport::ecosystem()`; `LanguageEdgePass` deliberately has no `ecosystem()`
method, and the framework collector derives a pass's ecosystem from the supports that own
it, with the milestone-1 snapshot asserting all owners of a shared pass agree (an earlier
draft put `ecosystem()` on both traits, which review flagged as reintroducing duplicated
registration knowledge — the exact disease this plan cures). Each consumer calls only the
output it needs — one scan per consumer, exactly as now — and the collector deduplicates
by `EdgePassId`, not by language and not by ecosystem, while centralizing ecosystem
candidate selection, filtering, and result conversion that lists 2 and 3 currently each
own a copy of. The existing `build_*` functions survive nearly unchanged behind the pass
methods.

Dead-code carve-out: list 4's edge builds do *not* all fit the generic passes, and forcing
them would smuggle mode flags into the scan contexts (a flag-parameter design this
repository's conventions reject). Python uses `build_cached_python_usage_edges_for_targets`
with an explicit target set; Scala uses `build_full_scala_usage_edges` rather than the
workspace builder; Rust performs analyzer-availability and language-file-cap checks before
building; JS/TS consumes scoped weights *plus* `JsTsScopedNodeStatus` to distinguish
resolved, ambiguous, and unseedable candidates. Those language-specific dead-code build
operations therefore live inside `DeadCodeSupport` (which already models the (a)-(d)
capability groups), and `LanguageEdgePass` is reused by dead-code only where the builder
semantics are genuinely identical to the general passes. `UsageEdgeResolver` is deleted
(zero polymorphic uses — documentation pretending to be dispatch); its documentation value
moves into `LanguageEdgePass`'s doc comments. An earlier draft returned one
`LanguageEdges` enum from a single method and, before that, a per-edge `dyn` sink; both
were rejected in review — the sink for per-edge virtual calls in the hot loop, the single
enum for the double-scan/lossy-product problem above. This remains the stress-case
decision of the plan: the contract is designed against the hardest consumers first, so the
registry never ships an interface JS/TS, the JVM trio, or dead-code cannot implement
honestly.

Decision 4: `IAnalyzer` splits along a semantic definition, checked mechanically. The new
trait — working name `CodeUnitIndex` — is defined by what it *is*: the read-only index over
a project's declarations — enumerating them, resolving names to them, rendering their
sources, skeletons, and signatures, and navigating parent/child structure. Membership
follows from that definition, and "the signature closes over types already in
`brokk-bifrost-core`" (`CodeUnit`, `ProjectFile`, `Language`, `Range`,
`SignatureMetadata`, plain strings/collections) is the mechanical *check* on the
definition, not the definition itself: when a method belongs semantically but its
signature drags in an analysis-side type, that is evidence the type is misplaced, and the
implementer resolves it per-method (move the type to core, or conclude the method does not
belong on the index) and records the call in this plan's decision log. The search entry
points are the known-hard case, adjudicated in milestone 2's inventory: `search_definitions`
and friends traffic in `SearchSymbolPatternBatch` / `QueryBatch` / `SearchSymbolCandidates`,
which live in `analyzer/i_analyzer.rs` today, and `SearchSymbolPatternBatch` owns compiled
`regex` values while `bifrost-core` has no `regex` dependency — so those methods move only
if we deliberately choose to move the batch types and the `regex` dependency into core, or
to redesign the signatures around core-owned request data; otherwise they stay on
`IAnalyzer`. `IAnalyzer: CodeUnitIndex + Send + Sync + Any` retains everything whose
signature touches analysis-side types (`UsageFactsIndex`, `FuzzyResult`,
`DefinitionIndexHandle`, `AnalyzerSnapshotCaches`, `SummaryFileProjection`,
structural/semantic providers, smell and budget types), all provider-accessor methods, and
the `as_capability` escape hatch.

The `*_for_test` counter hooks (including the two Scala-specific ones) do not stay put,
and their quarantine has a constraint review surfaced: they are not `cfg(test)`-only.
The root integration suites enable the analysis crate's `test-support` feature (the root
manifest's dev-dependency does so for all workspace test builds) and call these hooks
through `&dyn IAnalyzer`, so an unrelated side trait would break those dynamic call
sites. The chosen design is a feature-gated object-safe accessor on `IAnalyzer`:

    #[cfg(any(test, feature = "test-support"))]
    fn test_hooks(&self) -> &dyn AnalyzerTestHooks;

with `MultiAnalyzer` forwarding to its delegates and call sites updated mechanically
(`warm.analyzer().test_hooks().<hook>()`). A cfg-dependent supertrait was rejected
(feature unification changing a trait graph is a coherence footgun), and an unconditional
default-no-op supertrait was rejected as organizational rather than actual quarantine.
The implementor set is larger than the twelve analyzers: `MultiAnalyzer`, `EmptyAnalyzer`
(`analyzer/workspace.rs:19`, a production implementor), and the test fakes all split too;
milestone 2 begins with a mechanical inventory rather than assuming the list. The split is
proven by finally moving `analyzer/capabilities.rs` and `analyzer/pool_memo.rs` to
`bifrost-core` with their generic bounds rewritten to `T: CodeUnitIndex` — the exact move
that stage 2 attempted and had to abandon because `IAnalyzer` was indivisible.

Decision 5: the semantic engine is already language-blind; keep it that way and remove the
test-fixture coupling. External review established (and re-verification confirmed) that
the two `service.rs` references to TypeScript — the `TypescriptAdapter` import at `:707`
and `JsTsSemanticLowerer::typescript()` at `:1235` — live inside `#[cfg(test)] mod tests`
(opening at `:697`): they construct test fixtures, and there is no production semantic
dispatch seam here at all. A `semantic_hooks` method is therefore absent from the
`LanguageSupport` surface — abstracting test-fixture construction would enlarge every
language's interface for zero runtime benefit, exactly the design-around-a-bug this plan
forbids. Milestone 1e instead relocates those fixtures (into a TypeScript-owned test
helper, a generic fake lowerer where appropriate, or an explicit test-only allowlist entry
for the gate), and a `semantic_hooks`-style capability is added later only if the
pre-flight census finds an actual production dependency.

Decision 6: Ruby gets a `UsageQueryResolver`-shaped scan. `ruby_graph.rs:73-173` inlines
what the other ten languages express through `UsageQueryResolver::try_new`/`find_usages`.
Since decision 3 deletes `UsageEdgeResolver` and this plan standardizes the strategy entry
points, the Ruby scan is folded into the common shape at the same time — small, mechanical,
and it removes the one asymmetry that would otherwise need a permanent footnote in the
`LanguageSupport` contract.

Decision 7: perf neutrality is a requirement, not a hope. All registry indirection is
per-query or per-scan (one exhaustive-match lookup plus one indirect call; one boxed
receiver-facts construction per bounded resolution query), never per-node or per-edge; the
language-internal hot loops remain monomorphic, and each edge consumer still triggers
exactly one scan per pass (decision 3). The reference differential and the scan_usages
surface tests are the behavioral gate; any measurable regression in the usage-graph
benchmarks fails the milestone.

Decision 8 (pre-work): the weighted-cache helpers leave `js_ts`, but by extraction, not by
file move, and they stay inside `brokk-bifrost-analysis` for now. Review established that
`analyzer/js_ts/cache.rs` is not only the four generic helpers: it also holds
`JsTsMemoCaches` (JS/TS-specific memo state over `JsTsUsageIndex`,
`DirectDescendantIndex`, `PoolSafeMemo`) and traffics in `moka::sync::Cache`, which
appears in `build_weighted_cache`'s return type — so a whole-file move is impossible, and
moving the helpers to `bifrost-core` would make `moka` a core dependency, taxing the fast
standalone core test loop that justified stage 2. Milestone 0 therefore extracts
`build_weighted_cache`, `weight_code_unit_vec_by_unit`, `weight_code_unit_set`, and
`weight_project_file_set` into a language-neutral `analyzer/weighted_cache.rs` inside
analysis, re-exported at the old `analyzer::js_ts::cache` paths; `JsTsMemoCaches` and the
JS/TS-specific weigher stay where they are. The cross-crate home for the helpers (core
with a `moka` dependency, or a lower utility crate) is deliberately deferred to the
extraction ExecPlan, where the dependency cost can be weighed against measured need. What
milestone 0 buys now is ending the languages-import-from-js_ts entanglement (nine
importers, the sole inter-language dependency outside the JVM realm, matrix section 5.3)
before the registry work begins.

## Coordination and sequencing risks

The census in this plan was taken at commit `999a0d5c`, and upstream actively mints new
per-language dispatch sites: `analyzer/source_ingestion.rs`, which landed the same week
this plan was written, contains a fresh `match language` with per-language highlight-query
arms (two of them `include_str!`s). Immediately before implementation begins, re-run the
reach-in sweep against current HEAD (the milestone 1 gate's syntax-aware checker, run in
report mode, is the right tool once it exists; until then, sweep `use` trees and path
expressions for language-module and concrete-type references, compared against the
inventory in this plan and the seam matrix) and disposition every new site: either it
becomes a `LanguageSupport` method (the highlight-query map is a natural
`fn highlight_query(&self)` candidate) or it joins the allowlist with a stated reason.
The `workspace.rs` Python surface (`activate_python_environment_packs`,
`PythonDependencyPackAdapter`) is dispositioned in the same pre-flight pass: it is
intentionally Python-specific public workspace API, so the default disposition is a named
allowlist entry with that justification, unless conversion to a capability turns out to be
trivial.

The Kotlin epic (#1234) closed complete on 2026-07-30, before this plan was committed, so
Kotlin's dispatch entries are part of the baseline census, not a live coordination
partner (an earlier revision of this plan treated the epic as in flight — corrected by
external review). The residual check is generic: at dispatch time, look for open PRs or
active agent branches touching the dispatch files, whatever their topic. Relatedly,
milestone 1 rewrites three of the highest-churn framework files (`receiver_query.rs`,
`finder.rs`, `workspace_graph.rs`); its per-list commits should land promptly rather than
accumulating on a long-lived branch, to keep merge windows small.

## Milestones

Milestone 0 — extract the weighted-cache helpers (decision 8). Create
`analyzer/weighted_cache.rs` inside `brokk-bifrost-analysis` holding
`build_weighted_cache`, `weight_code_unit_vec_by_unit`, `weight_code_unit_set`, and
`weight_project_file_set`; leave `JsTsMemoCaches` and the JS/TS weigher in
`analyzer/js_ts/cache.rs`; re-export the four helpers at their old `analyzer::js_ts::cache`
paths so the nine importing language modules compile unchanged (retargeting those imports
to the neutral path can ride along or land with milestone 1f). No manifest changes; `moka`
remains an analysis dependency. Acceptance: workspace tests green.

Milestone 1 — the registry, and the deletion of every framework language reference. Create
`analyzer/languages.rs` with `LanguageSupport`, `LanguageEdgePass`, the edge output types,
and the exhaustive-match `language_support` function; add a `<Lang>Support` unit struct to
each of the twelve language modules; convert, in order (each its own commit, tests green at
every step): (a) finder.rs list 1 and dead-code list 4's strategy chain onto
`usage_strategy`, with `Language::None` flowing through the registry's `None` to the
existing terminal outcome; (b) receiver_query's two bounded-resolver tables onto trait
methods, plus (per the pre-flight census) the `get_type/mod.rs:189` type-resolution
table, the seventh list's `forward_query_provider` downcast (each support owns its own
`resolve_analyzer` downcast, mirroring `warm_usage_analysis`), and
`package_parent_name` as a default trait method (default `"."`, Go/C++ overriding);
(c) the edge-pass conversion of decision 3 — workspace_graph.rs list 2 onto
`edge_weights`, scan_usages.rs list 3 onto `edge_sites`, deduplicating by `EdgePassId`
(one shared JS/TS pass; three JVM passes), unifying the two consumers' collection plumbing
into one framework-side collector, deleting `UsageEdgeResolver`; dead-code's edge builds
move into `DeadCodeSupport` per the carve-out, reusing passes only where semantics are
identical; (d) Ruby's resolver fold-in (decision 6); (e) the TypeScript test fixtures in
`semantic/service.rs` relocated or allowlisted per decision 5 — no production change, no
new SPI surface; (f) the sixth list: `build_language_delegate` and its concrete-analyzer
imports move from `workspace.rs` into the `multi_analyzer.rs` assembly layer,
`warm_rust_usage_analysis` routes through the default-no-op `warm_usage_analysis`
capability with the Rust downcast moving into `RustSupport`, and the Python workspace
surface is dispositioned per the coordination section (note the census found a second
Python-specific import there, `resolve_python_semantic_pack_dependencies` — same
disposition); then the remaining scattered reach-ins (candidate augmentation with the
protected/supplemental split of decision 2 — the budget-relevant PHP *call* sites are
`finder.rs:193,197`, not the cited definition range — searchtools' cpp identity block,
which spans `selectors.rs` *and* `sources.rs`, small `match language` sites), each
either onto a trait method or explicitly allowlisted with a comment stating why it is
assembly-layer code. The census adds three registry-natural conversions here:
`structural_spec_for` (`analyzer/mod.rs:362`) becomes `structural_spec(&self)`,
`parser_language_for_flavor` (`analyzer/mod.rs:313`) becomes a grammar accessor
(flavor parameter preserved; the Scala/Kotlin module reach-ins move onto their
supports), and `highlight_query_for` (`source_ingestion.rs:245`) becomes
`highlight_query(&self) -> Option<&'static str>` with the two `include_str!` arms
moving onto `ScalaSupport`/`KotlinSupport`. It also fixes the allowlist to the named
entries in the census doc section 4 (`summary.rs`, the `ScalaExportInfo` signatures in
`tree_sitter_analyzer.rs`/`store/mod.rs` with their extraction-plan follow-up, the
`analyzer/mod.rs` and `usages/mod.rs` re-export hubs, `benchmark.rs`), and preserves
`workspace.rs`'s `Language::None => unreachable!` panic contract when construction
moves to the assembly layer (assembly filters `None` before building — the commit
message must say so).

Finish with the self-policing gate, which must be syntax-aware. A token scan for
`analyzer::rust::` misses the real reach-in forms — `finder.rs` today imports
`crate::analyzer::usages::rust_graph::RustExportUsageGraphStrategy` and
`crate::analyzer::RustAnalyzer`, neither of which contains that token — and blanking
comments/strings fixes only false positives, not these false negatives. The gate is a
test (a `syn`-based dev-dependency parse is the reliable option) that walks
`crates/bifrost-analysis/src`, parses each file, and rejects, outside the per-language
directories, `analyzer/languages.rs`, `analyzer/multi_analyzer.rs`, and an explicit
allowlist: use-tree or path-expression references into language analyzer modules
(`analyzer::<lang>::…`), into per-language usage-graph modules (`usages::<lang>_graph::…`),
and to concrete per-language type names (the `*Analyzer`, `*Adapter`, `*UsageGraphStrategy`,
`*Support` families). Failures must print the exact offending path or identifier with file
and line, not just a filename. The gate must be module-tree-aware for `cfg(test)`: the
census found sixteen `tests.rs` files that carry no in-file `#[cfg(test)]` because the
attribute sits on the parent's `mod tests;` declaration, and two of them
(`analyzer/structural/search/tests.rs`, `searchtools/tests.rs`) would false-fire under a
file-independent walker — so the gate walks the module tree from `lib.rs`, tracking
`cfg(test)` on `mod` items, rather than globbing files. The `get_definition/<lang>.rs`
and `get_type/<lang>` submodules count as per-language directories for the gate's
exemption. Bare `match Language` sites with no module coupling (census doc section 6:
`exception_handling.rs`, the `lexical_definitions.rs` node-kind tables, epoch cells,
display-name tables, the string-keyed overlay roots) are out of the gate's scope by
design and stay documented rather than policed. Because `syn` sees syntax, comment and string false
positives (the seam-matrix census hit them in raw-string fixtures at
`analyzer/rust/diagnostics.rs:965` and `searchtools/tests.rs:1069`) do not arise. Registry
completeness needs no test — the exhaustive match enforces it at compile time.

Two more artifacts ship with this milestone. A capability-matrix snapshot test iterates
the registry and records, for all twelve languages, every *observable* capability fact:
which optional accessors return `Some` versus `None`, which `DeadCodeSupport` and edge
variants are reported, which `EdgePassId`s exist. A capability silently appearing or
disappearing then becomes a reviewed diff instead of a runtime surprise — centralized
defaults keep absence *silent* by design, and this snapshot is what makes silence
*visible*; it also gives the `capabilities.md` documentation matrix a single source of
truth. Alongside the presentation snapshot, the same test asserts registry *invariants*
that compiler exhaustiveness cannot see: `support.language()` equals the match key for
every arm; `language_support(Language::None)` is `None`; all supports sharing an
`EdgePassId` agree on `ecosystem()` (the single owner, per decision 3); JavaScript and
TypeScript share exactly one pass ID; Java, Scala, and Kotlin have three distinct IDs
within one ecosystem; and no unrelated languages share an ID. The snapshot deliberately
claims only observable behavior: Rust cannot distinguish an inherited default method from
an override behind `dyn`, and a manually maintained implemented-versus-default table would
recreate exactly the parallel capability list this refactor deletes. And a short "adding a
language" runbook under `.agents/docs/` describing the post-registry procedure (implement
`LanguageSupport`, add the registry match arm, add the assembly-enum variant, register the
semantic lowerer, done). The runbook doubles as design validation: if it does not come out
short, the SPI is wrong, and we fix it now rather than after eleven extractions bake it in.

Fallback semantics need an inventory before they are centralized. Today each missing list
entry has its own user-visible consequence: dead-code silently skips the language,
receiver queries return a specific unsupported-reason, policy runs classify results
`unreliable`, MCP surfaces particular error strings, and `Language::None` reaches a
terminal graph outcome. Converting these to registry-`None` and trait defaults must not
change any of them, and the reference differential does not cover most of them. Before
conversion, record the current consequence of each absent capability; acceptance pins
those behaviors unchanged, including budget-constrained candidate-augmentation cases per
decision 2 and four dead-code-specific pins per decision 3's carve-out: Python still uses
the target-restricted cached path, Scala still uses its full builder, JS/TS
ambiguous/unseedable scoped-node statuses remain inconclusive, and the file-cap and
truncation diagnostics retain their exact text.

Acceptance: the syntax-aware gate, capability snapshot, and registry invariants passing;
the absent-capability inventory's behaviors pinned; full workspace gates green; the
reference differential flat against the pre-milestone baseline on a warmed corpus run.

Milestone 2 — the `IAnalyzer` split. Begin with the mechanical inventory decision 4
requires: every production and test `IAnalyzer` implementor (the twelve analyzers,
`MultiAnalyzer`, `EmptyAnalyzer` at `analyzer/workspace.rs:19`, and the test fakes); every
proposed `CodeUnitIndex` method; every non-core type appearing in each signature; and
every dependency that moving each such type would add to `bifrost-core`. Adjudicate the
search entry points explicitly (move `SearchSymbolPatternBatch`/`QueryBatch`/
`SearchSymbolCandidates` plus the `regex` dependency into core, redesign the signatures
around core-owned request data, or leave those methods on `IAnalyzer`), recording the
choice and reasons in the decision log. Then introduce `CodeUnitIndex` in
`crates/bifrost-core/src/analyzer/`; make `IAnalyzer` extend it; split every implementor's
`impl` blocks, quarantining the `*_for_test` counter hooks behind the feature-gated
`test_hooks()` accessor of decision 4 (with `MultiAnalyzer` forwarding) in the same pass;
move `capabilities.rs` and `pool_memo.rs` to core with bounds rewritten to `CodeUnitIndex`
(preserving `PoolSafeMemo::get`'s `#[cfg(test)]` gating exactly); re-export at old paths.

This milestone also ships the stability documentation, because `CodeUnitIndex` is the
first deliberately low-level trait landing in a published crate. The decision (Jonathan,
2026-08-04) is documentation over mechanism: no trait sealing, no `#[doc(hidden)]`
sweeps, no split versioning. The tier boundary already exists structurally — the
`brokk-bifrost` facade curates its re-exports item-by-item, so "depend on the facade" is
the supported surface (the same altitude as the Python client) and depending directly on a
sub-crate is visibly leaving the paved road. Make that explicit in prose: one crate-level
doc line on each internal crate ("Internal implementation detail of `brokk-bifrost`; no
stability guarantees — depend on `brokk-bifrost` instead", the `regex-automata` /
`wasm-bindgen-backend` idiom, surfaced on the crates.io and docs.rs pages where a would-be
consumer actually looks), plus a short Stability section in
`docs/src/content/docs/rust-library.md`: the facade's exported surface is what we
unofficially commit not to break gratuitously; everything beneath it may change in any
release.

Acceptance: workspace green; `brokk-bifrost-core` compiles and its unit tests pass
standalone (`cargo test -p brokk-bifrost-core --lib`); the root integration suites that
exercise `*_for_test` hooks through `&dyn IAnalyzer` (for example the
`issue_1175`/`issue_1194`/`issue_1219` scan suites) pass — these build with the
`test-support` feature via the root manifest's dev-dependency, so a scoped validation must
not skip them; `scripts/check-workspace-packages.sh` green (code and dependency edges
moved between two published crates, and re-exported paths must survive packaging — note
`syn`, as a dev-dependency, stays out of the published dependency graph, and any
dependency newly added to a *published* manifest triggers the dependency/license inventory
per the CI licenses gate); no downstream crate source changes.

Milestone 3 — checkpoint, not code. Re-run the phase-2 evaluation methodology (cold
`--timings` featureless workspace build, warm touch-rebuild loops) and record the numbers
in `.agents/docs/analysis-crate-split-phase2-evaluation-2026-08.md` as a follow-up section.
This stage is expected to be build-time-neutral; the deliverable is the measurement plus a
stop/go recommendation for the per-language extractions, which are a separate future
ExecPlan. That recommendation must also name the dependency structure extraction will use
(lower the SPI contracts into a dependency-safe crate, or keep analysis-owned adapter
shims — see Purpose), since the two differ materially in cost. Nothing in milestones 0-2
is wasted if the answer is stop: the lockstep-list hazard is gone either way.

## Validation

Every milestone runs the standard gates from CLAUDE.md: `cargo fmt`, `cargo clippy
--workspace --all-targets --all-features -- -D warnings` (through
`scripts/with-isolated-cargo-target.sh`; `PYO3_PYTHON` set per the uv 3.12 environment),
`cargo-nextest run --workspace` with `BIFROST_SEMANTIC_INDEX=off`, and workspace doctests.
Milestone 1 additionally requires behavior invariance evidence: the suite_usages,
suite_smells, scan_usages surface, and get_definition suites unchanged, plus one
`bifrost_reference_differential --cache-mode ephemeral` smoke on a mixed-language corpus
showing an identical divergence census before and after, plus the budget-constrained
candidate tests and dead-code pins of decisions 2 and 3. Milestone 2 additionally requires
the package-archive gate and the root `test-support` integration suites named in its
acceptance. The syntax-aware source gate is the permanent regression guard; it is the
analogue of the structural adapter suite's `STRUCTURAL_ADAPTER_PENDING` gate and must fail
loudly with the offending path and location, not just a count.

## Progress

- [x] Pre-flight: reach-in census re-run against current HEAD — no upstream churn since
      `999a0d5c`; seventh list + breadth omissions found and dispositioned in
      `.agents/docs/registry-preflight-census-2026-08.md`; open PRs checked (#1558
      policy-only, no overlap)
- [x] Pre-flight: absent-capability behavior inventory recorded in
      `.agents/docs/registry-preflight-absent-capability-inventory-2026-08.md`
      (Language::None outcomes per consumer, the receiver-query gate/unreachable
      three-place invariant, budget-constrained candidate ordering with test shapes,
      the four dead-code pins incl. Scala's inverted cap polarity, Ruby fold-in
      acceptance points)
- [x] Milestone 0: weighted-cache helpers extracted to analyzer/weighted_cache.rs
      (JsTsMemoCaches stays), old paths re-exported, gates green (46cfb520, merged
      395bf0f0; note for 1f: several language modules hold byte-identical private
      copies of weight_project_file_set/weight_code_unit_set -- retarget to the
      shared module when imports are retargeted)
- [x] Milestone 1a: LanguageSupport trait + Option-returning exhaustive-match registry +
      twelve Support structs + finder/dead-code strategy dispatch (281624d6 + 104290f8;
      Python/C++ dead_code_strategy deliberately None; strategies promoted to statics
      via const fn new(); JS/TS share one strategy static in js_ts; post-merge
      workspace nextest 8214/8214)
- [x] Milestone 1b: receiver_query bounded-resolver tables onto trait methods
      (472a0c07, 0bb65ff0, a9c3c6b5, 84b7393e; three-place receiver invariant collapsed
      to one structural_receiver capability, nine-set unchanged; get_type table
      converted via independent type_lookup capability -- Cpp/Php/Python/Ruby have
      receiver resolvers but no type lookup, so the two capabilities are separate
      methods; forward-query import block deleted; workspace nextest 8219/8219)
- [x] Milestone 1c: LanguageEdgePass with EdgePassId dedup; edge_sites/edge_weights split;
      lists 2 and 3 converted onto one shared collector; dead-code edge builds into
      DeadCodeSupport; UsageEdgeResolver deleted
- [x] Milestone 1d: Ruby UsageQueryResolver fold-in (`RubyQueryResolver<'a>` holds the
      `&'a RubyAnalyzer`; the strategy is now the sibling-shaped wrapper; all eleven
      inventory asymmetries preserved, four of them newly pinned by unit tests)
- [x] Milestone 1e: resolved by the census-corrected gate design with no code change --
      the module-tree-aware gate exempts cfg(test) code, and every service.rs
      TypeScript reference sits inside mod tests (census re-verified, incl. the seven
      additional TypescriptAdapter uses); relocation would satisfy a rule that no
      longer exists. 1f's gate landing proves the exemption in practice
- [x] Milestone 1f: workspace.rs construction match moved to assembly (02cdf219); the three
      registry-natural tables (b5aa157f); candidate augmentation with the
      protected/supplemental split (61db3ab0); the JS/TS receiver-facts factory (4259e8e0);
      census section 3's small reach-ins (13a656c3); weighted-cache shims retargeted and
      their byte-identical copies deduped (32409f0d); syntax-aware source gate landed green
      with its leftovers dispositioned (cb823d32); capability snapshot + registry invariants
      consolidated to eight tests (97c4986d); adding-a-language runbook written, 45 lines
- [x] Milestone 1 acceptance: differential smoke flat -- byte-identical censuses and
      per-site payloads (56506 sites, 11 languages, ~44k LOC) between 508b0737
      (pre-1a) and 74bf60a3 (1f complete), evidence in
      .agents/docs/registry-milestone1-differential-evidence-2026-08.md; the corpus
      has no Ruby/Kotlin coverage, so 1d rests on its four unit pins; absent-capability
      behaviors pinned by the milestone tests; workspace suites green throughout.
      Separate pre-existing finding (both legs, filed as #1595/#1596): dtolnay__anyhow
      trips the f25cb966 encode_unit_fq_segments assert and one repo panic aborts the
      whole corpus run
- [x] Milestone 2 inventory: 17 implementors (the census missed `TreeSitterAnalyzer<A>`,
      whose impl is path-qualified and generic), 41 CodeUnitIndex methods, zero non-core
      signature types and zero core dependency additions from the split itself;
      search adjudication recorded (18c9c6d7,
      `.agents/docs/registry-milestone2-inventory-2026-08.md`)
- [x] Milestone 2: CodeUnitIndex split + feature-gated test_hooks() quarantine (9f7e49e6);
      capabilities.rs + pool_memo.rs moved to core with bounds on CodeUnitIndex, adding
      `rayon` and nothing else (0de0e116); six internal-crate doc stamps +
      rust-library.md Stability section (00796f43). Package gate, dependency gate and the
      root test-support suites all green; workspace nextest 8230/8230
- [ ] Milestone 3: measurements recorded; stop/go recommendation written, including the
      extraction dependency structure (SPI lowering vs. analysis-owned shims)

## Decision log

- 2026-08-04: Plan created. Ordering rationale (registry before any extraction, js_ts
  stress cases designed first) is Jonathan's de-risk call: the dispatch lists and the
  edge-shape mismatch are the same inversion problem, so the registry must be validated
  against the hardest consumer before any file moves make rework expensive.
- 2026-08-04: Static explicit registry chosen over linkme/inventory-style distributed
  registration. AnalyzerDelegate enum retained as assembly-layer storage.
- 2026-08-04 (superseded twice, see the sink-to-enum and enum-to-pass entries below):
  sink-based edge recording initially chosen over generalizing UsageEdgeResolver's return
  type.
- 2026-08-04 (partially superseded): IAnalyzer split criterion recorded as signature
  closure; later refined to a semantic definition with closure as the mechanical check.
  The original note that Scala test hooks were "deliberately not addressed" is superseded:
  all *_for_test hooks are quarantined in milestone 2.
- 2026-08-04: First revision round (Tolnay/d'Antras-framed review, adopted by Jonathan).
  LanguageDescriptor struct-of-function-pointers became the LanguageSupport trait with
  default-method fallbacks; the LazyLock HashMap registry became an exhaustive match
  (completeness compiler-enforced; coverage unit test dropped); the dyn UsageEdgeSink was
  replaced by a wholesale-return design because per-edge virtual dispatch violated
  decision 7; Box<dyn> strategy construction became &'static dyn borrows of ZST statics;
  the *_for_test quarantine moved into milestone 2 proper; milestone 1e gained a
  root-cause-before-abstracting requirement; CodeUnitIndex gained its semantic definition.
- 2026-08-04: Second revision round (lens sweep). Added the coordination section, the
  capability snapshot and adding-a-language runbook, the absent-capability behavior
  inventory, and the documentation-over-mechanism stability posture (sealing rejected by
  Jonathan: at 0.x with no real consumers, the supported tier is the facade's curated
  re-exports, expressed as doc stamps plus a rust-library.md stability note).
- 2026-08-04: Third revision round (external colleague review at 09eb52b2; every checkable
  claim verified in-tree before adoption). Blocking fixes: the registry returns
  Option<&'static dyn LanguageSupport> with an explicit Language::None => None arm; the
  single LanguageEdges return enum was replaced by LanguageEdgePass with EdgePassId
  identity and separate edge_sites/edge_weights outputs (sites and weights are mutually
  non-reconstructible; pass cardinality is not one-per-language). Major fixes: the source
  gate became syntax-aware; semantic_hooks was removed from the SPI after verifying the
  service.rs TypeScript references are test-only; the capability snapshot was scoped to
  observable behavior; milestone 2 gained the implementor/type/dependency inventory
  including EmptyAnalyzer and the search-method adjudication; candidate augmentation
  gained the protected/supplemental split; the stale Kotlin sequencing was removed;
  superseded log entries marked.
- 2026-08-04: Fourth revision round (external colleague review at 7ff7ce33; claims
  verified in-tree: JsTsMemoCaches/moka in cache.rs, build_language_delegate at
  workspace.rs:406 with the RustAnalyzer warm reach-in at :460 and the Python pack surface
  at :11/:203, JsTsReceiverFactProvider's lifetime-parameterized shape at
  receiver_analysis.rs:38, and the test-support feature chain with root suites calling
  hooks through dyn IAnalyzer). Milestone 0 changed from whole-file move to helper
  extraction into a language-neutral module *inside analysis*, deferring the cross-crate
  home (and the moka-into-core cost) to the extraction plan — reviewer's option 2, chosen
  to protect the standalone core test loop; the git-follow acceptance dropped.
  workspace.rs recognized as the sixth dispatch list: construction moves to the assembly
  layer, warm_rust_usage_analysis becomes a default-no-op warm_usage_analysis capability,
  and the Python workspace surface is dispositioned in pre-flight (default: named
  allowlist as intentional Python-specific public API). receiver_facts became the
  make_receiver_facts factory with a lifetime-carrying context (Box per bounded query;
  callback and flat-method forms recorded as rejected alternatives). The extraction claim
  in Purpose was rewritten per the reviewer's wording: in-place inversion removes the
  census blocker; extraction additionally needs SPI lowering or analysis-owned shims, and
  milestone 3 must choose. Test-hook quarantine fixed as a feature-gated test_hooks()
  accessor (cfg-dependent supertrait rejected as a coherence footgun; unconditional
  no-op supertrait rejected as non-quarantine), with the root test-support suites added to
  milestone 2 acceptance. Dead-code edge builds carved out into DeadCodeSupport rather
  than threading an EdgeScanPurpose mode flag through the generic contexts (flag-parameter
  smell), with four behavior pins added. The package-archive gate was added to milestone 2
  (milestone 0 no longer touches manifests under the extraction choice). The registry
  snapshot gained invariant assertions, and ecosystem() was removed from LanguageEdgePass
  so LanguageSupport is the single owner of ecosystem knowledge (dual sources flagged as
  reintroducing duplicated registration knowledge).
- 2026-08-04: Milestone 1c landed as three commits, not four. The trait-plus-list-2 and
  list-3 conversions merged because `edge_sites` is dead code until its consumer exists, so
  splitting them cannot keep both commits clippy-clean under `-D warnings`.
  Implementation decisions worth recording:
  (a) `EdgePassId` is an eleven-variant enum with an explicit `ALL` ordering that the
  collector iterates. Order is behavior, in two places compiler exhaustiveness cannot see:
  the workspace graph's `resolved_ecosystems` collapses only *consecutive* duplicates, so
  the JVM trio must stay adjacent, and the dead-code report's `skipped` list is capped at
  ten unsorted entries, so bucket processing order is user-visible. `ALL` reproduces the
  dead-code order exactly and keeps ecosystems adjacent; cross-ecosystem order is not
  observable in either edge consumer because their keys carry the ecosystem and both sort
  before output.
  (b) The shared collector is `edge_passes()`, returning `(id, ecosystem, pass)`. It owns
  pass enumeration, dedup and the ecosystem-agreement assert only. Ecosystem *selection*
  (the workspace graph gates on `selected_ecosystems` and non-empty candidates; scan_usages
  gates on nothing), node-set choice, cancellation interleaving and result conversion stay
  with each consumer, because those are exactly where the two differ and merging them would
  have needed a mode flag.
  (c) `DeadCodeSupport` is a plain `Copy` struct of two options, `strategy` and
  `bulk: Option<&'static dyn DeadCodeBulkProof>`. The proof's four methods keep each
  documented divergence inside its language; the framework keeps the drivers. Per-language
  routing memos are `Box<dyn Any + Send>` from `new_memo`, replacing a dozen `Option`
  locals in the report function -- typed per language rather than pooled across all of them.
  (d) The bulk cap and could-not-be-built diagnostics unified without losing a pin: Rust's
  and JS/TS's strings are the generic ones with the labels "Rust" and "JS/TS", which the
  proofs supply along with the file count their cap is measured against. Only Rust's
  analyzer-availability string is genuinely language-specific, and it arrives through
  `DeadCodeBulkPreflight::Unavailable`.
  (e) Deleting `UsageEdgeResolver` exposed two methods it had kept alive with no caller
  (`PythonEdgeResolver::build_edges`, `JsTsEdgeResolver::build_edge_weights`), both removed.
  (f) `go_implicit_entry_point` and helpers moved to `usages::go_graph`, mirroring
  `cpp_graph::is_cpp_global_main`: both the dead-code candidate filter and the bulk routing
  need it. The per-language *scoring* selection (`bulk_graph_finding`) stayed in
  dead_code_smells.rs as a bare `match Language` with no module reach-in -- census section 6
  class, out of the gate's scope, and not part of 1c.
- 2026-08-04: Pre-flight census (at ec74ddac, recorded in
  .agents/docs/registry-preflight-census-2026-08.md). No dispatch site changed since
  999a0d5c; the deltas are census breadth omissions. Scope absorbed: the seventh list
  (global_usage_definition_index's ForwardQueryProvider table -> forward_query_provider
  on LanguageSupport; package separator -> default method), the get_type resolver table
  (into milestone 1b), structural_spec_for / parser_language_for_flavor /
  highlight_query_for (into milestone 1f as SPI accessors). Named allowlist entries
  fixed: summary.rs (intentionally Java-specific public API, the Python-surface
  precedent), the ScalaExportInfo production signatures in tree_sitter_analyzer.rs and
  store/mod.rs (type-level leak; lowering it is an extraction-plan prerequisite, not
  milestone-1 scope), the analyzer/mod.rs and usages/mod.rs re-export hubs, and
  benchmark.rs. Gate corrected to walk the module tree from lib.rs tracking cfg(test)
  on mod items (sixteen parent-gated tests.rs files, two of which would false-fire).
  Out-of-scope match-Language inventory (exception_handling.rs's per-language
  implementation set, lexical_definitions node-kind tables, epoch cells, the three
  divergent display-name tables, the string-keyed overlay roots) documented for the
  extraction plan rather than converted. bifrost-lsp's own downcast tables
  (import_ambiguity.rs, type_definition.rs) noted: outside this plan's gate and scope,
  but they depend on resolve_analyzer's contract surviving unchanged — which it does
  (AnalyzerDelegate retained per decision 1).
- 2026-08-04: Milestone 1d landed as a purely structural fold-in. `UsageQueryResolver`
  needed no change to accommodate Ruby, so it was not touched. Only one check moved:
  the analyzer-capability gate is now `RubyQueryResolver::try_new`, which is where the
  siblings put it; because the language gate still runs before it in the strategy, the
  gate order and therefore every observable outcome is unchanged, including the
  deliberately non-sibling string "Ruby analyzer is unavailable". The shape gate stayed
  in the resolver body (no sibling has one, and `RubyTargetSpec::from_target` needs the
  target). The two asymmetries that a future normalizer would most plausibly "fix" --
  post-budget scan-set augmentation with the target source and Zeitwerk referrers, and
  partial-results-on-cancel where the siblings return `empty_success` -- carry a
  constraint doc comment on the resolver saying they are load-bearing. Four unit tests
  in `ruby_graph.rs` now pin what the absent-capability inventory's section 5 acceptance
  paragraph asks for: the three gate strings plus the `RubyUsageGraphStrategy` label,
  the augmentation in both `scan_scope.allows` directions, partial-on-cancel via the
  `cancel_after_checks_for_test` sweep the finder already uses, and the `Resolved`-wrapped
  `TooManyCallsites` cap. They are in-crate because `find_graph_usages`, `UsageScanScope`
  and cancellation injection are all `pub(crate)`.
- 2026-08-04: Milestone 1f's final chunk -- the gate, the snapshot, the runbook, and the
  milestone-0 cleanup (32409f0d, cb823d32, 97c4986d, plus this entry). Recorded in four
  parts.
  (a) Cleanup. The nine language modules reaching the weighted-cache helpers through js_ts
  re-export shims now name `analyzer::weighted_cache` directly and both shims are gone;
  milestone 0's note is discharged. Four modules (rust, ruby, python, go) held
  byte-identical private copies of `weight_project_file_set`/`weight_code_unit_set` and now
  import the shared ones; cpp, csharp and java were left alone because theirs genuinely
  differ (cpp and csharp measure a `ProjectFile` as root plus rel_path, java adds the key's
  weight to every value's). All eleven `<Lang>UsageGraphStrategy` re-exports in
  `usages/mod.rs` survive: the root integration suites still reach every one through
  `brokk_bifrost::usages`, so they are allowlisted rather than deleted.
  (b) The gate. `tests/suite_cross_language/language_reach_in_gate.rs`, `syn` plus
  proc-macro2 span-locations as dev-dependencies. It walks from `lib.rs` tracking
  `cfg(test)` on mod items, asserts it reached every `.rs` file under `src` (an unfollowed
  module is a loud failure, not an unpoliced file), and carries a second test asserting
  every allowlist entry is still load-bearing when rescanned non-exempt. That second test
  paid for itself immediately: it retired three census-named entries on its first run.
  `analyzer/structural/execution/benchmark.rs` selects fixtures by string literal, and
  `searchtools/selectors.rs` and `sources.rs` reach C++ through snake_case free functions
  and `CppCallableUnitRole` -- none of which the plan's module-and-four-type-families rule
  covers, so allowlisting them would have been decorative. Their justification comments stay
  in the source.
  (c) Leftovers, 151 hits across seven files. Converted: finder.rs's eleven
  `impl GraphUsageAnalyzer` forwarding impls (the plan's own exemplar) became trait impls in
  each `<lang>_graph.rs`, deleting the macro and eleven imports; receiver_query.rs's two
  `resolve_analyzer::<XAnalyzer>` downcast tables became `signature_metadata_limited`
  (default `None`, preserving the old `_ => None` for Java/JS/TS) and
  `declaration_ranges_limited` (no default, all twelve answer); lexical_definitions.rs's two
  became `focus_resolves_lexically` and `skips_local_declaration`. Allowlisted with reasons:
  `lib.rs` (crate-root re-export surface, the `analyzer/mod.rs` class one level up),
  `get_definition/mod.rs` and `call_sites.rs` and `dead_code_smells.rs` (per-language
  implementation sets in framework files, census section 6, the `exception_handling.rs`
  class), `get_type/mod.rs` (re-export hub over its own submodules), and receiver_query.rs's
  remaining Java resolution-session route -- `BoundedJavaResolution` in a framework signature
  is the `ScalaExportInfo` class of type-level leak, so it carries the same extraction-plan
  follow-up. Worth recording: `parsed_tree.rs:16` did *not* fire, correctly -- it is a bare
  `match Language` with no module coupling, which is exactly the line the gate is meant to
  draw.
  (d) Snapshot and runbook. `CAPABILITY_MATRIX` is a formatted table over the twelve
  languages: ecosystem, edge pass, package separator, dead-code strategy and bulk proof id,
  structural receiver, receiver facts, type lookup, highlight query. Three capabilities are
  named as deliberately out of it because none answers without a built workspace
  (`candidate_augmentation`, `signature_metadata_limited`, `declaration_ranges_limited`).
  Four enumeration tests folded into it with their reasoning migrated to its doc comment;
  eleven registry tests became eight covering strictly more. The runbook
  (`.agents/docs/adding-a-language-runbook.md`) came out at 45 lines and five steps, which
  is the design validation the plan asked for: the SPI holds.
- 2026-08-04: Milestone 2 landed as four commits (18c9c6d7, 9f7e49e6, 0de0e116, 00796f43),
  with the full inventory in `.agents/docs/registry-milestone2-inventory-2026-08.md`.
  Decisions worth recording here:
  (a) The implementor census was wrong by one, in the way that mattered most:
  `TreeSitterAnalyzer<A>` implements `IAnalyzer` as
  `impl<A> crate::analyzer::IAnalyzer for TreeSitterAnalyzer<A> where A: LanguageAdapter`,
  which a `^impl IAnalyzer for` sweep does not see, and it holds the bodies all twelve
  language wrappers forward to. Seventeen implementors, 1018 method bodies: 418
  `CodeUnitIndex`, 130 `AnalyzerTestHooks`, 470 retained.
  (b) Search adjudication: the batch types are cleanly separable -- `search_symbol_candidates`
  is the *only* method naming `SearchSymbolPatternBatch`/`SearchSymbolCandidates` -- so the
  boundary is drawn at the compiled request rather than at the word "search". The five
  plain-string lookups move to `CodeUnitIndex`; `search_symbol_candidates` and
  `autocomplete_definitions` (whose default body calls `regex::escape`) stay. `regex` does
  not enter core. Excluding `lookup_candidates_by_identifier` would have left an index
  trait that cannot look a declaration up by name, which is the arbitrary-feeling outcome
  the plan says to stop for.
  (c) Membership needed no type moves at all: every one of the 41 methods was already
  closed over core types. Three per-method resolutions went the other way, "the method
  does not belong on the index": `list_symbols*` (core-typed signature, but its renderer
  resolves display names through the milestone-1 `language_support` registry -- moving the
  type would have meant moving the whole SPI), `metrics` (aggregate report, not index
  access), and the location-to-declaration group `enclosing_code_unit`/
  `enclosing_code_unit_for_lines`/`is_access_expression`/`find_nearest_declaration`/
  `declaration_syntax_kind`, which answer from a parse tree and are not among decision 4's
  four named operations.
  (d) The quarantine surfaced two real duplications rather than just relocating methods.
  Ten inherent `pub fn <hook>_for_test` wrappers on the C#, Go and Rust analyzers were
  byte-identical forwards to the same-named trait hook, and since inherent methods win name
  resolution they let a concrete-typed caller bypass `test_hooks()` while a `dyn`-typed one
  went through it; deleted. And `TreeSitterAnalyzer` had
  `search_candidate_hydration_count_for_test` as an inherent method its `IAnalyzer` impl
  never overrode, so every `dyn` view of it silently reported 0 -- latent until routing the
  forward through `test_hooks()` turned it into a red `issue_1199` test. Fixed at the
  source by adding both overrides.
  (e) `test_hooks()` keeps a default body returning a `&'static` no-op. That is exactly
  today's behavior for the three implementors that override nothing, and decision 4's
  rejection of an "unconditional default-no-op supertrait" is about a supertrait, which
  this is not; the `cfg` gate is the quarantine.
  (f) The cost of a supertrait split is imports, not call rewrites: 121 files gained a
  `use ...::CodeUnitIndex;`, because Rust wants the defining trait in scope even for a
  supertrait method on `dyn IAnalyzer`. Ten analysis files take it inside their
  `#[cfg(test)]` module because only their tests need it. No call expression changed shape,
  so the milestone's "no downstream source changes" acceptance holds in the sense it was
  written -- re-exported paths survived -- but not literally.
  (g) `PoolSafeMemo::get` kept its `#[cfg(test)]` gate verbatim, which is now core's
  `cfg(test)`. One analysis test reached through it for presence only and now asserts the
  identical condition via `is_ready()`. Widening the gate to `test-support` was the
  alternative and was rejected: nothing outside core needs the stored `Arc`, which is all
  `get` offers over `is_ready`.
  (h) The move adds exactly one dependency to `brokk-bifrost-core`: `rayon`, for
  `build_reverse_file_index`'s `par_iter` and `pool_memo`'s `current_thread_index`. It is
  already a workspace dependency at the same version and already in the published graph, so
  it is new to core's manifest but not to the license inventory. `check-workspace-dependencies.mjs`
  is unaffected -- core's *workspace* dependency set is still empty.
  (i) Stability stamps went on the six packages `rust-library.md` already enumerates as
  lower-level (core, analysis, policy, nlp, runtime, mcp), not on `brokk-bifrost-lsp`,
  which that same page documents as a supported direct dependency for LSP-only hosts. The
  new Stability section names it as the exception instead of leaving the contradiction in
  place. `brokk-bifrost-semantic-packs` is unstamped as release-only pack tooling.
