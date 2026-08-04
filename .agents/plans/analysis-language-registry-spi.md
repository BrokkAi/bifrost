# Language registry and analyzer SPI: dispatch inversion inside brokk-bifrost-analysis

This ExecPlan is the gate-1 design for phase 3 of the analysis-crate vertical split. It is
self-contained: everything needed to implement it is in this file plus the current working
tree. Two checked-in companion documents provide background evidence but are not required
reading to execute the plan: `.agents/docs/analysis-crate-seam-matrix-2026-08.md` (the
measured reference inventory this design is derived from) and
`.agents/docs/analysis-crate-split-phase2-evaluation-2026-08.md` (why wall-clock build time
is not the goal of this stage). File/line citations were verified at commit `999a0d5c` and
re-verified selectively at `09eb52b2` during external review; line numbers drift, so treat
them as starting points for a search, not gospel. Two census corrections from that review
are incorporated below and flagged where they appear: the semantic engine's TypeScript
references are test-only, and the two workspace edge consumers produce *different* edge
products, not copies of one.

## Purpose

Today the code-intelligence framework inside `crates/bifrost-analysis` reaches each of the
twelve analyzable languages *by name*, from at least five independently hand-maintained
places. When a language gains a capability, a human must remember to update every list;
when they forget, the language silently lacks the capability on one path while having it on
another. This is the same "two copies maintained in lockstep" hazard class that produced
the MCP pre-handshake authorization bypass documented in CLAUDE.md, and it has already
produced real divergence here: the dead-code path's list has only 9 languages (C++ and
Python are handled by separate special cases), Ruby never received a `UsageQueryResolver`
implementation, and JS/TS cannot participate in the shared workspace-edge-weights shape at
all.

After this plan is implemented, exactly one file in the crate enumerates the languages. Every
framework consumer (usage finding, workspace edges, receiver resolution, dead-code analysis,
searchtools) looks capabilities up in a registry keyed by `Language`. A new language, or a
new capability on an existing language, is one trait-impl edit. A self-policing test fails
the build if any framework file names a language module again.

This also unblocks phase-3 extraction: once no framework file names a language, moving a
language into its own crate is a mechanical file move plus visibility promotions, with its
`LanguageSupport` implementation as its registration point. That is deliberately *out of
scope* here — this plan changes no crate boundaries except one small pre-work move
(milestone 0) and one proof move (milestone 2). Everything else happens inside
`brokk-bifrost-analysis`, which keeps the promotion pain out of this stage entirely:
registry and languages share a crate, so `pub(crate)` suffices throughout.

## Orientation: the five language lists and the named reach-ins

A "dispatch list" here means a place where framework code (code that serves all languages)
matches on `Language` or names concrete per-language types in order to route work. As of
`999a0d5c` there are five, plus a set of scattered single-item reach-ins.

The five lists:

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
   ten-entry per-language `build_*_usage_edges` sequence at `:906-1342` and a four-language
   bulk-eligibility block at `:1997-2085`.
5. `analyzer/multi_analyzer.rs` — `AnalyzerDelegate`, a 12-variant enum of concrete
   analyzers, with construction, plus `resolve_analyzer<T: Any>` (the sanctioned
   downcast-through-`MultiAnalyzer` helper).

The scattered reach-ins, all documented item-by-item in the seam matrix sections 4.1-4.7:
`analyzer/usages/receiver_query.rs:16,25` imports eleven `resolve_<lang>_bounded` and eleven
`resolve_<lang>_type_bounded` functions and dispatches them at `:2061` and `:2018`;
`receiver_query.rs:47` downcasts to all twelve analyzer types;
`analyzer/usages/get_definition/mod.rs:78` names nine;
`analyzer/usages/candidates.rs:652,657` call Python/Rust candidate-file hooks;
`analyzer/usages/finder.rs:367-402` calls PHP composer/import-alias candidate expansion;
`receiver_query.rs:31,36` pull six `pub(in crate::analyzer::usages)` items from
`js_ts_graph::receiver_analysis` plus `JsTsReceiverFactProvider` — no other language's
receiver analysis is reached this way; and small `match language` sites at
`workspace_graph.rs:38,57,124` (`UsageEcosystem`), `receiver_query.rs:2097` (unsupported
reason), `:2143,2883,2953`, and `parsed_tree.rs:16`. Census correction: the seam matrix
listed `analyzer/semantic/service.rs:707,1235` as production references to
`TypescriptAdapter` and `JsTsSemanticLowerer::typescript`; external review established, and
re-verification confirmed, that both sit inside that file's `#[cfg(test)] mod tests`
(opening at `service.rs:697`) — the matrix's stated extraction limit (section 1.3: test
modules inside production files counted as production) misclassified them. The semantic
engine's production code is already fully language-blind; see decision 5.

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
preserves greppability and adds no build dependencies. The registry file and
`multi_analyzer.rs`'s `AnalyzerDelegate` enum become the only two files allowed to name
language modules; the delegate enum stays because concrete per-language analyzer *storage*
is the assembly layer's job, and collapsing it into trait objects would change the
`resolve_analyzer` contract for no benefit at this stage.

Decision 2: `LanguageSupport` is a trait with default methods — one method per capability
the five lists and reach-ins currently encode. A trait rather than a struct of function
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
        fn usage_strategy(&self) -> &'static dyn GraphUsageAnalyzer;    // lists 1 and 4
        fn edge_pass(&self) -> Option<&'static dyn LanguageEdgePass> { None } // lists 2, 3 (decision 3)
        fn resolve_definition_bounded(&self, ...) -> ...;               // receiver_query.rs:16
        fn resolve_type_bounded(&self, ...) -> ...;                     // receiver_query.rs:25
        fn receiver_facts(&self) -> Option<&dyn ReceiverFactProvider> { None } // js_ts today, default elsewhere
        fn dead_code(&self) -> DeadCodeSupport { ... }                  // list 4's (a)-(d) groups
        fn candidate_augmentation(&self, ctx: &CandidateCtx<'_>) -> Option<CandidateAugmentation> { None }
        fn ecosystem(&self) -> UsageEcosystem;                          // workspace_graph.rs:38
        fn graph_unsupported_reason(&self, ...) -> ... { ... }          // receiver_query.rs:2097
    }

`usage_strategy` returns `&'static dyn GraphUsageAnalyzer` rather than `Box<dyn ...>`
because every strategy is a stateless unit struct: a static borrow of a promoted static
states that property structurally and avoids implying an allocation that a boxed ZST would
not even perform. The governing rule is behavioral, not structural: after milestone 1, no
file outside `analyzer/languages.rs`, `analyzer/multi_analyzer.rs`, and the per-language
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
        fn ecosystem(&self) -> UsageEcosystem;      // JVM passes: three ids, one ecosystem
        fn edge_sites(&self, ctx: &EdgeSiteScanCtx<'_>) -> Option<LanguageEdgeSites>;
        fn edge_weights(&self, ctx: &EdgeWeightScanCtx<'_>) -> Option<LanguageEdgeWeights>;
    }

    pub(crate) enum LanguageEdgeWeights {
        Fqn(UsageEdgeWeights),
        Scoped(JsTsScopedUsageEdges),   // js_ts's {file, fqn}-keyed weights product
    }

`LanguageEdgeSites` wraps fqn-keyed, location-bearing `UsageEdges` (every language,
including JS/TS via `build_jsts_usage_edges`, already produces this shape on the sites
path, so no enum is needed there today). Each consumer calls only the output it needs —
one scan per consumer, exactly as now — and the framework-side collector deduplicates by
`EdgePassId`, not by language and not by ecosystem, while centralizing ecosystem candidate
selection, filtering, and result conversion that lists 2 and 3 currently each own a copy
of. The existing `build_*` functions survive nearly unchanged behind the pass methods.
`UsageEdgeResolver` is deleted (zero polymorphic uses — documentation pretending to be
dispatch); its documentation value moves into `LanguageEdgePass`'s doc comments. An
earlier draft returned one `LanguageEdges` enum from a single method and, before that, a
per-edge `dyn` sink; both were rejected in review — the sink for per-edge virtual calls in
the hot loop, the single enum for the double-scan/lossy-product problem above. This
remains the stress-case decision of the plan: the contract is designed against the hardest
consumers first, so the registry never ships an interface JS/TS or the JVM trio cannot
implement honestly.

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
the `as_capability` escape hatch. The `*_for_test` counter hooks (including the two
Scala-specific ones) do not stay put: they are quarantined in the same pass into a
separate test-hooks trait, because splitting ninety methods across all implementors is the
once-per-refactor opportunity — deferring the quarantine would mean touching every impl
block a second time later. The implementor set is larger than the twelve analyzers:
`MultiAnalyzer`, `EmptyAnalyzer` (`analyzer/workspace.rs:19`, a production implementor),
and the test fakes all split too; milestone 2 begins with a mechanical inventory rather
than assuming the list. The split is proven by finally moving `analyzer/capabilities.rs`
and `analyzer/pool_memo.rs` to `bifrost-core` with their generic bounds rewritten to
`T: CodeUnitIndex` — the exact move that stage 2 attempted and had to abandon because
`IAnalyzer` was indivisible.

Decision 5: the semantic engine is already language-blind; keep it that way and remove the
test-fixture coupling. External review established (and re-verification confirmed) that
the two `service.rs` references to TypeScript — the `TypescriptAdapter` import at `:707`
and `JsTsSemanticLowerer::typescript()` at `:1235` — live inside `#[cfg(test)] mod tests`
(opening at `:697`): they construct test fixtures, and there is no production semantic
dispatch seam here at all. The earlier draft's `semantic_hooks` method is therefore
removed from the initial `LanguageSupport` surface — abstracting test-fixture
construction would enlarge every language's interface for zero runtime benefit, exactly
the design-around-a-bug this plan forbids. Milestone 1e instead relocates those fixtures
(into a TypeScript-owned test helper, a generic fake lowerer where appropriate, or an
explicit test-only allowlist entry for the gate), and a `semantic_hooks`-style capability
is added later only if the pre-flight census finds an actual production dependency.

Decision 6: Ruby gets a `UsageQueryResolver`-shaped scan. `ruby_graph.rs:73-173` inlines
what the other ten languages express through `UsageQueryResolver::try_new`/`find_usages`.
Since decision 3 deletes `UsageEdgeResolver` and this plan standardizes the strategy entry
points, the Ruby scan is folded into the common shape at the same time — small, mechanical,
and it removes the one asymmetry that would otherwise need a permanent footnote in the
`LanguageSupport` contract.

Decision 7: perf neutrality is a requirement, not a hope. All registry indirection is
per-query or per-scan (one exhaustive-match lookup plus one indirect call), never per-node
or per-edge; the language-internal hot loops remain monomorphic, and each edge consumer
still triggers exactly one scan per pass (decision 3). The reference differential and the
scan_usages surface tests are the behavioral gate; any measurable regression in the
usage-graph benchmarks fails the milestone.

Decision 8 (pre-work): `analyzer/js_ts/cache.rs` moves to `brokk-bifrost-core` as
`compact_graph`-adjacent utility code (working name `weighted_cache.rs`), because it is a
generic weighted-cache helper that nine *other* languages import — the sole inter-language
dependency outside the JVM realm, per matrix section 5.3. This is required for any future
extraction regardless of every other decision, is invisible to behavior, and shrinks the
entangled surface before the registry work begins.

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

The Kotlin epic (#1234) closed complete on 2026-07-30, before this plan was committed, so
Kotlin's dispatch entries are part of the baseline census, not a live coordination
partner (an earlier revision of this plan treated the epic as in flight — corrected by
external review). The residual check is generic: at dispatch time, look for open PRs or
active agent branches touching the dispatch files, whatever their topic. Relatedly,
milestone 1 rewrites three of the highest-churn framework files (`receiver_query.rs`,
`finder.rs`, `workspace_graph.rs`); its per-list commits should land promptly rather than
accumulating on a long-lived branch, to keep merge windows small.

## Milestones

Milestone 0 — relocate the weighted cache. Move `analyzer/js_ts/cache.rs` (four public
functions: `build_weighted_cache`, `weight_code_unit_vec_by_unit`, `weight_code_unit_set`,
`weight_project_file_set`) to `crates/bifrost-core/src/weighted_cache.rs`, re-export from
`brokk-bifrost-analysis` at the old `analyzer::js_ts::cache` path so the nine importing
language modules compile unchanged, run the standard gates, commit. Acceptance: workspace
tests green; `git log --follow` shows a rename, not a delete/add.

Milestone 1 — the registry, and the deletion of every framework language reference. Create
`analyzer/languages.rs` with `LanguageSupport`, `LanguageEdgePass`, the edge output types,
and the exhaustive-match `language_support` function; add a `<Lang>Support` unit struct to
each of the twelve language modules; convert, in order (each its own commit, tests green at
every step): (a) finder.rs list 1 and dead-code list 4's strategy chain onto
`usage_strategy`, with `Language::None` flowing through the registry's `None` to the
existing terminal outcome; (b) receiver_query's two bounded-resolver tables onto trait
methods; (c) the edge-pass conversion of decision 3 — workspace_graph.rs list 2 onto
`edge_weights`, scan_usages.rs list 3 onto `edge_sites`, dead-code's per-language edge
builds onto the same passes, deduplicating by `EdgePassId` (one shared JS/TS pass; three
JVM passes, one ecosystem), deleting `UsageEdgeResolver` and unifying the two consumers'
collection plumbing into one framework-side collector; (d) Ruby's resolver fold-in
(decision 6); (e) the TypeScript test fixtures in `semantic/service.rs` relocated or
allowlisted per decision 5 — no production change, no new SPI surface; (f) the js_ts
receiver-facts generalization and the remaining scattered reach-ins (candidate
augmentation with the protected/supplemental split of decision 2, searchtools' cpp
identity block, small `match language` sites), each either onto a trait method or
explicitly allowlisted with a comment stating why it is assembly-layer code.

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
and line, not just a filename. Because `syn` sees syntax, comment and string false
positives (the seam-matrix census hit them in raw-string fixtures at
`analyzer/rust/diagnostics.rs:965` and `searchtools/tests.rs:1069`) do not arise. Registry
completeness needs no test — the exhaustive match enforces it at compile time.

Two more artifacts ship with this milestone. A capability-matrix snapshot test iterates
the registry and records, for all twelve languages, every *observable* capability fact:
which optional accessors return `Some` versus `None`, which `DeadCodeSupport` and edge
variants are reported, which `EdgePassId`s exist and how they group by ecosystem. A
capability silently appearing or disappearing then becomes a reviewed diff instead of a
runtime surprise — centralized defaults keep absence *silent* by design, and this snapshot
is what makes silence *visible*; it also gives the `capabilities.md` documentation matrix
a single source of truth. The snapshot deliberately claims only observable behavior: Rust
cannot distinguish an inherited default method from an override behind `dyn`, and a
manually maintained implemented-versus-default table would recreate exactly the parallel
capability list this refactor deletes. And a short "adding a language" runbook under
`.agents/docs/` describing the post-registry procedure (implement `LanguageSupport`, add
the match arm, register the semantic lowerer, done). The runbook doubles as design
validation: if it does not come out short, the SPI is wrong, and we fix it now rather than
after eleven extractions bake it in.

Fallback semantics need an inventory before they are centralized. Today each missing list
entry has its own user-visible consequence: dead-code silently skips the language,
receiver queries return a specific unsupported-reason, policy runs classify results
`unreliable`, MCP surfaces particular error strings, and `Language::None` reaches a
terminal graph outcome. Converting these to registry-`None` and trait defaults must not
change any of them, and the reference differential does not cover most of them. Before
conversion, record the current consequence of each absent capability; acceptance pins
those behaviors unchanged, including budget-constrained candidate-augmentation cases per
decision 2.

Acceptance: the syntax-aware gate and capability snapshot passing; the absent-capability
inventory's behaviors pinned; full workspace gates green; the reference differential flat
against the pre-milestone baseline on a warmed corpus run.

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
`impl` blocks, quarantining the `*_for_test` counter hooks into their own test-hooks trait
in the same pass; move `capabilities.rs` and `pool_memo.rs` to core with bounds rewritten
to `CodeUnitIndex` (preserving `PoolSafeMemo::get`'s `#[cfg(test)]` gating exactly);
re-export at old paths.

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
standalone (`cargo test -p brokk-bifrost-core --lib`); no downstream crate source changes.

Milestone 3 — checkpoint, not code. Re-run the phase-2 evaluation methodology (cold
`--timings` featureless workspace build, warm touch-rebuild loops) and record the numbers
in `.agents/docs/analysis-crate-split-phase2-evaluation-2026-08.md` as a follow-up section.
This stage is expected to be build-time-neutral; the deliverable is the measurement plus a
stop/go recommendation for the per-language extractions, which are a separate future
ExecPlan. Nothing in milestones 0-2 is wasted if the answer is stop: the lockstep-list
hazard is gone either way.

## Validation

Every milestone runs the standard gates from CLAUDE.md: `cargo fmt`, `cargo clippy
--workspace --all-targets --all-features -- -D warnings` (through
`scripts/with-isolated-cargo-target.sh`; `PYO3_PYTHON` set per the uv 3.12 environment),
`cargo-nextest run --workspace` with `BIFROST_SEMANTIC_INDEX=off`, and workspace doctests.
Milestone 1 additionally requires behavior invariance evidence: the suite_usages,
suite_smells, scan_usages surface, and get_definition suites unchanged, plus one
`bifrost_reference_differential --cache-mode ephemeral` smoke on a mixed-language corpus
showing an identical divergence census before and after, plus the budget-constrained
candidate tests of decision 2. The syntax-aware source gate is the permanent regression
guard; it is the analogue of the structural adapter suite's `STRUCTURAL_ADAPTER_PENDING`
gate and must fail loudly with the offending path and location, not just a count.

## Progress

- [ ] Pre-flight: reach-in census re-run against current HEAD (source_ingestion.rs and any
      newer sites dispositioned); open PRs/branches touching dispatch files checked
- [ ] Pre-flight: absent-capability behavior inventory recorded (including Language::None
      terminal outcomes and budget-constrained candidate semantics)
- [ ] Milestone 0: weighted cache relocated to core, gates green
- [ ] Milestone 1a: LanguageSupport trait + Option-returning exhaustive-match registry +
      twelve Support structs + finder/dead-code strategy dispatch
- [ ] Milestone 1b: receiver_query bounded-resolver tables onto trait methods
- [ ] Milestone 1c: LanguageEdgePass with EdgePassId dedup; edge_sites/edge_weights split;
      lists 2 and 3 and dead-code edges converted onto one shared collector;
      UsageEdgeResolver deleted
- [ ] Milestone 1d: Ruby UsageQueryResolver fold-in
- [ ] Milestone 1e: TypeScript test fixtures in semantic/service.rs relocated or
      allowlisted; no SPI change
- [ ] Milestone 1f: remaining reach-ins converted or allowlisted; syntax-aware source gate
      landed; behavior-observable capability snapshot landed; adding-a-language runbook
      written and short
- [ ] Milestone 1 acceptance: differential smoke flat, absent-capability behaviors pinned
      (incl. budget-constrained candidates), all suites green
- [ ] Milestone 2 inventory: implementors (incl. EmptyAnalyzer), methods, non-core
      signature types, dependency additions; search-method adjudication recorded
- [ ] Milestone 2: CodeUnitIndex split; test-hook quarantine; capabilities.rs +
      pool_memo.rs moved to core; internal-crate doc stamps + rust-library.md stability note
- [ ] Milestone 3: measurements recorded; stop/go recommendation written

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
  Option<&'static dyn LanguageSupport> with an explicit Language::None => None arm,
  because None is a currently handled input that must not become a panic; the single
  LanguageEdges return enum was replaced by LanguageEdgePass with EdgePassId identity and
  separate edge_sites/edge_weights outputs, because the two consumers need different,
  mutually non-reconstructible finalizations (sites with locations vs. kind-count weights)
  and pass cardinality is not one-per-language (one combined JS/TS pass; three JVM passes
  sharing one ecosystem). Major fixes: the source gate became syntax-aware (token scans
  miss usages::rust_graph::* and re-exported RustAnalyzer forms entirely); semantic_hooks
  was removed from the SPI after verifying the service.rs TypeScript references are
  test-only (inside mod tests at :697 — a seam-matrix section-1.3 classification artifact),
  making milestone 1e a test-fixture relocation; the capability snapshot was scoped to
  observable behavior only (dyn cannot expose default-vs-override, and a manual metadata
  table would recreate the parallel-list disease); milestone 2 gained the implementor/type
  /dependency inventory including EmptyAnalyzer and the explicit search-method
  adjudication (SearchSymbolPatternBatch owns compiled regex values; core has no regex
  dependency); candidate augmentation gained the protected/supplemental split with
  cancellation context and budget-constrained tests; the Kotlin coordination branch was
  removed as stale (#1234 closed complete 2026-07-30, verified); superseded decision-log
  entries are now marked as such; and decision 7's leftover "HashMap lookup" wording was
  corrected to the match-based registry.
