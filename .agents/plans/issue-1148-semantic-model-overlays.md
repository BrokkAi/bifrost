# Project active semantic facts into first-class navigation overlays

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds.

The canonical instructions for this document are in `.agents/PLANS.md`. Maintain this plan in accordance with that file.

## Purpose / Big Picture

Bifrost can compile, catalog, activate, and exactly match semantic-model packs, but the resulting declaration facts are invisible to ordinary library consumers. Symbol search, definition and usage navigation, type hierarchy, CodeQuery, MCP, LSP, and Python still accept only filesystem-backed `CodeUnit` and `ProjectFile` identities. Treating a declaration that exists only in a model as a fake workspace file would make source navigation lie and would corrupt cache and equality assumptions.

After this change, one activated semantic-model generation produces an immutable declaration overlay owned by the same analyzer snapshot as the runtime matcher. A declaration in that overlay has a stable semantic identity, explicit origin and activation provenance, and one of two honest locations: an authored source or artifact anchor that Bifrost can actually navigate, or a deterministic `bifrost-model://` URI with a deterministic virtual range. Normal symbol, definition, usage, hierarchy, and CodeQuery entry points consult this overlay. Their serialized results preserve provenance for human renderers, MCP, LSP, and Python consumers. Authored or exact-artifact declarations outrank modeled declarations, model facts augment only absent information, and unresolved real/model or model/model conflicts fail closed. Reacquiring after a catalog install, replacement, or removal cannot reuse stale declarations.

This issue does not materialize generated source, add model-only entries to `Project::all_files()`, or claim that a model URI contains authored source text.

## Progress

- [x] (2026-07-31 17:11Z) Verified live issue #1148, its completed #1145/#1147 prerequisites, the attached clean issue branch, and current `origin/master`; fast-forwarded the branch to `90f5eeba` without switching or rebasing.
- [x] (2026-07-31 17:11Z) Read `.agents/PLANS.md`, the #1147 and #1149 ExecPlans, the semantic runtime/catalog/schema, core analyzer identities, and the symbol/navigation/usage/hierarchy/CodeQuery/LSP result boundaries.
- [x] (2026-07-31 17:11Z) Diagnosed the missing first-class model location domain, lost shard provenance in declaration matches, absent production overlay ownership, incomplete cross-domain precedence, and catalog-blind runtime cache key.
- [x] (2026-07-31 17:11Z) Chose the snapshot-owned overlay, stable URI, provenance, fail-closed merge, and catalog mutation identity design recorded below.
- [x] (2026-07-31 18:43Z) Milestone 1: added activated declaration/rule provenance, stable authored-or-model locations, immutable bounded overlay indexes, exact catalog mutation identity, and complete-only runtime publication.
- [x] (2026-07-31 18:43Z) Milestone 2: integrated unique overlays into search, locations, modeled source descriptions, definition/declaration navigation, authored augmentation, stable IDs/URIs, and fail-closed conflicts.
- [x] (2026-07-31 18:43Z) Milestone 3: integrated declaration and generated-rule relations into modeled usage, hierarchy, CodeQuery, human/serde results, LSP definition/workspace-symbol/type-hierarchy, and stable follow-up identity checks.
- [x] (2026-07-31 18:43Z) Milestone 4: added eleven behavior regressions and documentation, passed formatting, strict Clippy, focused runtime/overlay/LSP validation, and completed three specialist reviews. The required repository policy run was performed and remains `unreliable` because five whole-repository policies exhaust discovery or stable-anchor budgets; issue-specific findings were fixed and the rerun reports only a pre-existing 2026-07-22 scan-usages fitter finding on changed-file paths.

## Surprises & Discoveries

- Observation: `SemanticModelMatch<T>` currently returns bare `&T` values, so declaration lookups discard the active shard that owns each fact.
  Evidence: `crates/bifrost-analysis/src/analyzer/semantic_model/runtime.rs` resolves type/member/relation postings to records only, while the newer `ActivatedProcedureSummary` retains both record and shard. Overlay provenance needs the latter pattern.

- Observation: `ProjectFile` is a real workspace-root plus relative filesystem path and every `CodeUnit` owns one.
  Evidence: `crates/bifrost-analysis/src/analyzer/model.rs` uses `ProjectFile` for filesystem operations and as part of `CodeUnit` equality, hashing, and ordering. A model-only `CodeUnit` would necessarily be a fake file, which #1148 forbids.

- Observation: the runtime cache key cannot notice catalog-only changes.
  Evidence: `acquire_active_semantic_models` keys `CompleteValueCache` with `runtime_request_key(request)`, which hashes activation evidence and limits but no catalog identity. `SemanticPackCatalog` currently has no mutation generation. Reusing the same analyzer snapshot and request after installing or removing a pack can return the old `Arc`.

- Observation: existing result types are path and range oriented, but they are also the shared serde boundary for MCP and Python.
  Evidence: `SearchSymbolsFile`, `SymbolLocation`, `DefinitionCandidate`, `UsageFileGroup`, and `CodeQueryDeclaration` are serialized directly. Extending shared result values with an honest URI/location and provenance avoids transport-specific copies; LSP still needs explicit handling because it currently accepts only `file://` locations.

- Observation: no production caller currently acquires the semantic runtime.
  Evidence: searches for `acquire_active_semantic_models` and active matcher lookup methods found runtime tests only. This issue can make acquisition publish an overlay and make ordinary consumers overlay-aware, but a higher-level evidence-discovery owner must still call acquisition for a real workspace generation.

- Observation: initial broad Bifrost MCP discovery on the legacy host was unreliable while narrow calls were healthy.
  Evidence: a parallel discovery batch cancelled after 11.4 seconds and a multi-symbol source request timed out after 8.6 seconds; exact single-file and single-symbol calls completed in milliseconds. The evidence was added to existing issues #1419 and #1411 respectively.

- Observation: the runtime semantic hash deliberately excludes equivalent catalog source attribution, so it is not sufficient as the overlay cache identity.
  Evidence: replacing an installed source with an equivalent second source preserves `active_model_set_hash` while activation provenance must change. The cache now pairs an exact active-runtime `Arc` with its overlay and the regression proves both runtime and overlay are replaced.

- Observation: attaching full semantic provenance directly enlarged `CodeQueryResultValue` enough to fail strict Clippy's enum-size check.
  Evidence: boxing only the optional `CodeQueryDeclaration.semantic_model` payload preserves identical serde output and returned the enum below the lint threshold.

- Observation: the initial modeled-usage response fitter repeatedly serialized the whole response while removing relations.
  Evidence: `bifrost.performance.serialization-in-loop` found both new loops. The fitter now serializes relations once, maintains exact JSON byte deltas while trimming, and a 200-relation test proves the final public response is at most 8 KiB.

## Decision Log

- Decision: Add a distinct semantic declaration/location domain instead of extending `CodeUnit` with model-only pseudo-files.
  Rationale: Source-backed analyzer invariants remain intact, while every consumer can explicitly distinguish authored anchors from virtual model identities. This also keeps `Project::all_files()`, file watchers, source caches, and path-based equality free of non-files.
  Date/Author: 2026-07-31 / Codex

- Decision: Build one immutable `SemanticModelOverlay` from a ready `ResolvedActiveSemanticModels` value and publish it in `SemanticModelRuntimeCache`.
  Rationale: Analyzer snapshot caches already define the generation lifetime. The overlay can borrow no catalog or SQLite state, can use compact owned indexes, and changes atomically with the active matcher. Ordinary `IAnalyzer` consumers obtain the current overlay through a default method backed by `snapshot_caches()`.
  Date/Author: 2026-07-31 / Codex

- Decision: Return activated type, member, relation, and rule records with their owning `ActiveSemanticModelShard` from runtime lookups.
  Rationale: Pack digest, producer/version, catalog source, compatibility, completeness, activation evidence, and active-set identity live on the owning manifest/shard rather than the bare fact. The established `ActivatedProcedureSummary` shape is the repository precedent.
  Date/Author: 2026-07-31 / Codex

- Decision: Encode virtual identities as versioned, URL-library-built `bifrost-model://v1/...` URIs derived from semantic pack and fact identity, never locator paths.
  Rationale: Pack/fact identities are deterministic across restarts and independent of checkout paths. Using `url::Url` prevents ad hoc escaping. The URI and its zero-source virtual range are navigation identities only; source-reading APIs return a bounded modeled description rather than fabricated source.
  Date/Author: 2026-07-31 / Codex

- Decision: Resolve authored anchors only when an existing analyzer can prove a real declaration at the locator; otherwise use the model URI.
  Rationale: A source-looking locator in a pack is evidence, not proof that the current workspace contains matching authored text. This permits Scala generated members to navigate to their honest case-class or constructor-parameter anchor when the analyzer proves it, while external/prebuilt facts remain model-located when no source is present.
  Date/Author: 2026-07-31 / Codex

- Decision: Merge at query boundaries with explicit precedence and ambiguity.
  Rationale: Unique authored workspace or exact artifact declarations win. A unique model declaration may fill an absent declaration or add a missing modeled member/relation. Equal-rank differing model facts, or incompatible real/model identities at the same requested symbol, produce an ambiguity/conflict result and no authoritative definition. No regex, source-text fallback, or arbitrary tie breaker is allowed.
  Date/Author: 2026-07-31 / Codex

- Decision: Include a catalog mutation identity in the runtime cache key.
  Rationale: A local monotonic mutation counter covers installs, session registration/removal, quarantine, and garbage collection performed through this catalog object. A SQLite data-version component covers durable commits by other catalog connections. The cache remains request-keyed but cannot reuse a value across catalog state changes.
  Date/Author: 2026-07-31 / Codex

- Decision: Extend shared serde DTOs additively with optional location/provenance fields and model-specific rows.
  Rationale: Existing authored output remains backward compatible within the repository while human, MCP, and Python consumers receive the same truth. LSP converts the same modeled location to its URI and stores stable identity in item data for follow-up hierarchy requests.
  Date/Author: 2026-07-31 / Codex

- Decision: Evaluate the structurally provable subset of active schema-v1 generator rules in the overlay, and leave resolver-dependent forms inactive.
  Rationale: Language-construct and annotation triggers, scalar structural captures, typed templates, and declaration/relation/alias emissions are sufficient for the initial reusable generated-member substrate. `resolved_owner`, `resolved_call`, repeated arguments, and resolved-owner captures require typed analyzer evidence that this issue cannot honestly invent. Documentation names that boundary; there is no regex or mini-parser fallback.
  Date/Author: 2026-07-31 / Codex

- Decision: Follow exactly one unambiguous `navigates_to` relation from a model URI.
  Rationale: Generated members can navigate to a real authored owner or another unique modeled declaration without pretending their URI is source. Multiple, conflicting, or absent targets produce explicit diagnostics and no arbitrary selection.
  Date/Author: 2026-07-31 / Codex

## Outcomes & Retrospective

Issue #1148 is implemented as a library/runtime boundary. A successful explicit semantic-runtime acquisition publishes one immutable, budgeted overlay containing activated declaration facts and the structurally provable generator-rule emissions. Stable `bifrost-model://v1/...` identities, authored anchors, pack/source/producer/rule/activation evidence, proof/completeness, and ambiguity now survive search, location/source/definition/usage navigation, CodeQuery, human rendering, serde/MCP/Python values, and LSP workspace-symbol/definition/type-hierarchy paths. Overlay facts never enter the project file set.

Catalog-local mutations and cross-connection SQLite changes invalidate acquisition. Equivalent semantic bytes with changed source attribution rebuild the runtime and overlay even though the semantic active-set hash intentionally remains stable. Overlay construction occurs outside the cache mutex, polls cancellation, accounts retained bytes with the matcher, and only publishes complete values. Authored declarations win; equal-rank declaration or relation conflicts fail closed. Modeled usage relations remain source-less semantic facts and are byte-budgeted; CodeQuery hierarchy honors direct, depth, transitive, and cycles; a unique generated `navigates_to` edge can land on exact authored source.

Validation completed on 2026-07-31: `cargo test --test suite_semantic -- semantic_model_overlay::` passed all 11 tests; `semantic_model_runtime::` passed all 12 tests; `cargo test -p brokk-bifrost-lsp --lib` passed 104 with one opt-in formatter test ignored; `cargo test -p brokk-bifrost-analysis --lib --no-run` built; strict Rustup-toolchain `cargo clippy -p brokk-bifrost-analysis -p brokk-bifrost-lsp --all-targets -- -D warnings` passed; and formatting plus `git diff --check` passed.

Three specialist reviews covered intent/architecture, correctness/security, and API/tests. Confirmed findings fixed stale cache reuse, construction under the cache lock, cancellation/retained-byte gaps, incomplete activation evidence, locator/proof conflation, declaration/relation conflict selection, source precedence, URI usage, hierarchy depth/cycles, LSP stale follow-ups/ranges/deduplication, generated navigation, and response-budget/human-rendering gaps.

The required `bifrost.code-smells` MCP run used evaluation date `2026-07-31` and no repository-defined executable roots (the other checked-in `.rqlp` files are built-in sources, docs, editor fixtures, or test fixtures). Its final status is `unreliable`, exit 2: expensive-nested-loop, file-read-in-loop, parsing-in-loop, serialization-in-loop, and sort-in-loop exhausted whole-workspace discovery or stable-anchor budgets. The two issue-introduced serialization findings and overlay identity sort finding were fixed. The only remaining finding in issue-touched implementation files is the pre-existing `render_scan_usages_with_budget` serialization loop from commit `0b3547c32`; this issue does not claim a clean policy gate.

Deliberately deferred: production discovery/configuration of which catalogs, evidence rows, and curated Scala/Lombok/macro packs to acquire remains with dependent delivery issues such as #1153. Resolver-backed generator triggers and repeated capture lists also remain inactive until typed analyzer evidence exists. No automatic global catalog root or text fallback was added.

## Context and Orientation

All paths below are relative to the repository root.

`crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines declaration facts. A `TypeFact` and `MemberFact` have stable IDs, names, structured kinds/signatures, and optional `Locator`; a `RelationFact` links stable IDs. A locator can name authored source or an artifact, but it does not itself prove that the current analyzer has navigable text.

`crates/bifrost-analysis/src/analyzer/semantic_model/artifact.rs` defines `CompiledPackManifest` and decoded shards. Manifest fields include pack identity/version, producer, provenance, completeness, compatibility, activation selectors, and semantic/content digests.

`crates/bifrost-analysis/src/analyzer/semantic_model/runtime.rs` owns `ResolvedActiveSemanticModels`, exact matcher indexes, activation explanations, and the snapshot cache acquisition path. Its declaration match currently loses the owning shard; adapt it to return `ActivatedSemanticModelRecord<'a, T>` in the same spirit as `ActivatedProcedureSummary`. The runtime cache lives inside `AnalyzerSnapshotCaches` in `i_analyzer.rs`.

`crates/bifrost-analysis/src/analyzer/semantic_model/identity.rs` already generates deterministic type and member IDs. Add URI construction and parsing beside that identity logic or in a cohesive new `overlay.rs`; do not place URI rules in each transport.

`crates/bifrost-analysis/src/analyzer/semantic_model/catalog/mod.rs` owns durable and session packs. Add a cheap `cache_identity()` made from a local mutation generation and SQLite `PRAGMA data_version`, incrementing the local generation only after successful mutating operations. The runtime request cache key incorporates this identity before cache acquisition.

`crates/bifrost-analysis/src/analyzer/i_analyzer.rs` defines the extension boundary and analyzer snapshot caches. Add a default `semantic_model_overlay()` accessor that returns the overlay published by runtime acquisition without requiring every analyzer implementation to add storage.

`crates/bifrost-analysis/src/searchtools/navigation.rs`, `selectors.rs`, and `scan_usages.rs` implement normal symbol, source/location, definition, and usage tools. Keep authored `CodeUnit` resolution unchanged, then merge overlay outcomes. Model-only results carry a URI and provenance, never a `ProjectFile`. A source-reading request for a model URI returns a clearly labeled modeled declaration description or a typed no-authored-source diagnostic, not invented language source.

`crates/bifrost-analysis/src/analyzer/capabilities.rs` and language hierarchy providers are source-oriented. Add overlay hierarchy helpers alongside the common semantic overlay, then merge them in public hierarchy entry points. Do not push virtual declarations into language-private `TypeHierarchyProvider` methods that promise `CodeUnit` values.

`crates/bifrost-analysis/src/analyzer/structural/search/results.rs` and `search/mod.rs` produce CodeQuery values. Add a model declaration result projection and evaluate only schema forms whose semantics are meaningful for declaration facts. Unsupported AST/source predicates must not match model facts. Relation-based queries may use exact modeled relations.

`crates/bifrost-lsp/src/lsp/handlers/workspace_symbol.rs`, `type_hierarchy.rs`, `hierarchy_support.rs`, and `conversion.rs` currently assume file URIs. Preserve `bifrost-model://` as a URI, use deterministic virtual ranges, and put the stable overlay identity in LSP `data` so subtype/supertype follow-ups can resolve through the snapshot overlay.

The shared search and CodeQuery values derive `Serialize`; MCP and the Rust-to-Python surface consume those values. Add round-trip/serialization tests at those existing boundaries rather than duplicating provenance structures in each crate.

## Plan of Work

### Milestone 1: first-class overlay identity, provenance, and lifetime

Add `crates/bifrost-analysis/src/analyzer/semantic_model/overlay.rs` and export its public values from `semantic_model/mod.rs`. Define a small serializable origin enum, proof/completeness/ambiguity fields, activation provenance, authored-anchor versus model-URI location, modeled symbol kinds, and immutable type/member/relation indexes. Keep manifest-backed strings owned by the overlay so it remains valid after the catalog drops.

Change runtime declaration matches to return activated records retaining the owning shard. Build the overlay only from unique winning facts; retain conflict records as explicit ambiguous entries that query paths can report but not navigate authoritatively. Resolve locators to authored anchors through exact analyzer declarations/ranges. If no exact declaration is proven, build a deterministic URL from active-set version, pack digest, fact kind, and stable fact ID. Use a stable virtual range and document that it is not source.

Extend `SemanticModelRuntimeCache` with atomic overlay publication and expose it via `AnalyzerSnapshotCaches` and `IAnalyzer`. On every ready cached or newly built runtime outcome, publish the corresponding overlay for the same active-set hash. On unavailable/incomplete/cancelled activation, do not replace a known-complete overlay with partial state.

Add catalog mutation identity and include it in the complete-value cache key. Tests must install, replace, remove, and session-register packs against the same analyzer snapshot and request, then prove a new runtime/overlay is built and no removed fact remains. Also test a second durable catalog connection when practical.

### Milestone 2: symbol and definition navigation

Add modeled result DTOs or additive optional fields to `SearchSymbolsResult`, `SymbolLocationsResult`, and `DefinitionCandidate`. Search the overlay with the same compiled pattern batch and cancellation limits as authored declarations, rank authored rows first, and keep model rows grouped by stable URI rather than a fake file. Every modeled hit includes provenance and ambiguity. If the authored and modeled declaration share a stable semantic identity, return the authored row with model provenance as augmentation rather than a duplicate.

Extend exact symbol/location resolution to accept stable model URIs and stable fact IDs returned by search. Definition-by-reference may consult the referenced identifier only after the language analyzer has structurally identified that reference. A unique authored definition wins; a unique overlay definition fills an empty result; a conflict produces a diagnostic and no authoritative candidate. Source retrieval for authored anchors remains normal. Model-only retrieval returns a bounded semantic description clearly labeled as modeled content.

Behavior tests in `tests/suite_semantic/semantic_model_overlay.rs` use `InlineTestProject` and compiled pack fixtures. Cover stable output across repeated builds and catalog reopen, exact and regex-like search, authored-anchor success, model-only URI fallback, authored precedence, modeled augmentation, equal-rank conflict, and absence from `Project::all_files()`.

### Milestone 3: relations, CodeQuery, and transport preservation

Project exact `RelationFact` and `HierarchyFact` values through overlay indexes. Usage navigation can expose a modeled relation only when its endpoint identities resolve exactly; it carries the modeled source/target location and provenance and never fabricates source hit text. Type hierarchy merges authored `CodeUnit` items with model-only URI items at the public result/LSP boundary. Follow-up hierarchy requests parse stable item data back into the current snapshot overlay.

Extend CodeQuery declaration results with location and provenance. Include overlay declarations for declaration/type/member predicates that can be evaluated from typed facts. Do not claim matches for source range, AST shape, text, containment, control-flow, dataflow, or other predicates requiring authored code. Exact relation forms can consume modeled relations when their typed semantics match.

Ensure MCP JSON, human rendering, LSP workspace symbols/definitions/hierarchy, and Python serialization keep origin, pack digest, producer/rule stable ID and version, activation reason/evidence, proof/completeness/ambiguity, and location. Add focused serialization tests to prove a generated/model URI is portable and does not contain the current checkout root.

### Milestone 4: validation and review

Update the semantic-model documentation with the overlay identity, precedence, provenance, virtual-source, and invalidation contracts. Keep examples explicit that a model URI is navigable metadata, not generated source.

Run formatting, focused featureless tests, task-scoped strict Clippy through the isolated-target helper, and the repository policy gate described in `AGENTS.md`. Use `bifrost.code-smells` together with every executable repository policy root named by the project in one request; `finding` requires review/fix and `unreliable` is failed validation. Complete intent, architecture, security, duplication, test, and infrastructure review with specialist agents as the guided-issue workflow requires, address confirmed findings, rerun changed gates, and update this plan with evidence. Do not commit, push, switch branches, or open a PR unless the user explicitly asks.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/3cb3/bifrost`.

Confirm state before each milestone:

    git status --short --branch
    git rev-parse --short HEAD
    git rev-list --left-right --count HEAD...origin/master

After milestone one:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- semantic_model_runtime::
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- semantic_model_overlay::identity
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- semantic_model_overlay::catalog_invalidation

After milestone two:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- semantic_model_overlay::navigation
    scripts/with-isolated-cargo-target.sh cargo test --test suite_symbols -- semantic_model_overlay

After milestone three:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- semantic_model_overlay::relations
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- semantic_model_overlay::code_query
    scripts/with-isolated-cargo-target.sh cargo test --test suite_lsp -- semantic_model_overlay
    scripts/with-isolated-cargo-target.sh cargo test --test suite_python -- semantic_model_overlay

Discover actual suite/filter names with `cargo test --test <suite> -- --list` and update this document if the repository uses a different existing harness. Do not create a new root `tests/*.rs` integration binary.

Final task-scoped gate, without `nlp`:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- semantic_model_overlay::
    scripts/with-isolated-cargo-target.sh cargo test --test suite_symbols -- semantic_model_overlay

Run additional LSP, MCP, and Python crate tests selected by the files changed. Record exact commands and results in `Progress` and `Outcomes & Retrospective`.

## Validation and Acceptance

Compile and install a declaration pack containing one type, one member, and exact relations. Acquire it against one analyzer snapshot and activation request. Search by short and qualified name, resolve the returned identity, inspect hierarchy and modeled usage relations, and query the declaration through CodeQuery. Each surface must report the same fact ID, stable location, active-model hash, pack digest, producer/version, completeness, activation evidence, and unambiguous proof state. Serialize the results through MCP/Python-facing serde and LSP conversion and require the same semantic identity.

Restart/reopen the catalog and rebuild from identical bytes. The model URI and virtual range must remain byte-for-byte identical and contain no absolute workspace or artifact path. `Project::all_files()` and analyzer file listings must remain unchanged.

Give a fact an exact authored locator and an inline project containing the corresponding declaration. The overlay must use the real authored location. Remove or alter that declaration and rebuild the analyzer generation; the same fact must fall back to its model URI unless another exact authored anchor is proven. For a Scala-shaped generated member fixture, map copy-like behavior to the case-class declaration and component-like behavior to the constructor parameter only when the analyzer supplies those exact anchors.

Create a real authored definition and a modeled definition for the same semantic identity. The authored location must win while modeled provenance remains visible as augmentation. Create two equal-rank differing modeled facts for one stable identity; search may report ambiguity, but definition, hierarchy, usage, and CodeQuery must not choose one. A lower-ranked fact must not displace a higher-ranked winner.

Using one unchanged analyzer snapshot and activation request, install a pack, acquire, replace the pack, acquire, remove it, and acquire again. The returned `Arc`/active-set hash and overlay contents must follow each catalog state with no stale declaration after removal. Repeat with a second catalog connection for durable mutation detection if supported by the test harness.

Cancellation and limits must leave the previous complete overlay intact and must never publish a partial overlay as complete. No query may scan source text or use regex as a substitute for structural reference resolution. Model-only source requests must not return language source or a fake `ProjectFile`.

## Idempotence and Recovery

Overlay construction is deterministic and read-only for a fixed analyzer snapshot, active model set, and catalog identity. Publishing an overlay replaces one `Arc` atomically; readers either see the prior complete generation or the next complete generation. A failed, cancelled, or budget-exhausted build publishes nothing. Repeating a successful acquisition with unchanged request and catalog identity reuses the complete runtime and equivalent overlay.

Catalog mutation counters advance only after successful mutations. SQLite data-version reads are side-effect free. If cross-connection data-version behavior proves unavailable in a catalog mode, preserve the local counter guarantee and record the narrower boundary in this plan rather than inventing filesystem timestamp invalidation.

Use `scripts/with-isolated-cargo-target.sh` for isolated builds. Do not create named target directories under `/tmp`. Preserve unrelated working-tree changes and use `apply_patch` for edits. Do not stage, commit, push, rebase, switch branches, or open a pull request without explicit user authorization.

## Artifacts and Notes

Live issue: `https://github.com/BrokkAi/bifrost/issues/1148`.

Relevant completed prerequisites and follow-through:

    #1145  versioned semantic-model schema and deterministic compiler
    #1147  active pack resolver and exact generation-scoped matcher
    #1149  reusable external artifact API-pack producers
    #1424  deterministic compiled procedure-summary binder
    #1425  exact activated procedure-summary lookup

The current implementation revision at planning time is `90f5eeba`. Bifrost MCP latency/protocol evidence from this planning pass is recorded on #1419 and #1411. Those issues are diagnostic context only and do not block this implementation.

## Interfaces and Dependencies

Final names may adjust to repository conventions, but the responsibilities should resemble:

    pub enum SemanticModelLocation {
        Authored(SemanticModelAuthoredAnchor),
        Model(SemanticModelVirtualLocation),
    }

    pub struct SemanticModelVirtualLocation {
        pub uri: String,
        pub range: SemanticModelRange,
    }

    pub struct SemanticModelProvenance {
        pub active_model_set_hash: String,
        pub pack_digest: String,
        pub pack_id: String,
        pub pack_version: String,
        pub producer: String,
        pub producer_version: String,
        pub record_id: String,
        pub origin: SemanticModelOriginKind,
        pub activation: SemanticModelActivationProvenance,
        pub completeness: SemanticModelCompleteness,
        pub ambiguous: bool,
    }

    pub struct SemanticModelSymbol {
        pub id: String,
        pub owner_id: Option<String>,
        pub name: String,
        pub qualified_name: String,
        pub kind: SemanticModelSymbolKind,
        pub signature: Option<String>,
        pub location: SemanticModelLocation,
        pub provenance: SemanticModelProvenance,
    }

    pub struct SemanticModelOverlay { /* immutable owned rows and exact indexes */ }

    impl SemanticModelOverlay {
        pub fn build(
            analyzer: &dyn IAnalyzer,
            active: &ResolvedActiveSemanticModels,
        ) -> Result<Self, SemanticModelOverlayError>;
        pub fn search(&self, patterns: &SearchSymbolPatternBatch) -> SemanticModelQueryResult<'_>;
        pub fn symbol_with_id(&self, id: &str) -> SemanticModelQueryResult<'_>;
        pub fn symbols_named(&self, name: &str) -> SemanticModelQueryResult<'_>;
        pub fn relations_from(&self, id: &str) -> SemanticModelRelationResult<'_>;
        pub fn relations_to(&self, id: &str) -> SemanticModelRelationResult<'_>;
    }

    pub struct ActivatedSemanticModelRecord<'a, T> {
        pub record: &'a T,
        pub shard: &'a ActiveSemanticModelShard,
    }

    impl SemanticPackCatalog {
        pub(crate) fn cache_identity(&self) -> Result<SemanticPackCatalogIdentity, CatalogError>;
    }

    pub trait IAnalyzer {
        fn semantic_model_overlay(&self) -> Option<Arc<SemanticModelOverlay>> {
            self.snapshot_caches().and_then(AnalyzerSnapshotCaches::semantic_model_overlay)
        }
    }

Use the existing `url`, serde, canonical hash, cancellation, `CompleteValueCache`, analyzer range, and semantic identity facilities. Do not add a new database, background worker, fake filesystem layer, or transport-private provenance model.

## Revision Notes

- 2026-07-31: Initial plan created after live issue verification and source diagnosis. The plan makes catalog mutation identity an explicit prerequisite because stale runtime cache reuse would violate #1148 even if query projection were otherwise correct.
