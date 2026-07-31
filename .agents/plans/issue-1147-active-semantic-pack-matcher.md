# Resolve active semantic packs and build a generation-scoped matcher

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current while implementation proceeds.

This repository's canonical ExecPlan rules are in `.agents/PLANS.md`. Maintain this document in accordance with that file.

## Purpose / Big Picture

Bifrost can already compile semantic-model packs, store them in a verified content-addressed catalog, and record a workspace's active pack references. It cannot yet turn exact workspace dependency and toolchain evidence into one immutable runtime model. Consequently, installed API facts and declarative generator rules are inert: analyzer code has no bounded in-memory structure it can query without returning to SQLite or scanning unrelated rules.

After this change, a caller can provide one analyzer generation's exact language, ecosystem, package, module, toolchain, target, configuration, and artifact-digest evidence. Bifrost deterministically selects compatible pack shards, explains active, inactive, disabled, shadowed, conflicting, and unavailable candidates, computes a semantic `active_model_set_hash`, and hydrates an immutable matcher. The matcher answers exact type, member, relation, annotation, macro, generator, language-construct, resolved-owner, and resolved-call lookups without SQLite access. Repeated construction for the same analyzer snapshot and activation request reuses one cancellation-aware, byte-bounded value; a changed analyzer generation receives a distinct cache owner and cannot reuse the stale matcher.

This issue stops at selection and matching. Issue #1148 will project matched facts into synthetic/external analyzer overlays and stable model URIs. Issue #1150 will discover ecosystem evidence and generate packs from local dependencies. Issue #1151 will expose author-facing lint and explain commands. Issue #1155 will establish release performance gates.

## Progress

- [x] (2026-07-31 10:22Z) Verified the attached issue branch, clean worktree, current `origin/master`, live issue #1147, and completed prerequisites #1145, #1146, and #1149.
- [x] (2026-07-31 10:22Z) Read `.agents/PLANS.md`, the #1145/#1146 plans, semantic-model schema/compiler/catalog/store code, snapshot cache patterns from #920, and the exact issue acceptance criteria.
- [x] (2026-07-31 10:22Z) Resolved the activation, identity, precedence, matching, cancellation, persistence, and validation design in this initial ExecPlan.
- [x] (2026-07-31 13:42Z) Milestone 1: implemented strict activation evidence, bounded catalog candidate evaluation, deterministic selection, explanations, controls, and semantic active-set hashing.
- [x] (2026-07-31 13:42Z) Milestone 2: built bounded immutable declaration and generator-rule exact-key indexes with conflict-preserving query outcomes and allocation-free key probes.
- [x] (2026-07-31 13:42Z) Milestone 3: integrated the runtime with analyzer-snapshot caches, complete-value single flight, active-set reconciliation/publication, cancellation, budgets, and stale-generation protection.
- [ ] Milestone 4: documentation, focused tests, formatting, strict library Clippy, and diff review are complete. The repository-wide policy run is unreliable because nine rules were cancelled after the nested-loop rule scanned 1,201,813 fact nodes, and all-targets Clippy also reports three pre-existing `unnecessary_to_owned` findings in `workspace_graph.rs`.

## Surprises & Discoveries

- Observation: The catalog's persisted `SemanticPackActiveSet::active_set_digest` and #1147's `active_model_set_hash` are different identities.
  Evidence: `crates/bifrost-analysis/src/analyzer/store/mod.rs::semantic_pack_active_set_digest` hashes manifest digest, source kind, source ID, and workspace-produced state. Those fields are needed for ownership and garbage collection. Runtime invalidation instead needs selected semantic shard identities and selection decisions; changing an equivalent source attribution must not rebuild overlays.

- Observation: `SemanticPackCatalog::candidates` is deliberately a broad discovery filter, not sufficient activation proof.
  Evidence: `coordinate_matches` treats a missing query coordinate as a wildcard, target/configuration checks are skipped when the query omits them, and `manifest_compatible` does not require every declared toolchain constraint to have matching evidence. The runtime must strictly re-evaluate selectors and compatibility against complete evidence before activation.

- Observation: Schema version one has only exact generator triggers.
  Evidence: `RuleTrigger` contains `LanguageConstruct`, `Annotation`, `MacroInvocation`, `GeneratorInvocation`, `ResolvedOwner`, and `ResolvedCall`, each keyed by exact strings. There is no authorable wildcard or arbitrary predicate in schema v1, so #1147 must not invent an unused fallback language. Exact candidate counts still need explicit work budgets and metrics; any future schema adding fallback predicates must add a bounded index path explicitly.

- Observation: Bifrost's existing `CompleteValueCache` already supplies the required cancellation-aware same-key single-flight behavior.
  Evidence: `crates/bifrost-analysis/src/analyzer/complete_value_cache.rs` publishes only complete immutable values, lets followers cancel, wakes followers when a leader exits without publication, and enforces retained weight. `AnalyzerSnapshotCaches` already owns structural and usage derived caches per analyzer snapshot.

- Observation: Initial broad Bifrost MCP discovery was unreliable in this worktree.
  Evidence: a parallel `list_files`/`get_summaries`/`search_symbols` request cancelled after about 56 seconds with request-wide budget errors; later exact `get_symbol_sources` requests remained pending beyond 90 seconds and beyond 20 seconds respectively until terminated. Narrow warm symbol searches and source reads often completed in under four seconds. Repository issue search found no open issue matching these exact symptoms; preserve the minimized draft in `Artifacts and Notes` for user-confirmed filing.

- Observation: The required whole-workspace policy gate did not produce a trustworthy result.
  Evidence: `run_policy` for `bifrost.code-smells` on 2026-07-31 returned `status: unreliable` and `exit_status: 2`. Three existing dynamic-evaluation findings completed, then the nested-loop rule examined 1,201,813 fact nodes and nine remaining performance rules were cancelled. No finding points at the issue #1147 files.

- Observation: Strict all-targets Clippy currently has unrelated baseline failures.
  Evidence: after fixing the new runtime's `filter_map_bool_then` finding, the isolated `cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings` run reported three `unnecessary_to_owned` findings in pre-existing `analyzer/usages/workspace_graph.rs` test fixtures. The isolated library-only strict Clippy gate passed, and a second warmed library-only strict gate passed after the final activation changes.

## Decision Log

- Decision: Keep catalog ownership identity and runtime semantic identity separate.
  Rationale: `active_set_digest` must retain source references so catalog GC and cross-process reconciliation remain correct. `active_model_set_hash` will be a domain-separated SHA-256 over the matcher representation version and the sorted selected shard semantic digests, payload kinds, and conflict disposition. It excludes source IDs, content-only provenance, compression, and catalog location so semantically identical bytes reached through another source reuse downstream products.
  Date/Author: 2026-07-31 / Codex

- Decision: Represent activation evidence as complete rows rather than independent bags of coordinates.
  Rationale: A selector can jointly constrain package, module, toolchain, target, configuration, and artifact digest. A row preserves that relationship and prevents the runtime from accidentally combining a package from one resolved artifact with the digest or configuration of another. Callers provide one or more rows per language/ecosystem generation, including a row with omitted package/module only for genuine language-intrinsic models.
  Date/Author: 2026-07-31 / Codex

- Decision: Treat catalog queries as candidate discovery and perform strict activation matching in the runtime.
  Rationale: Broad catalog semantics are useful for indexed discovery and diagnostics but missing evidence must not satisfy a selector. Runtime activation requires every populated selector field and every declared toolchain compatibility constraint to be proven by the supplied context. Bifrost version compatibility is mandatory. Exact artifact-digest evidence outranks coordinate-only evidence.
  Date/Author: 2026-07-31 / Codex

- Decision: Make explicit enable/disable controls compatible-evidence gates, not bypasses.
  Rationale: An override may choose among evidence-compatible candidates or suppress one, and an explicit enable may acknowledge `safety.review_required`. It may not activate a pack for the wrong language, package, version, toolchain, target, configuration, artifact digest, or Bifrost version. Contradictory controls at the same scope are invalid rather than last-write-wins; workspace controls outrank user controls.
  Date/Author: 2026-07-31 / Codex

- Decision: Preserve ambiguity instead of silently choosing equal-rank conflicting facts or rules.
  Rationale: Evidence rank is exact artifact digest before coordinate/version evidence before language-only evidence. Within the same evidence rank, source precedence is ephemeral workspace, durable workspace-produced, generated, installed, pre-shipped, then embedded. A higher rank shadows a lower rank. Different semantic records with the same stable ID at the same rank become an explicit conflict and are not returned as one authoritative match. Equivalent records deduplicate. This leaves #1148 a truthful boundary for merging real workspace source above pack facts.
  Date/Author: 2026-07-31 / Codex

- Decision: Store decoded shards once and index them by compact integer addresses.
  Rationale: `ActiveSemanticModelSet` owns a deterministic array of loaded immutable shards. Hash maps point to `(shard_index, record_index)` addresses for types, members, relations, and rules. This avoids cloning large facts and avoids per-entry `Arc` graphs while retaining stable lookup order.
  Date/Author: 2026-07-31 / Codex

- Decision: Reuse `CompleteValueCache` inside `AnalyzerSnapshotCaches` and publish only fully evaluated runtimes.
  Rationale: The cache owner already identifies one analyzer snapshot. The key binds runtime representation version and the canonical activation-request digest. Cancelled, over-budget, catalog-error, corrupt-load, reconciliation-error, or stale-generation leaders do not publish. A caller may receive an explicit incomplete safe-miss report for useful already-loaded candidates, but it is never retained as a complete value and an empty incomplete result is never presented as valid coverage.
  Date/Author: 2026-07-31 / Codex

- Decision: Keep schema-v1 matching exact and do not add a speculative wildcard engine.
  Rationale: All current rule triggers are exact. The matcher records exact candidates examined and proves unrelated rules are not scanned. A future schema with wildcard predicates must add a new representation version, explicit fallback budgets, and near-miss tests rather than hiding a text scan in this issue.
  Date/Author: 2026-07-31 / Codex

## Outcomes & Retrospective

The strict activation runtime, immutable exact matcher, snapshot-owned cache, active-set publication, public documentation, and focused validation are implemented. Nine runtime integration tests cover strict near misses and explanations, controls, semantic hash stability, every schema-v1 trigger, allocation-free exact lookups after catalog drop, equal-rank conflict preservation, source shadowing, bounded failure, and warm `Arc` reuse with store publication. Existing semantic-model/compiler/docs tests (30), catalog tests (22), and complete-value-cache unit tests (8) pass. The implementation-specific strict Clippy gate passes. Final repository-wide validation remains explicitly incomplete because the policy runner returned an unreliable report and unrelated all-targets Clippy baseline findings remain outside this issue.

## Context and Orientation

All paths below are relative to the repository root. Semantic-model packs are reviewed YAML/JSON or producer-created Rust values compiled into typed canonical manifests and independently loadable shards. A shard contains either declaration facts or generator rules. A declaration fact describes an external type, member, or relationship. A generator rule has one exact trigger, declared captures, and bounded typed emissions. No pack contains executable code or fake source.

`crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines version-one authoring values: `ActivationSelector`, `TypeFact`, `MemberFact`, `RelationFact`, `GeneratorRule`, and `RuleTrigger`. `crates/bifrost-analysis/src/analyzer/semantic_model/artifact.rs` defines compiled manifests, shard descriptors, decoded `CompiledShard` values, semantic/content/stored digests, and defensive limits. The descriptor's `semantic_sha256` covers compatibility, activation, completeness, safety, and payload semantics; it is the right shard-level input to runtime invalidation.

`crates/bifrost-analysis/src/analyzer/semantic_model/catalog/mod.rs` owns the shared content-addressed catalog. `SemanticPackCatalog::candidates` narrows by language/ecosystem and an indexed coordinate, target, configuration, or artifact field without reading shard payloads. `load` revalidates and decodes one opaque candidate; bad durable content becomes a quarantined safe miss. `replace_workspace_active_set` and `reconcile_workspace_active_set` coordinate the catalog with `AnalyzerStore` so selected durable packs remain protected from garbage collection.

`crates/bifrost-analysis/src/analyzer/store/mod.rs` stores `SemanticPackActiveReference` rows and their ownership digest. That state is catalog lifecycle authority, not runtime matcher identity. Preserve the migration and digest semantics added by #1146.

`crates/bifrost-analysis/src/analyzer/complete_value_cache.rs` is the only same-key single-flight primitive to use. A leader receives a permit and may publish one complete `Arc` value. Followers wait cooperatively and can cancel. Dropping a permit without publication wakes a follower to retry. `crates/bifrost-analysis/src/analyzer/i_analyzer.rs::AnalyzerSnapshotCaches` belongs to one analyzer snapshot and currently contains structural derived layers and workspace usage graphs. Add semantic-model runtime caching there rather than introducing another lifecycle owner.

An activation evidence row is one exact, jointly meaningful observation: language and ecosystem plus optional package, module, toolchain, target, configuration, and artifact SHA-256. A populated selector field requires corresponding evidence in the same row. A selector's absent field is a wildcard. A manifest toolchain constraint must be satisfied by a named, versioned toolchain in an evidence row. This is stricter than catalog discovery.

An active model set is the immutable selected semantic content. It owns loaded shards, exact-key indexes, explanations, retained-size accounting, and `active_model_set_hash`. A match is an index lookup that returns zero or more addressed records plus disposition and provenance. It never queries SQLite or reads a pack file.

## Plan of Work

### Milestone 1: strict activation and explainable selection

Create `crates/bifrost-analysis/src/analyzer/semantic_model/runtime.rs` and export its public contract from `semantic_model/mod.rs`. Define activation evidence rows, scoped controls, limits, diagnostics/explanations, evidence/source ranks, selected shard metadata, and active-set hashing. Canonicalization must sort and deduplicate evidence and controls, reject malformed digests, missing language/ecosystem names, unversioned evidence required by a version constraint, and contradictory controls.

Extend the catalog only where the runtime needs opaque metadata or bounded evaluation. `CatalogCandidate` should expose stable manifest/shard/source identity and enough manifest identity to apply controls without trusting caller strings. Add a bounded candidate-evaluation path that reuses existing indexed discovery and reports manifest/selector incompatibility for plausible rows without loading shard bytes. Do not turn explain into an unbounded all-catalog scan. Keep `candidates` as the compatible-candidate convenience API used by existing callers and tests.

The runtime leader queries each canonical evidence row, deduplicates candidate source records, strictly re-evaluates every loaded selector and manifest compatibility constraint, applies user then workspace controls, and assigns an evidence and source rank. `review_required` candidates remain inactive unless a compatible explicit enable acknowledges them. Higher-ranked semantically conflicting stable IDs shadow lower-ranked values; equal-ranked conflicts remain explicit. Normal inactive, disabled, incompatible, and shadowed candidates are complete decisions. Catalog errors, corruption, cancellation, and exhausted budgets are incomplete outcomes and are not cached.

Add behavior-focused integration tests in `tests/suite_semantic/semantic_model_runtime.rs` and register one `mod semantic_model_runtime;` line in `tests/suite_semantic/main.rs`. Reuse compiled inline fixtures or the checked-in semantic-model fixtures; do not add a root integration binary. Tests must prove deterministic selection across input order, strict missing-evidence rejection, package/toolchain/target/configuration/artifact near misses, review-required enablement, override precedence, semantic hash stability across equivalent source attribution, hash changes for changed semantic shards, shadowing, equal-rank conflicts, and useful explanations.

At the end of this milestone run the focused semantic-model compiler, catalog, store, and runtime tests, `cargo fmt --all -- --check`, and featureless strict Clippy for `brokk-bifrost-analysis` through `scripts/with-isolated-cargo-target.sh`. Update this plan with exact evidence, review the milestone diff, and commit only milestone files with a multiline checkpoint message.

### Milestone 2: immutable exact-key matcher

Expand `runtime.rs` with `ActiveSemanticModelSet` and its immutable matcher. Store loaded shards in deterministic rank/identity order. Build compact address indexes using `crate::hash::HashMap`: types by stable ID, exact name, and alias; members by stable ID and `(owner_id, exact_name)` including aliases; relations by stable ID, exact `from`, and exact `to`; generator rules by trigger variant and exact key. `ResolvedCall` uses the ordered `(owner, name)` pair. Do not use regexes, substring matching, source text, FTS, or per-query sorting.

Every lookup accepts a small request object and returns a deterministic outcome containing addressed records, conflicts if present, candidates examined, active-model hash, and explanation handles. Exact lookups must examine only the posting for that key. Schema version one has no fallback rules; metrics report zero fallback candidates. Retained-byte accounting includes loaded decoded shards, owned strings, maps, address arrays, explanations, and conflict records. Building polls `CancellationToken` between shards and bounded record batches and enforces maximum candidates, shards, records, index entries, working bytes, and retained bytes.

Tests must cover every `RuleTrigger` variant, declaration aliases, same-name wrong-owner near misses, relation directions, stable output ordering, duplicate semantic values, equal-rank ambiguity, count and byte limits, integer conversion bounds, cancellation, and retained-byte monotonicity. A no-SQL test builds the matcher, records catalog lookup counters, drops the catalog, performs repeated matches, and proves results and counters remain unchanged.

Commit this independently verifiable milestone after focused tests, formatting, featureless strict Clippy, plan update, and a matcher/correctness review.

### Milestone 3: generation-scoped lifecycle and active-set publication

Add `SemanticModelRuntimeCache` to `runtime.rs`, backed by `CompleteValueCache<SemanticModelRuntimeKey, ActiveSemanticModelSet>`. Add one field and accessor to `AnalyzerSnapshotCaches` in `crates/bifrost-analysis/src/analyzer/i_analyzer.rs`; construct it from the existing analyzer memo-cache budget in `TreeSitterAnalyzer::build_snapshot_caches` and `MultiAnalyzer` construction. Keep one conservative fraction of the existing memo budget rather than adding a second independent global budget. Update `AnalyzerSnapshotCaches::default` and tests accordingly.

Expose a public acquisition function that accepts `&dyn IAnalyzer`, `&SemanticPackCatalog`, optional persistent `&AnalyzerStore` plus scope ID, a canonical activation request, and `&CancellationToken`. Built-in analyzers use their snapshot cache. External analyzers without snapshot ownership receive an explicit uncached build outcome rather than a fabricated long-lived generation. Capture `IAnalyzer::snapshot_source_generations()` before the build and require `snapshot_generations_match` before activation publication and before cache publication.

For persistent activation, call `reconcile_workspace_active_set` before selection. After a complete matcher is built and freshness is rechecked, atomically replace the workspace active references through the catalog/store coordination API, then publish the cache value. Cancellation or failure preserves the prior active set. In-memory workspaces use registered session sources. Read-only catalogs may build an uncached/session result from already verified content but cannot claim durable activation publication. Make that limitation explicit in the outcome.

Tests must cover warm `Arc` reuse, one leader for concurrent same-key construction, cancelled leader and follower behavior, dropped-leader retry, over-budget nonpublication, two different activation-request keys, new analyzer generation isolation, generation change during build, reconciliation before selection, failure preserving the prior active set, durable/session source constraints, and active-set publication only after complete matcher construction.

Commit the lifecycle milestone after focused concurrency and persistence tests, formatting, featureless strict Clippy, plan update, and a cache/concurrency review.

### Milestone 4: documentation, observability, and completion gate

Update `docs/src/content/docs/semantic-model-packs.md` to replace the compiler/catalog-only runtime boundary with the implemented activation and matcher boundary. Define strict evidence, source and evidence precedence, the two active-set hashes, review-required controls, exact schema-v1 matching, incomplete safe misses, no-SQL matching, and the boundary before #1148 overlays. Update `.agents/docs/semantic-artifact-lifecycle-matrix.md` with matcher identity, owner, invalidation, retained-memory accounting, cancellation, and persistence rules.

Expose bounded build and lookup profiles sufficient to report catalog candidate rows, loaded shards/records, exact postings, conflicts, working and retained bytes, waits, cache lifecycle, cancellation, and SQL/catalog activity confined to activation. Do not create the full benchmark campaign owned by #1155. Add a deterministic measurement-style test only if ordinary behavior tests cannot prove the no-SQL and retained-memory acceptance criteria.

Run `cargo fmt --all -- --check`; focused semantic-model, persistence, complete-value-cache, snapshot, and documentation tests; featureless `cargo test` for the changed crate/suites; and `scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings` only at the actual pre-push/full gate after checking disk and concurrent NLP builds as required by repository instructions. Run the installed `bifrost-policy-checking` workflow against `bifrost.code-smells` and every executable repository policy root in one request. Treat `unreliable` as failed validation and record any already-owned whole-workspace budget limitation exactly.

Perform an adversarial review of the complete issue diff with emphasis on false activation, stale generation reuse, equal-rank conflict loss, catalog/active-set races, cancellation publication, unbounded candidate scans, retained-byte undercounting, and SQL in the match path. Fix confirmed findings, rerun affected tests, update this plan's living sections and revision note, and commit the final cleanup separately.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/a638/bifrost`.

The branch and remote were established at planning time:

    git fetch origin --prune
    git status --short --branch
    git rev-parse HEAD origin/master

Expected at plan creation:

    1147-resolve-active-semantic-packs-and-build-a-generation-scoped-in-memory-matcher
    HEAD = origin/master = b736b00c57f7f4bc88f370e34a696adf663476fa

Focused development commands begin with:

    cargo test --test suite_semantic -- semantic_model_runtime
    cargo test --test suite_semantic -- semantic_model_pack
    cargo test --test suite_persistence -- semantic_pack_catalog
    cargo test --lib complete_value_cache
    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings

If a focused test name changes during implementation, update this section with the exact final command rather than leaving a stale placeholder. Expected success is a zero exit status with the new behavior tests executed, not an `ok. 0 passed` feature-gated result.

Before the actual pre-push all-feature gate, inspect disk and active Cargo processes, then run:

    df -h .
    pgrep -af 'cargo|rustc'
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Do not run an opportunistic all-feature/NLP test suite before that gate. If Python-enabled tests become necessary, invoke them through `uv run --python 3.12` and never enable `extension-module` for test executables.

## Validation and Acceptance

The change is accepted when a test installs or registers several compatible and near-miss packs, constructs one analyzer-generation runtime from exact evidence, and observes all of the following behavior:

- Reordering evidence, catalog source rows, or authoring-map presentation produces the same selected semantic content, explanations, and `active_model_set_hash`.
- Missing or wrong package version, module, toolchain version, target, configuration, artifact digest, ecosystem, or Bifrost compatibility never activates a constrained shard.
- Workspace models outrank installed models, installed models outrank shipped models, exact artifact evidence outranks coordinate-only evidence, review-required packs need an explicit compatible enable, and equal-rank semantic conflicts remain ambiguous.
- Every schema-v1 trigger and declaration lookup uses an exact posting. A same-named rule in another owner/package is not examined or returned.
- Repeated matcher queries work after the catalog is dropped and do not change catalog lookup counters, proving no SQLite or pack-file access on the match path.
- Same-snapshot concurrent construction runs one leader and returns one `Arc`; cancellation, corruption, budget exhaustion, and stale generations publish nothing; a later request can retry.
- A complete fresh build publishes the exact catalog/store active references only after validation. Failed replacement leaves the previous set intact.
- Retained bytes and build work are bounded and observable, and the public result distinguishes a genuine empty compatible set from incomplete or unavailable coverage.
- Existing compiler, producer, catalog, store, snapshot-cache, and semantic-model documentation tests continue to pass.

## Idempotence and Recovery

All activation and matcher builds are read-only until the final coordinated active-set replacement. Repeating a build with identical evidence is safe and returns the same semantic hash. Repeating a successful active-set replacement is idempotent. Catalog installation, corruption quarantine, and GC remain owned by #1146 APIs; this issue does not delete catalog objects directly.

If a leader is cancelled, panics before publication, exceeds a budget, or loses generation freshness, dropping its `CompleteValuePermit` leaves no ready value and wakes followers to retry. If persistent active-set coordination fails, keep the previous workspace active set and return an unavailable outcome. Re-run reconciliation before the next build. Never repair this by publishing an empty matcher or clearing the store.

Tests that create catalogs and workspaces use temporary directories or `InlineTestProject`; no manually named Cargo target directories are allowed. Isolated Cargo targets must use `scripts/with-isolated-cargo-target.sh`, which cleans them on success, failure, or interruption.

## Artifacts and Notes

The issue #1147 dependency chain at plan creation is:

    #1145 schema/compiler: complete
    #1146 catalog/accounting/GC: complete at b736b00c / PR #1395
    #1149 reusable API-pack producers: complete
    #1147 activation/matcher: current issue
    #1148 overlays, #1150 dependency generation, and #1154 distribution: blocked on #1147

Draft follow-up for the MCP responsiveness incident, pending user confirmation required by the issue-writing workflow:

    Title: Bifrost MCP source discovery can exceed request budgets or remain pending indefinitely

    Workspace/revision: /Users/dave/.codex/worktrees/a638/bifrost at b736b00c57f7f4bc88f370e34a696adf663476fa.

    Reproduction 1: run list_files for crates/bifrost-analysis/src/analyzer/semantic_model, get_summaries for semantic_model/store/structural files, and search_symbols for semantic-pack matcher names concurrently on the default plugin. After about 56 seconds, list_files and get_summaries returned request-wide cancellation/budget errors and search_symbols returned a cancelled partial result with zero files.

    Reproduction 2: after narrower warm calls succeeded, request get_symbol_sources for Provenance, Locator, Safety, manifest_compatible, and selector_matches. The request remained pending beyond 90 seconds and had to be terminated. A later four-symbol get_symbol_sources call likewise remained pending beyond 20 seconds until termination.

    Expected: each bounded code-intelligence request completes or returns a timely typed cancellation within the configured request budget. One stuck source read must not remain pending indefinitely.

    Starting points: MCP request deadline/cancellation orchestration and the code-intelligence host path fixed by #1370. Preserve the distinction between cold initialization latency, analyzer-wide concurrent request contention, and an individual request failing to observe its deadline.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/semantic_model/runtime.rs`, define public contracts equivalent to the following. Exact field ownership may use `Box<str>` and boxed slices to reduce retained bytes, but the semantic distinctions must remain.

    pub const SEMANTIC_MODEL_RUNTIME_REPRESENTATION_VERSION: u32 = 1;

    pub struct SemanticModelActivationEvidence {
        pub language: String,
        pub ecosystem: String,
        pub package: Option<CatalogCoordinate>,
        pub module: Option<CatalogCoordinate>,
        pub toolchain: Option<CatalogCoordinate>,
        pub target: Option<String>,
        pub configuration: Option<String>,
        pub artifact_sha256: Option<String>,
    }

    pub enum SemanticModelControlScope {
        User,
        Workspace,
    }

    pub enum SemanticModelControlAction {
        Enable,
        Disable,
    }

    pub struct SemanticModelPackSelector {
        pub pack_id: String,
        pub version: Option<semver::VersionReq>,
        pub manifest_digest: Option<String>,
    }

    pub struct SemanticModelActivationControl {
        pub scope: SemanticModelControlScope,
        pub action: SemanticModelControlAction,
        pub selector: SemanticModelPackSelector,
    }

    pub struct SemanticModelActivationRequest {
        pub bifrost_version: semver::Version,
        pub evidence: Vec<SemanticModelActivationEvidence>,
        pub controls: Vec<SemanticModelActivationControl>,
        pub limits: SemanticModelRuntimeLimits,
    }

    pub enum SemanticModelRuntimeOutcome {
        Ready { active: Arc<ActiveSemanticModelSet>, lifecycle: SemanticModelRuntimeLifecycle },
        Incomplete { usable: Option<Arc<ActiveSemanticModelSet>>, report: SemanticModelActivationReport },
        Cancelled { report: SemanticModelActivationReport },
        Unavailable { report: SemanticModelActivationReport },
    }

    pub struct ActiveSemanticModelSet;

    impl ActiveSemanticModelSet {
        pub fn active_model_set_hash(&self) -> &str;
        pub fn retained_bytes(&self) -> u64;
        pub fn activation_report(&self) -> &SemanticModelActivationReport;
        pub fn types_named(&self, name: &str) -> SemanticModelMatch<'_, TypeFact>;
        pub fn members_named(&self, owner_id: &str, name: &str) -> SemanticModelMatch<'_, MemberFact>;
        pub fn relations_from(&self, stable_id: &str) -> SemanticModelMatch<'_, RelationFact>;
        pub fn relations_to(&self, stable_id: &str) -> SemanticModelMatch<'_, RelationFact>;
        pub fn rules_for(&self, trigger: &RuleTriggerKey<'_>) -> SemanticModelMatch<'_, GeneratorRule>;
    }

Use `SemanticPackCatalog`, `AnalyzerStore`, `IAnalyzer::snapshot_source_generations`, `IAnalyzer::snapshot_generations_match`, `CancellationToken`, `CompleteValueCache`, `sha2`, `semver`, and `crate::hash` collections already present. Add no third-party dependency. Use `assert!` or `debug_assert!` for internal impossible states, propagate contextual fallible operations, and never discard spawned work or errors.

`SemanticModelRuntimeLimits` must bound catalog evaluations, unique candidates, loaded shards, decoded records, index entries, working bytes, retained bytes, and explanation records. Cancellation polling must be based on deterministic work batches, not wall-clock sleeps. Public diagnostics include the complete bounded collections and suppressed counts when limits truncate reporting.

Plan revision note (2026-07-31 10:22Z): Created the initial self-contained plan after live dependency verification and source/history discovery. It separates catalog ownership from semantic runtime identity, requires strict row-based activation evidence, resolves deterministic precedence and conflicts, reuses snapshot-owned complete-value single flight, confines schema-v1 matching to exact indexes, and defines four independently verifiable implementation milestones.

Plan revision note (2026-07-31 13:42Z): Implemented milestones 1-3 and the code/documentation portions of milestone 4. Recorded 9 new runtime tests, 60 passing compatibility tests, two passing strict library Clippy runs, the unrelated all-targets Clippy baseline failures, and the required policy run's unreliable cancellation result. Kept the MCP responsiveness follow-up as a user-confirmed draft rather than filing it automatically.
