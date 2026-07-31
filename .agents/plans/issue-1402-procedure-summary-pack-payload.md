# Add activation-neutral procedure-summary pack payloads

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agents/PLANS.md` from the repository root. It implements GitHub issue #1402, a native child of #813 that cross-references #823, #1144, and #1147.

## Purpose / Big Picture

After this change, a semantic-model pack author can describe external procedure behavior in reviewed YAML or JSON and compile it into the same deterministic, content-addressed artifact format already used for declaration facts and generator rules. The result can be defensively decoded, installed, selected, verified, accounted for, quarantined, and garbage-collected without activating any summary in an analyzer. A focused integration test demonstrates that equivalent YAML and JSON produce byte-identical procedure-summary artifacts and that a verified catalog load returns the same typed records.

This is deliberately an activation-neutral transport slice. A later #1147 change will bind the artifact-relative targets and stable location names in the compiled records to exact generation-scoped `SemanticLocator`, `SummaryLocationKey`, compatibility, dependency, and provenance values before constructing `SemanticProcedureSummary` and `ExternalSemanticSummarySet` instances. This change must not call `ValueFlowPlan::with_external_summaries`, change solver behavior, or add per-call SQLite queries.

## Progress

- [x] (2026-07-31T11:40Z) Fetched `origin`, confirmed the worktree is clean and detached at `origin/master` commit `e9c823af2c229e0277306d03a90ecc30213ce6b5`, and rechecked #813, #823, #1144, #1146, #1147, and overlapping pull requests live.
- [x] (2026-07-31T11:41Z) Created issue #1402, assigned and labeled it, and attached it as a native child of #813 with #823/#1144/#1147 cross-references.
- [x] (2026-07-31T11:44Z) Inspected the semantic-pack compiler, validator, artifact decoder, catalog persistence, reusable-summary contract, fixtures, docs, and the active local #1147 worktree.
- [x] (2026-07-31T13:12Z) Added separate authored and compiled procedure-summary DTOs, deterministic lowering, derived model identity/content hash/contract metadata, and defensive metadata verification without runtime-only identities.
- [x] (2026-07-31T13:28Z) Added validation, normalization, generated schema, JSON/YAML fixtures, strict tagged-variant parsing, metadata-tamper coverage, and artifact round-trip tests while retaining exact declaration and generator goldens.
- [x] (2026-07-31T13:34Z) Added catalog schema version 3, a data-preserving payload-kind migration, and verified install/select/load/accounting coverage without summary-specific tables or queries.
- [x] (2026-07-31T13:36Z) Updated the public semantic-model documentation with the typed procedure vocabulary, completeness semantics, derived metadata, and activation-neutral boundary.
- [x] (2026-07-31T15:04Z) Passed 23 focused semantic-pack tests, 24 catalog tests, documentation coverage, artifact tamper/inventory tests, formatting, and five-specialist review after fixing every accepted finding.
- [x] (2026-07-31T15:23Z) Passed isolated `cargo clippy --all-targets --all-features -- -D warnings` after pinning Cargo and rustdoc to the same Homebrew toolchain; the combined repository policy gate was run twice and remained `unreliable` because broad built-in queries exhausted discovery budgets, with findings reviewed as pre-existing or intentional per-record normalization.
- [x] (2026-07-31T15:31Z) Updated issue #1402 with the delivered boundary and #1147 follow-up; after explicit user authorization, attached the worktree to `dave/issue-1402-procedure-summaries` for publication.
- [x] (2026-07-31T15:39Z) Committed the issue-scoped files and rebased onto `origin/master` at `bb708002`, which included the newly merged generation-scoped semantic-model runtime.
- [x] (2026-07-31T15:44Z) Reconciled catalog initialization and documentation conflicts, assigned procedure summaries a distinct active-set hash discriminator without adding matcher postings, and passed post-rebase procedure, runtime, migration, concurrent-installer, formatting, and diff checks.
- [x] (2026-07-31T15:37Z) Pushed `dave/issue-1402-procedure-summaries` and opened ready pull request #1410.
- [x] (2026-07-31T16:06Z) Fixed the Windows Rust CI documentation assertion, rebased onto `origin/master` at `6e6cf22c`, and passed the exact failing test, formatting, and diff checks. The required `bifrost.code-smells` run remained `unreliable` (exit 2); its broad pre-existing findings do not touch the documentation-only correction.
- [x] (2026-07-31T16:09Z) Committed and pushed the CI correction on the synced branch; every refreshed PR check, including the Windows Rust lane and final PR verification, passed.
- [x] (2026-07-31T16:48Z) Fetched again after CI, rebased cleanly onto the then-current `origin/master` at `07a7ba49`, and prepared the final synchronized head for publication.

## Surprises & Discoveries

- Observation: The task worktree has no attached branch even though the delivery instructions say to remain on the current branch and later push a pull request from it.
  Evidence: `git status --short --branch` reported `## HEAD (no branch)`, and `git show -s --format='%H%n%D' HEAD` reported `e9c823af...` with `HEAD, origin/master, origin/HEAD`. The user subsequently authorized creating `dave/issue-1402-procedure-summaries`, rebasing it onto current `origin/master`, and publishing a ready pull request.

- Observation: #1147 has no open GitHub pull request, but a sibling local worktree is actively implementing it and already edits two likely overlap files.
  Evidence: `/Users/dave/.codex/worktrees/a638/bifrost` was on `1147-resolve-active-semantic-packs-and-build-a-generation-scoped-in-memory-matcher`, one commit ahead with unstaged edits including `semantic_model/artifact.rs` and `semantic_model/catalog/mod.rs`. During publication, the corresponding runtime landed on `origin/master` as #1405. The rebase kept #1402 free of value-flow activation: procedure shards receive a distinct deterministic active-set discriminator but contribute no declaration or generator matcher postings.

- Observation: Bifrost code-intelligence latency remains inconsistent on the self-repository.
  Evidence: one concurrent search/summary/relevance batch returned only cancellations after 42.441 seconds, while subsequent narrow symbol and source calls completed in 0.02-0.45 seconds. A two-target symbol-qualified usage scan returned only time-budget failures after 14.597 seconds. Both current-plugin reproductions were added to #1228.

- Observation: `CompiledPayload` currently serializes the authored payload directly, so merely adding a new authored variant would not satisfy the requirement for an explicit compiled DTO.
  Evidence: `artifact.rs` defines `pub struct CompiledPayload(pub(crate) AuthoredPayload)`. The implementation must introduce a compiled representation whose declaration and generator JSON remains byte-for-byte identical to the current transparent representation.

- Observation: Catalog persistence is generic at the row and object levels, but its shard table constrains payload kinds to the two pre-existing strings.
  Evidence: `catalog_pack_shards.payload_kind` has a SQLite `CHECK` constraint. Schema version 3 therefore rebuilds only that table and its dependent selector/routing tables, preserving rows while widening the accepted kind set. It adds no procedure-specific table or query.

- Observation: Internally tagged serde unit variants can accept extra object fields despite enum-level `deny_unknown_fields`.
  Evidence: The unknown-field matrix initially accepted an extra field on `receiver`. Representing no-data ports as empty struct variants retains identical JSON while making strict rejection effective for every tagged variant.

- Observation: `origin/master` advanced during implementation and now includes the catalog concurrent-initialization repair at `5ba0471a`.
  Evidence: The task remains detached at `e9c823af`, while live `origin/master` is `dc3335c4`. The current WAL-mode retry behavior was carried into the edited v3 catalog file without rebasing or switching so this slice does not reintroduce the observed transient lock failure.

- Observation: The repository policy pack cannot currently provide a reliable completion gate on this workspace.
  Evidence: Two identical `bifrost.code-smells` runs dated 2026-07-31 returned `status: unreliable`; broad nested-loop/file-read/parsing/serialization/sort policies exhausted discovery budgets. Reported findings are existing code and fixtures outside this issue, except canonical per-shard/per-record sorts in `semantic_model/compiler.rs`, which are required distinct-input normalization rather than loop-invariant repeated work.

## Decision Log

- Decision: Keep `SEMANTIC_MODEL_SCHEMA_VERSION` at 1 and add the procedure-summary payload as a backward-compatible tagged variant.
  Rationale: The schema already rejects unknown variants and future versions. Adding a new payload kind does not reinterpret existing fields. Existing golden manifest and shard bytes will prove the legacy semantic and content hashes are unchanged.
  Date/Author: 2026-07-31 / Codex

- Decision: Define authored summary targets as a canonical artifact-relative path plus a stable procedure symbol, and define all intra-payload references through stable record, event, and location IDs.
  Rationale: These values are portable and sufficient for #1147 to bind against exact mounted artifacts. Workspace mounts, dense handles, temporary roots, runtime dependency fingerprints, behavior keys, and context keys stay outside authored and compiled records.
  Date/Author: 2026-07-31 / Codex

- Decision: Use the existing summary vocabulary exactly: receiver and parameter inputs; normal return, receiver, capture, heap, and exceptional exits; allocation, call, escape, unknown-call, unknown-boundary, and ambiguous-call effects.
  Rationale: The transport contract should name what `SummaryPort`, `SummaryExit`, and `SummaryEffectKey` already mean. It must not invent a second flow algebra. Calls name other procedure records instead of serializing `SummaryDependencyKey`.
  Date/Author: 2026-07-31 / Codex

- Decision: Treat pack completeness as an upper bound on record completeness and do not let authored transfers or effects claim proof status.
  Rationale: Pack provenance and the later binding/compiler boundary determine runtime `SummaryEvidence` and `SummaryOrigin`. Authored data may declare `partial` for an individual record but may not declare a record `complete` inside a partial pack or claim `proven` evidence that the compiler cannot establish.
  Date/Author: 2026-07-31 / Codex

- Decision: Keep catalog persistence generic.
  Rationale: #1146 already stores manifest-bound opaque shard bytes and payload-kind metadata. #1402 needs the new kind to serialize to `procedure_summaries`, a narrow schema migration for the existing kind constraint, and tests proving generic install/load/account/GC behavior; no procedure tables or per-call queries are needed.
  Date/Author: 2026-07-31 / Codex

## Outcomes & Retrospective

The implementation is complete and activation-neutral. Authored and independently typed compiled procedure records cover stable targets, typed ports/exits/locations, transfers, all existing effect forms, compiler-derived model identity/contract/content metadata, explicit completeness, and pack-envelope provenance. Canonical compilation preserves the existing declaration and generator golden bytes. Defensive decoding verifies local semantics, derived metadata, typed cross-shard call closure, and domain-separated cross-shard target uniqueness.

Catalog schema v3 widens only the generic payload-kind constraint through a forward data-preserving migration. Procedure artifacts install, select, verify-load, preserve exact CAS bytes, and account without activation. No summary-specific SQL, runtime matcher, workspace handle, solver hook, policy syntax, or `ValueFlowPlan` integration was added.

Validation passed: 23 focused semantic-pack tests, 24 catalog tests (with the pre-existing 500 ms lease test also passing alone after one parallel-load expiry), documentation checks, artifact tamper/inventory regressions, `cargo fmt --all -- --check`, and isolated all-target/all-feature Clippy with warnings denied. Five specialist reviews are clean after all findings were fixed. The only failed gate is the repository policy service itself: two identical combined runs returned canonical `unreliable` reports because broad queries exhausted discovery budgets; their findings were reviewed and are not introduced defects.

Ready pull request #1410 is open from `dave/issue-1402-procedure-summaries`. Its first CI run exposed a documentation-contract regression from the prior conflict resolution: a tested lifecycle phrase was wrapped across lines. The branch restores the public lifecycle phrase as contiguous text, the exact failing test passes locally, and every refreshed GitHub check passed. A final clean rebase synchronized the branch with `origin/master` at `07a7ba49`; that new head requires the same refreshed checks before merge. The generation-scoped semantic-model runtime is present, but a later value-flow integration must still bind procedure records into reusable runtime summaries.

## Context and Orientation

`crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` is the strict YAML/JSON authoring model. `AuthoredPayload` is a tagged enum with `declaration_facts` and `generator_rules`; every object rejects unknown fields. `validate.rs` applies semantic and finite-size checks and emits deterministically sorted diagnostics. `compiler.rs` validates, normalizes semantic sets, constructs compiled shards, computes canonical bytes and three digest roles, and optionally deflates storage bytes. `artifact.rs` owns the compiled manifest/shard DTOs, defensive decoding, digest verification, and inventory/routing metadata. `catalog/mod.rs` persists and verifies generic compiled pack artifacts without interpreting payload records.

`crates/bifrost-analysis/src/analyzer/dataflow/reusable_summary.rs` owns runtime reusable-summary semantics. A `SummaryPort` can be a receiver, parameter ordinal, normal return, exceptional return, capture location, or heap location. A `SummaryTransfer` maps a non-return input port to a typed normal or exceptional exit with evidence. `SummaryEffectKey` represents allocation, exact call, escape, unknown call, an unknown-call boundary without a representable input, or an ambiguous call. `SemanticProcedureSummary` additionally carries exact mounted semantic artifacts, declaration locators, versioned behavior/context/dependency identities, runtime provenance, recursive topology, and completeness. Those runtime identities are intentionally not wire DTOs.

The authored payload introduced here uses `AuthoredProcedureSummary`, `AuthoredProcedureTarget`, `AuthoredSummaryInput`, `AuthoredSummaryOutput`, `AuthoredSummaryTransfer`, `AuthoredSummaryEffect`, and declared `AuthoredSummaryLocation` records. The compiled payload uses corresponding `CompiledProcedureSummary` types with a non-zero summary contract version derived by the compiler. Stable location and event IDs remain readable canonical strings; #1147 later hashes and binds them into runtime keys. A call effect names one record ID and an ambiguous call names a non-empty bounded set of record IDs, so compilation can reject missing or duplicate references without constructing runtime dependency keys.

`tests/suite_semantic/semantic_model_pack.rs` is the behavior-focused compiler and artifact suite. Checked fixtures live under `tests/fixtures/semantic-model-packs/`, and exact legacy artifacts pin declaration and generator output. `tests/suite_persistence/semantic_pack_catalog.rs` is the existing persistence suite; #1402 adds coverage there rather than creating a new root integration binary. `docs/src/content/docs/semantic-model-packs.md` is public documentation whose YAML examples are checked by `tests/suite_semantic/semantic_model_docs.rs`. `schemas/semantic-model-pack-v1.schema.json` is generated from the Rust authoring model and must exactly match `authoring_json_schema()`.

## Plan of Work

First, extend `model.rs` with the authored DTOs. A procedure-summary payload contains a non-empty vector of records. Each record has a globally stable ID, an artifact-relative target (`path` plus `symbol`), a record completeness value, declared capture/heap locations, transfers, and effects. Inputs accept only receiver or parameter variants. Outputs accept normal return, receiver, capture, heap, or exceptional return. Location references carry a kind so a capture cannot silently bind as heap. Effects mirror the existing runtime effect variants and use stable event IDs plus record references for exact or ambiguous calls.

Second, replace the transparent authored wrapper in `artifact.rs` with an explicit compiled payload representation. Conversion in `compiler.rs` copies declaration and generator payloads into structurally identical compiled variants and lowers authored procedure records into compiled DTOs with `contract_version` set to the current reusable-summary contract. This conversion must not construct a workspace mount, semantic artifact key, declaration locator, procedure handle, compatibility key, internal digest key, or runtime summary. Accessors expose the new typed compiled records for later #1147 work.

Third, extend `validate.rs` and `compiler::normalize`. Validation checks every string through existing stable-ID, text, or canonical locator-path helpers; caps record internals in addition to the existing shard/pack byte and record caps; validates parameter ordinals and non-empty transfer/effect collections; rejects return ports as inputs and incompatible normal/exceptional outputs; requires every capture/heap reference to name a declared location of the same kind; rejects duplicate artifact-relative targets even when record IDs differ; requires call record references to exist; rejects empty or duplicate ambiguous candidates; and enforces that a record cannot be complete when the pack is partial. Normalization sorts records, declared locations, transfers, effects, and ambiguous candidates by their semantic serialized form while preserving only genuinely ordered values such as parameter ordinals.

Fourth, extend artifact routing and inventory. `PayloadKind` gains `ProcedureSummaries`; compiled and decoded payload accessors return the typed records. Procedure shards derive a bounded routing key for the payload kind but do not expose per-procedure SQL selectors. The manifest descriptor records the procedure record count and inventories summary IDs plus exact/ambiguous callee references so manifest validation can enforce cross-shard closure. Defensive decode re-runs local validation, verifies compiled metadata, descriptor kind/count/inventory, and rejects noncanonical or corrupt shards through the existing path.

Fifth, add JSON and YAML procedure fixtures and focused tests. The canonical fixture includes receiver/parameter transfers to return, receiver, heap, and exceptional outputs; declared capture and heap locations; allocation, call, escape, unknown-call, unknown-boundary, and ambiguous-call effects; and partial completeness. Tests prove YAML/JSON equality, record-order neutrality, no temporary root leakage, explicit compiled contract fields, round-trip decode, unknown-field rejection, duplicate targets, invalid ordinals and ports, incompatible effects, missing locations and callees, malformed provenance at the envelope, oversized values/collections, partial-versus-complete rejection, corruption, and existing golden stability.

Sixth, extend the catalog kind string, migrate the existing constrained shard-kind column, and add persistence tests. Compile the new fixture, install it through `SemanticPackCatalog`, select it with the existing activation selector, verified-load it, assert `PayloadKind::ProcedureSummaries` and exact decoded records, verify accounting, and exercise a data-preserving version-two migration. Shard bytes remain opaque and no procedure-specific persistence is added.

Finally, update the public semantic-model documentation and schema, run validation, review the diff with the guided-issue specialist reviewers, and update this plan with outcomes. Only after the code is complete and the detached-HEAD contradiction is resolved may files be staged explicitly, committed, pushed, and proposed as a ready pull request.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/a2d6/bifrost`.

Inspect and implement the DTO and compiler changes, updating this plan after each milestone. Generate the JSON schema using the repository's existing schema-generation test or a focused helper discovered in the tree; do not hand-maintain divergent schema content. Add the checked fixtures under `tests/fixtures/semantic-model-packs/` and register only tests in the existing `suite_semantic` and `suite_persistence` harness modules.

Run focused compiler and documentation coverage:

    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic semantic_model_pack
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic semantic_model_docs

Run focused catalog coverage:

    scripts/with-isolated-cargo-target.sh cargo test --test suite_persistence semantic_pack_catalog

Then run formatting and the requested all-feature lint gate, checking free disk before the all-feature build and ensuring no sibling NLP build is active:

    cargo fmt --all -- --check
    df -h .
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Before completion, use the installed Bifrost policy tool once against the built-in `bifrost.code-smells` pack and every executable repository policy root named by the repository, with `evaluation_date` set to `2026-07-31` and `fail_on` set to `warning`. Treat `finding` as review work and `unreliable` as failed validation, fix accepted findings, and rerun the same selection.

## Validation and Acceptance

The semantic-model pack suite must pass with tests that demonstrate identical YAML/JSON canonical bytes and hashes for the procedure fixture, unchanged checked legacy artifacts, deterministic order normalization, strict invalid input rejection, and manifest-bound round-trip decoding. The schema equality test must pass with the checked version-one schema.

The persistence suite must pass with a new behavior-focused test that installs a procedure-summary pack, selects it through the existing indexed selector path, loads and decodes it through manifest verification, observes the procedure payload kind and records, and confirms the generic catalog path retains its existing corruption/quarantine and garbage-collection behavior.

No production code may reference `ValueFlowPlan::with_external_summaries` from the semantic-model compiler, artifact, or catalog modules. No new SQL table or query may encode procedure-summary semantics. A source search over the new fixture and compiled raw bytes must find no `/Users/`, `/tmp/`, `/private/tmp/`, workspace mount ID, procedure handle, dense ID, context key, behavior key, or dependency fingerprint.

All focused tests, formatting, all-feature Clippy, and the combined repository policy check must complete successfully. Specialist review must find no unresolved critical or high issues, and accepted medium/low findings must be fixed or explicitly recorded with rationale.

## Idempotence and Recovery

Compilation, schema generation, formatting, and tests are repeatable. Isolated Cargo targets are removed by `scripts/with-isolated-cargo-target.sh` on success, failure, or interruption. Do not set `BIFROST_KEEP_TARGET=1` unless a retained artifact is deliberately needed and documented here.

The catalog tests use temporary directories and do not modify a developer catalog. Fixture generation must write only the explicit checked fixture files. If a golden artifact changes unexpectedly, stop and compare the semantic and content views before accepting it; declaration and generator golden bytes are compatibility guards, not files to refresh mechanically.

The active #1147 sibling worktree is read-only from this task. Do not edit, reset, clean, rebase, or commit it. If integrating its changes becomes necessary, stop and coordinate instead of copying its unstaged work. Publication from this worktree is authorized only on `dave/issue-1402-procedure-summaries`.

## Artifacts and Notes

Issue #1402: `https://github.com/BrokkAi/bifrost/issues/1402`

Repository baseline:

    HEAD e9c823af2c229e0277306d03a90ecc30213ce6b5
    origin/master e9c823af2c229e0277306d03a90ecc30213ce6b5
    worktree state: detached, clean

Current runtime vocabulary:

    SummaryPort = Receiver | Parameter(u32) | NormalReturn | ExceptionalReturn | Capture(key) | Heap(key)
    SummaryEffectKey = Allocation | Call | Escape | UnknownCall | UnknownCallBoundary | AmbiguousCall

The transport DTO must preserve these meanings while postponing runtime key construction to #1147.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/semantic_model/model.rs`, add the authored procedure types and a `ProcedureSummaries { summaries: Vec<AuthoredProcedureSummary> }` payload variant. Every enum must use explicit serde tagging and `deny_unknown_fields`; every public authored type must derive `JsonSchema`.

In `crates/bifrost-analysis/src/analyzer/semantic_model/artifact.rs`, define an explicit serializable compiled payload with declaration, generator, and procedure variants whose first two serialized shapes are identical to the current `AuthoredPayload` shapes. Add public read-only accessors for the typed compiled procedure records and `PayloadKind::ProcedureSummaries`.

In `crates/bifrost-analysis/src/analyzer/semantic_model/compiler.rs`, add a deterministic lowering from `AuthoredPayload` to `CompiledPayload`. The procedure lowering derives the non-zero summary contract version from `SUMMARY_SCHEMA_VERSION` or an intentionally exported semantic-model bridge constant; it does not accept the contract version from source.

In `crates/bifrost-analysis/src/analyzer/semantic_model/validate.rs`, validate all procedure records with the existing diagnostic model and `ValidationLimits`. Add finite constants only where existing pack byte/record/text/depth limits do not bound nested transfers, effects, locations, and ambiguous candidates tightly enough.

In `crates/bifrost-analysis/src/analyzer/semantic_model/catalog/mod.rs` and the catalog migrations, extend `payload_kind_name` and the existing constrained shard-kind column no more than is necessary for the generic catalog to persist and report the new kind.

The only new dependencies are types already present in this crate plus existing `serde`, `schemars`, hashing, compression, SQLite, and test dependencies. No new crate dependency, procedure-specific persistence, runtime matcher, solver hook, or policy surface is required.

Plan revision note (2026-07-31): Initial plan written after live issue creation, repository/code diagnosis, #1147 overlap inspection, and current Bifrost latency reporting. It records the activation-neutral boundary and explicit authored-versus-compiled DTO decision before implementation.

Plan revision note (2026-07-31): Updated after implementation and the first focused semantic-pack pass. Recorded the required generic catalog migration and strict empty-variant serde representation discovered by tests.

Plan revision note (2026-07-31): Updated during specialist review after adding explicit exit kinds, portable Windows-prefix rejection, engine-aligned model/effect-reference bounds, cached canonical sort keys, and manifest inventory for procedure call closure.

Plan revision note (2026-07-31): Updated after five-specialist review, focused validation, two unreliable repository policy runs, and live remote drift. Recorded typed inventory namespaces, cross-shard target digests, immutable migration history, packaged testdata, and the current publishing blocker.
