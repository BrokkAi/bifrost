# Generate and reuse semantic packs from exact local dependencies

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost already discovers locally available JVM and .NET dependencies, can convert one exact JAR or assembly into a typed semantic-model pack, and can store and activate immutable packs. Those pieces are not connected. Each analyzer currently parses dependencies into a private in-memory index and discards the produced pack and artifact digest.

After this change, a host that supplies an explicit shared semantic-pack catalog can ask Bifrost to prepare exact local dependency packs. Bifrost will retain the dependency coordinate and build-target evidence, hash only the selected artifact bytes, reuse a compatible generated pack when the same artifact inputs and producer/schema versions have already been seen, or produce, compile, and install a new immutable pack. The result will contain exact activation evidence plus bounded coverage diagnostics. No operation scans an entire package cache, downloads a dependency, or implicitly builds a project.

The behavior is observable with offline fixtures. Two workspaces that resolve the same artifact set through one catalog root reuse one stored production. Changing one dependency produces a new pack only for that dependency and changes only the dependent semantic overlay. Missing, unreadable, unsupported, cancelled, or over-budget dependencies report incomplete coverage and never become authoritative empty semantic results.

## Progress

- [x] (2026-08-01 07:44Z) Verified live issue #1150, its closed prerequisites #1146, #1147, and #1149, the clean prepared branch, and current remote state.
- [x] (2026-08-01 07:44Z) Diagnosed the dependency-discovery, artifact-producer, compiler, catalog, activation-runtime, overlay, and analyzer-invalidation boundaries.
- [x] (2026-08-01 07:44Z) Recorded the approved implementation design in this ExecPlan.
- [x] (2026-08-01 07:56Z) Milestone 1: added exact generated-production identity, transactional catalog registration and verified reuse, schema migration, and concurrency/integrity coverage.
- [x] (2026-08-01 08:19Z) Milestone 2: added the shared exact-byte preparation coordinator, bounded profiles/diagnostics, cooperative file-read cancellation, compilation/installation boundaries, and reuse/invalidation tests.
- [ ] Milestone 3: retain JVM coordinates and deterministically combine source and binary evidence.
- [ ] Milestone 4: retain .NET package, target, configuration, and asset-role provenance.
- [ ] Milestone 5: compose dependency preparation with semantic-model activation and prove targeted invalidation.
- [ ] Milestone 6: complete documentation, focused and broad validation, repository policy checking, and specialist review.

## Surprises & Discoveries

- Observation: All prerequisite mechanisms exist, but no production call path joins them.
  Evidence: `JvmExternalDeclarationIndex::produce_java_type_facts` and `CSharpExternalDeclarationIndex::index_assembly` invoke exact-artifact producers and immediately project the authored facts into private maps. Only policy evaluation currently calls `acquire_active_semantic_models`.
- Observation: Existing dependency resolution erases activation identity before production.
  Evidence: `ResolvedJvmArtifact` contains only binary and optional source paths, while C# `assemblies_from_assets` returns only `PathBuf` values even though its `project.assets.json` input contains package, target, and asset-role information.
- Observation: The catalog stores producer/schema metadata and artifact selectors but has no exact generated-production lookup.
  Evidence: catalog schema version 3 records manifests, sources, selectors, and immutable objects. `catalog_sources` is many-to-many and cannot uniquely answer whether one artifact-input/producer/schema key already owns a compatible manifest.
- Observation: Java source and class packs share declaration IDs but have different locators and semantic digests.
  Evidence: activating both as equal-rank `Generated` packs can create conflicts. The legacy index instead lets source facts win while retaining binary-only types.
- Observation: the prepared branch was current at initial diagnosis but was five commits behind `origin/master` when implementation began.
  Evidence: `git rev-list --left-right --count origin/master...HEAD` returned `5 0` at `1c2f1923`. Repository rules prohibit branch movement without explicit authorization, so implementation continues on the existing branch.
- Observation: concurrent catalog opens exposed a pre-existing staging cleanup race once generated installs exercised four writers at once.
  Evidence: one opener enumerated a temporary file that another writer published before `DirEntry::metadata`, causing `stat staged catalog object` to fail with `NotFound`. Stale cleanup now treats disappearance during metadata/removal as successful concurrent progress, while preserving all other errors.
- Observation: persistence and semantic integration harnesses belong to the workspace root package, not `brokk-bifrost-analysis`.
  Evidence: Cargo rejected `-p brokk-bifrost-analysis --test suite_persistence` and identified the `brokk-bifrost` package; the corrected milestone-1 command passed 30 focused tests.
- Observation: the shell resolves Cargo and Rustc through rustup but resolves `cargo-clippy` from Homebrew, whose same-version compiler has a different build identity.
  Evidence: ordinary and isolated `cargo clippy` failed with E0514 on a freshly compiled `cc` crate. Invoking rustup's matching `/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/cargo-clippy` directly completed the milestone-2 library Clippy gate with `-D warnings`.

## Decision Log

- Decision: Keep the semantic-pack catalog explicitly supplied by the host.
  Rationale: issue #1146 deliberately made catalog-root selection a host responsibility because the analysis library runs under several hosts and must not silently choose a platform-specific global directory.
  Date/Author: 2026-08-01 / Codex
- Decision: Add a catalog production record keyed by canonical artifact inputs, producer identity, and semantic schema version.
  Rationale: manifest and object hashes deduplicate stored bytes but do not answer whether an artifact has already been processed by the current producer semantics. An explicit production key permits a bounded lookup before parsing and compiling.
  Date/Author: 2026-08-01 / Codex
- Decision: Represent one dependency as an ordered artifact set, normally a binary plus an optional source archive.
  Rationale: source and binary bytes jointly affect the produced semantic facts. Binding both kinds and digests into one production identity makes either change invalidate the result and avoids equal-rank runtime conflicts between two packs for the same dependency.
  Date/Author: 2026-08-01 / Codex
- Decision: Resolve Java source/binary precedence before pack compilation.
  Rationale: stable declaration IDs permit a deterministic merge. Source facts supply the preferred locator and authored shape for matching identities; non-conflicting binary-only facts augment them; incompatible equal identities become explicit partial-coverage diagnostics rather than runtime ambiguity.
  Date/Author: 2026-08-01 / Codex
- Decision: Preserve legacy external-index APIs as compatibility projections over the same resolved/produced facts during this issue.
  Rationale: Java, Scala, Kotlin, and C# resolution already depend on those maps. Removing them would broaden #1150 into a consumer migration and risk regressions unrelated to pack generation and reuse.
  Date/Author: 2026-08-01 / Codex
- Decision: Return dependency-pack preparation and coverage as an explicit result that can be composed with the existing activation request.
  Rationale: the coordinator must be useful to policy, MCP, LSP, and other hosts without owning their catalog path, workspace store, controls, or lifecycle. The existing activation runtime remains the only overlay/matcher authority.
  Date/Author: 2026-08-01 / Codex

## Outcomes & Retrospective

Milestones 1 and 2 are complete. The catalog can derive a domain-separated production identity from exact input bytes plus producer/schema semantics, install a compiled pack and production binding in one writer transaction, verify compatible reuse from read-only or writable catalogs, reject key rebinding, and safely quarantine corrupt metadata. Schema v3 migrates without losing existing packs, and garbage collection removes obsolete production bindings through the manifest foreign key.

The shared coordinator now reads only the resolved artifact paths under explicit byte/count limits, checks cancellation between 64 KiB reads and before lookup/production/compile/install, excludes paths and mtimes from the production identity, retains normalized activation evidence, validates adapter producer/schema/language/ecosystem claims, and never reports missing or partial coverage as complete. Five integration tests prove path-independent reuse, exact-byte invalidation, cancellation without publication, missing-artifact diagnostics, and partial-pack reuse; the focused catalog suite still passes 30 tests and the cooperative reader has direct unit coverage. Formatting, diff checks, and task-scoped library Clippy are clean. JVM and .NET adapters remain to be implemented.

## Context and Orientation

A semantic-model pack is a typed description of declarations or generated behavior that is not ordinary workspace source. `crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines the authored representation. `compiler.rs` validates, normalizes, serializes, compresses, and hashes that representation. `catalog/` stores immutable compiled manifests and shard objects in a caller-selected shared root. `runtime.rs` selects compatible shards from exact evidence, builds a generation-local in-memory matcher, and publishes an overlay to the analyzer snapshot.

An exact-artifact producer consumes one bounded local file. `producer.rs` defines `ArtifactProductionRequest`, `ArtifactProduction`, `ArtifactProducerLimits`, and `ExternalArtifactPackProducer`. `jvm/java_artifact.rs` implements Java source/class JAR production. `csharp/external.rs` implements .NET assembly production. Both producers already hash the bytes they read and add the digest to their activation selector.

Dependency discovery remains ecosystem-specific. `jvm/dependency_discovery.rs` reads exact Maven POM dependencies and Gradle lockfiles, with an explicitly enabled offline build-tool mode. `jvm/external.rs` resolves only exact coordinate directories under configured Maven or Gradle roots. `csharp/dependency_discovery.rs` finds bounded `obj/project.assets.json` inputs, and `csharp/external.rs` resolves assemblies only beneath approved package roots or bounded project outputs. These safety boundaries must remain intact.

A generated-production identity is not a manifest digest. It is a domain-separated canonical hash of every semantic input used before a manifest exists: the ordered artifact kinds and byte digests, producer name and version, semantic-model schema version, language/ecosystem adapter version, and normalized coordinate/target/configuration evidence. It must exclude paths and mtimes so two workspaces with identical bytes reuse the same production. The catalog binds that key to one verified manifest and validates the binding on every lookup.

Coverage is complete only when every selected dependency artifact was read, produced, compiled, and installed without an omission diagnostic. Partial dependency coverage is still useful, but it must remain explicitly partial. Cancellation, corruption, missing files, unsupported metadata, or work limits never publish an empty result as authoritative absence.

## Plan of Work

Milestone 1 adds catalog production identity. Create migration `crates/bifrost-analysis/migrations/semantic-pack-catalog/0004-generated-productions.sql`, advance the catalog schema in `catalog/db.rs`, and add typed production-key and lookup/registration APIs in `catalog/mod.rs`. The table will bind a 64-character lowercase production digest to one verified manifest with the producer/schema fields needed for integrity checks. Registration happens in the same writer transaction as the source binding or through a transactionally checked follow-up that cannot expose a production record for an unverified manifest. Lookup verifies the referenced manifest and returns a safe miss on absent or quarantined data. Add migration, idempotent reuse, changed-producer/schema, corruption, read-only, concurrent registration, and GC tests in `tests/suite_persistence/semantic_pack_catalog.rs`.

Milestone 2 adds `crates/bifrost-analysis/src/analyzer/semantic_model/dependency.rs` and exports it from `semantic_model/mod.rs`. Define common resolved-dependency, artifact-input, coordinate, coverage-diagnostic, profile, limits, and preparation-outcome types. Define a small object-safe ecosystem adapter whose instance captures ecosystem-specific configuration and discovers bounded resolved dependencies, identifies producer semantics, and produces one authored pack for a resolved artifact set. Implement the shared coordinator: validate and canonicalize the resolved record, read and hash exact artifacts with cancellation checks, derive the production key, look up the catalog, produce and compile on a miss, install/register atomically, and emit exact `SemanticModelActivationEvidence`. Check cancellation before every external command, artifact, archive-entry batch, compile/install boundary, and activation publication. Only complete successful values may be reused as complete; partial results retain bounded diagnostics and are not misreported as absence.

Milestone 3 adapts the JVM path. Change `DiscoveredJvmDependencies` and `ResolvedJvmArtifact` so an artifact keeps its exact Maven coordinate and origin through Maven repository, Gradle cache, offline Maven/Gradle report, and explicit-path resolution. Implement a JVM dependency-pack adapter beside the existing discovery/external code. For a class JAR with a source JAR, hash both and produce one authored declaration pack by merging stable type/member/relation IDs: source facts win equivalent identities and locators; binary-only facts augment; unequal same-ID facts report a bounded conflict and keep deterministic source precedence. Reuse the merged result to build the legacy index, preserving Java package-private behavior and Scala/Kotlin source-JAR behavior. Keep cache walking limited to the exact coordinate directory and keep build tools explicitly offline.

Milestone 4 adapts .NET. Replace path-only `assemblies_from_assets` output with a bounded resolved assembly record that retains package name/version, target framework, configuration or asset role, exact path, and project-reference provenance. Canonically prefer reference/compile assets over runtime duplicates for the same semantic assembly, while keeping distinct target frameworks/configurations separate activation evidence. Explicit assembly paths use honest path-derived provenance without inventing package coordinates. Implement the .NET adapter using `CSharpAssemblyPackProducer`, and build the legacy external index from the same produced facts. Preserve approved-root, canonical-path, file-count, table-row, heap, signature-depth, and output-count limits.

Milestone 5 composes preparation with `SemanticModelActivationRequest` and `acquire_active_semantic_models` through a small explicit helper or returned evidence API. Do not open catalogs in analyzer constructors. Tests will prepare the same dependency set in two workspace analyzers sharing one temporary catalog and prove the second preparation is a reuse. Change one artifact and prove only its production key, selected manifest, active-model-set hash, and dependent overlay change while unrelated pack objects and evidence remain stable. Prove cancelled or partial preparation cannot replace a previously complete workspace active set with an authoritative empty one.

Milestone 6 documents the host contract and lifecycle in `docs/src/content/docs/semantic-model-packs.md` and `.agents/docs/semantic-artifact-lifecycle-matrix.md`. Run focused tests after each milestone, format Rust, run strict task-scoped featureless Clippy, run `git diff --check`, and execute the repository's combined `bifrost.code-smells` plus explicit repository policy roots through one MCP `run_policy` request. Then run the guided workflow's five specialist reviews in parallel, fix every accepted critical/high finding and selected lower-severity findings, update this plan, and complete the final relevant validation. NLP is not enabled because this change does not touch semantic search.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/29b8/bifrost` on branch `1150-generate-and-cache-semantic-packs-from-exact-locally-available-dependencies`. Do not create or switch branches, rebase, push, or open a pull request without an explicit request. Because this is an ExecPlan, checkpoint each completed milestone with a multiline commit that stages only that milestone's files.

After milestone 1 run:

    cargo test -p brokk-bifrost --test suite_persistence -- semantic_pack_catalog::
    cargo fmt --all -- --check
    git diff --check

After milestone 2 run:

    cargo test -p brokk-bifrost-analysis --lib semantic_model::dependency
    cargo test -p brokk-bifrost --test suite_semantic -- dependency_semantic_pack::
    cargo fmt --all -- --check
    git diff --check

After milestones 3 and 4 run:

    cargo test -p brokk-bifrost-analysis --lib dependency_discovery
    cargo test -p brokk-bifrost --test suite_semantic -- external_artifact_pack::
    cargo test -p brokk-bifrost --test suite_semantic -- dependency_semantic_pack::
    cargo fmt --all -- --check
    git diff --check

After milestone 5 run:

    cargo test -p brokk-bifrost --test suite_semantic -- semantic_model_runtime::
    cargo test -p brokk-bifrost --test suite_semantic -- semantic_model_overlay::
    cargo test -p brokk-bifrost --test suite_semantic -- dependency_semantic_pack::

For final task-scoped validation run:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-analysis --lib
    cargo test -p brokk-bifrost --test suite_persistence -- semantic_pack_catalog::
    cargo test -p brokk-bifrost --test suite_semantic -- dependency_semantic_pack:: external_artifact_pack:: semantic_model_runtime:: semantic_model_overlay::
    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings
    git diff --check

If command filters accepted by Cargo differ from the examples, inspect the harness names and run separate exact filters rather than weakening the tested scope. Do not enable `nlp` unless later changes actually touch semantic search or a separately authorized comprehensive gate is performed.

## Validation and Acceptance

An offline Maven fixture with exact `group:artifact:version`, a class JAR, and an optional source JAR must produce one catalog production whose activation evidence contains the coordinate and exact production artifact digest. Running the same preparation from a second workspace against the same catalog must report reuse and leave object/accounting counts unchanged.

An offline Gradle fixture may enumerate only direct children beneath the exact locked coordinate's hash directories. Unrelated coordinates and arbitrary cache entries must not be read or activated. Offline build-tool mode must remain opt-in and pass the existing offline/no-daemon arguments.

A `.NET project.assets.json` fixture must retain exact package/version and target evidence for restored reference or compile assemblies, prefer those over equivalent runtime assets, and never accept a path outside approved package or workspace roots. Explicit assembly paths must work without fabricated package identity.

Changing one artifact byte sequence must create a new production key and manifest for that dependency, preserve unrelated catalog objects, and change the active model set only for an activation request containing the changed digest. Changing only a path or mtime while keeping bytes and normalized evidence identical must reuse the existing production.

Changing the producer version, adapter semantics version, or semantic-model schema version must miss the old production even when artifact bytes are identical. Corrupt or quarantined catalog content must be a safe miss and may be regenerated only through the writable catalog path.

Source and binary JARs that describe the same declarations must produce one conflict-free active pack. Source locators win equivalent declarations; binary-only generated members remain navigable. An incompatible same-ID fact produces a bounded partial diagnostic rather than silently replacing either fact.

Cancellation before installation must leave no generated-production row or workspace activation change. Cancellation after another process has installed the same verified production may return a reuse only if the lookup and integrity checks completed before cancellation publication. Missing, unreadable, malformed, unsupported, oversized, or truncated inputs must remain actionable incomplete coverage and must not claim an unknown symbol is definitely absent.

Dependency files must remain outside `Project::all_files()`, workspace declarations, and ordinary source persistence. Runtime matching after activation performs no SQLite lookup per AST node or call.

## Idempotence and Recovery

All discovery and production operations are read-only with respect to the analyzed workspace. Catalog installation is content-addressed and atomic; rerunning preparation either reuses a verified production or safely retries an incomplete installation. Temporary build-tool reports and generated fixtures use automatically removed temporary directories.

Migration 4 must be additive and safe to rerun through the existing schema-version mechanism. A read-only version-3 catalog must report the existing explicit schema mismatch instead of mutating. If a test or implementation attempt fails before a milestone commit, retain the working tree for diagnosis and repair it forward; do not reset unrelated user work.

If catalog registration observes a competing production for the same key, validate that both bindings refer to the same verified manifest. Equivalent bindings succeed idempotently. A different manifest for the same production key is an integrity error and is never resolved by last-write-wins.

## Artifacts and Notes

Initial implementation base:

    branch: 1150-generate-and-cache-semantic-packs-from-exact-locally-available-dependencies
    HEAD: 1c2f19235ba553cacef427556663deec713be37d
    origin/master...HEAD at implementation start: 5 0
    BIFROST_MCP_RMCP: on

During diagnosis, a cold parallel Bifrost tool batch took 35.004 seconds and cancelled before observing useful workspace results. The same calls were fast after warmup. Current-tip rmcp evidence was added to open issue #1423; do not widen #1150 to fix code-intelligence initialization latency.

## Interfaces and Dependencies

In `semantic_model/catalog/mod.rs`, add public types equivalent to:

    pub struct GeneratedProductionKey {
        pub digest: String,
        pub producer_name: String,
        pub producer_version: String,
        pub schema_version: u32,
    }

    pub struct GeneratedProduction {
        pub key: GeneratedProductionKey,
        pub manifest_digest: String,
    }

    impl SemanticPackCatalog {
        pub fn generated_production(
            &self,
            key: &GeneratedProductionKey,
        ) -> Result<Option<GeneratedProduction>, CatalogError>;

        pub fn install_generated(
            &self,
            key: &GeneratedProductionKey,
            pack: &CompiledSemanticModelPack,
            source_id: &str,
        ) -> Result<GeneratedProduction, CatalogError>;
    }

The exact shape may collapse redundant fields into a validated opaque key, but lookup must verify the producer/schema fields rather than trusting only the digest string.

In `semantic_model/dependency.rs`, add types equivalent to:

    pub struct DependencyArtifactInput {
        pub kind: ExternalArtifactKind,
        pub path: PathBuf,
    }

    pub struct ResolvedDependency {
        pub language: String,
        pub ecosystem: String,
        pub package: Option<CatalogCoordinate>,
        pub module: Option<CatalogCoordinate>,
        pub toolchain: Option<CatalogCoordinate>,
        pub target: Option<String>,
        pub configuration: Option<String>,
        pub artifacts: Vec<DependencyArtifactInput>,
        pub provenance: Provenance,
    }

    pub trait DependencyPackEcosystem {
        fn adapter_id(&self) -> &str;
        fn adapter_version(&self) -> &str;
        fn discover(
            &self,
            cancellation: &CancellationToken,
            limits: DependencyPackLimits,
        ) -> DependencyDiscoveryOutcome;
        fn produce(
            &self,
            dependency: &ResolvedDependency,
            cancellation: &CancellationToken,
            limits: DependencyPackLimits,
        ) -> ArtifactProduction;
    }

    pub fn prepare_dependency_packs(
        catalog: &SemanticPackCatalog,
        adapters: &[&dyn DependencyPackEcosystem],
        cancellation: &CancellationToken,
        limits: DependencyPackLimits,
    ) -> DependencyPackPreparationOutcome;

The final API may accept a `Project` and ecosystem configuration through adapter constructors rather than the trait call. Keep it object-safe, keep catalog authority explicit, and do not add mode flags that combine materially different JVM and .NET behavior.

Use existing `serde`, `serde_json`, `semver`, `sha2`, `rusqlite`, `zip`, `tempfile`, project/process helpers, and `CancellationToken`. Do not add a package-manager client, network dependency, compiler driver, platform-directory resolver, regex parser, or another compression/hash implementation.

Plan revision note, 2026-08-01 07:44Z: Created the initial decision-complete ExecPlan after live issue/dependency verification, code-intelligence diagnosis, independent specialist diagnosis, user approval, and review of `.agents/PLANS.md`. It fixes the explicit catalog boundary, production identity, source/binary merge, compatibility projection, coverage, cancellation, and milestone validation strategy.
