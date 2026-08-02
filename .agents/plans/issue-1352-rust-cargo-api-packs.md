# Index exact Rust dependency APIs without executing dependency code

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this change, a host that already possesses a Cargo dependency description and pre-generated Rust API artifacts can ask Bifrost to index the exact public APIs selected for a workspace. Definitions, symbols, signatures, hierarchy, references, and re-exports from registry, git, and external path dependencies will participate in Bifrost's semantic overlay without adding dependency source or Cargo build output to the project's authored files.

The operation is deliberately passive. Bifrost reads only paths explicitly supplied by the host. It does not invoke Cargo or rustdoc, scan a Cargo cache or target directory, download crates, compile dependencies, run build scripts, or load procedural macros. Missing, inconsistent, unsupported, or over-budget evidence produces bounded incomplete-coverage diagnostics rather than an authoritative claim that a symbol does not exist.

The behavior is observable through offline integration fixtures. One fixture supplies Cargo metadata version 1 JSON, a lockfile, an explicit target and feature selection, and rustdoc JSON for dependencies from registry, git, and path sources. Preparing and activating those packs makes their public APIs navigable through stable `bifrost-model://` identities while `Project::all_files()` remains unchanged. Repeating preparation reuses the same immutable packs. Changing one target, feature set, checksum, producer version, or rustdoc artifact invalidates only the affected production.

## Progress

- [x] (2026-08-02 09:31Z) Verified live issue #1352, its closed prerequisites, the clean issue branch, and current remote state.
- [x] (2026-08-02 09:31Z) Diagnosed the shared producer, dependency coordinator, catalog, activation, overlay, Rust Cargo-route, configuration, and semantic-model boundaries.
- [x] (2026-08-02 09:31Z) Received approval for the implementation design and recorded this self-contained ExecPlan.
- [x] (2026-08-02 09:43Z) Milestone 1: pinned `rustdoc-types` format 60, added the passive configuration records and bounded typed Cargo metadata, lockfile, and rustdoc readers, and passed four offline boundary tests.
- [x] (2026-08-02 09:50Z) Milestone 2: validated selected Cargo targets, walked the resolved graph iteratively, matched exact lockfile records, emitted `RustdocJson` dependencies, and passed eight focused discovery/provenance tests.
- [ ] Milestone 3: produce deterministic Rust declaration packs, adding only the shared semantic IR required to describe Rust APIs honestly.
- [ ] Milestone 4: connect exact-byte reuse, activation, overlay navigation, and invalidation.
- [ ] Milestone 5: add end-to-end edge-case coverage, latency/memory measurements, user-facing documentation, and final validation.
- [ ] Milestone 6: complete the five-specialist review, triage findings, rerun validation, and prepare delivery.

## Surprises & Discoveries

- Observation: all generic dependency-pack infrastructure exists, but Rust has no external artifact kind, dependency adapter, or configuration surface.
  Evidence: `ExternalArtifactKind` contains Java, Scala, JDK, and .NET variants; `AnalyzerConfig` exposes JVM and C# configuration only; `DependencyPackAdapter` and the exact-byte preparation coordinator are already ecosystem-neutral.
- Observation: rustdoc JSON is useful but remains an experimental nightly output rather than a stable compiler contract.
  Evidence: the Rust documentation requires `-Z unstable-options --output-format json`. The JSON root carries `format_version`, which increments on breaking schema changes, and the published `rustdoc-types` crate mirrors one exact format.
- Observation: Cargo metadata is stable and versioned, but metadata alone cannot describe resolver-v2 feature relationships separately for every target and dependency kind.
  Evidence: Cargo's unit-graph documentation explicitly states that `cargo metadata` cannot represent those relationships. Therefore exact target and per-package feature selections must be separate supplied evidence, not inferred by Bifrost.
- Observation: the current shared declaration IR already supports modules, functions, constants, signatures, hierarchy, aliases, and artifact locators, but lacks explicit union, static, macro, generic-constraint, and implementation representations.
  Evidence: `TypeKind` has no union variant, `MemberKind` has no static or macro variants, `Signature` contains only string type parameters plus parameters/return, and `RelationKind` contains only navigation/reference edges.
- Observation: RMCP code-intelligence initialization and several broad source requests exceeded their request-wide budgets during diagnosis and planning.
  Evidence: current-tip `BIFROST_MCP_RMCP=on` calls returned `-32603`; the warm-call evidence was added to open issue #1448. Narrow retries and local reads remained usable.
- Observation: exact target validation requires the Cargo metadata package target list, while exact dependency reachability requires named `resolve.nodes[].deps[]` edges rather than the older flat dependency ID list.
  Evidence: the Milestone 2 fixture now rejects a selected name/kind absent from its package and rejects an explicitly bound rustdoc artifact that is not reachable from any selected root target.

## Decision Log

- Decision: Make the ingestion contract a Bifrost-owned evidence bundle, not a command runner.
  Rationale: the issue forbids implicit compilation, downloads, build scripts, and procedural-macro execution. An explicit bundle keeps artifact generation outside the analysis process and makes every semantic input hashable and reproducible.
  Date/Author: 2026-08-02 / Codex
- Decision: Require Cargo metadata format version 1 JSON, `Cargo.lock`, explicit target/configuration and per-package feature selections, and explicit rustdoc JSON bindings.
  Rationale: metadata and the lockfile identify exact packages, sources, checksums, and graph edges, while explicit selection evidence closes the target/feature ambiguity that Cargo metadata cannot represent.
  Date/Author: 2026-08-02 / Codex
- Decision: Pin one exact `rustdoc-types` version and reject every other rustdoc `format_version` as incomplete coverage.
  Rationale: rustdoc JSON is experimental. A versioned producer boundary is honest and deterministic; permissive `serde_json::Value` probing would silently couple correctness to schema drift.
  Date/Author: 2026-08-02 / Codex
- Decision: Reuse `DependencyPackAdapter`, `prepare_discovered_dependency_semantic_packs`, the generated-production catalog, activation runtime, and overlay rather than create a Rust-specific cache or index.
  Rationale: issues #1149, #1150, and #1148 established these neutral contracts specifically so ecosystem adapters do not duplicate lifecycle, integrity, and overlay logic.
  Date/Author: 2026-08-02 / Codex
- Decision: Extend the shared declaration IR only where Rust requires an honest language-neutral concept.
  Rationale: unions, static members, macro declarations, generic constraints, and implementations occur outside Rust too. Encoding them as fake classes, methods, or source strings would corrupt navigation and future consumers.
  Date/Author: 2026-08-02 / Codex
- Decision: Use stable artifact locators derived from package and rustdoc item identity, never local registry, git-checkout, or target paths.
  Rationale: local paths differ across workspaces and must not defeat cache reuse or appear as authored `ProjectFile` ranges. The overlay already maps artifact-only declarations to stable model URIs.
  Date/Author: 2026-08-02 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. `AnalyzerConfig` now has a default-empty Rust dependency API evidence surface, and the analysis crate pins `rustdoc-types 0.60.0` with default features disabled. The prototype reads Cargo metadata, `Cargo.lock`, and rustdoc JSON only through the existing cancellable bounded exact-artifact reader, rejects unsupported Cargo metadata, lockfile, configured rustdoc, and observed rustdoc versions, checks the rustdoc target against the explicit selection, and normalizes feature ordering before later identity work. Four focused tests passed; they construct all files in temporary directories and execute no child process.

Milestone 2 is complete. Public discovery resolves configuration-relative evidence paths, validates selected package/name/kind targets, computes graph reachability with an iterative queue, requires one exact name/version/source lockfile record for every bound artifact, and checks rustdoc crate version against Cargo package version. It emits package/module/toolchain/target/configuration activation evidence plus sorted source kind, exact source, checksum, stable selected-target label, explicit and metadata feature, dependency rename, rustdoc toolchain, and format provenance. Local package paths and metadata package IDs are excluded from production provenance. Eight focused tests pass, including complete public discovery, unreachable-package and missing-lockfile failures, rename/checksum/feature retention, target mismatch, version mismatch boundary, and cancellation.

## Context and Orientation

A semantic-model pack is an immutable typed description of declarations that are not ordinary authored workspace source. `crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines authored facts. `compiler.rs` validates and compiles those facts into deterministic shards. `catalog/` stores compiled objects and maps exact production inputs to verified manifests. `runtime.rs` selects compatible packs once per analyzer generation. `overlay.rs` projects active declarations into normal search, navigation, usage, and hierarchy paths without fabricating `ProjectFile` values.

`crates/bifrost-analysis/src/analyzer/semantic_model/producer.rs` defines `ExternalArtifactPackProducer`, bounded artifact reading, producer diagnostics, and `ExternalArtifactKind`. `dependency.rs` defines the ecosystem-neutral `ResolvedDependency`, exact artifact roles, `DependencyPackAdapter`, bounded discovery/preparation outcomes, exact input hashing, catalog reuse, compilation, installation, and activation evidence. JVM code in `analyzer/jvm/external.rs` and Java/JDK/Scala artifact producers are the closest patterns. C# code in `analyzer/csharp/external.rs` demonstrates project metadata plus binary artifact selection.

`crates/bifrost-analysis/src/analyzer/rust/cargo_routes.rs` resolves authored workspace modules and path dependencies for the existing tree-sitter Rust analyzer. It reads manifests but does not consume Cargo metadata or lockfiles, does not index registry/git dependency APIs, and must not be stretched into an external artifact cache. The new adapter belongs beside it under `analyzer/rust/`, sharing small structured Cargo helpers only when they genuinely apply to both paths.

An evidence bundle means a set of paths and typed selection values supplied through `AnalyzerConfig`. It contains one Cargo metadata format-version-1 JSON document, its corresponding `Cargo.lock`, an explicit target triple and configuration label, explicit selected root targets, per-package enabled feature lists, and explicit rustdoc JSON artifact bindings. An artifact binding identifies the Cargo package ID, crate name, rustdoc path, rustdoc producer/toolchain string, and expected rustdoc format. Bifrost validates cross-file agreement before treating the evidence as complete.

Rustdoc JSON is a typed item graph. Its crate root points into an item index containing public modules, types, functions, constants, statics, aliases, traits, implementations, macros, re-exports, generics, where predicates, spans, and target information. The producer traverses this graph iteratively. It does not parse Rust source text, expand macros, resolve bodies, or run any tool.

## Plan of Work

Milestone 1 adds the evidence contract and proves the unstable-format boundary without changing runtime behavior. Add an exact `rustdoc-types` workspace dependency and expose it only through `brokk-bifrost-analysis`. Extend `AnalyzerConfig` with a default-empty `RustAnalyzerConfig` containing explicit evidence bundles. Define those configuration records next to the other analyzer configuration types. Add `analyzer/rust/dependency_discovery.rs` with bounded readers and typed deserialization for metadata version 1, Cargo lockfile packages, explicit selections, and artifact bindings. Use existing `serde_json` and `toml`; do not write a line-oriented or delimiter-based Cargo parser. Add unit fixtures for a matching bundle, unsupported metadata/rustdoc versions, target mismatch, missing selection, and cancellation. The milestone ends when a bundle produces a deterministic `DependencyDiscoveryOutcome` without reading dependency source or invoking a process.

Milestone 2 turns a valid bundle into exact resolved dependencies. Match every selected metadata package to one lockfile record by normalized name, version, and source, retaining the checksum when present. Validate every graph package and edge used by the selection. Preserve dependency rename from metadata dependency-edge names separately from package/crate identity. Emit normalized provenance for metadata version, lockfile version, source kind and exact source, checksum, target triple, selected target kinds, configuration, enabled feature list, rustdoc producer/toolchain, and rustdoc format. Registry, git, and external path packages are supported only when an explicit rustdoc artifact is bound. Missing or ambiguous evidence emits bounded diagnostics and marks discovery partial. No directory search is permitted. Focused tests prove reordered metadata maps/features produce the same records, distinct same-name versions remain distinct, renamed dependencies keep the package identity, and path changes do not enter semantic identity.

Milestone 3 creates `analyzer/rust/rustdoc_artifact.rs` and `RustdocJsonPackProducer`. Add `ExternalArtifactKind::RustdocJson`. The producer accepts exact bytes retained by the shared coordinator, deserializes the pinned rustdoc root, checks `format_version`, crate version, target, and bound Cargo evidence, then traverses public reachability iteratively. It maps crates/modules, structs, enums, unions, traits, aliases, fields, variants, functions, constants, statics, associated items, inherent methods, trait methods, implementations, generic parameters, where predicates, and re-exports into deterministic authored facts. Declarative and procedural macro names are emitted only when rustdoc exposes them publicly; bodies and expansions are never modeled.

Before forcing Rust into an inadequate shape, extend `semantic_model/model.rs` with the minimal neutral variants and records needed for union types, static and macro members, structured generic constraints, and implementation facts. Thread them through schema generation, validation, canonical compilation, payload inventory, digest calculation, artifact encoding/decoding, catalog tests, and overlay projection. Existing v1 fixtures must either remain valid through defaulted additive fields or receive a deliberate schema-version migration recorded in this plan. Never reinterpret a prior field incompatibly. Implementation facts attach associated members and trait/self-type relations without inventing a concrete owner for blanket implementations. Unsupported rustdoc item shapes remain explicit partial diagnostics.

Milestone 4 implements `RustDependencyPackAdapter` in `analyzer/rust/external.rs`. It recognizes only exact RustdocJson artifacts, calls the retained-byte producer, and returns one authored pack per exact Cargo package/selection. Its adapter and producer versions, rustdoc format, exact artifact bytes, target, configuration, features, source/checksum, and normalized graph evidence participate in the existing production key. Integrate public exports without opening a catalog inside `RustAnalyzer`. Hosts continue to call the existing preparation coordinator and compose its activation evidence explicitly. End-to-end tests prepare, activate, and query one fixture, then repeat to prove reuse and alter one feature/artifact to prove isolated invalidation.

Milestone 5 completes behavior and measurements. Create `tests/suite_semantic/rust_dependency_semantic_pack.rs` and register it in the existing `suite_semantic/main.rs`; do not create a root integration binary. Cover registry, git, and path sources, dependency renames, cfg/feature/target surfaces, proc-macro declarations, blanket implementations, crate/module name collisions, re-exports, unsupported/missing artifacts, deterministic map ordering, and external files staying outside `Project::all_files()`. Exercise definition, symbol, signature/hover, hierarchy, and reference paths through stable model URIs. Add a measurement case under the existing semantic measurement suite that reports input bytes, decoded records, produced facts, phase elapsed time, retained byte estimates, cold generation, and warm reuse. Update `docs/src/content/docs/semantic-model-packs.md` with the passive evidence contract and explicit generation boundary.

Milestone 6 runs the required review and closes findings. Diff against `origin/master`, run the guided security, duplication, senior-development, DevOps, and architecture reviews in parallel, consolidate and fix accepted findings, and rerun focused validation. Use the installed Bifrost policy skill to run `bifrost.code-smells` plus every executable repository policy root in one request. A finding must be reviewed or fixed; an unreliable result is not a passed gate. Keep any mechanically expressible new smell as a possible RQL follow-up without broadening this issue unless the query is reliable and release-ready.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/cb17/bifrost`.

After Milestone 1, run:

    cargo test -p brokk-bifrost-analysis --lib rust::dependency_discovery
    cargo fmt --all -- --check
    git diff --check

Expect all new evidence-boundary tests to pass without executing a child process. Inspect tests to confirm all artifact and metadata paths are fixture-owned.

After Milestone 2, rerun the discovery tests and add:

    cargo test -p brokk-bifrost-analysis --lib semantic_model::dependency

Expect exact package matching, provenance normalization, cancellation, and incomplete diagnostics to pass.

After Milestone 3, run:

    cargo test -p brokk-bifrost-analysis --lib rustdoc_artifact
    cargo test -p brokk-bifrost --test suite_semantic -- semantic_model_pack:: external_artifact_pack::

Expect Rust item projection and all existing pack compiler/decoder fixtures to pass.

After Milestone 4, run:

    cargo test -p brokk-bifrost --test suite_semantic -- rust_dependency_semantic_pack:: dependency_semantic_pack:: semantic_model_runtime:: semantic_model_overlay::

Expect the fixture dependency to become navigable through model URIs, the second preparation to report reuse, and a changed feature/artifact to replace only its own manifest/evidence.

After Milestone 5, run the complete task-scoped gate:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-analysis --lib
    cargo test -p brokk-bifrost --test suite_semantic -- rust_dependency_semantic_pack:: dependency_semantic_pack:: external_artifact_pack:: semantic_model_pack:: semantic_model_runtime:: semantic_model_overlay::
    cargo clippy -p brokk-bifrost-analysis -p brokk-bifrost --all-targets -- -D warnings
    git diff --check

Do not enable `nlp` for these issue-scoped checks. Before any authorized push or comprehensive gate, inspect disk space and use `scripts/with-isolated-cargo-target.sh` for all-feature Clippy as required by repository instructions.

## Validation and Acceptance

The primary acceptance scenario creates a workspace containing a small Rust consumer and an evidence bundle for three external dependencies: registry, git, and path. Their rustdoc fixtures include modules, structs, an enum, a union, a trait, an alias, functions, constants, statics, associated items, a re-export, a feature-gated API, a proc-macro declaration, and an implementation. Preparation must return complete packs for supported shapes, activation must publish stable model symbols, and normal navigation/search/hierarchy/reference queries must find those declarations without adding artifact/source paths to `Project::all_files()`.

Changing JSON object order, local artifact paths, or mtimes while retaining identical normalized evidence and bytes must reuse the same production. Changing target, features, checksum, rustdoc format/producer, or artifact bytes must miss. Changing one package must preserve unrelated manifest digests and overlay records. A missing artifact, mismatched lockfile, unsupported rustdoc format, unresolved blanket implementation, cancelled read, or exceeded budget must make coverage incomplete with an actionable bounded diagnostic and must not publish authoritative empty evidence.

The measurement scenario records cold discovery/production and warm reuse separately. It must report artifact bytes and record/fact counts, elapsed phases, and an explicit retained-memory estimate. No hard performance threshold will be invented until the fixture supplies repeated evidence, but any interactive operation over five seconds requires issue-tracker follow-up under repository policy.

## Idempotence and Recovery

Evidence discovery and artifact production are read-only with respect to the analyzed workspace. Catalog writes use the existing content-addressed atomic installation path, so rerunning preparation safely reuses or reconstructs only incomplete/corrupt productions. Tests use automatically removed temporary directories. No test may depend on a real Cargo home, registry cache, network, compiler, or rustdoc executable.

If a milestone fails, retain its changes, update `Progress` and `Surprises & Discoveries`, and repair forward. Do not reset unrelated work. If the pinned rustdoc type crate cannot decode the intended fixture, stop after the prototype, record the exact format mismatch, and revise the versioned boundary before adding production code. If the shared IR change would require representing Rust source text through parsing or delimiter scanning, stop and redesign the typed fact instead.

## Artifacts and Notes

Initial implementation base:

    branch: 1352-index-rust-dependency-apis-from-exact-cargo-artifacts
    HEAD: ddb435c1
    origin/master...HEAD: 0 0
    BIFROST_MCP_RMCP: on

Relevant landed commits are `c60676f8` for external producers, `c09365ae` for overlays, `4e716f57` for exact dependency production and caching, and `ddb435c1` for JDK/Scala packs.

Official format evidence observed during design: Cargo metadata JSON is stable when `--format-version` is explicit; Cargo metadata alone does not represent resolver feature relationships for every target/dependency kind; rustdoc JSON requires unstable options; rustdoc's root `format_version` increments on breaking changes. These facts justify the explicit selection bundle and pinned decoder.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/config.rs`, add default-empty Rust configuration records equivalent to:

    pub struct RustAnalyzerConfig {
        pub dependency_api_evidence: Vec<RustDependencyApiEvidence>,
    }

    pub struct RustDependencyApiEvidence {
        pub metadata_path: PathBuf,
        pub lockfile_path: PathBuf,
        pub target: String,
        pub configuration: String,
        pub selected_targets: Vec<RustSelectedTarget>,
        pub packages: Vec<RustPackageApiArtifact>,
    }

    pub struct RustPackageApiArtifact {
        pub package_id: String,
        pub crate_name: String,
        pub enabled_features: Vec<String>,
        pub rustdoc_json_path: PathBuf,
        pub rustdoc_toolchain: String,
        pub rustdoc_format_version: u32,
    }

Exact field names may be refined before the first public use, but the information boundary must not weaken. `RustSelectedTarget` records the selected workspace package and Cargo target kind without asking Bifrost to infer which Cargo command the host meant.

In `analyzer/rust/dependency_discovery.rs`, expose a bounded function equivalent to:

    pub fn discover_rust_semantic_pack_dependencies(
        project: &Project,
        config: &RustAnalyzerConfig,
        limits: &DependencyPackLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyDiscoveryOutcome;

In `analyzer/rust/rustdoc_artifact.rs`, define `RustdocJsonPackProducer` implementing `ExternalArtifactPackProducer`, plus a retained-byte entry point used by `RustDependencyPackAdapter` so the shared coordinator does not reread an artifact after hashing it.

In `analyzer/rust/external.rs`, define `RustDependencyPackAdapter` implementing `DependencyPackAdapter`. Its producer identity is versioned independently of Bifrost's crate version and changes whenever projection semantics change.

Add the exact workspace dependency `rustdoc-types = "=0.60.0"` with default features disabled. Use its typed `Crate`, item, type, generic, where-predicate, implementation, macro, visibility, and target records. Do not add a Cargo command wrapper. Parse metadata with typed local serde records for the stable format-version-1 subset and parse the lockfile with typed TOML records using the existing `toml` dependency.

Plan revision note, 2026-08-02 09:31Z: Created the initial decision-complete ExecPlan after live issue/dependency verification, code-intelligence diagnosis, user approval, repository plan review, and official Cargo/rustdoc format research. It fixes the passive evidence boundary, exact selection identity, pinned rustdoc schema, shared-IR obligations, milestones, validation, and recovery strategy.

Plan revision note, 2026-08-02 09:43Z: Recorded Milestone 1 completion after the pinned decoder compiled and four focused passive-ingestion tests passed. The implemented boundary checks the observed rustdoc version before full decode, uses existing bounded exact-artifact reads for all three inputs, and retains typed decoded records for exact package resolution in Milestone 2.

Plan revision note, 2026-08-02 09:50Z: Recorded Milestone 2 completion after eight exact discovery tests passed. The resolver now validates selected targets and graph reachability, binds one exact lockfile entry, retains normalized activation and production provenance, and exposes a public passive discovery API without adding cache walking or a process runner.
