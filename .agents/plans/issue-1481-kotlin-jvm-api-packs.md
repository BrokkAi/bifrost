# Index exact Kotlin/JVM dependency and standard-library APIs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintain this document in accordance with `.agents/PLANS.md`. A contributor should be able to resume the work from this file and the repository alone.

## Purpose / Big Picture

After this change, a Kotlin/JVM workspace can turn exact local Maven or Gradle dependency artifacts into deterministic semantic API packs. Kotlin callers can navigate to classes, constructors, methods, properties, objects and companions, top-level declarations, and extensions using Kotlin source identities instead of compiler-generated `FooKt` facade names. Exact supported `kotlin-stdlib` evidence activates a version-matched standard-library pack; absent or unknown version evidence never selects the newest pack by guesswork.

The feature is passive and offline. Bifrost reads only artifacts already selected by the existing JVM dependency discovery modes, does not execute Gradle, Maven, Kotlin, annotation processors, plugins, or dependency code, and does not add dependency files to the workspace project. Production-path tests demonstrate pack production, activation, Kotlin definition navigation, structured signatures and overload identity, hierarchy, extensions, precedence, deterministic payloads, and safe partial outcomes. Shared overlay tests continue to own generic hover, symbol-search, and reference rendering behavior.

## Progress

- [x] (2026-08-03 06:15Z) Verified issue #1481, the clean issue branch, `origin/master`, the existing Java/Scala producers, JVM discovery and adapter, semantic overlay, Kotlin declaration extraction, and Kotlin definition lookup.
- [x] (2026-08-03 06:15Z) Recorded the implementation as this self-contained ExecPlan.
- [x] (2026-08-03 06:52Z) Implemented a bounded Kotlin source-JAR producer with source-level types, members, signatures, extension surfaces, and hierarchy facts; its focused tests pass 2/2.
- [x] (2026-08-03 06:52Z) Classified Kotlin source, binary-metadata, and exact `kotlin-stdlib` artifacts through the shared JVM adapter; source-backed production and honest binary-only unavailability tests pass 2/2.
- [x] (2026-08-03 09:01Z) Routed Kotlin types, constructors, callables, values, direct instance members, companions, imports, and top-level declarations through the active overlay while retaining workspace-first outcomes.
- [x] (2026-08-03 09:01Z) Added a production-path fixture, pinned Kotlin 2.2.20 standard-library release specification and notice, release workflow input, regeneration documentation, and measured real-artifact generation/activation/lookups.
- [x] (2026-08-03 11:42Z) Completed adversarial correctness, security, architecture, and test reviews; repaired fail-open archive classification, overload loss, extension identity collisions, false type qualification, modeled ancestry/extensions/return chaining, signature-depth and locator bounds, and record-limit work.
- [x] (2026-08-03 14:10Z) Completed final focused reruns, formatting, exact release generation/verification, policy review, and clean architecture/security/test specialist reviews. Strict task-scoped clippy was attempted repeatedly after targeted Cargo cleanup but is blocked by the local Homebrew toolchain's reproducible E0514 incompatibility between `clippy-driver` and freshly rebuilt `cc` metadata.

## Surprises & Discoveries

- Observation: Kotlin source parsing already publishes source-level `CodeUnit` identities and `SignatureMetadata` for constructors, properties, extension receivers, callable arity, return types, companions, type aliases, and supertypes.
  Evidence: `crates/bifrost-analysis/src/analyzer/kotlin/declarations.rs` documents that no `FooKt` or `$` encodings enter identities and exposes all of those facts through `ParsedFile`.

- Observation: semantic-model navigation already turns a resolver's exact unresolved reference text into an external model definition, including overload sets.
  Evidence: `render_definition_lookup` in `crates/bifrost-analysis/src/searchtools/navigation.rs` consults `SemanticModelOverlay::symbols_named` when ordinary definition candidates are empty.

- Observation: the current exact JVM dependency path labels every non-Scala dependency as Java, even when a paired source JAR contains Kotlin.
  Evidence: `resolved_semantic_pack_dependency` selects only `ScalaSourceJar` or `JavaSourceJar`, and `JvmDependencyPackAdapter::produce` dispatches only Scala, Java, and JDK artifact kinds.

- Observation: the existing `jclassfile` dependency exposes runtime annotation descriptors structurally, so binary Kotlin classification can recognize `kotlin.Metadata` without scanning constant-pool text or guessing facade names.
  Evidence: `jar_contains_kotlin_metadata` parses bounded class entries and checks only `RuntimeVisibleAnnotations` and `RuntimeInvisibleAnnotations` annotation type descriptors.

- Observation: Kotlin 2.2.20's official source archive contains eight source entries using syntax the currently pinned Kotlin grammar does not accept, while the remaining source surface produces 7,377 declaration records including `kotlin.collections.List` and 15 `kotlin.collections.map` overloads.
  Evidence: exact release-bundle generation and verification succeeded with `completeness=partial`; `.agents/docs/issue-1481-kotlin-pack-measurement-2026-08-03.md` records the bounded diagnostic count and measurements.

- Observation: `ParsedFile` groups Kotlin overloads under one `CodeUnit`, with declaration ranges and signature metadata retaining the individual declarations.
  Evidence: the initial producer selected only the first range; the reviewed producer now emits each range/signature and its tests prove parameter and receiver-only overloads remain distinct.

- Observation: exact activation intentionally includes the artifact digest, so byte-distinct ZIP encodings of identical logical sources must not have identical compiled manifests.
  Evidence: reordered archives now prove equal normalized authored payloads while their exact digests remain distinct activation evidence.

- Observation: the installed Homebrew `cargo clippy` cannot consume even a freshly rebuilt `cc` build dependency despite both sides reporting rustc 1.96.0 with the same commit hash.
  Evidence: normal and isolated task-scoped clippy runs, including a retry after `cargo clean -p brokk-bifrost-analysis -p cc`, all fail at `build.rs` with E0514 before linting Bifrost code; ordinary check/tests and release builds pass with the same toolchain.

## Decision Log

- Decision: Reuse Kotlin's existing tree-sitter declaration extractor as the source of declaration identity and AST location, and add structured AST projection helpers only where the shared `ParsedFile` does not retain enough typed information.
  Rationale: This keeps workspace and dependency identities compatible and avoids a second Kotlin mini-parser or source-text fallback.
  Date/Author: 2026-08-03 / Codex

- Decision: Keep all Kotlin packs in the existing JVM dependency adapter, compiler, catalog, overlay, and shared realm rather than creating a Kotlin-only index or runtime.
  Rationale: Java, Scala, and Kotlin share exact artifact discovery and activation but retain language-specific resolution and precedence.
  Date/Author: 2026-08-03 / Codex

- Decision: Treat an unreadable or unsupported Kotlin binary metadata version as partial or inactive unless a compatible source JAR supplies the API; never infer Kotlin declarations from JVM facade naming conventions.
  Rationale: A Java classfile view cannot honestly reconstruct Kotlin top-level declarations, extensions, properties, nullability, or source identities.
  Date/Author: 2026-08-03 / Codex

- Decision: Implement source-JAR production and runtime navigation before adding the published standard-library asset.
  Rationale: A production-path exact dependency fixture proves the producer and consumer contracts before release metadata makes them externally selectable.
  Date/Author: 2026-08-03 / Codex

- Decision: Resolve unqualified structured types only against explicit imports and the archive-wide declaration inventory using Kotlin's same-package, star-import, and shared JVM default-import order; preserve unresolved spellings instead of inventing a package.
  Rationale: Exact packs must never turn incomplete dependency context into a false fully-qualified identity.
  Date/Author: 2026-08-03 / Codex

## Outcomes & Retrospective

The implementation and specialist review repairs are complete. Exact Kotlin source archives produce authored declaration packs through the shared JVM adapter; binary-only Kotlin artifacts are identified structurally but deliberately wait for a compatible prebuilt pack. Kotlin navigation consumes activated facts without synthesizing workspace files, including modeled inheritance, constrained and generic extensions, workspace-subclass bridges, and chained modeled return types. The release tool reproducibly generated and verified the pinned Kotlin 2.2.20 standard-library pack with 7,377 declaration records. Focused regressions, format, release verification, and the required policy selection pass; the only incomplete validation is clippy, which is blocked before linting by the recorded local E0514 toolchain incompatibility.

## Context and Orientation

The repository is a Rust workspace. `crates/bifrost-analysis/src/analyzer/jvm/external.rs` discovers exact JVM artifacts selected by configuration or existing Maven/Gradle metadata, converts them to `ResolvedDependency` records, and dispatches `JvmDependencyPackAdapter`. The same file also contains `JvmExternalDeclarationIndex`, the older shared classpath index currently used for external type existence.

An authored semantic API pack is a deterministic set of `TypeFact`, `MemberFact`, and hierarchy/relation facts. `crates/bifrost-analysis/src/analyzer/semantic_model/producer.rs` defines artifact kinds and bounded producer contracts. `dependency.rs` prepares exact artifacts and compiles packs. `overlay.rs` projects activated facts into `SemanticModelSymbol`s without adding dependency files to `Project::all_files`. `searchtools/navigation.rs`, `sources.rs`, structural search, and usage search consume the overlay.

`crates/bifrost-analysis/src/analyzer/jvm/java_artifact.rs` is the class/source JAR precedent. `scala_artifact.rs` is the closest source-semantic precedent: it parses a complete source archive, emits public/protected types and members, preserves source locators and hierarchy, sorts facts deterministically, observes cancellation, and diagnoses bounded partial output. `jdk_artifact.rs` and `tests/suite_semantic/jvm_standard_library_pack.rs` show standard-library generation and activation.

`crates/bifrost-analysis/src/analyzer/kotlin/declarations.rs` parses workspace Kotlin with the vendored pinned grammar. It emits source-level declarations, signatures, parameter arity, written return types, extension receiver types, companion metadata, type aliases, and raw supertypes. `kotlin/types.rs` implements Kotlin's import/default-import/type precedence and currently returns external types only from `JvmExternalDeclarationIndex`. `usages/get_definition/kotlin.rs` resolves callable and member references to workspace `CodeUnit`s. The semantic overlay cannot be fabricated as a workspace `CodeUnit`; instead the resolver must preserve an exact qualified model identity in `DefinitionLookupOutcome.reference.text`, allowing the existing navigation renderer to return the model location.

Kotlin compiler metadata is the structured declaration payload stored in the `kotlin.Metadata` annotation on JVM classfiles. Binary support must decode a bounded supported metadata schema or report partial coverage. Reading Java method names or guessing a `FileKt` facade is not Kotlin metadata support.

## Plan of Work

Milestone 1 adds a Kotlin source archive producer. Add `KotlinSourceJar` to `ExternalArtifactKind`, add `crates/bifrost-analysis/src/analyzer/jvm/kotlin_artifact.rs`, export its producer from `jvm/mod.rs` and the crate facade, and dispatch it from `JvmDependencyPackAdapter`. The producer opens one exact ZIP through the shared bounded artifact loader, parses `.kt` entries with the pinned Kotlin grammar, and uses `parse_kotlin_file` plus AST nodes to project externally visible declarations. It emits classes, interfaces, objects, companions, enums, annotations, type aliases, constructors, methods, properties, top-level functions and properties, extensions, overload signatures, generic parameters, parameter names and optionality, written return types and nullability, and hierarchy. `internal` and `private` declarations do not enter consumer packs; effective visibility includes enclosing declarations. Locators use the source entry and Kotlin source-level FQN. Facts and diagnostics are sorted before completion. Unit tests cover representative APIs, near misses, archive order/path determinism, limits, malformed files, and cancellation.

Milestone 2 makes exact discovery Kotlin-aware. Inspect only already resolved source and binary artifacts. A source archive containing `.kt` declarations is `KotlinSourceJar`; exact `org.jetbrains.kotlin:kotlin-stdlib*` coordinates carry Kotlin language/toolchain and target evidence with their exact version. Other artifacts with Kotlin source use Kotlin language evidence without changing the shared JVM coordinate identity. Binary artifacts remain available to the Java producer for honest Java-facing declarations; Kotlin-facing completeness is partial unless a bounded structured Kotlin metadata decoder produces compatible Kotlin facts. If a suitable maintained Rust decoder is unavailable, implement only the minimum owned decoder backed by the official Kotlin metadata schema and pin supported metadata versions; do not scan string pools or infer facades. Merge equivalent source and binary Kotlin identities, prefer source locators, retain conflicts as ambiguity, and record coordinate, version, digest, metadata version, target, configuration, producer, pack hash, completeness, and activation provenance.

Milestone 3 connects Kotlin resolution to activated facts. Add Kotlin-specific overlay lookup helpers around `SemanticModelOverlay` rather than converting external declarations to `CodeUnit`. Extend Kotlin's type-existence predicate with unique visible Kotlin overlay types after authored workspace and shared-realm source declarations. Extend bare callable/property lookup, receiver members, companion/object members, supertypes, top-level imports, and extension selection to consider unique visible Kotlin overlay symbols using existing Kotlin ordering and arity/receiver metadata. When the winning candidate is modeled, return a no-workspace-target outcome whose reference text is the exact model qualified name; the navigation renderer then produces the model definition. Preserve authored workspace/generated-output precedence, return ambiguity for conflicting overlay identities, and do not let Java/Scala candidates change Kotlin precedence.

Milestone 4 proves lifecycle and published stdlib behavior. Add `tests/suite_semantic/kotlin_dependency_semantic_pack.rs` and register it in the existing semantic suite harness. Runtime-created exact Maven evidence and source fixtures cover a class and constructor, property, companion member, top-level function, extension function, overload identity, hierarchy, modeled return chaining, definition navigation, and workspace precedence. Focused producer/discovery tests cover malformed archives, deterministic archive order, cancellation, limits, binary-only unavailability, and exact evidence. Confirm the existing JVM/Kotlin suites remain green. Add a pinned `kotlin-stdlib` JSON specification and license notice under `semantic-packs/jvm/`, teach `brokk-bifrost-semantic-packs` release generation to use the Kotlin producer, update the JVM README and release workflow inputs, and record cold/warm production, activation, retained bytes, declaration count, and representative lookup timings in `.agents/docs/issue-1481-kotlin-pack-measurement-2026-08-03.md` linked to #1155.

Milestone 5 validates and reviews. Run focused producer, discovery, resolver, integration, and existing JVM/Kotlin regression tests; run `cargo fmt --all -- --check` and `git diff --check`; then run featureless strict clippy through `scripts/with-isolated-cargo-target.sh`. Do not enable `nlp` for task-scoped validation. Run the guided specialist review and fix confirmed findings. Finally use the installed Bifrost policy tools in one request selecting `bifrost.code-smells` plus every executable repository policy root explicitly named by repository instructions. A `finding` requires review or repair and `unreliable` is not green.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/51a5/bifrost` on branch `1481-kotlin-index-exact-kotlinjvm-dependency-and-standard-library-api-packs`. Before and after every milestone run:

    git status --short --branch
    cargo fmt --all -- --check
    git diff --check

Use focused commands as implementation reveals final test names:

    cargo test -p brokk-bifrost-analysis analyzer::jvm::kotlin_artifact --lib
    cargo test -p brokk-bifrost-analysis analyzer::jvm::external --lib
    cargo test -p brokk-bifrost-analysis analyzer::kotlin --lib
    cargo test --test suite_analyzers kotlin
    cargo test --test suite_semantic kotlin_dependency_semantic_pack
    cargo test --test suite_semantic jvm_standard_library_pack

For final task-scoped linting use the auto-cleaning helper:

    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings

Commit each independently passing milestone on the current branch with a multiline message explaining the user-visible result and design rationale. Stage only files changed by that milestone; never use `git add -A`. Do not push or open a pull request without an explicit user request.

## Validation and Acceptance

Given exact local Kotlin dependency evidence, preparation produces a complete or explicitly partial pack without network access or process execution. Two archives with identical logical files in different ZIP order and at different filesystem paths produce the same normalized authored facts; their compiled activation remains digest-sensitive by design. Changing the coordinate, version, artifact digest, metadata version, target, or configuration changes activation or yields an actionable incomplete result instead of reusing a stale pack.

From a workspace Kotlin file, definition navigation for representative declaration kinds returns a dependency source/model location whose identity contains the Kotlin package declaration and never `FooKt`. Structured model facts retain declared parameter names, overloads, generics, nullability, return types, and extension receivers for shared consumers. Hierarchy and chained receiver lookup use the same external identities. An authored workspace declaration wins a collision. Dependency archives and logical entries never appear in `Project::all_files`.

An exact supported `org.jetbrains.kotlin:kotlin-stdlib` version activates representative collection types and extensions. Unknown, unsupported, stale, malformed, absent, or corrupt evidence yields an empty, partial, incompatible, ambiguous, or unreliable outcome as appropriate, never newest-version selection or facade guessing. Existing Java dependency and Scala standard-library behavior remains unchanged.

The feature is complete only after focused tests, format, strict task-scoped clippy, specialist review, and the required policy selection have trustworthy passing results. Update `Progress`, `Surprises & Discoveries`, `Decision Log`, `Outcomes & Retrospective`, and this command transcript as evidence is produced.

## Idempotence and Recovery

Discovery and production are read-only. Tests create temporary archives with the existing inline/temp harness and drop them automatically. Producers read archives without extraction, so interruption leaves no partial dependency tree. Content-addressed compilation and catalog installation are safe to retry.

If source production fails, retain a minimized `.kt` fixture and AST shape and fix the shared structured extractor or a shared AST helper. Do not replace missing AST support with regex, string splitting, or delimiter scanning. If binary metadata support is blocked by unsupported versions, emit a bounded diagnostic and keep the pack partial; do not fall back to `FooKt` or Java getter guessing. If a standard-library artifact cannot be reproduced exactly, do not update its pinned specification.

Use `scripts/with-isolated-cargo-target.sh` for isolated builds. Do not create manually named cargo targets in `/tmp`, and do not remove unrelated targets or user files. Before each commit inspect `git diff --name-only` and stage only the milestone's files.

## Artifacts and Notes

Initial branch state:

    fbad832bf Add exact Ruby gem semantic API packs (#1482)
    branch and origin issue branch both at origin/master
    worktree clean
    BIFROST_MCP_RMCP=on

Initial reusable seams:

    resolve_jvm_semantic_pack_dependencies -> exact JVM evidence
    JvmDependencyPackAdapter -> Java/Scala/JDK producer dispatch and source/binary merge
    parse_kotlin_file -> source-level Kotlin declarations and signatures
    SemanticModelOverlay -> activated external types, members, relations, provenance
    render_definition_lookup -> exact unresolved FQN to modeled definition

Append concise passing-test counts, policy status, review results, measurements, and changed-file inventories here after each milestone. Do not paste large logs.

Milestone 1 and 2 focused evidence:

    cargo test -p brokk-bifrost-analysis analyzer::jvm::kotlin_artifact --lib
    2 passed; 0 failed

    cargo test -p brokk-bifrost-analysis kotlin_library_ --lib
    2 passed; 0 failed

Changed inventory: `kotlin_artifact.rs`, JVM producer dispatch and classification, semantic artifact-kind plumbing, and this ExecPlan.

Milestone 3 and 4 focused evidence:

    cargo test --test suite_semantic kotlin_dependency_semantic_pack::exact_kotlin_source_dependency_navigates_by_kotlin_identity
    1 passed; 0 failed

    cargo test --test suite_symbols kotlin_
    49 passed; 0 failed

    cargo test --test suite_analyzers kotlin_
    72 passed; 0 failed

    cargo test -p brokk-bifrost-semantic-packs --features release-tooling release_bundle --lib
    2 passed; 0 failed

    target/debug/bifrost-semantic-pack generate <temp> semantic-packs/jvm/kotlin-stdlib-2.2.20.json /private/tmp/kotlin-stdlib-2.2.20-sources.jar
    target/debug/bifrost-semantic-pack verify <temp>
    generated and verified 1 pinned semantic pack; 7,377 records; explicitly partial with 8 bounded parser diagnostics

Final review and validation evidence:

    cargo test -p brokk-bifrost-analysis kotlin_artifact --lib
    4 passed; 0 failed

    cargo test -p brokk-bifrost-analysis analyzer::jvm::external::tests --lib
    29 passed; 0 failed

    cargo test --test suite_semantic kotlin_dependency_semantic_pack
    1 passed; 0 failed

    cargo test --test suite_symbols kotlin_
    49 passed; 0 failed

    cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- generate <temp> semantic-packs/jvm/kotlin-stdlib-2.2.20.json /private/tmp/kotlin-stdlib-2.2.20-sources.jar
    cargo run --locked --release --features release-tooling -p brokk-bifrost-semantic-packs --bin bifrost-semantic-pack -- verify <temp>
    generated and verified 1 pinned semantic pack

    bifrost run_policy: bifrost.code-smells
    complete finding report; changed-file sort-in-loop matches reviewed as intentional normalization, no unreliable result

    final architecture review: clean, no actionable P1/P2
    final security/resource review: clean, no actionable P1/P2
    final test review: focused tests pass, no remaining P1

    cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings
    blocked before linting by E0514 on freshly rebuilt cc metadata (local Homebrew toolchain)

## Interfaces and Dependencies

Define and export in `crates/bifrost-analysis/src/analyzer/jvm/kotlin_artifact.rs`:

    #[derive(Debug, Clone, Copy, Default)]
    pub struct KotlinSourceJarPackProducer;

It must implement `ExternalArtifactPackProducer` and mirror the loaded-artifact entry point used by Java, Scala, and JDK producers:

    pub(crate) fn produce_loaded_artifact(
        &self,
        request: &ArtifactProductionRequest,
        limits: &ArtifactProducerLimits,
        cancellation: Option<&CancellationToken>,
        artifact: &ExactArtifact,
    ) -> ArtifactProduction;

Add `ExternalArtifactKind::KotlinSourceJar`. If binary metadata is implemented, add a distinct `KotlinClassJar` only if dispatch, cache keys, and completeness genuinely differ from `JavaClassJar`; otherwise keep one exact binary artifact and select Kotlin decoding from evidence rather than multiplying artifact vocabulary.

Kotlin overlay helpers must consume `SemanticModelOverlay`, `SemanticModelSymbol`, `SemanticModelOverlayDisposition`, and structured `Signature`/`ReceiverFact` directly. They must not synthesize workspace `ProjectFile` or `CodeUnit` values for dependency declarations. Existing `DependencyPackAdapter`, `compile_pack`, `SemanticPackCatalog`, activation matcher, and overlay types remain the only runtime pipeline.

Revision note (2026-08-03): Initial plan created after live issue, repository, Java/Scala precedent, Kotlin parser, and overlay inspection. It resolves the source-versus-binary honesty boundary and sequences runtime proof before published stdlib metadata.
