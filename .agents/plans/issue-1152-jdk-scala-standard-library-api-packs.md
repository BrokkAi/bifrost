# Generate versioned JDK and Scala standard-library API packs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost can already turn an exact Java source or class JAR into a typed semantic-model pack, cache packs produced from local dependencies, activate compatible shards, and expose activated declarations through code-navigation tools. It cannot yet generate and publish versioned packs for the JDK or Scala standard library. Scala source JARs are parsed today, but the private external index keeps only public type names and discards members, signatures, hierarchy, generic metadata, and extension receivers.

After this change, a release operator can give Bifrost pinned JDK and Scala source artifacts and obtain deterministic, content-addressed API packs whose large payloads remain outside Git. A workspace with exact toolchain evidence can activate only compatible core shards and navigate common library types, members, and explicit hierarchy without copying library sources into the workspace. Unknown or incompatible toolchains remain inactive with an explanation.

The first release is intentionally semantic rather than compiler-emulating. Packs preserve source-declared APIs and explicit hierarchy. Java's implicit `Object` parent and the unambiguous Scala universal roots are resolved lazily through the overlay's existing constant-time indexes instead of storing a redundant root edge for every type or retaining a second cache. Scala case-class-generated `copy`, component accessors, and companion construction are owned by issue #1153 and are not invented by this source-pack producer.

## Progress

- [x] (2026-08-01 18:05Z) Verified issue #1152, its closed prerequisites, the current issue branch, and `origin/master`; rebased the clean branch onto `origin/master` at `218f4cf5` with explicit user authorization.
- [x] (2026-08-01 18:20Z) Diagnosed the existing Java producer, Scala source-JAR projection, semantic pack runtime, optional distribution crate, and release workflow boundaries.
- [x] (2026-08-01 18:40Z) Recorded the approved source-exact and lazy-universal-root design in this ExecPlan.
- [x] (2026-08-01 20:15Z) Milestone 1: implemented deterministic Scala source-archive API production and replaced the lossy private Scala projection with the shared structured facts; focused producer and legacy-index tests pass.
- [x] (2026-08-01 21:25Z) Milestone 2: implemented deterministic module-aware JDK source archive production with explicit flat/module-prefixed layouts and independent `java.base` activation; focused JDK and Java producer tests pass.
- [x] (2026-08-01 23:30Z) Milestone 3: integrated compact lazy universal-root lookup, module-export filtering, source-precise Java array/varargs signatures, and real Scala/JDK pack compilation; focused tests and strict Clippy pass.
- [ ] Milestone 4: complete end-to-end member/source navigation, deterministic bytes, mismatch explanations, and bounded retained-memory measurements; activation and hierarchy navigation coverage is in place.
- [ ] Milestone 5: add pinned release inputs, content-addressed release bundles, licenses/notices, measurements, and release workflow integration.
- [ ] Milestone 6: complete focused validation, repository policy checks, guided specialist review, and accepted fixes.

## Surprises & Discoveries

- Observation: Bifrost already uses the full Scala tree-sitter declaration pipeline while reading Scala entries from source JARs.
  Evidence: `scala_source_types` in `crates/bifrost-analysis/src/analyzer/jvm/external.rs` calls `parse_scala_file`, whose `ParsedFile` records types, constructors, methods, fields, signatures, signature metadata, supertypes, traits, and extension receivers. The projection then filters to classes and constructs type-only `JvmExternalType` records.

- Observation: the current Scala visibility helper is too narrow for this issue.
  Evidence: `scala_declaration_is_public` returns false for both `private` and `protected`, while #1152 requires public and protected API declarations.

- Observation: activated declaration packs already support generic navigation, sources, hierarchy relations, and usage lookup without language-specific copies in each analyzer.
  Evidence: `SemanticModelOverlay` indexes symbols by ID, name, URI, and owner and indexes relations in both directions; `searchtools/navigation.rs`, `searchtools/sources.rs`, and `searchtools/scan_usages.rs` consume that overlay.

- Observation: compiler-generated case-class surfaces have a separate owner.
  Evidence: issue #1153 explicitly owns `copy`, component accessors, companion construction, and their definition/usage relationships. Adding those heuristically to a source API pack would duplicate that behavior model and blur provenance.

- Observation: the first broad RMCP symbol search in this task crossed the interactive budget.
  Evidence: with `BIFROST_MCP_RMCP=on`, `search_symbols` failed after 5.015 seconds because the workspace snapshot was not ready; the identical warm retry returned complete results in 305 ms. Open issue #1423 already owns cold initialization and batching failures of this shape.

- Observation: the reusable Scala source facts did not previously retain constructor parameter type paths or arity.
  Evidence: archive production initially had declarations for primary constructors but no structured parameter signatures. Extending `scala_source_facts_from_tree` to collect the same AST-derived parameter paths used for methods made constructor signatures available without parsing source text.

- Observation: artifact identity and semantic determinism are separate contracts.
  Evidence: rebuilding logically identical ZIPs with different central-directory order changes the exact input SHA-256 activation evidence by design. The determinism test therefore copies identical artifact bytes to a second path and proves path independence; logical-order determinism remains covered by sorting emitted entries and facts before compilation.

- Observation: ordinary dependency-JAR extraction bounds are not suitable JDK source bounds.
  Evidence: the Java producer's 10,000-entry and 128 MiB extracted-source limits could reject or truncate a full JDK `src.zip`. The JDK producer now has separate bounded limits of 100,000 entries, 1 GiB extracted source, and a 128 MiB central directory while the exact compressed artifact remains governed by caller-provided producer limits.

- Observation: full JDK generation does not need to retain every uncompressed source file at once.
  Evidence: the producer records bounded archive indices and declared type names in its first pass, then rereads and fully parses one source entry at a time. This retains only exact ZIP bytes, compact entry metadata, known names, and produced declarations rather than duplicating the archive as a large `Vec<String>`.

- Observation: public Java visibility is insufficient to identify the JDK's supported API surface.
  Evidence: the Temurin 21.0.8 source archive contains public declarations in internal packages. Parsing `module-info.java` export directives structurally and retaining only unqualified exports reduced output to 44 externally useful module shards and `java.base` to 1,392 types and 14,002 members.

- Observation: real source archives exposed stable-identity collisions hidden by tiny fixtures.
  Evidence: Scala companions share source-level names with their classes, legal backticked names may contain spaces, and unresolved complex signatures still need overload arity. Java varargs, trailing dimensions, and multidimensional arrays were losing AST-carried shape. The producer and shared identity now preserve these distinctions; both pinned real archives compile successfully.

- Observation: Scala 2.13.16 declares its universal roots in source.
  Evidence: the pinned source JAR produced `scala.Any`, `AnyRef`, `AnyVal`, `Predef`, and collection APIs without synthetic declarations. The complete compiled pack contains 1,200 merged source-level type surfaces and 6,929 members, with 830,127 stored bytes and 4,380,375 raw bytes.

- Observation: a full JDK source pack is usable but honestly partial with the current type vocabulary.
  Evidence: Temurin 21.0.8 produced 44 compiled shards totaling 5,846,861 stored bytes and 34,890,611 raw bytes. Unsupported advanced source type shapes emit bounded warnings rather than guessed facts; the real smoke still validates and compiles the retained API.

## Decision Log

- Decision: derive Scala standard-library APIs from source archives using Bifrost's existing structured Scala parser.
  Rationale: source preserves Scala names, companions, traits, source locators, extension declarations, and source-level signatures better than JVM bytecode. Reusing the parser avoids a text mini-parser and keeps workspace and archive semantics aligned.
  Date/Author: 2026-08-01 / Codex

- Decision: keep the first pack source-exact and leave compiler-generated case-class behavior to #1153.
  Rationale: source archives do not authoritatively declare every compiler-synthesized surface, and #1153 already defines activation and provenance for those facts. This pack must not silently claim compiler precision it does not have.
  Date/Author: 2026-08-01 / Codex

- Decision: store explicit source hierarchy and resolve only unambiguous universal roots lazily, without a dedicated fallback cache.
  Rationale: storing `Object` or `Any` relations for every type increases compiled and retained bytes without adding information. The overlay already indexes names and relations in hash maps, so a queried fallback is constant-time and a second cache would retain redundant state. Explicit workspace and pack hierarchy always wins; inactive or conflicting roots produce no fallback. Java uses the semantic `java.lang.Object` root and Scala uses semantic `scala.Any`, deliberately avoiding compiler-emulation of intermediate roots.
  Date/Author: 2026-08-01 / Codex

- Decision: merge Scala class/trait and companion-object declarations into one source-level type surface while preserving static identity on companion members.
  Rationale: user-facing Scala lookup uses the shared source name, while instance and companion members remain semantically distinct. Including staticness and parameter arity in canonical member identity prevents overload collisions without introducing bytecode-only `$` names into the source pack.
  Date/Author: 2026-08-01 / Codex

- Decision: restrict modern JDK shards to unqualified module exports.
  Rationale: public/protected modifiers alone leak internal implementation packages. `module-info.java` is the structured, version-specific authority for which packages are exported to all consumers; qualified exports remain internal to named friend modules.
  Date/Author: 2026-08-01 / Codex

- Decision: keep curated inputs and distribution policy in `brokk-bifrost-semantic-packs`, downstream of generic analysis.
  Rationale: `brokk-bifrost-analysis` owns generic producer/compiler/catalog/runtime mechanics; embeddings that do not want Bifrost-curated content must remain able to depend on analysis alone.
  Date/Author: 2026-08-01 / Codex

- Decision: generated pack payloads remain outside Git.
  Rationale: repository changes should contain generator source, compact pinned input manifests, checksums, license/notices, tiny fixtures, and regeneration instructions. Large immutable manifests and shards belong in release assets.
  Date/Author: 2026-08-01 / Codex

## Outcomes & Retrospective

Milestone 1 now provides a bounded `ScalaSourceJarPackProducer` that parses each Scala entry once, emits public/protected source-declared types and members with stable JVM identities, signatures, explicit hierarchy, companions/modules, type aliases, and extension surfaces, and sorts output deterministically. The legacy JVM external declaration index now projects Scala type shells from these produced facts instead of maintaining a second parser and visibility model. Three producer tests and the existing Scala source-JAR external-index test pass. Compiler-generated case-class APIs remain deliberately absent for #1153.

Milestone 2 adds `JdkSourceArchivePackProducer` with caller-declared `ModulePrefixed` and `Flat` layouts. Modern archives must provide a `module-info.java` marker for every source-bearing module; flat production rejects module-prefixed markers instead of guessing. Each module emits an independently activated, deterministically ordered shard, with flat archives assigned explicitly to `java.base`. The producer reuses the Java AST conversion and stable identities, supports JDK-scale bounded archives, and avoids retaining all source text. Two JDK tests and all four Java artifact producer tests pass under strict Clippy.

Milestone 3 adds semantic lazy-root traversal to `SemanticModelOverlay` and hierarchy navigation. Explicit ancestors are traversed iteratively first; only a unique active `java.lang.Object` or `scala.Any` is appended when a type has no authored `extends` edge. The integration suite proves workspace and model-only navigation, explicit-parent precedence, inactive version behavior, and that dependency sources never enter the project file set. Real Scala 2.13.16 and Temurin 21.0.8 archives now compile end to end. Their failures uncovered and fixed companion merging, legal Scala escaped identifiers, annotated generic names, static/arity member identity, JDK module exports, and structured Java varargs/array dimensions. Focused Scala, Java, JDK, and semantic integration tests plus task-scoped strict Clippy pass.

## Context and Orientation

A semantic-model pack is a typed, versioned description of declarations or generated behavior that does not need to appear as ordinary workspace source. `crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines authored packs, declaration facts, member facts, signatures, hierarchy facts, locators, activation selectors, and provenance. `artifact.rs` defines deterministic compiled manifests and shard artifacts. `compiler.rs` validates, normalizes, serializes, compresses, and hashes authored content. `catalog/` stores immutable compiled artifacts by digest. `runtime.rs` selects compatible shards from exact evidence and builds a bounded in-memory matcher. `overlay.rs` projects the active facts into symbols and relations used by code-navigation tools.

`crates/bifrost-analysis/src/analyzer/jvm/java_artifact.rs` implements `JavaJarPackProducer`. It accepts a bounded exact source or class archive, produces public/protected types and members, preserves signatures and explicit hierarchy, filters nested declarations by effective visibility, and emits one declaration shard. Source and binary artifacts share stable JVM declaration identities but retain different locators.

`crates/bifrost-analysis/src/analyzer/jvm/external.rs` discovers Maven/Gradle artifacts and builds the legacy private JVM external index used by Java, Scala, and Kotlin resolution. `SourceJarLanguage` recognizes Java, Scala, and Kotlin entries. Java source facts are already produced through `JavaJarPackProducer`; Scala source entries call `scala_source_types`, which uses the real Scala parser but keeps only public type shells. The first producer milestone must remove this semantic divergence by making pack production the shared authoritative parsing path and projecting legacy types from the same facts.

`crates/bifrost-analysis/src/analyzer/scala/declarations.rs` parses Scala 2 and Scala 3 syntax into `ParsedFile`. It records `CodeUnit` declarations and ranges, owner relationships, signatures, `SignatureMetadata`, raw supertypes and structured lookup paths, trait markers, constructors, class-parameter fields, type aliases, enums, and extension methods. New production must consume these structured records and syntax nodes. It must not parse signatures or paths with regular expressions, string splitting, or delimiter scanning.

`crates/bifrost-semantic-packs` is the downstream distribution crate created by #1154. Its production embedded registry is empty pending #1152 and #1153. It currently validates and explicitly registers borrowed compiled packs but does not generate release bundles or describe downloadable assets. Release workflow support lives in `.github/workflows/release.yml`; package dependency boundaries are enforced by `scripts/check-workspace-dependencies.mjs` and package archives by `scripts/check-workspace-packages.sh`.

The JDK commonly ships source as `src.zip`. Modern archives place Java files below a module prefix such as `java.base/java/lang/Object.java`; layouts from older releases or vendors may omit that prefix. The generator must accept an explicit pinned input layout and validate it, not guess from the newest release. Scala standard-library sources normally arrive as Maven `-sources.jar` artifacts. The pack selector must include the exact Scala binary/library version and artifact digest.

## Plan of Work

Milestone 1 adds a Scala source-archive producer beside the Java producer. Add `crates/bifrost-analysis/src/analyzer/jvm/scala_artifact.rs` and expose it from `jvm/mod.rs`. Extend the exact artifact producer vocabulary in `semantic_model/producer.rs` only as needed to distinguish Scala source archives without weakening Java or .NET kind checks. Refactor the Scala declaration module to expose a typed visibility result that distinguishes public, protected, and non-API declarations. Walk archive entries iteratively under the existing central-directory, entry-count, per-entry, total-byte, record-count, signature-depth, diagnostic-count, and cancellation limits.

For each valid Scala source entry, parse once with tree-sitter and `parse_scala_file`. Convert public/protected type declarations into `TypeFact` values using stable JVM identities. Convert owned constructors, methods, and fields into `MemberFact` values. Preserve source label, structured parameter types where available, return types, type parameters, dispatch/abstract modifiers, explicit supertypes, traits, companions, extension receiver surfaces, and `Locator::Source` values containing the archive entry and source symbol. Unsupported syntax produces bounded partial diagnostics rather than invented facts or total failure. The producer emits deterministic ordering independent of ZIP entry order.

Change `JvmExternalDeclarationIndex::index_source_jar` so Scala type shells are projected from the same produced facts, retaining its current bounded source lookup behavior during the transition. Do not add a mode flag to the Java producer or a generic source parser with language switches; Java and Scala producers are separate cohesive functions and may share only archive-reading or stable-identity helpers that are genuinely identical.

Milestone 2 adds `crates/bifrost-analysis/src/analyzer/jvm/jdk_artifact.rs`. It reads an exact JDK source ZIP through the bounded artifact reader, validates the caller-declared archive layout, groups entries by module, and feeds each Java entry through the existing structured Java source conversion. Refactor `java_artifact.rs` enough to expose reusable parsing of one source entry and final fact conversion without adding a Java/JDK mode parameter. Each module becomes a deterministic shard with an exact toolchain selector; `java.base` can activate without unrelated modules. For a pinned release where source is unavailable, a separate explicit binary production request may use class metadata and must report binary provenance and partial source coverage honestly.

Milestone 3 integrates universal-root resolution. Add a structured resolver rule: after workspace declarations and explicit hierarchy have no class parent, Java may consult the unique active compatible `java.lang.Object` fact; Scala may consult the unique active compatible `scala.Any` fact. Reuse the overlay's existing name and relation indexes rather than retaining a redundant cache. Never let fallback replace explicit hierarchy, cross a toolchain mismatch, or turn an unavailable or conflicting core pack into a false resolution. Case-class-generated inheritance and members remain absent here. Record compiled pack sizes during real-artifact smoke tests; complete retained-memory and cold/warm query measurements in Milestone 4.

Milestone 4 adds behavior-focused integration coverage in `tests/suite_semantic/jvm_standard_library_pack.rs` and registers it in `tests/suite_semantic/main.rs`. Tiny source archives may be assembled in test-owned temporary directories because they test archive behavior rather than an ordinary ad hoc project; consumer projects use `InlineTestProject`. Activate compiled fixture packs through the real catalog/runtime/overlay path and prove navigation for JDK nested types, constructors, interface hierarchy, `Object` overrides, Scala traits, `Any`/`AnyVal` families, `Predef`, collections, companions, and source-declared extensions. Prove dependency contents never enter `Project::all_files()`. Generate identical logical inputs in different ZIP orders and paths and assert identical semantic bytes and digests. Prove mismatched toolchains and Scala versions remain inactive with an explanation.

Milestone 5 extends `brokk-bifrost-semantic-packs` with release-bundle generation and a small CLI. Add compact pinned production inputs under `semantic-packs/jvm/`; each entry names exact JDK or Scala versions, artifact locations, input SHA-256 values, archive layout, selectors, source revision, license, and notice files. The CLI accepts only explicit inputs and output roots, produces content-addressed manifest/shard files outside Git, and emits a canonical release index binding every asset to compatibility, producer/schema version, source digest, compressed/uncompressed bytes, and licenses. It never selects the newest available artifact and never downloads implicitly during ordinary analysis or tests.

Update `.github/workflows/release.yml` and its Node tests so a release can regenerate or verify the pinned bundles, run the package and notice gates, and upload immutable shards, indexes, checksums, notices, and measurement JSON. Do not publish a version, tag, release, or crate from this task. The scheduled first crates.io bootstrap for `brokk-bifrost-semantic-packs` remains a separate authorized release operation.

Milestone 6 performs the final gate. Run focused featureless Rust tests throughout. At completion run formatting, strict task-scoped Clippy, all affected integration suites, dependency/workflow tests, deterministic regeneration, `git diff --check`, and the repository policy selection from the active workspace. Follow the guided-issue specialist review, fix accepted findings, update this plan after every milestone and review, and commit only files changed for the milestone with a multiline message explaining why.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/937d/bifrost` on branch `1152-generate-and-publish-versioned-jdk-and-scala-standard-library-api-packs`. Do not create or switch branches. At the design milestone the branch is based on `origin/master` commit `218f4cf5`.

For each Rust milestone, run formatting and the focused tests identified by the new test names:

    cargo fmt --all -- --check
    cargo test -p brokk-bifrost-analysis scala_artifact
    cargo test -p brokk-bifrost-analysis jdk_artifact
    cargo test --test suite_semantic jvm_standard_library_pack

Package/workflow work adds focused Node tests and package inspection:

    node --test scripts/release-promotion-workflow.test.mjs scripts/check-workspace-dependencies.test.mjs
    cargo package --list -p brokk-bifrost-semantic-packs

Use `scripts/with-isolated-cargo-target.sh` for strict Clippy or other isolated builds rather than manually naming a temporary Cargo target:

    /Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/cargo-clippy clippy -p brokk-bifrost-analysis --all-targets -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-semantic-packs --all-targets -- -D warnings

Do not enable `nlp` for routine milestone validation. A comprehensive all-feature gate is required only if this branch is later pushed or release-qualified, and Python-enabled commands must run through uv's Python 3.12 environment.

After code changes and before completion, use the installed Bifrost policy skill to run `bifrost.code-smells` together with every executable repository policy root explicitly named by the repository. Treat `unreliable` as failed validation, record exact limitations, and rerun after fixes.

## Validation and Acceptance

The Scala producer is accepted when a tiny Scala 2 archive and a tiny Scala 3 archive produce public/protected types, traits, companions, constructors, members, signatures, explicit hierarchy, and source-declared extensions; private declarations remain absent; malformed or unsupported entries produce bounded partial diagnostics. Reordering archive entries or renaming an identical archive does not change semantic bytes or digests.

The JDK producer is accepted when a modern module-prefixed fixture produces separate `java.base` and non-base shards, activating `java.base` alone exposes `Object`, `String`, interfaces, nested types, and members, and the non-base declaration remains unavailable. A declared legacy layout has its own positive fixture; an archive that does not match its declared layout fails with an actionable diagnostic instead of guessing.

Navigation is accepted when a workspace class override resolves against an explicit library ancestor or universal root only after checking workspace/source declarations first; repeated warm lookup reuses generation-local state; inactive or mismatched packs never answer. Scala `copy` remains absent from source packs and is tested only as a non-claim so #1153 can supply it with generated-model provenance.

Distribution is accepted when the same pinned inputs generate byte-identical release indexes, manifests, and shards twice; every asset digest and size verifies; license/notices are present; large outputs are absent from `git status`; and the release workflow tests show assets are immutable and the semantic-packs crate remains downstream of analysis.

Measurements must publish generation time, compressed/uncompressed size per shard, activation time, retained overlay bytes, and cold/warm representative queries. The Decision Log must record whether the lazy-root design was retained or replaced based on those measurements.

## Idempotence and Recovery

All generators read exact inputs and write into a caller-selected output directory. Repeating a completed generation either verifies or replaces only content-addressed files with identical bytes. Tests use automatically removed temporary directories. No command downloads artifacts during ordinary analysis, mutates a user's dependency cache, changes workspace source files, publishes a crate, creates a tag, or creates a GitHub release.

If production is cancelled or hits a bound, it returns explicit partial or failed diagnostics and never publishes an authoritative empty pack. Catalog installation remains atomic and content-addressed. A failed milestone is repaired forward in the existing worktree; do not reset unrelated user changes. Stage only the files changed for the milestone.

## Artifacts and Notes

Initial synchronized state:

    branch: 1152-generate-and-publish-versioned-jdk-and-scala-standard-library-api-packs
    HEAD: 218f4cf5
    origin/master: 218f4cf5
    BIFROST_MCP_RMCP: on

The production registry in `crates/bifrost-semantic-packs/src/lib.rs` remains empty until reviewed content or release-index integration is ready. Large standard-library artifacts are never embedded merely to make that constant non-empty.

## Interfaces and Dependencies

The exact names may be refined while keeping responsibilities stable. In `crates/bifrost-analysis/src/analyzer/jvm/scala_artifact.rs`, define a producer equivalent to:

    pub struct ScalaSourceJarPackProducer;

    impl ExternalArtifactPackProducer for ScalaSourceJarPackProducer {
        fn produce_exact_artifact(
            &self,
            request: &ArtifactProductionRequest,
            limits: &ArtifactProducerLimits,
        ) -> ArtifactProduction;
    }

Its cancellation-aware implementation must mirror the existing trait extension used by `JavaJarPackProducer`. Fact identities use the shared semantic-model identity helpers and the JVM ecosystem so Java/Scala interoperation does not create parallel identities for the same classfile-level declaration.

In `crates/bifrost-analysis/src/analyzer/scala/declarations.rs`, expose a typed visibility helper equivalent to:

    pub(crate) enum ScalaDeclarationVisibility {
        Public,
        Protected,
        NonApi,
    }

Do not return a boolean once protected declarations matter. Qualified private/protected forms must be interpreted from syntax nodes, not text scanning.

In `crates/bifrost-analysis/src/analyzer/jvm/jdk_artifact.rs`, define an explicit input layout and producer. The layout is caller-provided evidence, not auto-upgraded:

    pub enum JdkSourceArchiveLayout {
        ModulePrefixed,
        Flat,
    }

The exact type may live in the downstream generation crate if generic analysis only needs already-separated entries. Whichever layer owns it must validate layout and emit deterministic module IDs.

The downstream release index must be canonical serialized data with a schema version, producer version, exact selectors, source and artifact digests, asset paths, byte sizes, license/notices, and revocation-compatible immutable identity. It may refer to downloadable assets, but generic analysis must not depend on this crate or network availability.

Revision note (2026-08-01): created the initial self-contained plan after live issue diagnosis and user approval. The plan records source-exact Scala/JDK capture, lazy universal-root evaluation, the #1153 case-class boundary, reproducible release assets, and milestone validation.

Revision note (2026-08-01): completed milestone 1. The implementation established Scala source archives as the authoritative structured path for both semantic packs and the legacy JVM type index, and recorded constructor-fact and exact-artifact determinism findings.

Revision note (2026-08-01): completed milestone 2. The implementation added explicit JDK archive layouts, per-module shards, JDK-scale bounded extraction, and a two-pass low-retention source walk while reusing the existing Java AST conversion.

Revision note (2026-08-01): completed milestone 3. Lazy universal roots now use the overlay's existing indexes without authored edge expansion or redundant caching. Real Scala 2.13.16 and Temurin 21.0.8 source artifacts compile successfully, module exports bound the JDK surface, and source-shape fixes preserve companions, escaped identifiers, varargs, and multidimensional arrays.
