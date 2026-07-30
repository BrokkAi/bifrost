# Produce reusable semantic-model packs from external artifacts

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Bifrost currently learns about dependency APIs through two analyzer-private indexes. The shared JVM index reads source and class JARs but records only types, while the C# index reads assemblies and records richer type and member metadata. After this work, callers can give Bifrost one exact, bounded Java source JAR, Java class JAR, or C# assembly and receive a deterministic semantic-model API pack containing the externally visible declarations that artifact provides. The result also reports an exact artifact digest and bounded explanations for anything omitted because metadata was unsupported, malformed, or over a safety limit.

The observable result is fixture-backed: producing a pack twice from the same artifact yields byte-identical compiled output; equivalent Java source and class declarations have the same declaration IDs but different origin locators; C# assemblies retain members, generic arity, signatures, and hierarchy; and malformed or limited artifacts return a usable partial result with diagnostics instead of preventing analyzer startup. Dependency contents remain external artifacts and never appear in `Project::all_files()`.

This issue does not install packs, download artifacts, solve classpaths, decompile method bodies, or add producers for Scala, Kotlin, TypeScript, Python, Ruby, Rust, or Go. Runtime installation and matching belong to the other children of issue #1144.

## Progress

- [x] (2026-07-30 13:02Z) Verified the live issue, dependency #1145, predecessor issues #354 and #355, the prepared branch, and current remote state.
- [x] (2026-07-30 13:02Z) Diagnosed the JVM, C#, and semantic-model boundaries and identified the missing exact-artifact producer seam.
- [x] (2026-07-30 13:02Z) Chose the producer result, identity, origin, diagnostic, compatibility-adapter, and milestone boundaries recorded below.
- [x] (2026-07-30 13:26Z) Implemented and validated the shared exact-artifact producer contract, bounded diagnostics, stable identity helpers, optional binary parameter names, and regenerated schema.
- [x] (2026-07-30 13:46Z) Implemented the exact C# assembly producer, structured CLI type decoding, bounded partial diagnostics, and a fact-backed compatibility projection for the existing resolver index.
- [x] (2026-07-30 14:15Z) Implemented Java source/class JAR production, cross-origin stable IDs, bounded JVM signature decoding, and JVM-index projection without regressing Scala or Kotlin source-JAR behavior.
- [ ] Complete cross-producer integration tests, documentation, specialist review, policy validation, and the final focused Rust validation matrix.

## Surprises & Discoveries

- Observation: Issue #1145 is already implemented on this branch even though the branch began as the issue #1149 placeholder branch.
  Evidence: `crates/bifrost-analysis/src/analyzer/semantic_model/` contains the strict authoring model, compiler, canonical artifact format, decoder, and tests introduced by PR #1310.
- Observation: The installed Bifrost navigation skills are present, but their MCP search and source-reading tools were not callable during planning.
  Evidence: the active tool inventory contained no `search_symbols`, `get_symbol_sources`, `get_summaries`, `scan_usages`, or policy tools, so planning used repository-local `rg`, focused file reads, git history, and live GitHub issue reads.
- Observation: The prepared branch tracks its matching remote exactly but is one commit behind current `origin/master`.
  Evidence: at planning time `HEAD` was `0ff33ba7`, `origin/master` was `4d548f6f`, and `git rev-list --left-right --count HEAD...origin/master` returned `0 1`. Repository instructions prohibit rebasing without an explicit request, so no branch movement occurred.
- Observation: The semantic-model compiler already provides pack, shard, content, and stored digests, but declaration identity is authored rather than derived.
  Evidence: `compile_pack` sorts facts by their supplied IDs and hashes the compiled payload. A source locator and an artifact locator therefore produce different shard semantic digests even when their declaration IDs match.
- Observation: C# is the lower-risk first producer because its existing index already retains members, generic arity, modifiers, interface names, metadata tokens, and decoded signatures.
  Evidence: `crates/bifrost-analysis/src/analyzer/csharp/external.rs` stores those facts in `CSharpExternalType` and `CSharpExternalMember`, while `JvmExternalType` remains type-only.
- Observation: The existing metadata libraries expose enough information to defer a separate generic-arity schema field.
  Evidence: `jclassfile` 0.6 exposes `Signature` and `MethodParameters` attributes, while the C# reader already counts GenericParam table rows. Milestone one therefore changed only `Parameter.name` to optional; producers must read generic parameter names where present and report partial metadata where absent rather than invent names.
- Observation: Clippy can select Homebrew `cargo-clippy` even when Cargo and `RUSTC` are pinned to rustup, producing incompatible metadata despite the same Rust version string.
  Evidence: the first isolated Clippy attempt failed with E0514 and identified the Homebrew compiler; rerunning with `PATH=/Users/dave/.cargo/bin:...`, rustup `RUSTC`, and rustup `RUSTDOC` passed.
- Observation: The checked-in C# fixture retains real GenericParam names for both the generic owner and its generic method, but binary method parameter names are not available through the focused metadata reader.
  Evidence: the produced `Client<T>` and `Convert<U>` facts contain `T` and `U` as structured type parameters while the `Convert` parameter is intentionally emitted with `name: None`.
- Observation: `TestProject::all_files()` correctly includes arbitrary files under its root, including a DLL; the external-artifact invariant therefore requires dependency artifacts to remain outside the workspace root rather than expecting file enumeration to filter extensions.
  Evidence: the first integration-test arrangement put the fixture DLL beside `Probe.cs` and correctly observed it in `all_files()`; moving the exact dependency artifact outside the project root proved producer use does not add it to the workspace set.
- Observation: tree-sitter Java exposes `type_parameters` as a named child rather than a consistently addressable field on every declaration shape.
  Evidence: the first source/class fixture run emitted the source `Surface` without `T`; selecting the structural `type_parameters` child and its first identifier restored matching source and binary generic metadata.
- Observation: a public nested class file under a private owner cannot be filtered correctly one class entry at a time.
  Evidence: `Surface$Hidden$Leaks.class` carries public flags of its own. Retaining private owners until a bounded post-pass applies enclosing visibility prevents that nested declaration from leaking into the produced pack.
- Observation: package-private Java types remain part of the legacy same-package resolver contract even though the reusable API pack deliberately emits only public and protected facts.
  Evidence: the existing JVM tests require `PackageHelper` and package-nested lookup from the same package. The compatibility index overlays produced public/protected facts while retaining its package-private type entries; package access is not exported as reusable pack API.

## Decision Log

- Decision: Keep dependency discovery outside the producer interface.
  Rationale: the producer consumes one exact artifact. Maven, Gradle, NuGet, project-reference, and filesystem discovery remain analyzer concerns, and downloading or universal classpath solving is explicitly out of scope.
  Date/Author: 2026-07-30 / Codex
- Decision: Put the language-neutral producer contract and stable identity helpers under `crates/bifrost-analysis/src/analyzer/semantic_model/`.
  Rationale: the contract produces the existing shared authoring model and must be reusable by later ecosystems without depending on the Java or C# analyzers.
  Date/Author: 2026-07-30 / Codex
- Decision: Return production diagnostics as bounded data rather than compiler errors.
  Rationale: malformed entries, unsupported metadata shapes, and exhausted caps can make a pack partial without making every declaration unusable. A failure to read or identify the requested exact artifact may produce no pack, but analyzer startup must still remain non-fatal.
  Date/Author: 2026-07-30 / Codex
- Decision: Derive declaration IDs from semantic identity and exclude origin information.
  Rationale: equivalent source and binary declarations must merge predictably. A type ID is derived from ecosystem plus normalized fully qualified identity. A member ID is derived from its owner ID, kind, normalized name, generic arity, and ordered parameter types. Artifact paths, source paths, metadata tokens, parameter names, and return types do not participate.
  Date/Author: 2026-07-30 / Codex
- Decision: Treat stable declaration identity and compiled-pack identity as different concepts.
  Rationale: equivalent source and binary facts share declaration IDs, while their `Locator` values and exact artifact digests are intentionally different. Because locators are compiled payload fields, source and binary pack/shard semantic hashes need not match.
  Date/Author: 2026-07-30 / Codex
- Decision: Preserve type information structurally during parsing.
  Rationale: the shared `TypeRef` tree is the destination. The C# decoder must return a structured intermediate rather than flattening metadata to strings and reparsing it. Java source uses tree-sitter fields. Java class metadata uses `jclassfile` structures or, only if the crate lacks the necessary support, a bounded grammar-aware descriptor/signature decoder rather than string splitting or regular expressions.
  Date/Author: 2026-07-30 / Codex
- Decision: Make parameter names optional and add explicit generic arity only if the binary prototypes prove names cannot be recovered.
  Rationale: parameter types are part of callable identity and are reliably available, while parameter names are not guaranteed in JVM or CLI binary metadata. Generic parameter names should be read from Signature or GenericParam metadata when present; absent names must not be invented. The smallest honest schema change wins.
  Date/Author: 2026-07-30 / Codex
- Decision: Use the C# producer as the first full adapter, then implement Java.
  Rationale: this validates the shared producer and diagnostic API against an already rich metadata implementation before the larger Java source/classfile extraction is added.
  Date/Author: 2026-07-30 / Codex
- Decision: Keep existing resolver APIs as compatibility projections over produced facts.
  Rationale: issue #1149 must prove current consumers can use produced packs, but it must not implement the runtime pack installation and matching work owned by other #1144 children. The existing lookup surfaces can be retained while their backing data comes from shared facts.
  Date/Author: 2026-07-30 / Codex
- Decision: Do not expand Scala or Kotlin into full API-pack producers in this issue.
  Rationale: the shared JVM index now recognizes their source JAR types, but #1149 names Java and C#. Their existing type-level behavior must remain green through a narrow legacy adapter until separate producers are authorized.
  Date/Author: 2026-07-30 / Codex

## Outcomes & Retrospective

Milestone one is complete. The public semantic-model surface now includes an exact-artifact request/result contract, bounded diagnostic collector, byte-limited reader with exact SHA-256, and domain-separated type/member identity helpers. Binary parameters may omit names without inventing data, and the generated schema records that contract. Twenty focused semantic-pack tests, eleven semantic-model unit tests, formatting, and strict featureless library Clippy passed. The next milestone is the C# assembly producer and compatibility projection.

Milestone two is complete. `CSharpAssemblyPackProducer` now reads one exact PE/CLI assembly, records its digest in activation, emits externally visible type and member facts with structured signatures, generic parameters, hierarchy, modifiers, effective nested visibility, and metadata-token locators, and reports malformed or record-limited production as bounded partial data. `CSharpExternalDeclarationIndex` consumes the produced facts through a compatibility projection and retains production diagnostics. Ten focused C# tests, the new semantic-suite producer test, formatting, and strict featureless library Clippy passed. The next milestone is the Java source/class JAR producer and JVM compatibility projection.

Milestone three is complete. `JavaJarPackProducer` reads one exact source or class JAR under entry, per-entry byte, total-byte, record, diagnostic, and signature-depth limits. Source declarations are extracted structurally from tree-sitter; class descriptors and Signature attributes use a bounded grammar cursor. Both forms emit types, nested effective visibility, members, generic parameters, structured signatures, hierarchy, modifiers, locators, and stable IDs. The existing JVM index invokes the producer for Java artifacts and overlays its type facts while preserving the Scala/Kotlin source-JAR path and package-private Java lookup contract. Thirty-two JVM-focused tests, four producer-specific tests, the Java semantic integration test, formatting, featureless checks, and strict featureless library Clippy passed. The remaining milestone is documentation, broader integration and package validation, specialist review, and repository policy execution.

## Context and Orientation

A semantic-model pack is a strict typed collection of declarations or generator rules. `crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines its authored Rust representation. `compiler.rs` validates and normalizes authored values, serializes canonical bytes, optionally compresses shards, and computes deterministic hashes. `artifact.rs` defines compiled manifests and defensive decoders. `validate.rs` enforces schema, identifier, reference, record, text, and recursive-type limits. `mod.rs` is the public export boundary.

An external artifact is dependency content that is not part of the user's workspace source tree. The JVM implementation in `crates/bifrost-analysis/src/analyzer/jvm/external.rs` discovers configured JARs, applies archive safety limits, parses Java/Scala/Kotlin source entries or JVM class files, and stores `JvmExternalType` values in a private lookup map. Java, Scala, and Kotlin analyzers consult that map without adding the dependency entries to `Project::all_files()`. The Java portion currently records only type name, kind, effective visibility, and a source/class locator.

The C# implementation in `crates/bifrost-analysis/src/analyzer/csharp/external.rs` discovers assemblies from configuration and project assets, reads PE/CLI metadata under byte, table-row, heap, output-count, and signature-depth limits, and stores `CSharpExternalType` and `CSharpExternalMember` values. It already retains type/member kinds, visibility, modifiers, generic arity, parameter and return type strings, interfaces, and assembly metadata tokens. It uses the base type only to classify enum, struct, and delegate kinds and discards the ordinary superclass relation. Most malformed or capped cases return `None`, making unsupported metadata indistinguishable from an artifact that declares nothing.

An exact-artifact producer is the new boundary in this plan. It receives one caller-selected path plus caller-supplied pack and activation metadata, reads that path within a byte limit, hashes the exact bytes, parses them without discovering anything else, and returns either a typed authored declaration pack or no pack together with bounded diagnostics. A partial pack is one where at least one requested declaration or fact could not be represented because of invalid input, unsupported metadata, or a safety cap. A diagnostic has a stable machine-readable code, a bounded message, and an artifact-relative entry name or metadata token when available. The result also records how many further diagnostics were suppressed after the diagnostic-count limit.

Stable declaration IDs allow facts from different origins to refer to the same semantic declaration. The helper introduced by this plan hashes a canonical, length-framed identity key under a versioned domain and renders a lowercase stable ID. Type keys contain ecosystem and normalized fully qualified type identity, including generic arity where it is part of that ecosystem's identity. Member keys contain the owner ID, member kind, normalized member name, generic arity, and ordered parameter types. Return type and parameter names are excluded because Java and C# do not overload on return type and binary parameter names are optional. The hash framing must reuse the repository's existing canonical hashing helpers rather than building ad hoc concatenated strings.

## Plan of Work

Milestone one establishes the shared boundary. Add `crates/bifrost-analysis/src/analyzer/semantic_model/producer.rs` with the exact-artifact request, artifact-kind enum, producer limits, bounded diagnostic collector, production result, and `ExternalArtifactPackProducer` trait. The request carries pack ID/version, compatibility, activation selectors, provenance/license/safety metadata, and the exact path; it never derives package coordinates or versions from a filename. The common reader rejects non-files and oversized artifacts before allocation, reads one bounded byte string, and computes its SHA-256 once. Add `identity.rs` with domain-separated, length-framed type and member ID helpers over structured identity inputs.

In the same milestone, prototype one ordinary and one generic member from the existing JVM class fixtures and the C# fixture before finalizing schema edits. Change `semantic_model::Parameter.name` to `Option<String>` because binary names are not guaranteed. Read JVM Signature and CLI GenericParam names when present. Add explicit arity fields only if those prototypes demonstrate that a valid binary can expose arity without recoverable names; do not synthesize names such as `T0`. Update validation, normalization, the generated JSON Schema, semantic-model fixtures, public docs, and existing semantic-model tests for every accepted model change. At the end, typed producer results validate and compile deterministically even when a binary callable has unnamed parameters, and identity tests prove that origin and parameter-name changes preserve IDs while ordered parameter-type changes do not.

Milestone two produces C# packs. Refactor the internal CLI signature decoder in `crates/bifrost-analysis/src/analyzer/csharp/external.rs` so it builds a structured decoded type tree that can convert directly to `semantic_model::TypeRef` and can still render the legacy strings used by current resolver accessors. Extend the focused metadata table reader only for facts required by the issue, including parameter names and generic parameters when present. Preserve every existing byte, row, heap, output, traversal, and signature-depth cap. Convert invalid PE/CLR data, malformed tables or signatures, cyclic/deep TypeSpec values, and omitted records into stable bounded diagnostics. Retain an ordinary base type as `HierarchyKind::Extends`, retain interfaces as `Implements`, and avoid emitting `System.Enum`, `System.ValueType`, or `System.MulticastDelegate` as misleading ordinary bases when they serve only as kind sentinels.

Implement `CSharpAssemblyPackProducer` for one exact assembly. It emits only public, protected, and protected-internal types and members after applying enclosing-type effective visibility. Type and member locators use the artifact path and CLI metadata token. The activation selector contains the exact artifact SHA-256 plus caller-supplied package/module information. Deterministic ordering is left to the shared compiler, while stable IDs come exclusively from `identity.rs`. Then make `CSharpExternalDeclarationIndex::build_for_project` run the producer for each already-discovered assembly and project the produced declaration facts into its existing lookup shape. Preserve `resolve_in_file`, `members_named`, aliases, generic identity matching, and source accessors. Retain aggregated production diagnostics on the index even if current analyzer diagnostics do not surface them yet.

Milestone three produces Java packs. Extend the Java branch of the source-JAR walk in `crates/bifrost-analysis/src/analyzer/jvm/external.rs` to emit type, member, signature, hierarchy, modifier, and locator facts from tree-sitter nodes and existing Java declaration/type helpers. Cover fields, constructors, methods, records, annotations, nested types, type and method parameters, superclass, interfaces, interface-member defaults, and enclosing effective visibility. Use AST field relationships and shared analyzer helpers; do not introduce source-text delimiter parsing. Parse errors, unsupported type shapes, oversized entries, archive entry/byte exhaustion, and declaration caps produce bounded partial diagnostics.

Replace the Java classfile type-only extraction with a structured decoder over `jclassfile` data. It emits fields, constructors, methods, generic arity and names when available, parameter and return types, superclass and interfaces, relevant static/abstract/final modifiers, nested-class metadata, and source/class locators. Descriptors and Signature attributes must become `TypeRef` trees without a flattened-string round trip. If `jclassfile` does not expose a sufficient parsed representation, add a small dedicated module implementing the documented JVM descriptor/signature grammar with a cursor, explicit stack or bounded depth, and exhaustive fixture tests; never use `split`, regular expressions, or delimiter scanning as a substitute for the grammar.

Implement `JavaJarPackProducer` for one exact source or class JAR. Preserve `MAX_ARCHIVE_ENTRIES`, per-entry source/class byte caps, total archive bytes, artifact bytes, total index bytes, and declaration-count limits. A source artifact and its binary artifact are separate exact production requests, so each has its own digest and locator. When the existing analyzer has both, merge projected facts by stable ID with source locators preferred, matching current behavior. Refactor `JvmExternalDeclarationIndex` to project Java facts from produced packs while keeping its public query behavior. Preserve the existing Scala and Kotlin source-JAR type path and tests without claiming full packs for those languages.

Milestone four proves the behavior end to end. Add `tests/suite_semantic/external_artifact_pack.rs` and register it in `tests/suite_semantic/main.rs`. Use checked-in, pinned fixtures under `tests/fixtures/`; reuse the C# assembly and suitable Java source/class fixtures where their declarations are genuinely equivalent. If a new JAR is required, check in its source, exact binary, SHA-256 file, and a README with a reproducible build command, following the C# fixture convention. The tests call both producers, compile and decode their packs, compare repeated bytes and digests, compare source/binary declaration IDs and origins, exercise positive and negative visibility cases, verify members/generics/signatures/hierarchy, assert diagnostic caps and suppressed counts, resolve representative facts through the compatibility indexes, and compare `Project::all_files()` before and after producer use.

Update `docs/src/content/docs/semantic-model-packs.md` and the checked-in schema to explain exact-artifact producers, stable declaration identity versus pack digest identity, optional binary metadata, partial diagnostics, cap behavior, and the non-installation boundary. Do not add runtime registry or activation behavior. Complete architecture, security, intent, duplication, and DevOps reviews through specialist agents, address confirmed findings, run the repository policy gate, and record all evidence in this plan.

## Milestones

Milestone one is complete when the shared exact-artifact contract and stable identity API compile, the schema represents unnamed binary parameters without invention, the artifact reader and diagnostic collector enforce lowered test limits, and focused semantic-model tests demonstrate stable origin-independent declaration IDs and deterministic compilation. Run the semantic-model test module and expect every new contract, identity, schema, and cap case to pass.

Milestone two is complete when the pinned C# fixture produces a deterministic compiled pack with externally visible types, nested effective visibility, members, structured signatures, generic information, ordinary hierarchy, interfaces, modifiers, metadata-token locators, and an exact artifact digest. Lowered limit and malformed metadata tests must return partial diagnostics, and the existing C# resolution tests must still pass through the fact-backed compatibility index.

Milestone three is complete when equivalent Java source and class JAR fixtures produce matching type/member declaration IDs with distinct locators and artifact digests. Both forms must cover public/protected visibility, private/package negative cases, nested effective visibility, generics, fields, constructors, methods, and hierarchy. Existing Java, Scala, and Kotlin external resolution tests must remain green, and malformed or capped Java artifacts must return bounded partial diagnostics.

Milestone four is complete when integration tests compile and defensively decode both ecosystems' packs, current consumers resolve representative external declarations without dependency entries appearing in `Project::all_files()`, documentation and schema checks pass, specialist reviews contain no unresolved critical or high finding, and the focused Rust and repository-policy validation described below succeeds.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/1a7d/bifrost`. Do not switch branches or rebase without explicit user instruction. After every implementation milestone, update this plan and commit only the files changed in that milestone with a multiline checkpoint message explaining the design rationale and validation evidence.

Before edits, confirm the worktree and branch:

    git status --short --branch
    git rev-parse --short HEAD
    git rev-list --left-right --count HEAD...origin/master

During milestone one, run:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- semantic_model_pack::

During milestone two, run the focused C# library tests and semantic producer integration tests. Discover the exact lib-test filter with `cargo test --lib -- --list | rg 'csharp.*external|external.*csharp'`, then use the narrow matching filter. Also run:

    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- external_artifact_pack::csharp

During milestone three, run the focused JVM external tests and Java producer integration tests. Discover the exact lib-test filter with `cargo test --lib -- --list | rg 'jvm.*external|external.*java'`, then use the narrow matching filter. Also run:

    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- external_artifact_pack::java

After milestone four, run the task-scoped gate without NLP:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --lib
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- semantic_model_pack::
    scripts/with-isolated-cargo-target.sh cargo test --test suite_semantic -- external_artifact_pack::
    npm --prefix docs run check
    npm --prefix docs run build
    scripts/check-crate-package.sh

Do not enable `nlp`; this issue does not touch semantic search, and routine task-scoped validation must not consume the feature's large model build. Before completing the code-changing task, use the installed `brokk:bifrost-policy-checking` skill. Run `bifrost.code-smells` together with every executable repository policy root explicitly named by the project in one request. A `finding` must be reviewed or fixed, and an `unreliable` response is a failed validation result rather than success.

Expected focused evidence after completion resembles:

    test external_artifact_pack::csharp_repeated_production_is_byte_identical ... ok
    test external_artifact_pack::java_source_and_class_share_declaration_ids ... ok
    test external_artifact_pack::partial_diagnostics_are_bounded ... ok
    test external_artifact_pack::dependency_entries_are_not_project_files ... ok

The exact test names may evolve, but this plan must be updated if they do.

## Validation and Acceptance

Produce a C# pack twice from `tests/fixtures/csharp-external/ExternalLibrary.dll`, compile both with the same options, and require identical manifest bytes, shard bytes, stored hashes, content hashes, and semantic hashes. Decode one result and assert the fixture's public generic class, nested visibility cases, methods, properties, fields, parameter/return types, interface and non-sentinel base relations, modifiers, and metadata-token locators. Lower at least the row, signature-depth, and diagnostic-count limits and observe a partial result with stable codes and a nonzero suppressed count when appropriate.

Produce Java source and class packs from pinned equivalent fixtures. Match facts by their stable declaration IDs and assert the same type and member identities for source and binary forms, while `Locator::Source` versus `Locator::Artifact`, exact artifact SHA-256, and compiled pack hashes differ. Assert public and protected facts are present, private and package-only facts are absent, a public nested declaration inside a private owner is absent, and generics, overloads, constructors, fields, superclass, and interfaces retain their structured shapes. Reorder ZIP entries and repeat production; canonical compiled output must remain identical.

Run the existing C# and JVM external-resolution tests after switching their backing construction to produced facts. They must return the same known types and members as before. Create a test project containing only ordinary workspace source plus a configured external artifact, record `Project::all_files()`, trigger producer-backed resolution, and require the set to remain unchanged with no JAR entry or assembly path included.

Give both producers malformed, oversized, deeply nested, and count-limited inputs. They must not panic, recurse without a bound, invent declarations, or turn analyzer construction into an error. When safe facts remain, the result contains a partial pack and bounded diagnostics. When the exact artifact cannot be read or identified, the result contains no pack and one bounded fatal diagnostic that the compatibility index treats as no external declarations.

Formatting, focused tests, featureless strict Clippy, documentation checks/build, package verification, specialist reviews, and repository policy execution must all have their final status recorded in `Progress`, `Surprises & Discoveries`, and `Outcomes & Retrospective` before this plan is complete.

## Idempotence and Recovery

Producer calls are read-only and deterministic for the same exact bytes and request metadata. They do not mutate dependency artifacts or workspace files. Generated schema updates are deterministic and should be repeated through the existing schema generation/test path rather than edited independently. Fixture archives and assemblies are immutable checked-in evidence; rebuild them only through documented commands and verify their SHA-256 files before accepting changes.

Use `scripts/with-isolated-cargo-target.sh` for isolated builds so temporary targets are removed on success, failure, or interruption. Do not create manually named Cargo target directories under `/tmp` or `/private/tmp`. If an implementation milestone fails halfway, keep the shared model compiling by completing additive types and adapters before deleting or replacing legacy DTO fields. Existing lookup APIs remain available until their fact-backed projections pass all old tests, which makes retrying safe.

Do not discard unrelated worktree changes. Stage and commit only files named in the current milestone. Do not switch branches, rebase, push, or open a pull request without explicit user authorization. If a fixture or schema decision changes, update every section of this plan and append a revision note below before continuing.

## Artifacts and Notes

Live issue relationships verified during planning:

    #1149  Generalize external artifact indexes into reusable API-pack producers
    #1145  Define a versioned semantic-model schema and deterministic pack compiler (closed)
    #354   Add Java external declaration index from source JARs and classfiles (closed)
    #355   Investigate C# external declaration index from assembly metadata (closed)

Relevant implementation history includes PR #445 for the JVM index, PR #874 for the C# index, and PR #1310 / commit `ffa79722` for the semantic-model schema and compiler. These references explain provenance only; the current source tree is authoritative during implementation.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/semantic_model/producer.rs`, define these responsibilities with final names adjusted only if repository conventions demand it:

    pub trait ExternalArtifactPackProducer {
        fn produce_exact_artifact(
            &self,
            request: &ArtifactProductionRequest,
            limits: &ArtifactProducerLimits,
        ) -> ArtifactProduction;
    }

    pub struct ArtifactProductionRequest {
        pub path: PathBuf,
        pub artifact_kind: ExternalArtifactKind,
        pub pack_id: String,
        pub pack_version: String,
        pub compatibility: Compatibility,
        pub activation: Vec<ActivationSelector>,
        pub provenance: Provenance,
        pub license: String,
        pub safety: Safety,
    }

    pub struct ArtifactProduction {
        pub artifact_sha256: Option<String>,
        pub pack: Option<AuthoredSemanticModelPack>,
        pub diagnostics: Vec<ProducerDiagnostic>,
        pub suppressed_diagnostics: usize,
    }

`ArtifactProducerLimits` includes the common maximum artifact bytes, produced records, recursive signature depth, diagnostic count, and diagnostic message bytes. Java and C# producers keep their stricter ecosystem-specific entry, archive, heap, and metadata-table limits and report which limit caused partial output. The common artifact reader uses `std::fs::File::take` or an equivalent bounded reader and `sha2`, both already used in the repository; it must not call unrestricted `fs::read` before validating file size.

In `identity.rs`, expose typed inputs rather than a variadic string helper. Use the existing canonical hash/domain-separation conventions from `crate::analyzer::canonical_hash` or the semantic-model artifact code, with a new versioned domain for external declaration identity. The rendered IDs must satisfy the semantic-model stable-ID validator.

`CSharpAssemblyPackProducer` lives next to the metadata parser in `crates/bifrost-analysis/src/analyzer/csharp/external.rs` unless implementation size justifies a cohesive `csharp/external/producer.rs`; do not split a short single-use adapter into a new module. `JavaJarPackProducer` follows the same rule in `jvm/external.rs`. Both construct `AuthoredPayload::DeclarationFacts` directly and call no compiler internally; callers can inspect the typed result, while tests and later lifecycle code call `compile_pack` explicitly.

The only new model dependency anticipated is optional parameter names. If the binary prototypes require separate generic arity, add it to `TypeFact` and `Signature`, validate that named parameters do not exceed or contradict it, and update schema/fixtures/docs in the same milestone. Do not add a generic fallback string type, arbitrary metadata map, or source-text parsing dependency.

Revision note (2026-07-30): Initial plan created after live issue verification, repository diagnosis, and guided planning review. It resolves the producer boundary, source/binary identity rule, bounded diagnostic behavior, ecosystem order, compatibility strategy, and validation expectations before implementation.

Revision note (2026-07-30 13:26Z): Recorded milestone one completion, focused test and Clippy evidence, the minimal optional-parameter schema change, and the toolchain-selection requirement discovered during validation.
