# Add high-confidence Scala unrecognized-symbol diagnostics

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, an editor connected to Bifrost can opt in to warnings for Scala names that are demonstrably unknown. The warning is useful only when it is safer to report than to stay quiet: Bifrost must first account for local declarations, project declarations, imports, Scala defaults, and configured JVM dependencies. A missing source JAR must not make valid code look broken; a dependency classfile is an acceptable source of type existence, and absent or ambiguous classpath evidence suppresses the warning.

The observable outcome is a Scala file containing a truly unknown local value or simple type reference receiving `scala_unrecognized_symbol` through the existing LSP opt-in. The same LSP request must return no Scala semantic warning for local bindings, same-package types, explicit or wildcard imports, modeled defaults, configured external JVM types, malformed source, dynamic/member selectors, or classpath uncertainty.

## Progress

- [x] (2026-07-27 07:35Z) Inspected the live issue, current issue branch, Java external-index implementation, Scala import and definition support, existing semantic diagnostic collectors, and LSP opt-in routing.
- [x] (2026-07-27 07:35Z) Recorded the approved design and implementation milestones in this ExecPlan.
- [x] (2026-07-27 07:38Z) Extracted the Java-owned external-index module into `src/analyzer/jvm/external.rs`, kept Java as its consumer, and preserved the focused Java archive/import tests.
- [x] (2026-07-27 07:47Z) Added structured Scala source-JAR declaration indexing, retaining classfile fallback and excluding private/protected source declarations.
- [x] (2026-07-27 07:50Z) Gave Scala snapshots the shared JVM index and dependency-input invalidation, then added the conservative Scala collector and analyzer hook.
- [x] (2026-07-27 07:53Z) Added focused collector, shared-index, and LSP opt-in behavior tests for unknown simple types, bare local references, known source/import/default boundaries, malformed input, and same-package source-JAR types.
- [x] (2026-07-27 08:18Z) Ran formatting, focused Scala/index/LSP tests, strict Clippy, the feature-enabled test suite, whitespace validation, and three independent implementation reviews.
- [x] (2026-07-27 08:23Z) Applied review follow-ups: bounded aggregate JVM archive work and Scala source expansion; modeled additional Scala/Java default types; resolved same-package singleton terms; and asserted the published Scala LSP diagnostic.

## Surprises & Discoveries

- Observation: the existing external index already resolves configured and discovered Maven/Gradle artifacts, prefers a source JAR when one is supplied, and falls back to classfiles.
  Evidence: `src/analyzer/java/external.rs` builds `JavaExternalDeclarationIndex` from `JavaAnalyzerConfig`, indexes `.java` entries before `.class` entries, and retains source provenance when both identify the same fully qualified name.
- Observation: that index is not yet a shared JVM facility and cannot answer Scala requests.
  Evidence: `src/analyzer/java/mod.rs` owns `JavaExternalDeclarationIndex` behind a Java-only `OnceLock`; `ScalaAnalyzer` discards `AnalyzerConfig.java` after constructing its inner tree-sitter analyzer.
- Observation: current source-JAR handling ignores Scala source files.
  Evidence: `index_source_jar` in `src/analyzer/java/external.rs` accepts only entries ending in `.java`; classfile indexing normalizes `$` to `.` but does not recover Scala source semantics.
- Observation: Scala already has structured, source-backed same-package and import facts but no semantic diagnostic hook.
  Evidence: `src/analyzer/scala/imports.rs` resolves explicit and wildcard imports and maintains same-package references; `IAnalyzer::semantic_diagnostics` defaults to empty and `ScalaAnalyzer` does not override it.
- Observation: the extraction needs a small visibility widening for the Java declaration parser helpers used by the moved index.
  Evidence: the former child module could call `java::declarations` through `super`; `jvm::external` requires those helpers to be `pub(crate)` while their API remains internal to this crate.
- Observation: Scala source-JAR declarations can reuse the normal structured Scala declaration collector without creating a dependency `ProjectFile` in the workspace.
  Evidence: a synthetic absolute-root `ProjectFile` supplies identity only to `parse_scala_file`; the resulting `CodeUnit` names are converted to external records and never enter the analyzer's file/declaration indexes.
- Observation: source-JAR declarations need an explicit visibility gate before they can override classfile evidence.
  Evidence: Scala permits `private` and `protected` type declarations. The shared index locates the parser-recorded declaration range and uses its structured modifier child to exclude non-public entries; the `Hidden` source-JAR regression remains absent from the index.
- Observation: source-JAR parsing needs tighter Scala-specific resource limits than Java source parsing because the Scala declaration collector materializes a richer declaration model.
  Evidence: review identified that an allowed 8 MiB Scala source entry could produce an excessive declaration set. The shared index now caps aggregate archive work, artifact count, Scala entry size, and retained Scala source types; exhausting a cap simply leaves diagnostics silent.

## Decision Log

- Decision: introduce a JVM-owned external type index rather than let Scala reach through a Java analyzer delegate.
  Rationale: a Scala-only workspace must be able to use configured dependency evidence, and a Java delegate may be absent. One index also prevents Java and Scala from independently reading the same archives.
  Date/Author: 2026-07-27 / Codex and user.
- Decision: retain the established `JavaExternal*` type names during the mechanical extraction, then rename only if Scala-facing APIs make the Java wording misleading.
  Rationale: the first checkpoint proves the ownership boundary without mixing a behavior-preserving file move with a broad mechanical identifier rewrite. The module path, not the private type spelling, establishes shared JVM ownership; the next milestone can rename types with Scala tests in place if that improves the resulting interface.
  Date/Author: 2026-07-27 / Codex.
- Decision: initially diagnose only simple type references and identifiers that appear directly as bare block expressions.
  Rationale: those two forms have complete structural classification and do not require member dispatch, call overload selection, implicit/given search, or general type inference. Other value, call, member, interpolation, and qualified-path shapes remain silent until Bifrost can prove them without false positives.
  Date/Author: 2026-07-27 / Codex.
- Decision: prefer parser-derived `.scala` source-JAR declarations, then use classfile declarations when no equivalent source declaration is available.
  Rationale: source has the clearest Scala spelling and package structure. Classfiles are the reliable fallback for generated code, dependencies without source artifacts, and sources the parser cannot trust.
  Date/Author: 2026-07-27 / Codex and user.
- Decision: keep dependency declarations external to `ProjectFile` and `CodeUnit`.
  Rationale: the feature needs knownness, not source navigation. Treating archives as workspace files would corrupt ordinary symbol, persistence, and usage-graph surfaces.
  Date/Author: 2026-07-27 / Codex.
- Decision: diagnostics fail closed at every unresolved import, default-import, implicit/given, dynamic, or external-classpath boundary.
  Rationale: #364 explicitly values high confidence over broad compiler parity. A suppressed warning is preferable to a false positive in editor diagnostics.
  Date/Author: 2026-07-27 / Codex and user.
- Decision: extend the intrinsic default-type set to the stable Scala and `java.lang` names that appear without explicit imports, including bounded `TupleN`/`FunctionN` families.
  Rationale: these default scopes are part of ordinary Scala name resolution even when no Scala-library source artifact is configured. The collector must never call them unknown merely because its external index lacks that artifact.
  Date/Author: 2026-07-27 / Codex.

## Outcomes & Retrospective

The implementation adds Scala source-JAR extraction, a Scala-owned lazy shared index, and a conservative semantic diagnostic collector. Java remains a consumer of the shared archive index. Review follow-ups make archive indexing fail closed under aggregate resource limits, cover default scopes and same-package singleton terms, and verify the published LSP diagnostic payload. Formatter, focused index/Scala/LSP tests, strict Clippy, the feature-enabled test suite, and whitespace validation completed successfully. The branch is `364-add-high-confidence-scala-unrecognized-symbol-diagnostics` and has an unrelated untracked `.brokk/` directory that this work preserved.

## Context and Orientation

`src/analyzer/i_analyzer.rs` defines `IAnalyzer`, including the `semantic_diagnostics` extension point. `src/analyzer/multi_analyzer.rs` delegates that call to the language analyzer, and `src/lsp/handlers/diagnostic.rs` converts semantic diagnostics into LSP pull and push diagnostic items only when the global `unrecognizedSymbolDiagnostics` option is enabled. The option and VS Code setting already exist; Scala needs only a language implementation.

`src/analyzer/scala/mod.rs` owns `ScalaAnalyzer`. Its `imports.rs` module provides source-backed explicit import, wildcard import, and same-package knowledge. The forward-definition implementation in `src/analyzer/usages/get_definition/scala.rs` has richer resolver behavior, including lexical and implicit-namespace precedence, but it is navigation code. The diagnostic collector must use shared Scala structures or narrowly extracted helpers; it must not reparse text with regular expressions or copy a private navigation resolver.

`src/analyzer/java/external.rs` currently builds `JavaExternalDeclarationIndex`. It reads exact dependency artifacts from the public `AnalyzerConfig.java` configuration, including bounded Maven/Gradle metadata discovery in `src/analyzer/java/dependency_discovery.rs`. It keeps `JavaExternalType` records outside normal workspace declarations. The index handles Java source JARs and JVM classfiles. `src/analyzer/java/imports.rs` consumes it for Java imports. `JavaAnalyzer::update` invalidates the lazy index when `is_java_dependency_input` reports a manifest or related dependency file change.

A JVM external type is a dependency type whose fully qualified name and access visibility are known from an archive but which is not a source file in the workspace. A source JAR is an archive containing source files, conventionally `*-sources.jar`; a classfile is compiled JVM bytecode, conventionally a `.class` entry in an ordinary JAR. For #364, both may prove that a type exists. Neither alone proves a method call, implicit conversion, given instance, or dynamically selected member exists.

## Plan of Work

First create `src/analyzer/jvm/mod.rs` and `src/analyzer/jvm/external.rs`, then register the module from `src/analyzer/mod.rs`. Move the archive bounds, exact artifact resolution, classfile parser, external type model, and public crate-private lookup operations out of `src/analyzer/java/external.rs`. Rename the model to JVM terminology such as `JvmExternalDeclarationIndex`, `JvmExternalType`, `JvmExternalTypeKind`, `JvmVisibility`, and `JvmExternalDeclarationSource`; update Java imports and tests in the same change. Keep `JavaAnalyzerConfig` as the existing public configuration owner for this milestone, because it already represents the JVM artifact/discovery inputs and changing public configuration names would be unrelated scope.

Keep Java dependency discovery in `src/analyzer/java/dependency_discovery.rs` initially, but make its discovered input merge callable by the shared index through a narrow crate-private function or move only the discovery-independent artifact builder to `src/analyzer/jvm`. The shared builder must accept the existing Java configuration and `Project`, merge the same safe/trusted discovery results, and retain the exact cache-bounded behavior. Java source-JAR parsing can remain a Java-specific parser helper invoked by the shared index; do not weaken Java visibility rules or index source archives twice.

Add a Scala source-JAR parser helper under `src/analyzer/scala`, called only by the shared index. It must use the tree-sitter Scala grammar and structured declaration/package nodes to collect only source declarations whose fully qualified type identity is unambiguous. Record `SourceJar` provenance with the archive and source-entry path. If the source is malformed, a package/declaration is ambiguous, an object-only source form cannot safely prove a type, or the source parser does not support the form, return no record and allow the existing classfile path to prove the type. Preserve source-over-classfile precedence only for a matching fully qualified name; never invent a name from an archive path.

Give `ScalaAnalyzer` a cloneable copy of the existing JVM dependency configuration and a lazy `OnceLock<JvmExternalDeclarationIndex>`, constructed with the Scala analyzer project. Update every Scala constructor, `clone_with_project`, `update`, and `update_all` so ordinary Scala source changes reuse the index while Java dependency-input changes allocate a fresh lock. Extend `AnalyzerDelegate::needs_config_update_for` so the Scala delegate receives the same manifest changes in a mixed workspace. Provide narrow Scala methods that answer whether a simple or qualified external type is definitely accessible through an explicit import, wildcard import, same package, or a modeled default package. They must return a three-way result where unresolved or conflicting evidence is distinguishable from definitely absent evidence.

Create `src/analyzer/scala/diagnostics.rs`. Follow the iterative, bounded collector pattern in `src/analyzer/rust/diagnostics.rs`, but use the Scala grammar and Scala helper APIs. First reject source over the configured byte limit and any tree containing a parse error. Then traverse with an explicit stack, tracking lexical value and type declarations separately in the order their scopes make visible. Inspect only leaf identifiers that a structured parent/field relationship proves are bare type or bare term reference positions. Do not inspect declaration names, parameter or pattern binders, package/import segments, symbol literals, keywords, named/member selectors, interpolation/dynamic constructs, or qualified paths whose root cannot be resolved exactly.

For each eligible reference, consult local lexical bindings, the current file's declarations, source-backed same-package declarations, explicit imports, wildcard imports, and the shared JVM type index. Model only the default symbols that Bifrost can prove from a present external index or an explicit, documented intrinsic set. If an unresolved import, wildcard collision, missing default/classpath source, implicit/given lookup, type-inference-dependent form, or external term/member boundary could explain the reference, treat the result as uncertain and emit nothing. Emit `scala_unrecognized_symbol` with source `bifrost-scala` only when every lookup is complete and the name is absent. Cap reports to prevent editor floods.

Wire the collector from `ScalaAnalyzer`'s `IAnalyzer` implementation by mapping a Scala diagnostic model into `SemanticDiagnostic`. Do not change `MultiAnalyzer`, LSP option parsing, or VS Code settings unless a Scala-specific integration test proves a gap.

Keep unit tests close to the code they exercise. Add index tests beside `src/analyzer/jvm/external.rs`, reusing safe generated-archive fixtures. Add Scala source-JAR tests that write an archive containing Scala source without relying on a local Scala compiler, and classfile fallback tests that reuse generated JVM class archives because classfile identity is language-neutral. Add collector tests in `src/analyzer/scala/diagnostics.rs` using `InlineTestProject`: an unknown local value and unknown simple type must report; lexical bindings, same-package types, aliases, explicit and wildcard imports, parser errors, declaration/binder names, member selectors, and uncertain imports must not. Add an external-type test configuring an artifact and asserting the Scala type is suppressed when source-JAR or classfile evidence exists, and remains suppressed when the classpath cannot be built. Extend `tests/bifrost_lsp_server.rs` with one Scala pull/push test that proves the existing global option gates the new diagnostic.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/1bb0/bifrost` on the existing issue branch. Do not switch branches, rebase, touch `.brokk/`, or stage unrelated files.

Milestone 1 is the JVM-index extraction. Move and rename only the external-index implementation and its direct imports, then run:

    cargo test jvm_external --lib
    cargo test java_external_declaration --lib
    cargo test --test java_imports_and_hierarchy java_external

The existing Java artifact resolution tests must continue to pass with the new module names. Update this ExecPlan's Progress, Discoveries, Decision Log, and bottom revision note, then create a multiline checkpoint commit containing only the milestone files.

Milestone 2 adds Scala source-JAR evidence plus Scala ownership of the lazy shared index. Run the focused index and Scala import tests:

    cargo test jvm_external --lib
    BIFROST_SEMANTIC_INDEX=off cargo test --test scala_import_test
    BIFROST_SEMANTIC_INDEX=off cargo test --test scala_analyzer_test

The source-JAR test must show Scala source provenance when parsable. A matching classfile must still make the type known when Scala source is absent or rejected. Update this plan and create a second checkpoint commit.

Milestone 3 adds the diagnostic collector and its LSP proof. Run:

    cargo test scala_semantic_diagnostics --lib
    BIFROST_SEMANTIC_INDEX=off cargo test --test bifrost_lsp_server scala_semantic_diagnostics

The collector test must show an exact `scala_unrecognized_symbol` for a known-missing simple type/value and no warning for every listed suppression scenario. The LSP test must show no semantic warning with the option disabled and the Scala diagnostic after enabling it. Update this plan and create a third checkpoint commit.

Finish with the required Rust gates from the repository instructions:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python
    git diff --check

If a command fails because the host has no JDK for existing generated-JAR tests, record that environment failure in this plan and run all independent Scala/collector tests; do not replace classfile tests with unchecked fixtures. If a source JAR cannot be parsed, retain the classfile fallback and add a regression that confirms diagnostics remain suppressed rather than guessing.

## Validation and Acceptance

The completed implementation is accepted when the following behaviors are demonstrated by tests:

1. A dependency type represented by parsable Scala source in a supplied source JAR is known to Scala and records source-JAR provenance. The same type remains known from a supplied classfile JAR when the source archive is missing or unparseable.
2. Existing Java external type resolution still recognizes explicit imports, wildcard imports, same-package types, `java.lang` defaults, artifact discovery, access visibility, and index invalidation exactly as before the extraction.
3. In a clean Scala document with complete source and classpath knowledge, an undeclared bare local value and an undeclared simple type produce `scala_unrecognized_symbol` from `bifrost-scala` when `unrecognizedSymbolDiagnostics` is enabled.
4. Local bindings, project declarations, same-package declarations, explicit imports, wildcard imports, modeled defaults, and configured external JVM types produce no Scala unrecognized-symbol diagnostic.
5. Malformed files, import ambiguity, unresolved imports, unknown classpath/default availability, implicit/given or inference-sensitive expressions, member selectors, and dynamic/interpolated forms produce no Scala semantic diagnostic.
6. Pull diagnostics and publish diagnostics honor the existing runtime option; disabling it removes only the semantic warning and retains parser diagnostics.

## Idempotence and Recovery

All archive fixtures must use test temporary directories and no binary artifact is committed. The shared index performs bounded, read-only archive access and uses the existing exact dependency configuration; it must never scan an entire Maven or Gradle cache. Re-running a focused test should recreate its temporary project and archive independently.

If the extraction breaks Java behavior, restore the Java consumer against the shared index before beginning Scala diagnostics; do not leave a duplicate Java and Scala artifact parser. If a new Scala source-JAR declaration cannot be represented without source-text heuristics, skip it and use the classfile path. If collector classification is uncertain, make the collector silent and add a regression; never add a regex or text-splitting fallback.

## Artifacts and Notes

Starting state:

    git status --short --branch
    ## 364-add-high-confidence-scala-unrecognized-symbol-diagnostics...origin/364-add-high-confidence-scala-unrecognized-symbol-diagnostics
    ?? .brokk/

    git rev-list --left-right --count HEAD...origin/master
    0 0

The untracked `.brokk/` directory predates this task and must remain unmodified.

## Interfaces and Dependencies

At the end of Milestone 1, the shared module must provide a crate-private interface equivalent to:

    pub(crate) struct JvmExternalDeclarationIndex { ... }

    impl JvmExternalDeclarationIndex {
        fn build_for_project(config: &JavaAnalyzerConfig, project: &dyn Project) -> Self;
        fn is_empty(&self) -> bool;
        fn resolve_qualified_name(&self, fqn: &str, access_package: &str) -> Option<&JvmExternalType>;
        fn resolve_explicit_import(&self, import_path: &str, access_package: &str) -> Option<&JvmExternalType>;
        fn resolve_wildcard_import(&self, package_name: &str, short_name: &str, access_package: &str) -> Option<&JvmExternalType>;
        fn resolve_same_package(&self, package_name: &str, short_name: &str) -> Option<&JvmExternalType>;
        fn resolve_java_lang(&self, short_name: &str) -> Option<&JvmExternalType>;
    }

`JvmExternalType` must retain a fully qualified name, package, simple name, kind, effective visibility, and `JvmExternalDeclarationSource`. The source enum must distinguish `SourceJar { artifact_path, source_path }` from `ClassFile { artifact_path, class_entry }`. A source record wins only for an identical FQN; no source record may erase a distinct classfile type.

At the end of Milestone 2, `ScalaAnalyzer` must own `JavaAnalyzerConfig` (or the smallest extracted immutable JVM dependency configuration) and `Arc<OnceLock<JvmExternalDeclarationIndex>>`, preserve both across normal snapshots, and reset the lock after `is_java_dependency_input` changes or a full refresh. The Scala external-knownness helper must represent resolved, absent, and uncertain results distinctly.

At the end of Milestone 3, `src/analyzer/scala/diagnostics.rs` must export:

    pub(crate) const SCALA_UNRECOGNIZED_SYMBOL: &str = "scala_unrecognized_symbol";
    pub(crate) const SCALA_SEMANTIC_DIAGNOSTIC_SOURCE: &str = "bifrost-scala";
    pub(crate) fn collect_scala_semantic_diagnostics(
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> Vec<ScalaSemanticDiagnostic>;

`ScalaSemanticDiagnostic` must convert into the existing `SemanticDiagnostic` type. The collector must use tree-sitter nodes and established analyzer structures, with an iterative traversal and explicit lexical scope state. No new network client, Scala compiler process, classpath crawler, or source-text parser is permitted.

Revision note, 2026-07-27: Initial approved ExecPlan created after live issue #364 diagnosis and planning. It records that the current source-JAR reader is Java-only and that Scala diagnostic confidence depends on extracting a single shared JVM external index.

Revision note, 2026-07-27: Completed the first mechanical extraction checkpoint. The index now lives under `src/analyzer/jvm`; Java behavior remains covered by its pre-existing focused tests. Kept legacy private type names temporarily to isolate the ownership move from the later Scala-facing design work.

Revision note, 2026-07-27: Added source-JAR parsing for parser-clean public Scala declarations, Scala lazy-index ownership and invalidation, the first conservative type/bare-local diagnostic shapes, and focused unit/integration/LSP tests. Left call, member, qualified, interpolation, and implicit/given-sensitive forms intentionally silent.

Revision note, 2026-07-27: Review follow-ups bound shared-index aggregate archive work and Scala source expansion, suppress default Scala/`java.lang` types and same-package singleton terms, and assert the Scala publish-diagnostics payload. Full required Rust gates passed after these changes.

Revision note, 2026-07-27: The first PR CI run exposed compile-only visibility fallout from relocating Java-owned tests into the sibling JVM module. Restored the narrow crate-private test seams, corrected the Scala archive fixture byte type, and imported the established Scala import-analysis capability before rerunning the strict local gate.

Revision note, 2026-07-27: The CI rerun exposed the remaining production helper paths that had retained their former Java-child visibility. Made only the moved index's declaration and dependency-discovery helpers crate-private, and corrected its Scala module paths before a final CI rerun.

Revision note, 2026-07-27: The final CI log isolated one remaining `pub(super)` method on the dependency discovery result. Widened that same internal merge seam to `pub(crate)`; no analyzer behavior changed.
