# Kotlin: packages, imports, hierarchy, and JVM artifacts (#1237)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` (repository-root relative path), the canonical rules for ExecPlans.

Tracking issue: https://github.com/BrokkAi/bifrost/issues/1237 (child of epic #1234, depends on #1236, coordinates with #1239).

## Purpose / Big Picture

Bifrost is a code-intelligence engine. It parses source files with tree-sitter grammars, extracts a language-neutral model of declarations (`CodeUnit`s: classes, functions, fields), and serves search, summaries, skeletons, navigation, and usage analysis over that model.

Issue #1236 made Kotlin a real *indexing* language: `.kt` and `.kts` files are detected, parsed, and indexed, and `get_definitions("com.example.Foo.bar")` returns the Kotlin function. But Kotlin today knows nothing about *names that come from somewhere else*. A Kotlin file's `import` lines are recorded as display strings only. A Kotlin class that writes `: Base` has no ancestor. A Kotlin file that uses a class from a Maven jar cannot tell that the name exists. And Kotlin sits outside the JVM "realm" that Java and Scala already share, so a Kotlin declaration is invisible to Java/Scala tooling and vice versa.

After this change:

* A Kotlin file's imports are structured facts (explicit, star, aliased) that resolve to real declarations, so `imported_code_units_of` returns the Kotlin, Java, or Scala declarations that a Kotlin file actually pulls in.
* `get_direct_ancestors` on a Kotlin class returns the classes and interfaces it extends or implements, resolved through the same import/package/nesting tiers Kotlin's own compiler uses.
* A Kotlin file that imports `com.example.dep.ExternalService` from a Maven or Gradle jar reports that name as *known* even with no workspace declaration for it, exactly as Java already does.
* Java, Scala, and Kotlin declarations live in one explicitly modeled JVM realm: one dependency universe (the jar index) and one usage-candidate universe (`UsageEcosystem::Jvm`), rather than three isolated ecosystems joined by pairwise bridges.

How to see it working: the tests in `tests/kotlin_imports_and_hierarchy.rs` and `tests/jvm_shared_realm.rs` (both new) fail before this change and pass after. Concretely, `cargo test --features nlp,python --test kotlin_imports_and_hierarchy` goes from "no such test target" to all tests passing, and the shared-realm test proves a Kotlin class extending a Java interface in the same workspace resolves to the Java `CodeUnit`.

## Progress

- [x] (2026-07-29) Research pass over the existing Java, Scala, and Kotlin analyzers, the JVM external-declaration index, and the workspace usage graph.
- [x] (2026-07-29) ExecPlan authored.
- [x] (2026-07-29) M1: Generalize the JVM external declaration index and dependency plumbing to cover Kotlin.
- [x] (2026-07-29) M2: Kotlin structured imports and `ImportAnalysisProvider`.
- [x] (2026-07-29) M3: Kotlin supertypes, type-name resolution, and `TypeHierarchyProvider`.
- [x] (2026-07-29) M4: Shared JVM usage-candidate realm (`UsageEcosystem::Jvm`).
- [x] (2026-07-29) M5: Cross-language JVM source realm resolution.
- [x] (2026-07-29) M6: Explicit unsupported outcomes, epoch bump, and full validation.

Use timestamps to measure rates of progress.

## Surprises & Discoveries

- Observation: `SourceJarLanguage` in `src/analyzer/jvm/external.rs` already proves the "one JVM index, several source languages" shape — it indexes `.java` and `.scala` entries from a single `-sources.jar` walk. Adding Kotlin is an extension of an existing seam, not a new subsystem.
  Evidence: `src/analyzer/jvm/external.rs` `index_source_jar` matches on entry suffix and dispatches to `source_types` or `scala_source_types`.

- Observation: The per-language edge builders in the workspace usage graph only ever scan files of their own language (`JavaEdgeResolver::try_new` calls `project.analyzable_files(Language::Java)`), so merging Java and Scala into one `UsageEcosystem` cannot double-count edges: the two builders write into one node space from disjoint file sets.
  Evidence: `src/analyzer/usages/java_graph/shared.rs:123-137`.

- Observation: `cargo clippy` cannot be run bare in this environment. Two rustc 1.96.0 installs exist (rustup under `~/.cargo/bin`, Homebrew under `/opt/homebrew/bin`); `cargo` resolves to rustup's but `cargo-clippy` resolves to Homebrew's, and the mismatch fails the build script. A clean target directory does not help, including via `scripts/with-isolated-cargo-target.sh`.
  Evidence: `error[E0514]: found crate 'cc' compiled by an incompatible version of rustc`. The working invocation is `PATH="$HOME/.cargo/bin:$PATH" cargo clippy --all-targets --all-features -- -D warnings`.

- Observation: `--features nlp,python` could not link during most of this work, so validation ran on `--features nlp` (which gates every suite this plan touches). Merging `origin/master` fixed it: #1295 stopped enabling `extension-module` for test builds, which was suppressing libpython linkage and producing hundreds of undefined `_Py*` symbols. The merge also introduced an `abi3-py312` floor, so pyo3's build script now rejects the macOS system `python3` (3.9) that wins the `PATH` lookup. The full gate therefore runs as `PYO3_PYTHON=$(brew --prefix python@3.13)/bin/python3.13 cargo test --features nlp,python`, exactly as the merged `CLAUDE.md` documents.
  Evidence: before the merge, `ld: symbol(s) not found for architecture arm64` on `_Py_InitializeEx`; after it, `cannot set a minimum Python version 3.12 higher than the interpreter version 3.9` until `PYO3_PYTHON` is set. Note this also applies to `cargo clippy --all-features`, which enables `python` and hits the same build script.

- Observation: The full-suite gate ran out of disk twice before completing. The machine's data volume was at 100% (121 MiB free) with 74 GB in this worktree's `target/`, 216 GB in a sibling worktree's, and 47 GB in two intentionally-retained isolated targets under `/private/tmp`. Deleting this worktree's `target/debug/incremental` (34 GB, pure regenerable cargo cache) was enough to finish; nothing outside this worktree was touched.
  Evidence: `error: failed to build archive ...: No space left on device (os error 28)`. `scripts/cleanup-bifrost-tmp.sh` reported only "skip retained" and "skip unmanaged" candidates, so it could not help without an explicit review of those directories.

- Observation: Editing any file under `src/` while a `cargo test` build is in flight silently invalidates the run — the build restarts and the earlier output is lost. Two full-suite attempts were wasted this way before the tree was frozen for the final run.
  Evidence: a `cargo test` background task that had been compiling for minutes exited without producing a single `test result:` line after an unrelated doc-comment edit landed mid-build.

- Observation: The full suite caught two real defects that every targeted suite had missed. First, `ImportAnalysisProvider` was implemented for `KotlinAnalyzer` and wired into `AnalyzerDelegate`, but `IAnalyzer::import_analysis_provider` was left at its default `None` — so a Kotlin analyzer reached through `&dyn IAnalyzer` reported having no import analysis, and the capability worked only via the concrete type or `MultiAnalyzer`. Second, the new module docs illustrated Kotlin syntax with indented blocks, which rustdoc compiles as Rust doctests.
  Evidence: `assertion failed: kotlin.import_analysis_provider().is_some()` in `analyzer_capability_parity`, and `expected one of ! or ::` on `class Child : Base(seed), Contract, Logged by logger` in the `--doc` target. The capability-parity matrix exists precisely to catch the first shape; the fix for the second is a `text` fence.

- Observation: A `cargo test` summary that counts `test result:` lines can report a clean run that actually failed. A doctest failure emits no such line, so a run showing `ok targets: 306, FAILED targets: 0` still exited 101 with `--doc` broken. Always check the process exit code and grep for target-level `error:` lines as well.
  Evidence: `EXIT=101` alongside `FAILED targets: 0`, resolved only by reading the log tail down to `error: 1 target failed: --doc`.

- Observation: Passing a larger candidate-fqn set to an existing builder is inert rather than dangerous, because each language's resolver can only resolve names through its own declaration index. Merging the ecosystems therefore preserves today's edges exactly while establishing the shared node space that #1239 will fill in.
  Evidence: `JavaAnalyzer::source_type_by_fqn` reads `self.inner.global_usage_definition_index()`, which is scoped to the Java delegate's own files.

## Decision Log

- Decision: Rename the JVM external-declaration types from `Java*` to `Jvm*` (`JvmExternalDeclarationIndex`, `JvmExternalType`, `JvmExternalTypeKind`, `JvmVisibility`, `JvmExternalDeclarationSource`), rename `JavaAnalyzerConfig` and friends to `JvmAnalyzerConfig` / `JvmExternalDependencies` / `JvmMavenCoordinate` / `JvmDependencyDiscovery*`, move `src/analyzer/java/dependency_discovery.rs` to `src/analyzer/jvm/dependency_discovery.rs`, and rename `AnalyzerConfig::java` to `AnalyzerConfig::jvm`.
  Rationale: the issue explicitly asks for `JavaExternalDeclarationIndex` and `SourceJarLanguage` to be *generalized* rather than copied. Three languages now share this index and this configuration; a `Java`-prefixed name would misdescribe the contract and invite a Kotlin-only copy later. `CLAUDE.md` states backwards compatibility is not yet a concern and that APIs should be cleaned up when requirements change. Only four source files and two integration tests touch these names.
  Date/Author: 2026-07-29, David Baker Effendi (via agent).

- Decision: Model Kotlin's type resolution on `JavaAnalyzer`'s tier ladder (qualified name, explicit/aliased import, star import, same package, default imports, external jar index) rather than on Scala's `ScalaNameResolver`/`ScalaProjectTypes` machinery.
  Rationale: Kotlin's name resolution is Java-shaped — a flat package namespace with file-level imports and no `import` inside a scope, no `given`/`export`, no path-dependent types. Scala's resolver exists to model lexical package clauses, nested package scoping, and wildcard shadowing tiers Kotlin does not have. Reusing the simpler ladder keeps the Kotlin resolver honest and reviewable.
  Date/Author: 2026-07-29, David Baker Effendi (via agent).

- Decision: Represent the shared JVM realm at the *ecosystem* level (`UsageEcosystem::Jvm` replacing `Java` and `Scala`, and now also covering Kotlin) while keeping every node's *source language* on the node itself.
  Rationale: the issue requires one candidate universe but explicitly forbids collapsing source-language identities. Keying the catalog on the realm gives Java, Scala, and Kotlin one node space; carrying `Language` on the node keeps `usage_graph` output able to say `java`, `scala`, or `kotlin` per node.
  Date/Author: 2026-07-29, David Baker Effendi (via agent).

- Decision: Cross-language *source* resolution in this issue is delivered as a query-time realm view (`src/analyzer/jvm/realm.rs`) that Kotlin consults, not as back-references stored inside each analyzer.
  Rationale: `MultiAnalyzer` owns the per-language delegates; storing sibling analyzers inside each delegate would create `Arc` cycles between Java, Scala, and Kotlin (`CLAUDE.md` warns against naive reference counting). A view constructed from `&dyn IAnalyzer` at the `MultiAnalyzer` boundary — the same `resolve_analyzer::<T>` precedent `src/analyzer/usages/java_graph/jvm_scala.rs` already uses — has no ownership at all.
  Date/Author: 2026-07-29, David Baker Effendi (via agent).

- Decision: `KotlinAnalyzer::referencing_files_of` stays Kotlin-to-Kotlin even under a multi-language analyzer, rather than becoming half realm-aware.
  Rationale: the index has two halves. The import half could consult the realm view, but the same-package half needs each JVM member's files and top-level declarations, which the realm's forward-query surface does not expose. Counting imports while silently dropping same-package references would be a worse answer than a clearly bounded one, so the whole question goes to #1239 with the rest of the usage-graph work. The boundary is stated on the method itself so a reader does not mistake it for an omission.
  Date/Author: 2026-07-29, David Baker Effendi (via agent).

- Decision: `MultiAnalyzer::get_direct_descendants` unions the owning language's answer with Kotlin's realm-aware descendant index, so a Java interface reports its Kotlin implementors.
  Rationale: this was the one cross-language direction reachable without touching Java's or Scala's resolvers, because Kotlin's own index already resolves across the realm — only the *query entry point* needed widening. The reverse direction (Java or Scala subclasses of a Kotlin type) does need those resolvers to become realm-aware, and stays with #1239.
  Date/Author: 2026-07-29, David Baker Effendi (via agent).

- Decision: Realm-aware and realm-less results are cached in separate slots on `KotlinAnalyzer` rather than one shared slot.
  Rationale: they answer strictly different questions. Serving a Kotlin-only cache entry to a caller that can see Java and Scala declarations would silently drop cross-language results; serving the wider entry to a bare `KotlinAnalyzer` would invent them. Two small caches are cheaper than either bug.
  Date/Author: 2026-07-29, David Baker Effendi (via agent).

- Decision: Java's and Scala's own hierarchy/import resolvers are *not* rewritten to consume the realm view in this issue; only Kotlin's are realm-aware.
  Rationale: #1239 owns the reference/usage/call-graph implementation over the shared JVM model, and rewriting Java's batched descendant index and Scala's lazy hierarchy index is that issue's blast radius, not this one's. This issue's Java/Scala-facing obligations — one dependency realm, one candidate realm, stable Kotlin identities consumable from both — are met without touching those resolvers. Recorded here so the next contributor does not read the omission as an oversight.
  Date/Author: 2026-07-29, David Baker Effendi (via agent).

## Outcomes & Retrospective

### 2026-07-29 — all six milestones complete

What now works that did not before. A Kotlin file's imports are structured
facts that resolve to declarations, in every form Kotlin has (explicit,
aliased, star over a package, star over an object-like owner, and paths
reaching nested types or object members). A Kotlin class's supertypes resolve
through the full ladder: same package, explicit import, alias, star import,
fully-qualified, nested owner path, lexically enclosing scope, and inherited
nested scope. Descendants invert all of it. A Kotlin file can tell whether a
name from a Maven or Gradle artifact exists, reading the same jar-backed index
Java and Scala use, which now indexes `.kt` entries in source jars. Java,
Scala, and Kotlin share one `UsageEcosystem::Jvm` candidate space while each
node keeps its own source language. And across languages, a Kotlin class
resolves a Java interface or a Scala trait declared next door, while a Java
interface reports its Kotlin implementors.

What the shape of the work turned out to be. Three of the six milestones were
mostly *removal of a special case* rather than addition: `SourceJarLanguage`
already had the "one archive, several languages" shape, `raw_supertypes` was
already the language-neutral slot Java and Go used, and the per-language edge
builders were already scoped to their own files, which is what made merging the
ecosystems safe. The genuinely new pieces were Kotlin's resolution ladder and
the realm view.

The one design question that took real thought was how a Kotlin analyzer could
see Java and Scala declarations without owning them. Storing sibling handles
would have made the three JVM analyzers mutually reference-counted and every
cycle would leak. Building the view per query from `&dyn IAnalyzer` owns
nothing and follows a precedent the Java↔Scala usage scan had already set. The
cost is that realm-aware and realm-less answers need separate cache slots,
which is cheap and, once written down, obvious.

What remains, all owned by named issues. Kotlin has no usage-edge builder, so
it is a realm member with no outbound edges (#1239). Java's and Scala's own
resolvers are not realm-aware, so Java and Scala subclasses of a Kotlin type do
not resolve (#1239). `referencing_files_of` stays Kotlin-to-Kotlin for the
reason in the Decision Log (#1239). Kotlin/JS and Kotlin/Native default imports
are not modelled, and `expect`/`actual` pairs are indexed with no link asserted
between them — both are tested as explicit outcomes rather than left to chance.

Two lessons about validation, both learned the expensive way. Targeted suites
proved every capability this plan set out to add and still missed two real
defects, because neither lived in the feature's own behaviour: one was a
capability the analyzer had but did not *advertise* through its trait object,
and one was a doc comment. Only the whole-suite run reaches those. And a
whole-suite run has to be judged by its exit code, not by counting passing
targets — the doctest failure produced no `test result` line at all.

Lesson worth carrying forward: writing the "what this deliberately does not do"
tests at the same time as the capability tests was what kept the boundaries
honest. Three of them (ambiguous star imports, an unconfigured classpath, a
supertype from a jar) turned out to describe behaviour that is easy to get
subtly wrong in the direction of over-claiming, and having them as assertions
rather than comments is what makes that stick.

## Context and Orientation

Everything below is relative to the repository root. Read this section even if the file names look familiar; several of them are renamed by this plan.

### What already exists

`src/analyzer/kotlin/` holds the Kotlin analyzer from issue #1236:

* `language.rs` exposes the pinned Kotlin tree-sitter grammar vendored under `vendor/tree-sitter-kotlin/` as `crate::analyzer::kotlin::language::LANGUAGE`.
* `declarations.rs` walks the syntax tree and produces a `ParsedFile` — the language-neutral per-file result: package name, declarations, ranges, ownership, signatures. It currently records imports only as raw display strings (`ParsedFile::import_statements`), not as structured facts.
* `adapter.rs` is the `LanguageAdapter` implementation the shared tree-sitter engine calls.
* `mod.rs` is `KotlinAnalyzer`, a thin wrapper that forwards nearly every `IAnalyzer` method to `TreeSitterAnalyzer<KotlinAdapter>`.

`src/analyzer/tree_sitter_analyzer.rs` defines `ParsedFile`. The fields that matter here are `imports: Vec<ImportInfo>` (structured import facts), `raw_supertypes: HashMap<CodeUnit, Vec<String>>` (the display text of each declared supertype), `supertype_lookup_paths: HashMap<CodeUnit, Vec<String>>` (an opaque per-language encoding of how to *resolve* each supertype), and `type_identifiers: HashSet<String>` (every type name spelled anywhere in the file, used to build a cheap same-package reference index). All four are persisted by `src/analyzer/store/mod.rs` in a language-agnostic way, so a language only has to populate them.

`ImportInfo` and `StructuredImportPath` live in `src/analyzer/model.rs`. `ImportInfo` has `raw_snippet` (display text), `is_wildcard`, `identifier` (the name the import binds), `alias`, and `path: Option<StructuredImportPath>`. `StructuredImportPath` has `segments: Vec<String>` (the dotted path, one entry per segment), plus lexical-scope fields that Kotlin does not need (Kotlin has no scoped imports).

`src/analyzer/capabilities.rs` defines the capability traits. `ImportAnalysisProvider` answers "what does this file import" and "which files reference this file". `TypeHierarchyProvider` answers `get_direct_ancestors` and `get_direct_descendants`; the helper `build_direct_descendant_index_from_candidates` inverts ancestors into a compact descendant index.

`src/analyzer/jvm/external.rs` is the shared JVM *dependency* index. Given configured Maven coordinates, explicit jar paths, or paths discovered from build metadata, it opens each jar and records the public types it declares. It reads `.class` entries with the `jclassfile` crate and `.java`/`.scala` entries from `-sources.jar` archives with tree-sitter. The result answers questions like "does `com.example.dep.ExternalService` exist and is it visible from package `app`" without any workspace declaration. Java and Scala both consult it; Kotlin does not.

`src/analyzer/java/dependency_discovery.rs` finds those jars: it parses `pom.xml`, Gradle lockfiles, and (in `OfflineBuildTools` mode) shells out to `mvn`/`gradle`. It already recognises `build.gradle.kts` and `settings.gradle.kts`, so Kotlin-built projects are already discovered — the file is simply misfiled under `java/`.

`src/analyzer/usages/workspace_graph.rs` defines `UsageEcosystem`, the coarse grouping that decides which resolver builds edges for which declarations, and `WorkspaceUsageCatalog`, which assigns every class/callable declaration a node keyed by `(ecosystem, fqn, optional defining file)`. Today `Java` and `Scala` are separate variants and `Kotlin` maps to `Unknown`.

`src/analyzer/usages/java_graph/jvm_scala.rs` is the existing cross-language precedent: when someone asks for usages of a Java type, it also scans Scala files for references to it. The issue asks for this to be generalized rather than duplicated as `java_kotlin` and `scala_kotlin`.

`src/analyzer/multi_analyzer.rs` defines `AnalyzerDelegate` (one analyzer per language) and `MultiAnalyzer` (routes each request to the delegate that owns the file or code unit). Kotlin's `import_analysis_provider()` and `type_hierarchy_provider()` currently return `None` with a comment pointing at this issue.

`src/analyzer/store/epoch.rs` computes a per-language "analysis epoch": a fingerprint of everything that would invalidate persisted analyzer output. It includes a manual `SALT` string per language, bumped whenever analyzer code changes the identities or facts a language emits without changing the grammar.

### Terms used in this plan

* **CodeUnit** — Bifrost's identity for one declaration: its file, kind (class/function/field), package, short name, and fully-qualified name.
* **fq name / fqn** — the dotted fully-qualified name of a declaration, e.g. `com.example.Outer.Inner.method`.
* **Realm** — the set of languages that share one name universe. The JVM realm is Java + Scala + Kotlin: a class compiled from any of them is the same kind of thing on the classpath, and code in any of them can name a class from the others.
* **Source jar** — a `-sources.jar` archive published alongside a compiled jar, containing the library's original source files.
* **Delegation specifier** — Kotlin's grammar name for an entry in the `: A, B by c` list after a class header. It covers superclasses, implemented interfaces, and interface delegation.
* **Star import** — Kotlin's `import a.b.*`, the equivalent of Java's `import a.b.*`.
* **Default imports** — the packages Kotlin implicitly imports into every file, e.g. `kotlin.collections.*`. No `import` line appears in the source, but the names are visible.

### Kotlin grammar facts this plan depends on

Verified against `vendor/tree-sitter-kotlin/grammar.js`:

* `source_file` → optional `package_header`, optional `import_list`, then statements.
* `package_header` → `"package"` then an `identifier` node whose named children are `simple_identifier` nodes, one per dotted segment.
* `import_list` → one or more `import_header`.
* `import_header` → `"import"`, an `identifier` node (aliased from `_import_identifier`, again one `simple_identifier` named child per segment), then optionally either a `wildcard_import` node (the literal `*`) or an `import_alias` node (`"as"` then a `type_identifier`).
* `class_declaration`, `object_declaration`, and `companion_object` each optionally carry `":" _delegation_specifiers`, a comma-separated list of `delegation_specifier` nodes.
* `delegation_specifier` → one of `constructor_invocation` (a `user_type` plus `value_arguments`), `explicit_delegation` (a `user_type` or `function_type`, then `by`, then an expression), a bare `user_type`, or a function type.
* `user_type` → dot-separated `_simple_user_type`s; its named children are `type_identifier` nodes plus optional `type_arguments` nodes.
* `enum_entry` → optional modifiers, a `simple_identifier`, optional `value_arguments`, optional `class_body`.

## Plan of Work

### Milestone 1 — Generalize the JVM dependency realm to include Kotlin

**Scope.** After this milestone the shared JVM dependency index is named for what it is, lives in one place, and understands Kotlin sources inside source jars. Nothing about Kotlin *analysis* changes yet; the proof is that a Kotlin `-sources.jar` contributes types to the index and that Java and Scala behaviour is unchanged.

**Work.**

Rename, in `src/analyzer/jvm/external.rs`: `JavaExternalDeclarationIndex` → `JvmExternalDeclarationIndex`, `JavaExternalType` → `JvmExternalType`, `JavaExternalTypeKind` → `JvmExternalTypeKind`, `JavaVisibility` → `JvmVisibility`, `JavaExternalDeclarationSource` → `JvmExternalDeclarationSource`, `ResolvedJavaArtifact` → `ResolvedJvmArtifact`. Update the four consumers: `src/analyzer/java/mod.rs`, `src/analyzer/java/imports.rs`, `src/analyzer/scala/mod.rs`, and `src/analyzer/jvm/external.rs` itself.

Rename, in `src/analyzer/config.rs`: `JavaAnalyzerConfig` → `JvmAnalyzerConfig`, `JavaExternalDependencies` → `JvmExternalDependencies`, `JavaExternalArtifact` → `JvmExternalArtifact`, `JavaMavenCoordinate` → `JvmMavenCoordinate`, `JavaDependencyDiscoveryMode` → `JvmDependencyDiscoveryMode`, `JavaDependencyDiscoveryConfig` → `JvmDependencyDiscoveryConfig`, and the `AnalyzerConfig::java` field → `AnalyzerConfig::jvm`. Re-export the new names from `src/analyzer/mod.rs` and `src/lib.rs`, and update `tests/java_imports_and_hierarchy.rs` and `tests/scala_semantic_diagnostics.rs`.

Move `src/analyzer/java/dependency_discovery.rs` to `src/analyzer/jvm/dependency_discovery.rs`, renaming `DiscoveredJavaDependencies` → `DiscoveredJvmDependencies` and `is_java_dependency_input` → `is_jvm_dependency_input`. Keep the Maven/Gradle logic byte-for-byte otherwise; it is already language-neutral.

Extend `SourceJarLanguage` with a `Kotlin` variant, matched on the `.kt` entry suffix with the same per-entry byte budget Scala uses (`MAX_SCALA_SOURCE_ENTRY_BYTES`, renamed `MAX_NON_JAVA_SOURCE_ENTRY_BYTES`), and add `kotlin_source_types(artifact_path, source_path, source) -> Vec<JvmExternalType>`. It parses with the Kotlin grammar, runs `crate::analyzer::kotlin::declarations::parse_kotlin_file` against a synthetic `ProjectFile`, keeps class-like declarations that are not `private`/`internal`, and caps the result at the same bounded count Scala uses (`MAX_SCALA_SOURCE_TYPES`, renamed `MAX_NON_JAVA_SOURCE_TYPES`). Publicness must be read from the declaration's `modifiers` node, not guessed: add `kotlin_declaration_is_public(node, source)` in `src/analyzer/kotlin/declarations.rs` alongside the existing modifier helpers.

Give `KotlinAnalyzer` the same `external_index: Arc<OnceLock<JvmExternalDeclarationIndex>>` field, `jvm_config` capture, and `external_declaration_index()` accessor that `JavaAnalyzer` and `ScalaAnalyzer` have, and invalidate it in `update` when `is_jvm_dependency_input` matches a changed file.

**Acceptance.** `cargo test --features nlp,python --test jvm_external_index` (new file `tests/jvm_external_index.rs`) passes. Its central test builds a `-sources.jar` in a temp directory using the `zip` crate (no `kotlinc`, no JDK), containing `com/example/dep/KotlinService.kt` declaring `class KotlinService` and `internal class Hidden`, points a `JvmMavenCoordinate` at it, and asserts that a Java file importing `com.example.dep.KotlinService` reports the name known while `Hidden` is not. Existing Java and Scala external-dependency tests still pass unchanged apart from the renames.

### Milestone 2 — Kotlin structured imports

**Scope.** After this milestone a Kotlin file's imports are structured facts, `KotlinAnalyzer` implements `ImportAnalysisProvider`, and `MultiAnalyzer` routes Kotlin files to it.

**Work.**

Create `src/analyzer/kotlin/imports.rs`. Add `kotlin_import_info_from_node(node: Node<'_>, source: &str) -> Option<ImportInfo>`, which reads an `import_header` node: the `identifier` child's `simple_identifier` named children become `StructuredImportPath::segments`; a `wildcard_import` child sets `is_wildcard` and clears `identifier`; an `import_alias` child's `type_identifier` becomes `alias` and the bound `identifier`. Backtick quoting is stripped with the existing `kotlin_identifier_text` helper. `raw_snippet` is rendered from the structured parts (`import a.b.C`, `import a.b.*`, `import a.b.C as D`) so no consumer has to re-derive structure from text.

Change `collect_kotlin_imports` in `src/analyzer/kotlin/declarations.rs` to push both the display string (`ParsedFile::import_statements`, unchanged behaviour) and the structured fact (`ParsedFile::imports`).

Populate `ParsedFile::type_identifiers` during the Kotlin walk: every `type_identifier` node reachable from a `user_type`, plus the leading `simple_identifier` of a qualified expression is *not* included (that is a value reference, not a type). This feeds the same-package reference index.

Add `impl ImportAnalysisProvider for KotlinAnalyzer` in `src/analyzer/kotlin/imports.rs`:

* `import_info_of` forwards to the engine.
* `imported_code_units_of` resolves each structured import: an explicit import resolves the full dotted path to a declaration; a star import contributes every top-level declaration whose package equals the path.
* `referencing_files_of` combines the memoized reverse import index (`crate::analyzer::memoized_reverse_import_index`) with a same-package reference index built exactly like Java's, i.e. keyed on `(package, type identifier)`.
* `could_import_file` answers same-package, explicit-import, and star-import reachability.

Define Kotlin's default imports as a checked-in constant in `src/analyzer/kotlin/imports.rs`:
`kotlin`, `kotlin.annotation`, `kotlin.collections`, `kotlin.comparisons`, `kotlin.io`, `kotlin.ranges`, `kotlin.sequences`, `kotlin.text`, `java.lang`, `kotlin.jvm`. Document in the module header that the last two are Kotlin/JVM-specific and that Kotlin/JS and Kotlin/Native default imports are deliberately not modelled (see Milestone 6).

Wire `AnalyzerDelegate::import_analysis_provider` to return the Kotlin analyzer.

**Acceptance.** New `tests/kotlin_imports_and_hierarchy.rs` covers: explicit import resolves to the declaration; aliased import binds under the alias; star import pulls in a package's top-level declarations; same-package reference needs no import; an import of a name that does not exist resolves to nothing rather than to a guess. Run `cargo test --features nlp,python --test kotlin_imports_and_hierarchy`.

### Milestone 3 — Kotlin supertypes, type resolution, and hierarchy

**Scope.** After this milestone `get_direct_ancestors` and `get_direct_descendants` work for Kotlin classes, interfaces, objects, and companions, and a Kotlin file can say whether a spelled type name is known — including names that only exist in a dependency jar.

**Work.**

Create `src/analyzer/kotlin/supertypes.rs` with `extract_kotlin_supertypes(declaration: Node<'_>, source: &str) -> Vec<KotlinSupertypeFact>`, where a fact carries the display text (`raw`) and a `KotlinSupertypeLookupPath` of dotted segments. It walks the `delegation_specifier` children of a `class_declaration`/`object_declaration`/`companion_object`, unwrapping `constructor_invocation` and `explicit_delegation` to their `user_type`, and reads the `user_type`'s `type_identifier` children in order (skipping `type_arguments`). Function-type delegation specifiers produce no fact. The lookup path is serialized with `serde_json` into `ParsedFile::supertype_lookup_paths`, mirroring `ScalaSupertypeLookupPath::encode`, so the fact survives persistence.

Record enum entries with a class body as descendants of their enum class, and record a `companion_object`'s owner relationship, so the hierarchy reflects Kotlin's real shape.

Create `src/analyzer/kotlin/types.rs` with the resolution ladder, taking the file, the spelled name, and a lookup closure so the same ladder serves forward queries and hierarchy resolution:

1. If the name is dotted and resolves as a fully-qualified name, take it.
2. Explicit (or aliased) import whose bound name is the leading segment; a trailing `.Rest` is appended to the import target to reach a nested type.
3. Enclosing-declaration scope: a nested type declared by the referencing declaration's own owners.
4. Inherited scope: a nested type declared by a resolved ancestor of an owner.
5. Same package.
6. Star imports; if two star imports resolve the same simple name to different targets, the outcome is *ambiguous* and resolves to nothing rather than to an arbitrary winner.
7. Kotlin default imports.
8. The shared JVM external index, in the same order, producing a `JvmExternalType` rather than a `CodeUnit`.

Expose `KotlinAnalyzer::resolve_type_name_in_file` and `KotlinAnalyzer::is_known_type_name_in_file`, matching Java's public surface.

Add `src/analyzer/kotlin/hierarchy.rs` with `impl TypeHierarchyProvider for KotlinAnalyzer`. `get_direct_ancestors` decodes the stored lookup paths and runs the ladder; `get_direct_descendants` builds a memoized `DirectDescendantIndex` with `build_direct_descendant_index_from_candidates`. Wire `AnalyzerDelegate::type_hierarchy_provider`.

Resolve `typealias` targets: `KotlinAnalyzer::type_alias_target(unit) -> Option<CodeUnit>` runs the ladder on the alias's right-hand side, and the resolution ladder consults type aliases at tier 5 so `class C : Renamed` where `typealias Renamed = Base` yields `Base`.

**Acceptance.** `tests/kotlin_imports_and_hierarchy.rs` grows: ancestors across files in the same package; ancestors through an explicit import; ancestors through an alias import; ancestors of a nested class named `Outer.Base`; an interface implemented by an `object`; a `typealias` used as a supertype; descendants inverted from all of the above; and an unresolvable supertype yielding no ancestor rather than a fabricated one. A separate test asserts a Kotlin file importing a type that exists only in a configured jar reports `is_known_type_name_in_file` true and `resolve_type_name_in_file` `None` (no fake `CodeUnit`), matching Java's contract.

### Milestone 4 — One JVM usage-candidate realm

**Scope.** After this milestone Java, Scala, and Kotlin declarations occupy one node space in the workspace usage catalog and graph, and `usage_graph` still reports each node's real source language.

**Work.**

In `src/analyzer/usages/workspace_graph.rs`, replace `UsageEcosystem::Java` and `UsageEcosystem::Scala` with a single `UsageEcosystem::Jvm`, and map `Language::Java | Language::Scala | Language::Kotlin` to it. `as_str()` returns `"jvm"`.

Add `WorkspaceUsageNode::source_language(&self) -> Language`, derived from the node's primary declaration, and a `language_label(&self) -> &'static str` that returns the real language name for JVM nodes and `ecosystem.as_str()` otherwise. Use it for `UsageGraphNode::language` in `src/searchtools/scan_usages.rs`.

In `build_workspace_usage_graph`, run *both* the Java and the Scala edge builders over `catalog.fqns(UsageEcosystem::Jvm)` and merge both results into the shared node space under the `Jvm` key. Do the same in `usage_graph` in `src/searchtools/scan_usages.rs`. Add a comment stating that Kotlin's own edge builder arrives with #1239 and that until then Kotlin nodes are realm members with no outbound edges — an explicit gap, not a silent one.

**Acceptance.** New `tests/jvm_shared_realm.rs` asserts that in a mixed Java/Scala/Kotlin workspace the usage graph contains nodes for declarations from all three languages, that each node reports its own language (`java`, `scala`, `kotlin`), and that the existing Java→Java and Scala→Scala edges are unchanged. Existing `tests/usage_graph_java_test.rs` and `tests/usage_graph_scala_test.rs` pass unchanged.

### Milestone 5 — Cross-language JVM source realm

**Scope.** After this milestone a Kotlin class that extends a Java interface, or imports a Scala trait, from the same workspace resolves to that declaration's `CodeUnit`.

**Work.**

Create `src/analyzer/jvm/realm.rs`:

    pub(crate) struct JvmSourceRealm<'a> {
        members: Vec<(Language, &'a dyn ForwardQueryProvider)>,
    }

    impl<'a> JvmSourceRealm<'a> {
        pub(crate) fn of(analyzer: &'a dyn IAnalyzer) -> Self;
        pub(crate) fn single(member: &'a dyn ForwardQueryProvider, language: Language) -> Self;
        pub(crate) fn types_by_fqn(&self, fqn: &str) -> Vec<CodeUnit>;
        pub(crate) fn package_exists(&self, package: &str) -> bool;
    }

`of` uses `resolve_analyzer::<JavaAnalyzer>`, `::<ScalaAnalyzer>`, and `::<KotlinAnalyzer>` — the precedent `src/analyzer/usages/java_graph/jvm_scala.rs` already sets — so it works for a bare analyzer and for a `MultiAnalyzer` alike, with no ownership and no cycles.

Give `KotlinAnalyzer` realm-parameterized entry points: `imported_code_units_in_realm(file, realm)` and `direct_ancestors_in_realm(unit, realm)`. The `ImportAnalysisProvider`/`TypeHierarchyProvider` impls call them with `JvmSourceRealm::single(self, Language::Kotlin)`; `MultiAnalyzer::imported_code_units_of` and `MultiAnalyzer::get_direct_ancestors` call them with `JvmSourceRealm::of(self)` when the file or code unit is Kotlin.

**Acceptance.** `tests/jvm_shared_realm.rs` grows: a Kotlin class implementing a Java interface in the same workspace has that Java `CodeUnit` as a direct ancestor; a Kotlin file importing a Scala trait resolves it; a Java class and a Kotlin class in the same package do not accidentally resolve each other's private nesting. All are exercised through a `MultiAnalyzer` built by `WorkspaceAnalyzer`.

### Milestone 6 — Explicit outcomes, epoch, and validation

**Scope.** Everything this issue deliberately does not support is *explicit*, the persisted store correctly invalidates, and the whole suite is green.

**Work.**

Append `kotlin-jvm-realm-1237` to the Kotlin `SALT` in `src/analyzer/store/epoch.rs`, so workspaces persisted under #1236 re-index rather than serving imports and supertypes that were never recorded.

Keep the following as explicit outcomes, each with a test and a comment naming the reason:

* A Kotlin multiplatform source set (`src/jsMain`, `src/nativeMain`) is indexed for declarations but its platform-specific default imports are not modelled; a name resolvable only through a Kotlin/JS or Kotlin/Native default import stays unresolved rather than being guessed.
* `expect`/`actual` declarations are indexed as ordinary declarations; no expect-to-actual link is claimed.
* With no configured or discovered classpath the external index is empty, and an unresolvable import stays unresolved — never silently "known".
* Two star imports that bind the same simple name to different targets resolve to nothing.
* Generated JVM surfaces (`FooKt` file facades, `$` synthetic names, `Companion` accessors as JVM statics) never appear in a Kotlin identity; the identity rules from #1236 are preserved. Assert this over the new import and hierarchy paths too.

Update `src/analyzer/kotlin/mod.rs`'s module header: #1237 is done; #1238/#1239/#1240/#1241 remain the open boundaries.

Run the full validation sequence in `Concrete Steps`.

## Concrete Steps

All commands run from the repository root (`/Users/dave/Workspace/BrokkAi/bifrost/.claude/worktrees/cargo-dist-cleanup-972b88` in the authoring worktree; any checkout root works).

Build and lint after every milestone:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings

Note: the `clippy-no-cuda` cargo alias is broken inside nested worktrees under `.claude/worktrees/*` because cargo merges duplicate alias arrays from both `.cargo/config.toml` files. Use the expanded command above there.

Per-milestone tests:

    cargo test --features nlp,python --test kotlin_imports_and_hierarchy
    cargo test --features nlp,python --test jvm_shared_realm
    cargo test --features nlp,python --test kotlin_analyzer_test
    cargo test --features nlp,python --lib analyzer::jvm::external

On macOS, prefix every `python`-enabled command with an interpreter at or above
the `abi3-py312` floor, because pyo3's build script resolves `python3` through
`PATH` and `/usr/bin/python3` (3.9) usually wins:

    PYO3_PYTHON=$(brew --prefix python@3.13)/bin/python3.13 cargo test --features nlp,python

This applies to `cargo clippy --all-features` too, since `--all-features`
enables `python`. See `Surprises & Discoveries`.

Regression sweep over the JVM languages this plan renames or re-keys:

    cargo test --features nlp,python --test java_imports_and_hierarchy
    cargo test --features nlp,python --test scala_type_hierarchy_test
    cargo test --features nlp,python --test scala_semantic_diagnostics
    cargo test --features nlp,python --test usage_graph_java_test
    cargo test --features nlp,python --test usage_graph_scala_test

Full gate before completion:

    cargo test --features nlp,python

`default = []`, so a featureless `cargo test` silently skips every `#![cfg(feature = "nlp")]` integration suite and reports `ok. 0 passed`, which looks green but proves nothing. Always pass `--features nlp,python`.

For isolated builds that must not pollute the shared target directory:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

## Validation and Acceptance

Acceptance is behavioural, not structural. After the whole plan:

* Given `lib/Base.kt` declaring `package lib` and `open class Base`, and `app/Child.kt` declaring `package app`, `import lib.Base`, `class Child : Base()`, `KotlinAnalyzer::get_direct_ancestors` on `app.Child` returns exactly one unit whose `fq_name()` is `lib.Base`. Before this change it returns an empty vector.
* Given the same files with `import lib.Base as Parent` and `class Child : Parent()`, the result is identical — the alias is resolved, not treated as an unknown name.
* Given `app/Child.kt` with `import lib.*` instead, the result is identical.
* Given `lib/Base.kt` moved into `package app`, and `app/Child.kt` with no import at all, the result is identical.
* Given a `-sources.jar` containing `com/example/dep/KotlinService.kt` and a `JvmMavenCoordinate` pointing at it, `KotlinAnalyzer::is_known_type_name_in_file` returns `true` for `KotlinService` in a file importing it, and `resolve_type_name_in_file` returns `None` (external types never become workspace `CodeUnit`s).
* Given a mixed workspace with `A.java`, `B.scala`, and `C.kt`, `searchtools::usage_graph` returns nodes for all three, each labelled with its own language, and every node's `fqn` is the source-level dotted name with no `$` and no `FooKt`.
* Given `Api.java` declaring `public interface Api` in package `app` and `Impl.kt` declaring `package app` and `class Impl : Api`, `MultiAnalyzer::get_direct_ancestors` on `app.Impl` returns the Java `app.Api` `CodeUnit`.

Every one of the above is asserted by a test named in the milestone acceptance sections; each fails before its milestone and passes after.

## Idempotence and Recovery

Every step is a source edit plus a test run; there is no migration and no destructive operation. Re-running `cargo fmt`, `cargo clippy`, and `cargo test` is always safe.

The one persistent artifact is the analyzer's SQLite store under `.bifrost/cache/bifrost_cache.db`. The Kotlin epoch salt bump in Milestone 6 makes previously persisted Kotlin rows logically dirty, so a workspace opened after this change re-parses its Kotlin files once; no manual cache deletion is needed. If a partially-implemented tree is abandoned mid-milestone, `git checkout -- src tests` restores it; nothing outside the repository is touched.

Do not create manually named `CARGO_TARGET_DIR=/tmp/bifrost-*` directories; use `scripts/with-isolated-cargo-target.sh`, which removes its unique target on success, failure, or interruption.

## Artifacts and Notes

Expected shape of the central new test (abbreviated, from `tests/kotlin_imports_and_hierarchy.rs`):

    #[test]
    fn kotlin_resolves_aliased_import_supertype() {
        let (_built, analyzer) = kotlin_analyzer(&[
            ("lib/Base.kt", "package lib\n\nopen class Base\n"),
            (
                "app/Child.kt",
                "package app\n\nimport lib.Base as Parent\n\nclass Child : Parent()\n",
            ),
        ]);
        let child = analyzer.get_definitions("app.Child").remove(0);
        let ancestors: Vec<String> = analyzer
            .get_direct_ancestors(&child)
            .iter()
            .map(CodeUnit::fq_name)
            .collect();
        assert_eq!(ancestors, vec!["lib.Base".to_string()]);
    }

Expected clippy output at each milestone boundary:

    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 12s

## Interfaces and Dependencies

In `src/analyzer/jvm/external.rs`, after the rename:

    pub(crate) struct JvmExternalDeclarationIndex { /* … */ }

    impl JvmExternalDeclarationIndex {
        pub(crate) fn build_for_project(config: &JvmAnalyzerConfig, project: &dyn Project) -> Self;
        pub(crate) fn resolve_explicit_import(&self, import_path: &str, access_package: &str) -> Option<&JvmExternalType>;
        pub(crate) fn resolve_wildcard_import(&self, package_name: &str, short_name: &str, access_package: &str) -> Option<&JvmExternalType>;
        pub(crate) fn resolve_same_package(&self, package_name: &str, short_name: &str) -> Option<&JvmExternalType>;
        pub(crate) fn resolve_java_lang(&self, short_name: &str) -> Option<&JvmExternalType>;
        pub(crate) fn resolve_qualified_name(&self, fqn: &str, access_package: &str) -> Option<&JvmExternalType>;
    }

    enum SourceJarLanguage { Java, Scala, Kotlin }

In `src/analyzer/kotlin/imports.rs`:

    pub(crate) fn kotlin_import_info_from_node(node: Node<'_>, source: &str) -> Option<ImportInfo>;
    pub(crate) const KOTLIN_DEFAULT_IMPORT_PACKAGES: &[&str];
    impl ImportAnalysisProvider for KotlinAnalyzer { /* … */ }

In `src/analyzer/kotlin/supertypes.rs`. The plan originally proposed a
`KotlinSupertypeFact` carrying both display text and a separately serialized
lookup path, mirroring Scala. That was dropped during implementation: the
dotted lookup path goes straight into the language-neutral
`ParsedFile::raw_supertypes` slot that Java and Go already use, which is what
lets Kotlin's descendant index reuse the shared batched declaration-facts path,
and the display text a reader wants is already the declaration's rendered
signature.

    pub(crate) fn extract_kotlin_supertypes(declaration: Node<'_>, source: &str) -> Vec<String>;
    pub(crate) fn kotlin_user_type_segments(user_type: Node<'_>, source: &str) -> Vec<String>;

In `src/analyzer/kotlin/types.rs`. `KotlinTypeName` is the ladder's own result
type; it exists so `Ambiguous` is a distinct answer from `Unresolved` rather
than both collapsing to `None`.

    pub(crate) enum KotlinTypeName { Resolved(String), Ambiguous, Unresolved }
    pub(crate) struct KotlinNameScope<'a> {
        pub(crate) package_name: &'a str,
        pub(crate) imports: &'a [ImportInfo],
        pub(crate) scope_owners: Vec<String>,
    }
    pub(crate) fn resolve_kotlin_type_name(
        name: &str,
        scope: &KotlinNameScope<'_>,
        exists: impl FnMut(&str) -> bool,
    ) -> KotlinTypeName;

    pub(crate) enum KotlinTypeResolution { Source(CodeUnit), External(JvmExternalType) }
    impl KotlinAnalyzer {
        pub fn resolve_type_name_in_file(&self, file: &ProjectFile, raw_name: &str) -> Option<CodeUnit>;
        pub fn is_known_type_name_in_file(&self, file: &ProjectFile, raw_name: &str) -> bool;
        pub(crate) fn scope_owners_for(&self, owner: &CodeUnit) -> Vec<String>;
        pub(crate) fn realm_type_by_fqn(&self, fqn: &str, realm: Option<&JvmSourceRealm<'_>>) -> Option<CodeUnit>;
    }

In `src/analyzer/kotlin/hierarchy.rs`:

    impl TypeHierarchyProvider for KotlinAnalyzer { /* … */ }
    impl KotlinAnalyzer {
        pub(crate) fn direct_ancestors_in_realm(&self, unit: &CodeUnit, realm: Option<&JvmSourceRealm<'_>>) -> Vec<CodeUnit>;
        pub(crate) fn direct_descendants_in_realm(&self, unit: &CodeUnit, realm: Option<&JvmSourceRealm<'_>>) -> HashSet<CodeUnit>;
    }

In `src/analyzer/jvm/realm.rs`. The realm answers per *peer*: the calling
analyzer has already answered for itself through its own indexes and caches
before it consults the realm, so including it again would only duplicate work.

    pub(crate) struct JvmSourceRealm<'a> { /* … */ }
    impl<'a> JvmSourceRealm<'a> {
        pub(crate) fn of(analyzer: &'a dyn IAnalyzer) -> Self;
        pub(crate) fn has_peers_of(&self, language: Language) -> bool;
        pub(crate) fn peer_types_by_fqn(&self, fqn: &str, language: Language) -> Vec<CodeUnit>;
        pub(crate) fn peer_declarations_by_fqn(&self, fqn: &str, language: Language) -> Vec<CodeUnit>;
    }

In `src/analyzer/usages/workspace_graph.rs`:

    pub(crate) enum UsageEcosystem { JavaScriptTypeScript, Python, Go, Rust, Jvm, CSharp, Cpp, Php, Ruby, Unknown }

    impl WorkspaceUsageNode {
        pub(crate) fn source_language(&self) -> Language;
        pub(crate) fn language_label(&self) -> &'static str;
    }

## Revision Notes

* 2026-07-29 — Revised at completion. `Interfaces and Dependencies` now reflects what was actually built; the two places it drifted are called out inline with the reason. `Progress` shows all six milestones done. `Decision Log` gained three entries made during implementation: the Kotlin realm-aware descendant union at the `MultiAnalyzer` boundary, the separate realm-aware cache slots, and why `referencing_files_of` stays Kotlin-to-Kotlin. `Surprises & Discoveries` gained the two environment findings that shaped validation (clippy needs the rustup `PATH`; `--features nlp,python` cannot link here) and the two that cost real time (a full disk, and editing `src/` mid-build silently discarding a test run). `Outcomes & Retrospective` is filled in.

* 2026-07-29 — Initial authoring. Structured as six milestones so each is independently verifiable: the dependency realm (M1) is provable without any Kotlin analysis change; imports (M2) and hierarchy (M3) are the user-visible Kotlin capabilities; the candidate realm (M4) and source realm (M5) are the cross-language obligations; M6 makes the deliberate gaps explicit. The Decision Log records why Java's and Scala's own resolvers stay untouched, so a future reader does not mistake that boundary for an oversight.
