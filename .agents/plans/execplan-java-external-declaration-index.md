# Add Java external declaration index from source JARs and classfiles

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, Bifrost can distinguish a Java type that is truly unknown from a Java type that exists only in a dependency artifact. This is needed before Java can safely report high-confidence unrecognized-symbol diagnostics: many valid Java files import types from dependency JARs, source JARs, and local Maven repositories that are not ordinary workspace source files.

The first slice is deliberately bounded. Bifrost will not scan all of `~/.m2`, run Maven, run Gradle, or infer a build graph. It will accept exact Maven coordinates and explicit artifact paths, resolve only those artifacts, and build an external type index from matching source JARs and classfile JARs. External declarations remain a separate Java model; they do not become `ProjectFile` declarations and do not appear in normal workspace file lists.

## Progress

- [x] (2026-07-02 12:20Z) Created this ExecPlan after inspecting issue #354, the Java analyzer, `AnalyzerConfig`, CI, and the `jclassfile` / `zip` crate APIs.
- [x] (2026-07-02 12:55Z) Added the Java external dependency config model and external declaration index.
- [x] (2026-07-02 12:55Z) Wired the Java analyzer to lazily build and consult the external index through a source-versus-external resolver.
- [x] (2026-07-02 13:05Z) Added generated-JAR unit and integration tests plus explicit CI JDK setup.
- [x] (2026-07-02 13:08Z) Created Maven/Gradle coordinate-discovery follow-up issue #443.
- [x] (2026-07-02 13:10Z) Ran focused tests: `cargo test java_external_declaration --lib` and `cargo test --test java_imports_and_hierarchy java_external`.
- [x] (2026-07-02 13:20Z) Ran formatting, `cargo clippy-no-cuda`, and `git diff --check`.

## Surprises & Discoveries

- Observation: The repository already tracks older compiled Java fixture `.class` files under `tests/fixtures/testcode-java/bin`.
  Evidence: `git ls-files 'tests/**/*.class' '*.class'` lists the existing Java fixture classes.
- Observation: CI currently installs Rust and Python explicitly, but does not explicitly install a JDK.
  Evidence: `.github/workflows/ci.yml` has `dtolnay/rust-toolchain` and Python setup steps, with no `actions/setup-java` step.
- Observation: `jclassfile` exposes a small parser API suitable for this slice.
  Evidence: `jclassfile::class_file::parse(&[u8]) -> Result<ClassFile>` parses class bytes, and `ClassFile` exposes `constant_pool`, `access_flags`, and `this_class`.
- Observation: Dependency fixture sources must be outside the analyzer project root.
  Evidence: The first resolver unit test found dependency source as normal workspace source until the fixture moved generated dependency sources and JARs outside the workspace directory.

## Decision Log

- Decision: Resolve exact Maven coordinates only; do not crawl dependency caches.
  Rationale: Broad scans of `~/.m2` are expensive, imprecise, and contrary to the requested follow-up shape. Exact coordinates give the future Maven/Gradle integration a clean handoff.
  Date/Author: 2026-07-02 / Codex.
- Decision: Generate new Java classfile fixtures during tests with `javac` and `jar`.
  Rationale: This proves the parser works against real classfiles without adding more binary `.class` files to git.
  Date/Author: 2026-07-02 / Codex.
- Decision: Keep external Java declarations separate from normal analyzer declarations.
  Rationale: Dependency contents are not workspace files and should not inflate `Project::all_files()`, persistence rows, symbol search, or source navigation locations.
  Date/Author: 2026-07-02 / Codex.
- Decision: Track Maven/Gradle coordinate discovery in follow-up issue #443.
  Rationale: Issue #354 now owns exact-coordinate and explicit-artifact reading. Build-tool integration should discover coordinates and feed this index, not broaden this change into Maven/Gradle resolution.
  Date/Author: 2026-07-02 / Codex.

## Outcomes & Retrospective

The implementation now has a Java external declaration index that resolves exact Maven coordinates and explicit artifact paths, prefers source JAR records over classfile records, and leaves dependency contents out of normal workspace declarations. Focused generated-JAR unit tests, the Java imports/hierarchy integration filter, formatting, clippy, and whitespace checks pass.

## Context and Orientation

`src/analyzer/java/mod.rs` defines `JavaAnalyzer`, which wraps `TreeSitterAnalyzer<JavaAdapter>`. Normal Java declarations are `CodeUnit`s discovered from workspace `.java` files. Java import and type-name resolution lives in `src/analyzer/java/imports.rs`; today it consults only workspace declarations through `self.inner.definitions(...)` and package indexes.

`src/analyzer/config.rs` defines `AnalyzerConfig`, which is passed into analyzer constructors and is the right place for explicit external Java dependency inputs. This plan adds Java-specific dependency inputs there, but no build-tool integration.

An external declaration is a type known from a dependency artifact. In this plan, an artifact is either a JAR path explicitly listed by the caller or a JAR path derived from an exact Maven coordinate. A Maven coordinate has `group_id`, `artifact_id`, and `version`; for example, `com.example:demo:1.2.3` resolves under a local repository root to `com/example/demo/1.2.3/demo-1.2.3.jar` and `demo-1.2.3-sources.jar`.

## Plan of Work

First, add the configuration model. In `src/analyzer/config.rs`, define `JavaExternalDependencies`, `JavaExternalArtifact`, and `JavaMavenCoordinate`. Add a `java_external_dependencies` field to `AnalyzerConfig`, defaulting to empty lists. Coordinates should resolve against configured repository roots; if no roots are configured, use the user's `~/.m2/repository` when a home directory can be found.

Second, add `src/analyzer/java/external.rs`. This module builds `JavaExternalDeclarationIndex` from the config and project root. It should normalize all artifact paths, read only exact artifacts, ignore missing/unreadable artifacts, and avoid recursive cache scans. It should parse source JAR `.java` entries with tree-sitter Java and class JAR `.class` entries with `jclassfile`. The model should include at least `JavaExternalType`, `JavaExternalTypeKind`, `JavaVisibility`, and `JavaExternalDeclarationSource`.

Third, wire `JavaAnalyzer` to hold the external dependency config and a lazy `OnceLock<JavaExternalDeclarationIndex>`. Add an internal method that resolves Java type names through normal source rules first and then through the external index. The existing public `resolve_type_name_in_file` should continue returning only `CodeUnit` so callers that need source locations do not accidentally receive fake dependency declarations.

Fourth, add tests. The tests should create a temporary Java project, write small Java sources, run `javac` to produce classfiles, and run `jar` to package both a binary JAR and a source JAR. Tests should also create a temporary Maven repository layout and configure the analyzer with exact coordinates. No new `.class` files should be committed.

Fifth, add explicit Java setup in `.github/workflows/ci.yml` for jobs that run Rust tests, and document the local JDK requirement in this ExecPlan and in any test failure message where practical.

Finally, create a separate GitHub issue for Maven/Gradle integration. That issue should cover discovering exact dependency coordinates from build files or tool output and feeding those coordinates into this external index. It must not be folded into this implementation.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/994a/bifrost`.

Run focused validation during implementation:

    cargo test java_external_declaration --lib
    cargo test --test java_imports_and_hierarchy java_external

Run final validation:

    cargo fmt
    cargo clippy-no-cuda
    git diff --check

Observed final validation:

    cargo test java_external_declaration --lib
    test result: ok. 5 passed; 0 failed

    cargo test --test java_imports_and_hierarchy java_external
    test result: ok. 1 passed; 0 failed

    cargo clippy-no-cuda
    Finished `dev` profile

    git diff --check
    no output

If `javac` or `jar` is missing locally, install a JDK and rerun the Java external declaration tests. The CI workflow should install a JDK explicitly so hosted runners do not rely on an implicit image detail.

## Validation and Acceptance

A Java test source importing an external dependency class by explicit import should resolve as known externally when the dependency is supplied by an exact Maven coordinate in a temporary Maven repository.

A Java test source importing an external dependency class through a wildcard import should resolve as known externally when the matching class exists in the configured artifact.

When both `artifact-version.jar` and `artifact-version-sources.jar` exist for the same coordinate, the index should prefer the source-JAR record for the same FQN.

Malformed JARs, missing coordinates, and unreadable artifacts should not fail Java analyzer construction. They should simply produce no external declarations for those inputs.

Dependency source and classfile entries should not appear in `Project::all_files()`, `JavaAnalyzer::all_declarations()`, or ordinary `CodeUnit` lookup.

## Idempotence and Recovery

All changes are normal source, test, workflow, and documentation edits. Re-running the generated-JAR tests should create fresh temporary directories and leave no repository-tracked artifacts behind. If an artifact parser fails on one entry, skip that entry and continue indexing the rest of the configured artifacts.

## Artifacts and Notes

No artifacts yet.

## Interfaces and Dependencies

Add these Cargo dependencies:

    jclassfile = "0.6.0"
    zip = { version = "2.4.2", default-features = false, features = ["deflate"] }

In `src/analyzer/config.rs`, define:

    pub struct JavaExternalDependencies {
        pub artifact_paths: Vec<JavaExternalArtifact>,
        pub coordinates: Vec<JavaMavenCoordinate>,
        pub repository_roots: Vec<PathBuf>,
    }

    pub struct JavaExternalArtifact {
        pub artifact_path: PathBuf,
        pub source_artifact_path: Option<PathBuf>,
    }

    pub struct JavaMavenCoordinate {
        pub group_id: String,
        pub artifact_id: String,
        pub version: String,
    }

In `src/analyzer/java/external.rs`, define:

    pub(crate) struct JavaExternalDeclarationIndex { ... }
    pub(crate) struct JavaExternalType { ... }
    pub(crate) enum JavaExternalTypeKind { Class, Interface, Enum, Annotation, Record }
    pub(crate) enum JavaVisibility { Public, Protected, PackagePrivate, Private }
    pub(crate) enum JavaExternalDeclarationSource { SourceJar { ... }, ClassFile { ... } }

Expose lookup methods that answer by fully qualified name, simple imported name, wildcard package, same package, and `java.lang` package. Keep this API Java-specific for now.

Revision note, 2026-07-02: Initial plan created before implementation to satisfy issue #354 and the repository ExecPlan requirement.

Revision note, 2026-07-02: Updated after implementing the external index, resolver hook, generated-JAR tests, CI JDK setup, and follow-up issue #443.
