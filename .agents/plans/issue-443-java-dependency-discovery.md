# Discover Java dependencies from Maven and Gradle

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this change, Java analysis can learn about dependency types without callers manually supplying every Maven coordinate. Safe metadata discovery is enabled by default: Bifrost reads exact direct Maven dependencies and Gradle lock state but does not execute project build logic. A trusted caller can explicitly enable offline Maven and Gradle execution to obtain the resolved transitive artifact set. Missing tools, incomplete caches, malformed metadata, and unresolved dependencies reduce coverage but never prevent analyzer construction or normal source analysis.

The observable proof is a temporary Java project containing only an import and a build descriptor. When the matching dependency JAR is present in an exact local Maven or Gradle cache location, `JavaAnalyzer::is_known_type_name_in_file` reports the imported dependency type as known even though no coordinate was explicitly configured. Dependency contents remain `JavaExternalType` records and never become workspace `CodeUnit` or `ProjectFile` values.

## Progress

- [x] (2026-07-16 14:05Z) Inspected issue #443, predecessor issue #354 and PR #445, the current external index, analyzer configuration, project abstraction, workspace update routing, formatter process lifecycle, and official Maven/Gradle dependency-reporting APIs.
- [x] (2026-07-16 14:05Z) Chose the external-declaration boundary, trust model, metadata subset, build-tool execution model, cache lookup constraints, and invalidation behavior with the user.
- [x] (2026-07-16 14:43Z) Added public discovery configuration, structural Maven POM parsing, modern and legacy Gradle lock parsing, and exact Maven/Gradle cache lookup. `cargo test java_dependency_discovery --lib` passes all seven focused parser and generated-JAR tests.
- [x] (2026-07-16 15:32Z) Extracted the formatter lifecycle into a shared bounded process runner and added trusted offline Maven/Gradle execution with top-level build-root selection, bounded reports, cross-platform parsers, and injected failure/partial-result tests. Formatter execution and shared descendant-cleanup tests pass.
- [x] (2026-07-16 15:50Z) Added build-input invalidation for Java snapshots, full-refresh/project-replacement invalidation, Java-only index reuse, and non-Java manifest routing in `MultiAnalyzer`. Generated-JAR rediscovery tests pass for direct and Java-plus-Python multi-analyzer snapshots.
- [x] (2026-07-16 16:55Z) Completed generated-JAR, parser, injected executor, process-lifecycle, invalidation, and multi-analyzer coverage. Focused discovery and external-resolution tests, the pinned full `nlp,python` suite (including doc tests), formatting, strict all-target/all-feature Clippy, and whitespace validation pass.

## Surprises & Discoveries

- Observation: Issue #354 already established the correct dependency boundary.
  Evidence: `src/analyzer/java/external.rs` stores dependency types as `JavaExternalType`, while `CodeUnit` in `src/analyzer/model.rs` requires a workspace `ProjectFile`.
- Observation: The external index is lazy but is currently shared across every Java source update.
  Evidence: `JavaAnalyzer::update` clones the same `Arc<OnceLock<JavaExternalDeclarationIndex>>`; build metadata changes would therefore remain stale without explicit invalidation.
- Observation: Multi-language analyzer updates discard non-language files unless a delegate declares them as configuration inputs.
  Evidence: `MultiAnalyzer::should_receive_changed_file` currently special-cases only JavaScript and TypeScript configuration files.
- Observation: The formatter already owns the difficult cross-platform process cleanup required by build-tool execution.
  Evidence: `src/lsp/handlers/formatting.rs` uses Unix sessions and Windows Job Objects to terminate descendants on cancellation and timeout.
- Observation: Gradle's artifact cache adds a content-hash directory beneath an exact coordinate, so exact lookup still requires one bounded directory-listing step.
  Evidence: The resolver enters only `<root>/<group>/<artifact>/<version>`, sorts its direct hash children, and considers JARs immediately beneath them; the end-to-end test places another valid JAR under an unrelated coordinate and proves it is not indexed.
- Observation: A bounded reader must continue draining after crossing its memory limit or a child that keeps writing can block before the timeout path can reap it.
  Evidence: The shared runner records overflow, discards subsequent bytes, and reports the limit only after EOF; formatter large-stdin/output concurrency and timeout tests still pass after extraction.
- Observation: Multi-analyzer routing must recognize dependency inputs before Java can decide whether to invalidate its lazy index.
  Evidence: Without the Java-specific `needs_config_update_for` case, `pom.xml` has `Language::None` and would leave the Java delegate unchanged; the Java-plus-Python regression now changes a POM and resolves the newly available dependency type after `MultiAnalyzer::update`.
- Observation: This host has two Rust 1.96.0 installations with different LLVM builds; Rustup builds dependencies while Homebrew's `cargo-clippy`/`rustdoc` can otherwise compile the crate itself.
  Evidence: Mixed toolchains produced `E0514` even though both report the same Rust commit. Prepending `/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin` to `PATH` makes both the full suite (including doc tests) and Clippy use the same toolchain.
- Observation: The managed isolated-target helper can race Cargo's parallel all-target Clippy subprocesses on this host.
  Evidence: A parallel run removed its target while descendant target checks were still writing dep-info. Re-running the same command with `CARGO_BUILD_JOBS=1` preserved the helper's cleanup contract and passed after 12m19s.

## Decision Log

- Decision: Keep dependency declarations as Java-specific external types in this issue.
  Rationale: A general external identity affects symbol search, navigation, persistence, and every usage graph. Issue #443 only needs dependency discovery, and fabricating workspace files would violate the boundary established by issue #354.
  Date/Author: 2026-07-16 / user and Codex.
- Decision: Add `Disabled`, `Metadata`, and `OfflineBuildTools` discovery modes; default to `Metadata`.
  Rationale: Metadata provides useful exact results without running repository code. Build-tool execution evaluates trusted project configuration and must therefore be explicit.
  Date/Author: 2026-07-16 / user and Codex.
- Decision: Expose the mode through `JavaAnalyzerConfig` only in this issue.
  Rationale: Java unrecognized-symbol diagnostics are not implemented yet, so a VS Code setting would have no visible consumer. Analyzer callers can opt in now, and editor configuration can follow with the diagnostic feature.
  Date/Author: 2026-07-16 / Codex, applying the documented default after the user left this choice unanswered.
- Decision: Parse Maven XML structurally, but do not parse Gradle Groovy or Kotlin source as text.
  Rationale: Maven POM XML has a bounded declarative subset. Gradle build files are executable programs; lockfiles are safe exact metadata and Gradle itself is the structured authority in trusted mode.
  Date/Author: 2026-07-16 / Codex.
- Decision: Do not invoke Maven or Gradle wrappers automatically.
  Rationale: A wrapper whose distribution is absent can access the network before Maven's or Gradle's offline argument takes effect. Installed or explicitly configured executables preserve the no-download contract.
  Date/Author: 2026-07-16 / Codex.
- Decision: Lookup in dependency caches is always rooted at an exact group/artifact/version directory.
  Rationale: Listing the bounded hash children beneath one exact Gradle coordinate is deterministic enough to find content-addressed artifacts without scanning `~/.gradle`; recursive cache crawling remains prohibited.
  Date/Author: 2026-07-16 / Codex.

## Outcomes & Retrospective

Safe metadata now provides automatic exact dependency awareness from Maven POMs and Gradle lockfiles, while trusted `OfflineBuildTools` mode adds resolved artifacts from installed/configured Maven and Gradle executables. Both paths keep declarations in `JavaExternalDeclarationIndex`; external types remain outside `CodeUnit`, `ProjectFile`, navigation, symbol search, persistence, and usage graphs. Java and multi-language snapshots rediscover lazily after build-input changes while reusing the index for ordinary Java edits.

Validation passed: `cargo test java_dependency_discovery --lib` (13 tests), `cargo test --test java_imports_and_hierarchy java_external`, formatter/process lifecycle tests, the full `cargo test --features nlp,python` suite (903 library tests plus integration and doc tests), `cargo fmt --all -- --check`, `git diff --check`, and `scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings` (12m19s). The last two full-suite/lint commands used the pinned Rustup toolchain noted above; the full suite also used the standard macOS PyO3 dynamic-lookup link flags and disabled semantic-model startup.

## Context and Orientation

`src/analyzer/config.rs` defines `AnalyzerConfig` and the existing `JavaExternalDependencies` input containing explicit artifact paths, Maven coordinates, and Maven-layout repository roots. `src/analyzer/java/external.rs` resolves those inputs, reads source and class JARs, and creates `JavaExternalDeclarationIndex`. `src/analyzer/java/mod.rs` owns the index behind a lazy `OnceLock`, and `src/analyzer/java/imports.rs` consults it after source resolution fails.

A build root is a directory from which Maven or Gradle evaluates one project graph. A Maven reactor root is a `pom.xml` not listed as a module of another discovered POM. A Gradle root is a directory containing `settings.gradle` or `settings.gradle.kts`; a standalone `build.gradle` or `build.gradle.kts` is a root only when it has no settings file ancestor inside the active workspace.

Safe metadata discovery reads all ignore-aware project files. For Maven it parses direct dependencies under the project's top-level `dependencies` element, never entries that appear only under `dependencyManagement` or profiles. It accepts dependencies with absent or `jar` type and no classifier, in compile, runtime, provided, or test scope. It expands exact whole-value and embedded `${property}` references from the same POM's `properties` plus `project.groupId`, `project.artifactId`, and `project.version`, rejecting missing or cyclic properties and dependencies without an exact group, artifact, and version. A system-scoped dependency is accepted only as an explicit artifact when its resolved `systemPath` names an existing file.

For Gradle, safe metadata discovery reads modern `gradle.lockfile` files and legacy files under `gradle/dependency-locks`. Each non-comment line before `=` must be exactly `group:artifact:version`; malformed and `empty=` lines are ignored. It does not infer which source set owns a coordinate because the existing Java external index is global.

Offline build-tool discovery includes safe metadata and then gathers exact local JAR paths. Maven runs `dependency:list` in offline batch mode with transitive test-scope dependencies, absolute filenames, and a temporary output file. Gradle runs a temporary init script with `--offline --no-daemon --console=plain`; the script registers one root task that visits resolvable project configurations, catches failures per configuration, and writes JSON Lines records containing module group, name, version, and artifact path. Only successful, existing JAR files are accepted. Tool failures retain explicit and safe metadata results.

## Plan of Work

First, add `JavaDependencyDiscoveryMode` and `JavaDependencyDiscoveryConfig` in `src/analyzer/config.rs`. The configuration contains the mode, optional `PathBuf` executable overrides, and a `Duration` timeout. Default mode is `Metadata`, default executables are `mvn` and `gradle` through `PATH`, and the default per-build-root timeout is 30 seconds. Add `gradle_cache_roots` to `JavaExternalDependencies`; empty roots consult `GRADLE_USER_HOME` and then the user home. Re-export the public types from `src/analyzer/mod.rs` and `src/lib.rs`.

Second, add `src/analyzer/java/dependency_discovery.rs`. It will enumerate project metadata, parse the bounded Maven and Gradle forms described above, find top-level tool roots, and return deduplicated `JavaMavenCoordinate` and `JavaExternalArtifact` values. Keep parsing pure and independently testable. Add exact Gradle cache resolution beside the existing Maven resolver in `external.rs`, sorting bounded candidate paths for deterministic results and preferring source JARs over class JARs.

Third, extract the process ownership and bounded pipe-reading portions of `src/lsp/handlers/formatting.rs` into a crate-private `src/process.rs`. The shared runner accepts an executable, argument vector, working directory, optional stdin, timeout, cancellation predicate, and stdout/stderr byte limits. It executes directly without a shell, owns descendants through a Unix session or Windows Job Object, and always terminates and joins workers on failure. Preserve all existing formatter messages and tests through a thin adapter.

Fourth, implement production Maven and Gradle runners behind a crate-private discovery executor interface. The production executor uses the shared process runner and temporary files; tests inject deterministic bytes or failures. Bound each result file and diagnostic stream, parse Maven paths without breaking Windows drive-letter colons, parse Gradle JSONL with `serde_json`, and merge successful records with safe metadata. Missing tools and all other errors are logged concisely at most once per build root and become empty results.

Fifth, change `JavaExternalDeclarationIndex::build` to accept `&dyn Project` plus the Java discovery configuration. `JavaAnalyzer` will pass its project and retain lazy construction. Define one build-input predicate covering `pom.xml`, Maven configuration under `.mvn`, Gradle build/settings scripts, `.gradle` and `.gradle.kts` scripts, `gradle.properties`, lockfiles, version catalogs, wrapper metadata, and `buildSrc` inputs. Java updates allocate a fresh `OnceLock` when such a file changes; ordinary Java source changes reuse the existing index; `update_all` always allocates a fresh index. Extend multi-analyzer configuration routing so the Java delegate receives these non-Java changes.

Finally, add behavior-focused tests. Reuse the generated JAR fixture patterns already in `src/analyzer/java/external.rs` and `tests/java_imports_and_hierarchy.rs`. Prove safe Maven and Gradle discovery, exact-cache boundedness, explicit-input merging, offline output parsing, graceful failure, source preference, and update invalidation. Update this living plan after every milestone and commit only the files changed by that milestone.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/e703/bifrost` on the existing issue branch. Do not switch branches or rebase.

After each milestone, run its focused tests, update this document, stage only the files changed in that milestone, and create a multiline checkpoint commit explaining the reason for the change.

Run focused discovery and integration tests during implementation:

    cargo test java_dependency_discovery --lib
    cargo test --test java_imports_and_hierarchy java_external

Run final validation:

    cargo test --features nlp,python
    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    git diff --check

The focused tests must report all matching tests passed. The full feature test suite and strict Clippy must exit zero. `cargo fmt` and `git diff --check` must leave no formatting or whitespace changes outstanding.

## Validation and Acceptance

A Maven project with a direct exact dependency in `pom.xml` and the matching JAR under a configured Maven repository must resolve a dependency type with default configuration. A coordinate that appears only in `dependencyManagement`, an unresolved property, or an unrelated repository directory must not become known.

A Gradle project with an exact coordinate in `gradle.lockfile` and the matching JAR beneath that coordinate's Gradle cache directory must resolve the dependency type with default configuration. A JAR under a different coordinate must not be inspected.

With `OfflineBuildTools`, injected Maven and Gradle executor results must contribute transitive and classifier JAR paths, deduplicate duplicates, and preserve source-JAR precedence. A missing executable, timeout, nonzero exit, malformed record, or absent JAR must not panic or fail analyzer construction.

After an external query initializes the lazy index, changing a Maven or Gradle input and calling `update` must cause the next query to see the new dependency set. Updating only a Java source file must reuse the already initialized external index. The same manifest invalidation must work when Java is one delegate in a multi-language workspace.

External dependency classes must remain absent from `Project::all_files`, `JavaAnalyzer::all_declarations`, symbol search, persistence, and usage-graph starting points.

## Idempotence and Recovery

Discovery is read-only with respect to the analyzed workspace. Temporary Maven output, Gradle init scripts, and Gradle output live in automatically removed temporary directories. Build tools always receive offline arguments and Gradle receives `--no-daemon`. Repeating discovery may read local caches and execute trusted build configuration again but does not update lockfiles or download dependencies.

If process-runner extraction temporarily breaks formatter tests, keep the old formatter adapter behavior intact and fix the shared runner before proceeding to build tools. If a tool output format is unavailable or malformed, discard only that tool root's records; never fall back to scanning a cache or parsing build scripts with regular expressions.

## Artifacts and Notes

The starting branch is clean and equal to both `origin/master` and the remote issue branch at commit `5d20c63e`.

## Interfaces and Dependencies

In `src/analyzer/config.rs`, add public types equivalent to:

    pub enum JavaDependencyDiscoveryMode {
        Disabled,
        Metadata,
        OfflineBuildTools,
    }

    pub struct JavaDependencyDiscoveryConfig {
        pub mode: JavaDependencyDiscoveryMode,
        pub maven_executable: Option<PathBuf>,
        pub gradle_executable: Option<PathBuf>,
        pub timeout: Duration,
    }

Add `dependency_discovery: JavaDependencyDiscoveryConfig` to `JavaAnalyzerConfig`, and add `gradle_cache_roots: Vec<PathBuf>` to `JavaExternalDependencies`. `Disabled` affects automatic discovery only; existing explicit artifacts and coordinates always remain active.

The discovery module returns the existing input model rather than exposing a second public dependency type. Internally, tool records may retain both a `JavaMavenCoordinate` and exact artifact path so custom repositories and Gradle's content-addressed cache do not need to be reverse engineered.

Use existing dependencies: `quick-xml` for POM XML and `serde_json` for Gradle JSONL. Do not add a Maven model, Gradle parser, Java sidecar, or network client dependency.

Revision note, 2026-07-16: Initial decision-complete ExecPlan created from issue #443, the predecessor implementation, repository constraints, and the user's approved plan.
