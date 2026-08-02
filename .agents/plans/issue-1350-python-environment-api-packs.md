# Index exact Python environments as semantic API packs

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

After this work, a Bifrost host can explicitly select a Python environment and obtain deterministic library API information without executing Python. Python source in the workspace will resolve declarations from its selected standard library and installed packages through Bifrost's semantic-model overlay. A definition request such as `re.compile` will return a stable `bifrost-model://` location backed by the selected stub or source artifact, and workspace-symbol, hover, signature help, hierarchy, and references will use the same selected facts where the existing overlay surface supports them.

The user-visible safety boundary is as important as the new API surface: Bifrost will only read configured directories and static distribution metadata. It must never start an interpreter, import a module, run a package installer, evaluate a setup script, or extend `Project::all_files()` with dependency files. Missing stubs and dynamic-only APIs remain explicit incomplete coverage, so they cannot turn an honest "not indexed" result into a false unrecognized-symbol diagnostic.

## Progress

- [x] (2026-08-02 09:00Z) Verified issue #1350, branch `1350-index-python-environments-and-stub-packages-as-exact-api-packs`, and its completed semantic-pack prerequisites.
- [x] (2026-08-02 09:00Z) Diagnosed the Python resolver boundary, reusable exact-artifact pipeline, current LSP overlay consumers, and harness locations.
- [x] (2026-08-02 09:00Z) Recorded the implementation design and acceptance-oriented milestones in this ExecPlan.
- [x] (2026-08-02 09:20Z) Added the disabled-by-default Python environment contract, bounded static root/distribution inventory, Python artifact kinds, and offline fixture coverage.
- [x] (2026-08-02 11:15Z) Added the static Python stub/source artifact producer and dependency-pack adapter, including AST-backed declaration facts and per-module stub precedence.
- [ ] Connect prepared Python packs to an explicitly host-owned activation lifecycle and every advertised query surface.
- [ ] Add deterministic fixture, LSP, cancellation, precedence, and measurement coverage; validate and document the shipped boundary.

## Surprises & Discoveries

- Observation: the reusable semantic-pack system is deliberately host-owned and does not currently run automatically during ordinary analyzer startup.
  Evidence: `crates/bifrost-analysis/src/analyzer/semantic_model/dependency.rs` prepares exact artifacts and activation evidence, while `acquire_active_semantic_models` is currently called by semantic tests and the policy coordinator. `WorkspaceAnalyzer::build` only constructs language analyzers.
- Observation: Python import resolution is intentionally workspace-only today.
  Evidence: `PythonAnalyzer::resolve_module_code_unit` and `python/imports.rs` consult Tree-sitter/store-backed `ProjectFile` indexes; `usages/get_definition/python.rs` reports external imports as an unindexed partial-workspace boundary.
- Observation: some overlay query support already exists, but hover, signature help, and references still depend on `CodeUnit`-backed definitions.
  Evidence: the LSP definition, type hierarchy, and workspace-symbol handlers query `semantic_model_overlay()`, whereas `hover.rs` and `signature_help.rs` only use lexical/`CodeUnit` candidates.
- Observation: the Bifrost RMCP host initially failed repeated `search_symbols` and `get_summaries` requests because the workspace snapshot was not ready.
  Evidence: the exact requests and revision were recorded in issue #1448; later calls succeeded after initialization.
- Observation: the required whole-workspace code-smell validation remains unreliable at the interactive deadline.
  Evidence: the 2026-08-02 `bifrost.code-smells` run reached its five-second deadline after completing correctness, database-in-loop, and nested-loop checks; file-read-in-loop and all later checks were inconclusive. This is owned by open issue #1398, not by this milestone.
- Observation: an isolated scoped Clippy run could not link the analysis build script because `cc` was compiled by a different local Rust toolchain.
  Evidence: `scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-analysis --lib -- -D warnings` failed with E0514 for `cc` after the focused producer suite had passed. This is a host toolchain-cache mismatch, not a Clippy diagnostic.

## Decision Log

- Decision: use an explicitly configured environment descriptor, not a Python executable or automatic environment discovery.
  Rationale: an executable implies runtime inspection and imports. Declared roots, interpreter-version evidence, and platform evidence make discovery offline, bounded, reproducible, and suitable for all hosts.
  Date/Author: 2026-08-02 / Codex
- Decision: retain one resolved distribution as an ordered artifact set and use the existing dependency-pack coordinator.
  Rationale: the coordinator already hashes exact bytes, caches immutable productions, limits reads, supports cancellation, and composes activation evidence. Python must add its static discovery and producer semantics rather than fork that lifecycle.
  Date/Author: 2026-08-02 / Codex
- Decision: determine import precedence before compilation: configured bundled/type stubs, then stub-only distributions, then inline `py.typed` modules, then safe implementation declarations.
  Rationale: one compiled pack must have stable declaration IDs and no equal-rank source conflict. Lower-ranked artifacts only add declarations absent from stronger facts; a same-ID disagreement is partial coverage with a diagnostic.
  Date/Author: 2026-08-02 / Codex
- Decision: expose an explicit host activation context rather than place a catalog path in `AnalyzerConfig`.
  Rationale: #1146 established that catalog selection and persistence ownership belong to the host. `AnalyzerConfig` may describe Python roots, but it must not silently open a global catalog. LSP and MCP opt in through a context they construct and own.
  Date/Author: 2026-08-02 / Codex
- Decision: external Python declarations use model URIs and overlay symbols, never synthetic `ProjectFile`s.
  Rationale: dependency files must remain outside `Project::all_files()`. Model locations retain artifact digest, distribution, relative entry path, and declaration range for navigation without making dependencies workspace source.
  Date/Author: 2026-08-02 / Codex

## Outcomes & Retrospective

Milestones 1 and 2 are complete. `PythonAnalyzerConfig` now requires explicit roots and version/platform evidence before external discovery can occur. `resolve_python_semantic_pack_dependencies` walks only those roots, reads `METADATA` and optional `top_level.txt`, produces deterministic `ResolvedDependency` values, rejects root-escaping symlinks, observes cancellation, and leaves `Project::all_files()` unchanged. `PythonDependencyPackAdapter` now feeds the shared exact-artifact coordinator without reading an interpreter: `PythonArtifactPackProducer` uses the existing Tree-sitter grammar to project modules, classes, protocols, methods, properties, overloads, typed variables, aliases, generics, signatures, and inheritance into semantic-model declaration facts. Stub files outrank same-module source files independent of artifact order. The focused producer fixture passed in an isolated Cargo target. Host activation and editor integration remain to be implemented.

## Context and Orientation

`crates/bifrost-analysis/src/analyzer/semantic_model/` contains the generic semantic-pack implementation. A semantic pack is an immutable, compiled description of declarations outside normal workspace source. `producer.rs` defines a bounded exact-file producer contract. `dependency.rs` reads already-resolved artifacts, hashes their bytes, reuses or installs catalog productions, and returns activation evidence. `runtime.rs` selects compatible packs and publishes a `SemanticModelOverlay` into an immutable analyzer snapshot. `overlay.rs` creates virtual `bifrost-model://v1/...` locations, so external declarations do not need a `ProjectFile`.

`crates/bifrost-analysis/src/analyzer/config.rs` presently contains only generic, JVM, and C# settings. `crates/bifrost-analysis/src/analyzer/python/` contains the workspace Python analyzer. Its `adapter.rs` parses one workspace `.py` file with Tree-sitter; `imports.rs` resolves module and export names through files already in the workspace. It does not inspect external packages. `crates/bifrost-analysis/src/analyzer/usages/get_definition/python.rs` deliberately marks unresolved external imports as incomplete rather than guessing.

`crates/bifrost-analysis/src/analyzer/workspace.rs` builds one language analyzer per workspace language. It is the correct shared place for an opt-in activation hook because it has the completed analyzer snapshot. The hook must receive a caller-owned catalog and activation persistence, never create one implicitly.

The LSP handlers in `crates/bifrost-lsp/src/lsp/handlers/` already use an overlay for definition, type hierarchy, and workspace symbol. Hover and signature help currently use only `CodeUnit`s; references must similarly gain an overlay route. All three must use the same overlay lookup and preserve existing workspace results and ambiguity behavior.

`tests/suite_semantic/main.rs` and `tests/suite_lsp_parity/main.rs` are consolidated integration harnesses. New suite tests belong beside their peers and need one `mod` entry in the corresponding `main.rs`. Use `tests/common/inline_project.rs` for small workspace fixtures. Environment artifacts belong in a temporary directory outside the fixture workspace so the test can prove `Project::all_files()` remains unchanged.

## Plan of Work

### Milestone 1: Declare and inventory an exact Python environment

Add `PythonAnalyzerConfig` to `crates/bifrost-analysis/src/analyzer/config.rs` and add it as the `python` field of `AnalyzerConfig`. It must default to disabled. The descriptor must carry an explicit interpreter implementation/version string, platform tag, one standard-library root, zero or more ordered stub roots, and zero or more selected distribution roots. Resolve relative roots against `Project::root()` at the Python discovery boundary, normalize only for comparison, and reject roots outside an explicitly declared descriptor rather than falling back to process environment, `sys.path`, or package caches.

Create `crates/bifrost-analysis/src/analyzer/python/external.rs` for static discovery. Define a `PythonEnvironmentDiscoveryOutcome` with sorted `ResolvedDependency` values, bounded diagnostics, `complete`, `cancelled`, and a profile containing directories and candidate artifacts considered. Reuse `DependencyDiscoveryOutcome` where the generic coordinator can consume it, but keep Python-only inventory/provenance types near the Python adapter.

Walk roots iteratively with explicit directory, file-count, metadata-size, and path-component limits. Skip symlinks that leave a configured root. Discover a distribution only from static `.dist-info`/`.egg-info` metadata and record its normalized name, exact version, `py.typed` marker, root role, Python version, and platform as activation/provenance evidence. Discover modules and packages from `.pyi` first, then `.py` only when the selection permits safe source fallback. Model namespace packages from directory layout without requiring `__init__.py`; do not claim a namespace member exists unless a selected artifact supplies it. Cancellation must be checked between directory entries, metadata files, and source files.

Add behavior-focused unit coverage in a new `tests/suite_semantic/python_dependency_pack.rs` and register it in `tests/suite_semantic/main.rs`. Its temporary environment must contain one standard-library module, a stub-only distribution, an inline typed distribution, an untyped implementation distribution, a namespace package, and a platform/version-guarded artifact. Assert stable inventory order across shuffled directory creation, no interpreter process invocation, bounded cancellation, correct static metadata provenance, and unchanged workspace `Project::all_files()`.

### Milestone 2: Compile Python declaration artifacts

Extend `ExternalArtifactKind` in `semantic_model/producer.rs` with Python stub and Python source artifact kinds, and update the exhaustive artifact-kind formatter in `semantic_model/dependency.rs`. Add `crates/bifrost-analysis/src/analyzer/python/artifact.rs`, exporting `PythonStubPackProducer` and the lower-level parser/projection helpers only where the adapter needs them. Reuse the Python Tree-sitter grammar and declaration collection where it represents `.pyi` and safe `.py` syntax accurately; do not parse Python with text splitting or import it to learn declarations.

The producer must emit `AuthoredSemanticModelPack` declaration facts for modules, classes, functions, methods, properties, variables, aliases, overload groups, parameter kinds, annotations, generics, protocols, inheritance, and re-exports. Give a declaration a stable ID derived from the Python qualified name plus semantic kind, not an absolute path. Use a model locator derived from the production digest, distribution identity, artifact-relative path, and source range. Convert unsupported syntax, conditional version/platform guards, dynamic `__getattr__`, wildcard re-exports without static targets, and malformed modules into bounded diagnostics and partial coverage rather than silently empty facts.

In `python/external.rs`, implement `PythonDependencyPackAdapter` for the generic `DependencyPackAdapter` trait. It must merge each selected distribution's ordered exact artifacts before compilation. Stronger artifact rows win for shared declaration IDs; weaker rows can add non-conflicting facts. A conflict must remain partial and retain both artifact-provenance diagnostics. The adapter's name/version, producer identity, `python` language, `python` ecosystem, interpreter/platform, distribution version, and every selected artifact digest must enter the existing production identity. Reuse the generic coordinator's file byte, record, diagnostic, and cancellation caps.

Extend `python_dependency_pack.rs` to prove byte-identical reuse from two differently named environment roots; changing only one `.pyi` produces a new pack for that distribution; the precedence order is deterministic; overloads and typed attributes survive compilation; and missing/dynamic APIs report partial coverage. Add producer-focused cases to `tests/suite_semantic/external_artifact_pack.rs` only when they exercise the common exact-producer contract across languages.

### Milestone 3: Make Python pack activation explicit and snapshot-safe

Introduce a public analysis-library context beside `WorkspaceAnalyzer` in `crates/bifrost-analysis/src/analyzer/workspace.rs`. Name it `SemanticModelWorkspaceContext` and make it contain caller-owned `&SemanticPackCatalog`, optional `SemanticModelActivationPersistence`, `SemanticModelActivationRequest`, `DependencyPackLimits`, and `CancellationToken`. Add a `WorkspaceAnalyzer::activate_python_environment_packs` operation that accepts this context plus the already-built workspace. It must: discover from `config.python`; prepare the discovered artifacts through `PythonDependencyPackAdapter`; compose the returned evidence into the supplied activation request; call `acquire_active_semantic_models`; and return a typed outcome containing discovery, preparation, and runtime reports. When discovery/preparation is cancelled or wholly unavailable, leave any prior overlay unchanged. Do not open catalogs, create environments, modify Python configuration, or load dependency paths into the project.

Thread that context through the LSP and MCP session construction only when their host configuration explicitly supplies it. Add an initialization option that carries declared roots and a catalog location chosen by the host integration layer; validate paths once at startup and surface bounded incomplete-coverage diagnostics in existing server logs/status reporting. Existing hosts with no context must retain their current behavior exactly. Do not add an implicit process-environment fallback.

Add integration tests to `python_dependency_pack.rs` and `semantic_model_overlay.rs` that build a `WorkspaceAnalyzer` for a one-file Python workspace, activate a fixture environment, and prove an external fact is available from the published overlay while the dependency path is absent from `analyzed_files()` and `Project::all_files()`. Verify repeated activation reuses the catalog production, changing one dependency invalidates only that pack, cancellation does not publish, and a cache read still obeys source-generation checks.

### Milestone 4: Route all advertised editor queries through the same overlay

Retain the existing LSP definition, type-hierarchy, and workspace-symbol overlay paths, but make their name/qualified-name selection Python-aware so an imported module member resolves before broad same-short-name fallback. Add model-location and provenance assertions to their existing tests.

In `crates/bifrost-lsp/src/lsp/handlers/hover.rs`, add a fallback after normal workspace resolution that queries the unique overlay symbol at the cursor/import context and renders its Python signature plus pack provenance. In `signature_help.rs`, add the corresponding overlay method/function/class signature route, including positional-only, keyword-only, variadic, and overload selection behavior. Do not manufacture a `CodeUnit` for an external symbol.

Add an overlay-aware reference route in the appropriate existing reference/navigation handler. It must return workspace uses that resolve to the unique selected external declaration, but it must not report dependency-source files as workspace references. If a dynamic/missing external API has only partial coverage or multiple equal candidates, return the existing incomplete/empty behavior rather than a false reference set.

Extend `tests/suite_lsp_parity/intellij_python_definition.rs` and `tests/suite_lsp_parity/intellij_python_find_usages.rs`, and add focused Python LSP fixture helpers if necessary. Unignore the existing `re` external-module find-usages case only after it can be driven with an explicit fixture environment. Add end-to-end cases for standard-library definition/hover/signature, stub-only package re-export, inline `py.typed` method hierarchy, namespace package, aliases, overloads, and an intentionally dynamic API that remains unresolved without an unrecognized-symbol error. Register any new module in `tests/suite_lsp_parity/main.rs`.

### Milestone 5: Measure, document, and release-check the boundary

Add a compact deterministic measurement in `tests/suite_semantic/measure_python_environment_pack.rs` and register it in the suite harness. It must record environment discovery duration, artifact count/bytes, packs reused/generated, overlay records, and retained bytes for the checked-in fixture. Establish a non-flaky ceiling from the fixture size and ensure cancellation is observed before an entire oversized artifact is retained.

Update `docs/src/content/docs/semantic-model-packs.md` with the Python activation contract: roots must be explicit, selection is offline, precedence order, provenance visible to users, virtual navigation URI behavior, supported static surface, incomplete/dynamic boundary, and catalog ownership. Add the host configuration example only after the final public API is fixed; it must not imply automatic interpreter discovery.

Run `cargo fmt`, focused featureless semantic and LSP suites, then the appropriate all-target Clippy gate. Before completion, use the Bifrost policy MCP selection required by `AGENTS.md`: list policies, then run `bifrost.code-smells` and every named executable repository root in one request with the current UTC date. Treat `finding` as work to fix and `unreliable` as failed validation. Record policy roots, report status, timings, and any known pre-existing diagnostics in this plan.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/9f7e/bifrost`.

1. Start with the small offline inventory/producer test while iterating:

       cargo test --test suite_semantic python_dependency_pack::

   Expect the fixture tests to create their environment outside the project root and to report deterministic selected modules and no workspace-file expansion.

2. Exercise the generic lifecycle and overlay tests after each adapter change:

       cargo test --test suite_semantic dependency_semantic_pack:: semantic_model_overlay:: python_dependency_pack::

   Expect exact-byte reuse to be `Reused` on the second run and no overlay after the cancellation fixture.

3. Exercise the real LSP boundary without NLP:

       cargo test --test suite_lsp_parity intellij_python_definition:: intellij_python_find_usages::

   Expect external definitions to have a `bifrost-model://v1/` URI and references to contain only workspace use sites.

4. Before each milestone checkpoint, format and run task-scoped linting:

       cargo fmt --check
       cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings

   Expand to the repository's full prescribed all-feature Clippy command only for the final pre-push gate. Do not enable NLP for routine Python semantic-pack iteration.

5. Before completing the issue, run the final gate through the managed target helper and clean up normally:

       scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
       scripts/with-isolated-cargo-target.sh uv run --python 3.12 -- cargo test --features nlp,python

   Check available disk before the final NLP build and do not run it concurrently with another worktree's NLP build.

## Validation and Acceptance

The feature is accepted only when the fixture environment proves all of the following observable behavior:

- The same declared environment inventory is produced after directory creation order changes; it includes only configured standard-library and selected distribution roots, records interpreter/distribution/version/digest/source provenance, and does not run Python or access the network.
- Stub precedence is deterministic across configured bundled stubs, stub-only distributions, inline `py.typed` packages, and safe source declarations. Re-exports, aliases, overloads, parameter kinds, annotations, generics, protocols, inheritance, variables, properties, and namespace packages have positive coverage and near-miss coverage.
- A Python workspace can navigate, hover, show signature help, browse hierarchy/symbols, and find workspace references for representative selected-library declarations through a single activated overlay. Definitions use model locations; dependency files are never returned as project files or references.
- Missing stubs and static-dynamic APIs remain partial with a bounded diagnostic. They do not produce an authoritative unrecognized-symbol diagnostic or an invented declaration/reference result.
- `Project::all_files()` and `IAnalyzer::analyzed_files()` omit every external artifact. Re-running with unchanged exact bytes reuses its catalog production; changing one artifact changes only its production. Cancellation, limits, and corrupt metadata cannot publish an empty complete result.
- The measurement fixture satisfies its documented time and memory ceilings, and the final policy check is clean or has explicitly recorded unrelated diagnostics.

## Idempotence and Recovery

All test environments are built under `tempfile` roots outside the workspace and are removed automatically. Catalog tests must use `SemanticPackCatalog::open_ephemeral` unless they are explicitly testing persistence, so reruns cannot change a developer's shared catalog. If a catalog fixture becomes corrupt, recreate only that temporary root; do not delete a user-owned catalog.

The producer never writes discovered source, stubs, or distribution metadata. A failed or cancelled discovery/preparation run returns diagnostics and leaves the last successfully published overlay in place. If a new host integration changes the public API during implementation, update the Decision Log, all affected test helpers, and the host documentation before proceeding.

## Artifacts and Notes

The current closest reusable patterns are `JvmDependencyPackAdapter` in `crates/bifrost-analysis/src/analyzer/jvm/external.rs`, `CSharpDependencyPackAdapter` in `crates/bifrost-analysis/src/analyzer/csharp/external.rs`, exact-byte lifecycle coverage in `tests/suite_semantic/dependency_semantic_pack.rs`, and virtual external declaration coverage in `tests/suite_semantic/semantic_model_overlay.rs`. They establish the shared contracts, but Python parsing, static metadata selection, precedence, and host activation must be implemented in Python-specific files rather than copied from JVM or .NET formats.

The initial RMCP navigation failure is tracked separately as #1448. It does not change the #1350 API-pack design, but future latency/readiness regressions during validation should be recorded with the exact Bifrost tool request, revision, host stack, and elapsed time.

Plan revision (2026-08-02): created from the live #1350 diagnosis. It defines explicit offline environment selection, the Python adapter boundary, host-owned activation, all advertised editor query surfaces, and staged acceptance tests before implementation begins.

Plan revision (2026-08-02): completed Milestone 1. The plan now records the concrete configuration and discovery implementation and its focused fixture validation; no dependency files are treated as workspace source.

Plan revision (2026-08-02): recorded the required policy validation. The selected built-in `bifrost.code-smells` pack was unreliable because of the pre-existing interactive-deadline problem tracked by #1398; no new policy finding was introduced by the milestone.

Plan revision (2026-08-02): completed Milestone 2. Python artifacts are parsed through Tree-sitter rather than source-text fallbacks, and the adapter preserves static stub-over-source precedence before pack facts are merged.

## Interfaces and Dependencies

At the end of Milestone 1, `crates/bifrost-analysis/src/analyzer/config.rs` must expose a disabled-by-default configuration equivalent to:

    pub struct PythonAnalyzerConfig {
        pub environment: Option<PythonEnvironmentConfig>,
    }

    pub struct PythonEnvironmentConfig {
        pub implementation: String,
        pub version: String,
        pub platform: String,
        pub standard_library_root: PathBuf,
        pub bundled_stub_roots: Vec<PathBuf>,
        pub distribution_roots: Vec<PathBuf>,
        pub limits: PythonEnvironmentLimits,
    }

At the end of Milestone 2, the Python module must expose a static adapter equivalent to:

    pub struct PythonDependencyPackAdapter;

    pub fn discover_python_environment(
        project_root: &Path,
        config: &PythonEnvironmentConfig,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyDiscoveryOutcome;

`PythonDependencyPackAdapter` implements `DependencyPackAdapter`; it has no interpreter, subprocess, network, or package-manager dependency.

At the end of Milestone 3, `WorkspaceAnalyzer` must expose an opt-in operation equivalent to:

    pub fn activate_python_environment_packs(
        &self,
        context: SemanticModelWorkspaceContext<'_>,
    ) -> PythonSemanticModelActivationOutcome;

The context owns no global state and borrows the caller's `SemanticPackCatalog`; the outcome exposes the discovery, preparation, and runtime reports so a host can distinguish ready, partial, unavailable, and cancelled operation. Existing `WorkspaceAnalyzer::build*` APIs remain valid and publish no Python dependency overlay unless the host invokes this explicit operation.
