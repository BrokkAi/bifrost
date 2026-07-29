# Extract Bifrost analysis, runtime, and protocol hosts into Cargo workspace packages

This ExecPlan is a living document. It must be maintained according to `.agents/PLANS.md` from the repository root. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be updated whenever work stops, a milestone completes, or a design decision changes.

## Purpose / Big Picture

Bifrost is currently one Rust package. A change confined to its Model Context Protocol (MCP) server still compiles the Language Server Protocol (LSP) server, while a change confined to LSP still enters the same broad package and integration-test fanout as MCP, Python, the command-line interface, benchmarks, and every language analyzer. After this plan is complete, Cargo will enforce a one-way dependency graph: language analysis feeds the protocol-neutral code-intelligence runtime, the MCP and LSP hosts depend on that runtime without depending on one another, and the existing `brokk-bifrost` package remains the stable command-line and Python facade.

A developer will be able to run `cargo test -p brokk-bifrost-mcp` or `cargo test -p brokk-bifrost-lsp` and compile only that host plus shared analysis/runtime dependencies. Existing users will continue to install `brokk-bifrost`, import `brokk_bifrost`, load the `bifrost_searchtools` Python extension, invoke the same MCP tools, and use the same LSP methods. The release workflow will validate the complete packaged workspace from one commit, publish implementation crates in dependency order, and publish the unchanged facade last.

## Progress

- [x] (2026-07-29 09:52Z) Refreshed the issue and fast-forwarded the worktree to `origin/master` commit `d1b33c61`, including the validated release-promotion DAG.
- [x] (2026-07-29 09:52Z) Mapped the current runtime, MCP, LSP, facade, benchmark, Python, packaging, and CI boundaries and confirmed concrete backwards dependencies.
- [x] (2026-07-29 09:52Z) Chose package identities, dependency direction, facade compatibility strategy, and pre-publication package-set validation strategy.
- [x] (2026-07-29 09:52Z) Authored this initial ExecPlan for issue #1275.
- [x] (2026-07-29 10:05Z) Established workspace metadata, four compiling package skeletons, an executable dependency-boundary check, and a package-neutral percent-decoder without moving protocol behavior.
- [x] (2026-07-29 11:44Z) Extracted analysis and the typed runtime into independently compiling packages, preserved the root Rust API, and passed 1,781 analysis unit tests plus runtime/facade contract tests.
- [x] (2026-07-29 12:38Z) Extracted the LSP host and its 193-test subprocess contract, preserved root/benchmark callers, and passed 297 independent package tests.
- [x] (2026-07-29 13:19Z) Extracted and independently validated the MCP host package, then reconnected the CLI, Python facade, and root build identity.
- [x] (2026-07-29 13:19Z) Moved both protocol subprocess contracts and CI impact mappings onto the proven package boundaries.
- [ ] Make crate packaging, notices, wheels, and the release-promotion DAG workspace-aware.
- [ ] Run the complete local validation, policy gate, packaged-consumer smoke, and cross-platform CI matrix.

## Surprises & Discoveries

- Observation: The protocol-neutral runtime boundary already exists and borrows a caller-owned `WorkspaceAnalyzer`, so neither host has to surrender its lifecycle model.
  Evidence: `src/code_intelligence.rs::CodeIntelligenceRuntime` accepts a workspace reference and optional `CancellationToken`; `SearchToolsService` supplies watcher-refreshed snapshots while LSP workers supply overlay-aware analyzers.

- Observation: Core search tooling has a backwards dependency on LSP for a generic percent-decoder.
  Evidence: `src/searchtools/mod.rs` imports `crate::lsp::conversion::percent_decode`, which is used by `src/searchtools/selectors.rs`.

- Observation: The benchmark application deliberately calls LSP hierarchy handlers and MCP transport helpers.
  Evidence: `src/benchmark/runner.rs` imports LSP conversion and hierarchy handlers, and `src/benchmark/mcp_session.rs` imports `mcp_common`. The benchmark therefore belongs above both hosts in the root application/facade package, not in analysis or runtime.

- Observation: `SearchToolsService` still reaches into an MCP descriptor module for policy-input size limits.
  Evidence: `src/searchtools_service.rs` references `crate::mcp_extended::MAX_RUN_POLICY_SELECTOR_BYTES` and `MAX_RUN_POLICY_PATH_BYTES`. Those limits belong with the typed MCP request/service contract when the MCP package is extracted.

- Observation: Package extraction changes publication, not only compilation. Cargo removes the local `path` portion of a versioned dependency when publishing a package, and each non-development workspace dependency must therefore be separately available from the registry.
  Evidence: The root facade cannot be verified as a standalone registry package unless its extracted dependencies have versions and the packaged set is tested with local registry overrides before publication.

- Observation: Vendored Scala and Kotlin native grammars are compiled by the root `build.rs`, but a packaged analysis crate cannot include files outside its own package directory.
  Evidence: `build.rs` compiles `vendor/tree-sitter-scala/src` and `vendor/tree-sitter-kotlin/src`; these sources must move under the analysis package or the analysis package will not build independently from its `.crate` archive.

- Observation: A four-file `get_summaries` request took 14.304 seconds and ended with the analyzer request-wide budget error during planning.
  Evidence: The reproduction was added to existing issue #1298. Planning used exact symbol/source reads and shell inspection afterward.

- Observation: Moving the root version into `[workspace.package]` during the skeleton milestone would break the existing release-version parser before package publication is otherwise changing.
  Evidence: `scripts/release-version.test.mjs` asserts that the single source of truth is the root `[package]` version. Milestone 1 therefore shares non-version package metadata and uses the dependency-boundary check to enforce temporary member-version equality; Milestone 5 moves the version source and release tooling together.

- Observation: Cancellation is an analysis execution primitive rather than runtime-owned state.
  Evidence: Analyzer traversal, search tooling, and work budgets consume `CancellationToken` directly. The analysis package therefore owns it and the runtime and root facade re-export the same type, avoiding a reverse dependency from analysis to runtime.

- Observation: Search result rendering must remain beside the analysis result types under Rust's orphan rules.
  Evidence: `searchtools_render.rs` defines inherent methods on `SearchSymbolsResult`, `SymbolSourcesResult`, and related analysis-owned types. Moving those implementations to MCP would make them illegal cross-crate inherent implementations, so analysis owns the protocol-neutral Markdown rendering while MCP will own transport envelopes and descriptors.

- Observation: Reference differential testing is protocol-neutral analysis audit machinery, not a root-host concern.
  Evidence: The module exercises analyzer resolution, usage graphs, syntax preparation, and persisted query scopes without importing LSP, MCP, CLI, or Python types, so it moved with analysis.

- Observation: The analysis package archive verifies independently and includes its native grammar/resource inputs.
  Evidence: `cargo package -p brokk-bifrost-analysis --allow-dirty --locked` verified a 577-file archive (6.3 MiB compressed). Ordinary runtime verification cannot yet resolve unpublished `brokk-bifrost-analysis = 0.8.12`; Milestone 5's unpacked package-set patches are required for that pre-publication proof.

- Observation: The root benchmark is the sole non-LSP caller of concrete hierarchy handlers.
  Evidence: After extraction, root compilation found only `src/benchmark/runner.rs` importing call- and type-hierarchy handlers. The LSP package now exposes those two modules through a documented-hidden `benchmark_api` rather than making the whole handler tree public.

- Observation: The subprocess LSP contract needs an executable owned by the package under test.
  Evidence: Cargo does not provide the root facade's `CARGO_BIN_EXE_bifrost` to another package's integration tests. A tiny `bifrost-lsp-test-server` binary accepts the compatibility `--root ... --server lsp` arguments and invokes the real package entry point, so the 193 protocol tests compile and run without selecting the root package.

- Observation: This workstation's default `rustdoc` and `rustc` are different builds of Rust 1.96.0.
  Evidence: executable tests passed, but the automatic doctest phase rejected artifacts built by the rustup Rustc because PATH selected Homebrew Rustdoc (LLVM 22.1.6 versus 22.1.2). `RUSTDOC=/Users/dave/.cargo/bin/rustdoc cargo test -p brokk-bifrost-lsp --doc --all-features` passed. This is a local toolchain-path issue, not an LSP failure.

- Observation: The subprocess MCP contract, like the LSP contract, needs an executable owned by the package under test.
  Evidence: `bifrost-mcp-test-server` accepts the MCP-only compatibility arguments and invokes the extracted host directly; 26 real protocol tests now run without selecting the root facade or LSP package.

- Observation: The MCP contract had one root CLI policy-mode assertion mixed into the host protocol suite.
  Evidence: The package test server intentionally implements only MCP serving. The existing root `bifrost_policy_cli` integration suite remains the owner of CLI policy-mode behavior, while the moved MCP suite retains tool registration, invocation, cancellation, rendering, workspace, and session-refresh coverage.

- Observation: Root build identity can remain facade-owned without introducing a reverse dependency.
  Evidence: The MCP host exposes a typed `run_stdio_server_with_build_identity` entry point; the root binary injects `BIFROST_BUILD_IDENTITY`, and `mcp_build_identity_facade` proves that an MCP initialize response reports the exact facade identity.

## Decision Log

- Decision: Keep the repository-root package named `brokk-bifrost`, with library name `brokk_bifrost`, as the only compatibility facade promised to existing users.
  Rationale: Issue #1275 explicitly excludes a public crate-name/API breakup. The root package must continue to own the `bifrost` binary, PyO3 module, benchmark/fuzzer applications, build identity, and compatibility re-exports.
  Date/Author: 2026-07-29 / Codex

- Decision: Create versioned packages named `brokk-bifrost-analysis`, `brokk-bifrost-runtime`, `brokk-bifrost-mcp`, and `brokk-bifrost-lsp` under `crates/bifrost-analysis`, `crates/bifrost-runtime`, `crates/bifrost-mcp`, and `crates/bifrost-lsp`.
  Rationale: The package names describe stable architectural roles, avoid a vague `core` bucket, and allow Cargo and the release workflow to express the required dependency order. These are implementation packages; public compatibility remains at `brokk-bifrost`.
  Date/Author: 2026-07-29 / Codex

- Decision: Use the dependency graph `analysis -> runtime -> {mcp, lsp} -> root facade`, where an arrow means “is depended on by.” MCP and LSP may also depend directly on analysis types when those types are their typed inputs or results, but neither host may depend on the other and neither analysis nor runtime may depend on a host.
  Rationale: `CodeIntelligenceRuntime` intentionally exposes analyzer-owned types. Forcing every analyzer type through a second wrapper crate would add churn without improving isolation; the important rule is the absence of host dependencies below the host layer.
  Date/Author: 2026-07-29 / Codex

- Decision: Keep versions in lockstep through `[workspace.package]` and give every facade dependency both `path` and `version` keys.
  Rationale: Local builds need paths, while packaged manifests discard paths and resolve the same version from the registry. Lockstep versions make the release order and compatibility contract deterministic.
  Date/Author: 2026-07-29 / Codex

- Decision: Move LSP before MCP after analysis/runtime extraction.
  Rationale: LSP is the smaller first independence proof: it has a clear `src/lsp/` boundary and no Python ownership. MCP includes `SearchToolsService`, renderers, tool registries, the CLI server path, NLP forwarding, and the Python facade, so it is the riskier second host migration.
  Date/Author: 2026-07-29 / Codex

- Decision: Validate the entire set of `.crate` archives before publishing by unpacking them into an isolated temporary consumer and overriding every implementation package to the unpacked path.
  Rationale: Stable Cargo packages workspace members separately. Before those versions exist on the public registry, ordinary facade package verification cannot download them. A temporary consumer with `[patch.crates-io]` entries proves that the normalized packaged manifests and packaged file contents build together without publishing partial state.
  Date/Author: 2026-07-29 / Codex

- Decision: Preserve full merge-queue and `master` validation while adding package-selective pull-request jobs only after the corresponding package boundary compiles independently.
  Rationale: Paths are not proof of a valid dependency boundary. The package graph must first make independent validation truthful, while shared or unknown changes continue selecting the full matrix.
  Date/Author: 2026-07-29 / Codex

- Decision: Keep the root `[package]` version authoritative until the packaging/release milestone, while requiring every skeleton manifest to use that same exact version through `scripts/check-workspace-dependencies.mjs`.
  Rationale: This keeps every milestone green and avoids changing release parsing twice. The final lockstep `[workspace.package]` version remains required and will land atomically with its consumers and tests.
  Date/Author: 2026-07-29 / Codex

- Decision: Let analysis own cancellation, protocol-neutral search-result rendering, model-context sampling, and reference-differential audits; let runtime re-export cancellation and own only typed orchestration.
  Rationale: These facilities directly depend on analysis types or are called below the runtime layer. Co-locating them preserves a one-way package graph and avoids wrapper types or illegal inherent implementations while keeping host transport concerns out of analysis.
  Date/Author: 2026-07-29 / Codex

- Decision: Keep LSP internals private and provide only a hidden benchmark adapter for the two hierarchy modules measured by the root benchmark.
  Rationale: Root sits above both hosts and legitimately benchmarks real handler paths, but broad public handler visibility would turn former same-crate implementation details into an accidental API.
  Date/Author: 2026-07-29 / Codex

- Decision: Keep the MCP package's legacy stdio entry point and add a typed build-identity variant for the facade.
  Rationale: Package-local callers retain a useful default based on the package version, while the public `bifrost` binary can preserve its richer source-derived identity without the MCP package depending back on root.
  Date/Author: 2026-07-29 / Codex

- Decision: Keep CLI policy-mode validation in the root integration suite rather than teaching the MCP package test server unrelated application modes.
  Rationale: The extracted package owns MCP transport and service behavior; root owns CLI argument dispatch. Separating those contracts makes the independent-host test truthful without reducing behavior coverage.
  Date/Author: 2026-07-29 / Codex

## Outcomes & Retrospective

Milestone 1 is complete. The repository is now a non-virtual Cargo workspace with the root facade as its default member and four version-matched implementation package skeletons. The checked-in graph validator rejects reverse dependencies, cross-host dependencies, host-only external dependencies below their layer, unexpected members, and version drift. Search tooling no longer imports the LSP module for percent decoding; the shared utility retains Unicode behavior and adds malformed-escape coverage. No production module has moved yet, so public behavior and root packaging remain unchanged.

Milestone 2 is complete. Analyzer, policy/query, search, storage, optional NLP, resource, vendored grammar, and reference-differential code now build in `brokk-bifrost-analysis`; `CodeIntelligenceRuntime` builds in `brokk-bifrost-runtime` with only analysis beneath it. The root crate is a compatibility facade for the moved API, proven by a real inline-project query. The runtime integration contract passes in its package, the full analysis library suite passes 1,781 tests with six intentional ignores, and the runtime dependency tree contains no LSP, MCP, or PyO3 dependency. The analysis `.crate` also verifies independently from its packaged contents.

Milestone 3 is complete. LSP transport, overlays, request lifecycle, progress, conversion, and handlers now compile in `brokk-bifrost-lsp`, and root preserves `brokk_bifrost::lsp` through a dependency re-export. The real subprocess contract and shared client harness moved with the host; the package's own test server keeps those tests independent of the facade. The package passed 104 unit tests and 193 subprocess tests, its tree contains analysis/runtime and LSP transport but no MCP package, and every remaining root integration test compile-checks against the relocated shared client. CI now runs the LSP package directly for LSP-selected changes.

Milestone 4 is complete. MCP descriptors, registry, transport, service lifecycle, watcher/scoped-project support, structured outputs, and tool argument handling now compile in `brokk-bifrost-mcp`. Root preserves the existing Rust paths, owns PyO3 and the public binary, and injects its build identity through the typed host entry point. The independent package passed 101 unit tests, 26 subprocess protocol tests, and its doctest compile; its dependency tree contains analysis/runtime but no LSP transport. The root facade query/MCP contract, broad integration-test compile, exact build-identity test, and all 59 Python tests pass. CI now selects the MCP package directly for MCP-only changes while shared changes still select both hosts.

## Context and Orientation

The repository root is both a Cargo package and the future workspace root. `Cargo.toml` currently defines `brokk-bifrost` as an `rlib` and `cdylib`, declares all analyzer, LSP, MCP, CLI, NLP, and Python dependencies, and relies on Cargo’s automatic discovery of binaries in `src/bin/` and integration tests in `tests/`. `pyproject.toml` asks Maturin to build that root package with `python` and `extension-module`, so the root package must remain the PyO3 extension package.

`src/analyzer/` and its supporting storage, project, path, graph, policy, structural-query, and search modules implement language analysis. In this plan, “analysis” means those protocol-independent facilities plus typed search operations that accept Rust values rather than JSON-RPC messages. The analysis package also owns the vendored Scala and Kotlin grammars because their native parser symbols are prerequisites for building the analyzers.

`src/code_intelligence.rs` defines `CodeIntelligenceRuntime`. A runtime is an in-process typed API: it executes parsed `CodeQuery` values and policy inputs against a caller-owned `WorkspaceAnalyzer`, honors limits and cancellation, and returns analyzer/policy result types. It does not own filesystem watchers, editor overlays, JSON-RPC request IDs, progress messages, tool descriptors, or text rendering.

`src/lsp/` and `src/lsp/server.rs` implement the LSP host. The LSP host owns open-document overlays, URI and UTF-16 range conversion, request/response framing, worker scheduling, progress, diagnostics, cancellation races, and editor-facing result projection. `tests/bifrost_lsp_server.rs` is its principal end-to-end contract test.

`src/searchtools_service.rs`, `src/searchtools_render.rs`, `src/mcp_common.rs`, the `src/mcp_*.rs` descriptor/registry modules, and `src/model_context.rs` implement the MCP host. The MCP host owns workspace/session lifecycle, request argument normalization, tool schemas and selection, protocol registration, JSON/text rendering, and MCP stdio behavior. `tests/bifrost_mcp_server.rs` is its principal end-to-end contract test. The Python module calls `SearchToolsService`, but remains in the facade because PyO3 and the published wheel are public distribution concerns.

`src/bin/bifrost.rs`, `src/python_module.rs`, `src/benchmark/`, `src/mcp_property_fuzzer/`, and development binaries remain in the root facade/application package. They are allowed to depend on both hosts. Existing paths such as `brokk_bifrost::analyzer`, `brokk_bifrost::lsp`, `brokk_bifrost::searchtools_service`, and the current root-level type re-exports must remain valid through dependency-crate re-exports.

The repository already has impact-selected CI in `scripts/ci-impact.mjs` and `.github/workflows/ci.yml`, crate checks in `scripts/check-crate-package.sh`, version and plugin synchronization in `scripts/release-version.mjs` and `scripts/check-codex-plugin-manifest.mjs`, notice generation in `scripts/generate-rust-third-party-notices.sh`, wheel creation in `.github/workflows/build-wheels.yml`, crate publication in `.github/workflows/publish-crate.yml`, and the promotion graph in `.github/workflows/release.yml`. All of them currently assume one root package.

## Plan of Work

### Milestone 1: Establish the workspace and remove backwards utility edges

Add a non-virtual `[workspace]` section to the existing root `Cargo.toml` with resolver `3`, the four implementation members, and `default-members = ["."]`. Put shared edition, license, repository, and homepage metadata in `[workspace.package]`, but keep the root package’s public description, version, keywords, crate types, excludes, and PyO3 features explicit during this milestone. Member manifests use the same explicit version, enforced by the graph validator. Milestone 5 moves the version into `[workspace.package]` atomically with release-version tooling. Put exact shared third-party versions in `[workspace.dependencies]` as production modules move, without changing the resolved `Cargo.lock` graph merely for the skeleton.

Create skeletal member manifests and libraries with `publish = true`; do not move public modules until each skeleton compiles. Each root dependency on an implementation crate must use both `path` and the inherited workspace version. Add `scripts/check-workspace-dependencies.mjs`, with tests in `scripts/check-workspace-dependencies.test.mjs`, to consume `cargo metadata --no-deps --format-version 1` and reject host-to-host edges, host dependencies below runtime, or unexpected workspace members.

Move `percent_decode` from `src/lsp/conversion.rs` into the existing protocol-neutral path utility layer and make both search tooling and LSP call it. Preserve its Unicode and malformed-escape tests at the neutral location. Keep benchmarks in the root package; their use of LSP and MCP is valid because the root sits above both hosts. Do not “fix” these edges with duplicated functions or source-text fallbacks.

This milestone is complete when the workspace metadata test passes, the lockfile remains one workspace lockfile, the root package still builds exactly as before, and no implementation crate contains copied production behavior. Commit the workspace skeleton and neutral utility change as the first checkpoint.

### Milestone 2: Extract analysis and the typed runtime

Move analyzer-owned modules from `src/` into `crates/bifrost-analysis/src/` while preserving their internal module relationships. This includes `analyzer`, analyzer storage/cache support, code quality, compact graphs, navigation/search algorithms, policy and structural-query code, protocol-neutral path/text/hash helpers, model-context sampling, protocol-neutral result rendering, reference-differential audits, and optional NLP indexing. Use `git mv` so history remains readable. Keep the project watcher with the MCP workspace-lifecycle host, and do not move `searchtools_service`, LSP, MCP descriptors, Python, CLI, benchmarks, or fuzzers into analysis.

Move the vendored Scala and Kotlin sources and any analyzer `include_str!` resources under `crates/bifrost-analysis/`. Split the current root `build.rs`: the analysis package’s build script compiles the vendored grammars using paths contained in its own package; the root build script retains only facade build-identity generation. Extend the root dirty fingerprint to cover all workspace member source and manifest paths so the binary’s build identity still changes for dirty host or runtime edits.

Move `CodeIntelligenceRuntime` into `crates/bifrost-runtime/src/`. Cancellation remains an analysis-owned execution primitive and is re-exported by runtime. The runtime package depends on analysis and exposes typed methods equivalent to the current query and policy methods. It must not depend on `serde_json::Value`, `lsp-server`, `lsp-types`, MCP descriptors/rendering, PyO3, or host request lifecycle types.

Replace the root implementations with compatibility re-exports. `src/lib.rs` must continue exposing `analyzer`, `code_intelligence`, `searchtools`, `policy`, `usages`, the existing root analyzer types, `CancellationToken`, and `NavigationOperation` at their current paths. Add `tests/public_facade_compat.rs` to compile representative existing imports and execute a small `InlineTestProject` query through the root facade.

Move `tests/code_intelligence_runtime.rs` to the runtime package, adapting only import paths and the shared inline-project harness location. Move analyzer-focused unit/integration support required for independent analysis tests into that package; leave broad root integration suites temporarily in place as compatibility coverage. The milestone passes when `cargo test -p brokk-bifrost-analysis`, `cargo test -p brokk-bifrost-runtime`, and the root facade compatibility test pass, and `cargo tree -p brokk-bifrost-runtime -e normal` contains neither host package nor LSP transport dependencies. Commit analysis/runtime extraction and its evidence as a checkpoint.

### Milestone 3: Extract LSP as the first independent host

Move `src/lsp/` into `crates/bifrost-lsp/src/`. Its manifest depends on analysis and runtime and owns `lsp-server`, `lsp-types`, and host-only test dependencies. Make the minimum cross-crate visibility changes needed for typed analyzer/runtime APIs; do not expose analyzer internals merely to preserve former `pub(crate)` shortcuts. When a host needs a capability that is genuinely protocol-neutral, add a narrowly typed public API to analysis/runtime and cover it there.

Move `tests/bifrost_lsp_server.rs` and `tests/common/lsp_client.rs` into the LSP package, retaining behavior for overlays, query/policy methods, cancellation, diagnostics, navigation, and UTF-16 projection. Re-export the LSP package from root as `brokk_bifrost::lsp`, and update root benchmarks to call the dependency package without duplicating handlers.

Update `scripts/ci-impact.mjs`, its fixtures/tests, and `.github/workflows/ci.yml` only after the package test passes. LSP-only paths under `crates/bifrost-lsp/` select the LSP contract job; analysis/runtime, workspace manifests, shared assets, and unknown paths select both hosts and the full cross-platform gate. The smallest observable independence proof for this issue is:

    cargo test -p brokk-bifrost-lsp --all-features
    cargo tree -p brokk-bifrost-lsp -e normal

The first command must run the LSP host tests without selecting the MCP package or root facade. The second output must contain `brokk-bifrost-analysis` and `brokk-bifrost-runtime` but not `brokk-bifrost-mcp`. Commit the independently compiling LSP host and CI mapping as a checkpoint.

### Milestone 4: Extract MCP and reconnect CLI/Python

Move `src/searchtools_service.rs`, `src/tool_arguments.rs`, the relevant structured-output helpers, and `src/mcp_common.rs` plus the `src/mcp_*.rs` tool descriptor/registry modules into `crates/bifrost-mcp/src/`. Keep typed analyzer search algorithms, model-context sampling, and result rendering in analysis. Move the run-policy selector/path byte limits beside `SearchToolsService`’s typed MCP preparation contract so the service no longer imports a descriptor module for validation constants.

Move `tests/bifrost_mcp_server.rs` and focused service/registry contract tests into the MCP package. Preserve exact tool names, JSON schemas, error codes, rendering, registration behavior, cancellation, workspace binding, and session refresh behavior. Define the MCP package’s `nlp` feature as a forwarding feature to analysis; it must remain optional and tests must construct services without real models or indexer threads.

Keep `src/python_module.rs` in the root facade and make it depend on the extracted `SearchToolsService`. Keep `python` and `extension-module` only on the root package; `python` enables PyO3 and the dependencies needed by the facade, while `nlp` forwards to analysis and MCP. Keep `src/bin/bifrost.rs` in root and route its LSP/MCP subcommands through the extracted hosts. Preserve `BIFROST_BUILD_IDENTITY` in root and pass it through a typed MCP server configuration instead of making the MCP package depend back on the facade.

Re-export the MCP modules and `SearchToolsService` types at their existing `brokk_bifrost` paths. Update root benchmark and property-fuzzer modules to depend downward on the MCP package. Add or extend `tests/public_facade_compat.rs` to cover representative MCP and Python-facing Rust paths.

After independent MCP tests pass, update the CI impact classifier so `crates/bifrost-mcp/` selects MCP contracts without LSP contracts, while shared packages continue selecting both. This milestone passes when `cargo test -p brokk-bifrost-mcp --features nlp`, `cargo tree -p brokk-bifrost-mcp -e normal`, the full MCP integration test, and `scripts/test_python.sh` pass. The dependency tree must not contain `brokk-bifrost-lsp`, `lsp-server`, or `lsp-types`. Commit MCP extraction and facade reconnection as a checkpoint.

### Milestone 5: Make package, notice, wheel, and release validation workspace-aware

Give all implementation manifests the shared version and legal metadata. Use explicit `include` or carefully ordered `exclude` rules so each `.crate` contains only its source, required licenses/readme metadata, analyzer resources, and native grammar inputs. Generalize `scripts/check-crate-package.sh` into a workspace package-set check or add `scripts/check-workspace-packages.sh`; retain the current assertions that repository metadata, tests, docs, editor sources, and development tooling do not leak into published archives.

The package-set check must run stable Cargo with `--no-verify` to create all five archives, unpack them under a helper-managed temporary directory, and create a minimal consumer whose dependency is the unpacked `brokk-bifrost` facade. Its `[patch.crates-io]` table points the four implementation package names to their unpacked directories. Build the consumer with default features and with `nlp,python` using the supported Python interpreter. This proves normalized manifests and file contents before registry publication. The helper must remove its temporary directory on success, failure, or interruption.

Update `scripts/release-version.mjs`, `scripts/check-codex-plugin-manifest.mjs`, `scripts/resolve-docs-version.mjs`, and their tests so the root/workspace version remains the single source of truth and every implementation package inherits exactly that version. Update `scripts/generate-rust-third-party-notices.sh` to cover the dependency union of the released binary and wheel without duplicating workspace packages as third-party libraries.

Update `.github/workflows/publish-crate.yml` and the parent promotion graph in `.github/workflows/release.yml`. Promotion validates one immutable commit and the complete package set, then publishes `brokk-bifrost-analysis`, `brokk-bifrost-runtime`, MCP and LSP, and finally `brokk-bifrost`. MCP and LSP may publish in parallel after runtime is available; facade publication waits for both. Add bounded registry-availability retries rather than arbitrary sleeps. A retry must verify the exact version and checksum before continuing. Wheel building remains rooted at `pyproject.toml` and must consume the same workspace commit and version.

Update `CONTRIBUTING.md` with package-selective commands and the package publication order. Do not market the implementation crates as new stable public APIs; describe them as versioned implementation dependencies of the stable facade.

### Milestone 6: Complete validation and boundary review

Run formatting, package-boundary checks, focused package tests, root compatibility tests, the feature-complete workspace suite, Python tests, package-set validation, and all-target/all-feature Clippy through the isolated target helper. Run the staged `bifrost.code-smells` policy pack together with every executable repository policy root. A policy `finding` must be reviewed or fixed; `unreliable` is a failed validation and must not be reported as clean.

Review `cargo metadata` and `cargo tree` evidence for every package. Search extracted analysis/runtime sources for `lsp_server`, `lsp_types`, `mcp_`, PyO3, JSON-RPC rendering, and host lifecycle identifiers. Search the host packages for one another. Confirm that no semantic implementation was replaced by regex, string splitting, or source-text scanning during visibility cleanup.

Allow the full required GitHub Actions matrix to validate Linux, Windows, macOS, Android, the supported feature combinations, package archives, wheels, CLI artifacts, and the merge-queue backstop. Record exact job links and outcomes in this plan. Commit any validation-only plan updates as the post-milestone checkpoint.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/428a/bifrost` on the existing issue branch. At every stopping point update `Progress`, `Surprises & Discoveries`, `Decision Log`, `Outcomes & Retrospective`, and the revision note at the bottom.

Begin and repeatedly inspect the graph with:

    git status --short --branch
    cargo metadata --no-deps --format-version 1
    cargo tree --workspace -e normal
    node --test scripts/check-workspace-dependencies.test.mjs

After the analysis/runtime milestone, run:

    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-analysis
    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-runtime
    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost --test public_facade_compat
    cargo tree -p brokk-bifrost-runtime -e normal

After LSP extraction, run:

    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-lsp --all-features
    cargo tree -p brokk-bifrost-lsp -e normal
    node --test scripts/ci-impact.test.mjs

After MCP extraction, run:

    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-mcp --features nlp
    cargo tree -p brokk-bifrost-mcp -e normal
    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost --test public_facade_compat
    scripts/test_python.sh
    node --test scripts/ci-impact.test.mjs

For the final local gate, use the supported Python 3.12-or-newer interpreter when `/usr/bin/python3` is too old:

    cargo fmt --all -- --check
    PYO3_PYTHON=$(brew --prefix python@3.13)/bin/python3.13 scripts/with-isolated-cargo-target.sh cargo test --workspace --features nlp,python
    scripts/with-isolated-cargo-target.sh cargo clippy --workspace --all-targets --all-features -- -D warnings
    scripts/check-workspace-packages.sh
    node --test scripts/*.test.mjs

Do not use `cargo test --all-features` as the feature-complete test gate because `extension-module` suppresses libpython linkage and is appropriate only for Maturin’s extension build. Do not create manually named Cargo target directories under `/tmp`; the isolated-target helper owns cleanup.

After each completed milestone, stage only the files from that milestone and commit a multiline checkpoint explaining why the boundary is safe. Do not use `git add -A`. Do not push, open a pull request, bump versions, tag, publish, or deploy unless the user explicitly requests that action.

## Validation and Acceptance

Acceptance is behavioral and architectural. `cargo test -p brokk-bifrost-lsp` must exercise the real LSP host without compiling the MCP host or root facade; `cargo test -p brokk-bifrost-mcp` must exercise the real MCP host without compiling LSP transport code. Cargo metadata and the checked-in boundary test must reject any reverse or host-to-host package edge.

The root compatibility test must compile representative pre-refactor Rust paths and execute a real typed query. The existing `bifrost` binary must report the same version/build identity and serve the same MCP and LSP methods. MCP golden/schema tests and LSP integration tests must show no contract drift. `scripts/test_python.sh` and the wheel job must import the same `bifrost_searchtools._native` module and successfully call the same service methods.

The packaged-consumer smoke must build from unpacked `.crate` archives rather than workspace source paths. Every archive must contain all required Rust/native/resource inputs and none of the excluded development material. The release-promotion tests must prove dependency-order publication and facade-last behavior from one validated tag/commit.

The feature-complete workspace test, all-target/all-feature Clippy command, formatter, policy gate, package checks, Node workflow tests, and full GitHub Actions matrix must pass. Cross-platform jobs must retain Linux, Windows, macOS, and Android coverage. A skipped host test caused by an incorrect impact mapping is a failure, not a successful optimization.

## Idempotence and Recovery

Use additive package skeletons and compatibility re-exports before deleting old declarations. `git mv` operations are safe to retry after checking `git status`; never recreate moved files by copying large source trees. If a milestone cannot compile without broad new public internals, stop at the last green checkpoint, record the failed boundary and exact compiler errors in this plan, and redesign the typed interface before continuing.

The dependency-check and package-set scripts must use `mktemp -d` and traps so retries do not leave archives or temporary registries behind. Cargo’s shared workspace `target/` remains the normal local cache; isolated validation uses `scripts/with-isolated-cargo-target.sh`. Use `scripts/cleanup-bifrost-tmp.sh` to inspect stale managed targets before applying cleanup.

Each milestone checkpoint is independently buildable. If a later host extraction proves invalid, revert only that milestone’s explicit files or create a forward fix; do not reset the worktree or discard unrelated user changes. Publication changes remain inert until an explicit release request and a real tag, so local implementation cannot accidentally publish packages.

## Artifacts and Notes

The final package graph must resemble:

    brokk-bifrost-analysis
              |
              v
    brokk-bifrost-runtime
          /             \
         v               v
    brokk-bifrost-mcp  brokk-bifrost-lsp
          \             /
           v           v
             brokk-bifrost
        (CLI, Python, benchmarks,
         fuzzers, compatibility API)

Representative successful dependency evidence is:

    $ cargo tree -p brokk-bifrost-lsp -e normal | rg 'brokk-bifrost-(analysis|runtime|mcp)'
    brokk-bifrost-analysis v0.8.12 (...)
    brokk-bifrost-runtime v0.8.12 (...)

There must be no `brokk-bifrost-mcp` match in that output. The reciprocal MCP command must have no `brokk-bifrost-lsp`, `lsp-server`, or `lsp-types` match.

Milestone 1 evidence:

    $ node scripts/check-workspace-dependencies.mjs
    workspace dependency graph is valid

    $ node --test scripts/check-workspace-dependencies.test.mjs
    tests 6
    pass 6
    fail 0

    $ cargo test -p brokk-bifrost-analysis -p brokk-bifrost-runtime -p brokk-bifrost-mcp -p brokk-bifrost-lsp
    test result: ok for all four skeleton packages and their doc tests

    $ cargo test -p brokk-bifrost --lib path_utils::tests::percent_decode_handles_unicode_spaces_and_malformed_escapes --quiet
    test result: ok. 1 passed

    $ scripts/check-crate-package.sh
    exit status 0

Milestone 2 evidence:

    $ cargo test -p brokk-bifrost-analysis --lib --quiet
    test result: ok. 1781 passed; 0 failed; 6 ignored

    $ cargo test -p brokk-bifrost-runtime --test code_intelligence_runtime
    test result: ok. 1 passed

    $ cargo test -p brokk-bifrost --test public_facade_compat
    test result: ok. 1 passed

    $ node scripts/check-workspace-dependencies.mjs
    workspace dependency graph is valid

    $ cargo check -p brokk-bifrost --lib --features nlp
    Finished `dev` profile successfully

    $ cargo package -p brokk-bifrost-analysis --allow-dirty --locked
    Packaged 577 files, 84.1MiB (6.3MiB compressed); verification succeeded

Milestone 3 evidence:

    $ cargo test -p brokk-bifrost-lsp --all-features --lib --bins --test bifrost_lsp_server --quiet
    test result: ok. 104 passed; 1 ignored (library)
    test result: ok. 193 passed (subprocess contract)

    $ RUSTDOC=/Users/dave/.cargo/bin/rustdoc cargo test -p brokk-bifrost-lsp --doc --all-features
    test result: ok. 0 passed; doctest compilation succeeded

    $ cargo check -p brokk-bifrost --tests
    Finished `dev` profile successfully

    $ cargo tree -p brokk-bifrost-lsp -e normal | rg 'brokk-bifrost-(analysis|runtime|mcp)|lsp-(server|types)'
    brokk-bifrost-analysis, brokk-bifrost-runtime, lsp-server, and lsp-types are present; brokk-bifrost-mcp is absent

    $ node --test scripts/ci-impact.test.mjs scripts/ci-impact-workflow.test.mjs scripts/check-workspace-dependencies.test.mjs
    tests 21; pass 21; fail 0

## Interfaces and Dependencies

`crates/bifrost-analysis` owns analyzer and typed search/policy/query data. It exposes only the types and functions required by runtime and hosts. It has no dependency on any other Bifrost workspace package.

`crates/bifrost-runtime` depends on analysis and defines:

    pub struct CodeIntelligenceRuntime<'a> {
        workspace: &'a WorkspaceAnalyzer,
        cancellation: Option<&'a CancellationToken>,
    }

    impl<'a> CodeIntelligenceRuntime<'a> {
        pub const fn new(
            workspace: &'a WorkspaceAnalyzer,
            cancellation: Option<&'a CancellationToken>,
        ) -> Self;

        pub fn execute_query(
            &self,
            query: &CodeQuery,
            limits: CodeQueryExecutionLimits,
        ) -> CodeQueryResponse;

        pub fn execute_query_with_registration_lease(
            &self,
            workspace_generation: u64,
            registrations: &ProtocolRegistrationSet,
            query: &CodeQuery,
            limits: CodeQueryExecutionLimits,
            summary_lease: ProductionTypestateSummaryLease,
        ) -> CodeQueryResponse;

        pub fn evaluate_policy_inputs(
            &self,
            root: &Path,
            policy_inputs: &[PolicyEvaluationInput],
            options: &PolicyEvaluationOptions,
        ) -> Result<PolicyBatchOutcome, PolicyCoordinatorError>;
    }

Preserve the existing `evaluate_policy_source` method as well. Inputs and results come from analysis; no protocol values enter this API.

`crates/bifrost-lsp` exposes the existing `run_lsp_stdio_server` entry point and public handler/conversion surface currently reachable through `brokk_bifrost::lsp`. It depends on analysis and runtime. All `lsp-server` and ordinary LSP protocol ownership lives here, except root benchmark code may retain a direct `lsp-types` development/application dependency when it constructs benchmark requests.

`crates/bifrost-mcp` exposes `SearchToolsService`, `SearchToolsServiceError`, `ToolOutput`, MCP render options, server registry/specification APIs, and stdio server entry points currently used by root. Add a typed server configuration carrying the facade build identity rather than reading a root constant through a reverse dependency. The package depends on analysis and runtime and owns MCP request limits, descriptors, normalization, lifecycle, and rendering.

The root `src/lib.rs` re-exports dependency crates and symbols so existing paths remain source compatible. The root manifest forwards `nlp` to the packages that implement semantic search, keeps `python = ["dep:pyo3"]` plus required facade dependencies, and keeps `extension-module = ["pyo3/extension-module"]`. Member packages must not define or enable `extension-module`.

Every internal dependency declaration uses the lockstep version and local path, for example:

    brokk-bifrost-runtime = {
        path = "crates/bifrost-runtime",
        version = "=0.8.12",
    }

During implementation, express the numeric version through supported workspace inheritance where Cargo permits it; the normalized published manifest must contain the exact version. The checked-in metadata test is the executable authority for allowed edges and version equality.

Revision note (2026-07-29): Created the initial issue #1275 ExecPlan after live issue review, current-master synchronization, source/dependency inspection, Cargo packaging verification, and release-surface review. It fixes the package graph and publication strategy up front because those constraints determine whether the stable facade can survive the extraction.

Revision note (2026-07-29): Completed Milestone 1 with a green workspace skeleton, dependency-graph validator, neutral percent-decoder, root package check, and existing quick-policy Node suite. Version-source consolidation is deliberately deferred to the package/release milestone so the current release contract stays green at every checkpoint.

Revision note (2026-07-29): Completed Milestone 2 by physically extracting analysis/resources/native grammars and the typed runtime, preserving the root API through re-exports, and validating the complete analysis suite, runtime contract, root facade, optional NLP compile, dependency graph, notices, and independent analysis archive.

Revision note (2026-07-29): Completed Milestone 3 by extracting LSP production code and its real-process contract into an independently testable package, retaining only a narrow hidden benchmark seam, updating CI selection/execution, and verifying all remaining root test targets compile with the relocated client harness.
