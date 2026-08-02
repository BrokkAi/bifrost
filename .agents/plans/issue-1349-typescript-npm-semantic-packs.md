# Index exact TypeScript npm declaration packages as semantic API packs

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

After this work, a TypeScript or JavaScript workspace with an already-installed, lockfile-proven npm dependency will expose that dependency's declaration API through Bifrost's semantic-model overlay. A user can navigate from an import or use to the modeled declaration, see its signature and hierarchy where the declaration format provides it, and find it in symbol and reference results without Bifrost treating `node_modules` as workspace source. The implementation is offline: it reads only local metadata, lockfiles, package manifests, and bounded `.d.ts` files; it never runs npm, `tsc`, install scripts, or a network resolver.

## Progress

- [x] (2026-08-02 00:00Z) Inspected issue #1349, its completed prerequisite plans, the shared semantic-pack producer/catalog/activation contracts, and the existing JVM/C# dependency adapters.
- [x] (2026-08-02 00:00Z) Confirmed that JS/TS has a cached `tsconfig` alias resolver but no npm dependency-pack adapter, declaration artifact kind, or host activation path.
- [x] (2026-08-02 09:44Z) Milestone 1: implemented bounded npm package-lock/shrinkwrap identity resolution, installed-manifest verification, exact declaration entry selection, scoped and `@types` modules, diagnostics, cancellation, and dependency-file isolation; two focused integration tests pass.
- [x] (2026-08-02 10:31Z) Milestone 2: implemented the deterministic tree-sitter TypeScript declaration producer and exact npm dependency adapter; focused producer tests cover exported and ambient types, overloads, generics, hierarchy, members, unexported near-misses, and renamed-root determinism.
- [ ] Prove generated npm packs activate through the existing shared overlay and navigation paths.
- [ ] Add behavior-focused fixture coverage and measured cold/warm/retained-memory evidence.
- [ ] Run formatting, focused tests, policy validation, and review the diff.

## Surprises & Discoveries

- Observation: the shared generated-pack coordinator is reusable, but it has no production JS/TS caller.
  Evidence: `DependencyPackAdapter` and `prepare_discovered_dependency_semantic_packs` are in `crates/bifrost-analysis/src/analyzer/semantic_model/dependency.rs`; current concrete adapters are only `JvmDependencyPackAdapter` and `CSharpDependencyPackAdapter`.
- Observation: the recently merged JDK/Scala work already proves that activated source-derived packs flow through generic search, source, hierarchy, and usage consumers without language-specific activation plumbing.
  Evidence: `tests/suite_semantic/jvm_standard_library_pack.rs` exercises the shared runtime and overlay for JDK and Scala packs; `searchtools/navigation.rs`, `searchtools/sources.rs`, and `searchtools/scan_usages.rs` consume `SemanticModelOverlay` generically.
- Observation: the existing `AliasResolver` is deliberately allowed to inspect a contained `node_modules` path for `tsconfig` extension. That narrow config lookup must not become dependency-source indexing.
  Evidence: `crates/bifrost-analysis/src/analyzer/js_ts/tsconfig.rs` resolves package `extends` paths below the canonical workspace root, while `Project::all_files()` remains the authoritative workspace-source listing.
- Observation: `InlineTestProject` deliberately uses `TestProject`, whose explicit fixture files include ignored dependency paths; testing the production file-listing boundary requires a `FilesystemProject` over the inline fixture root.
  Evidence: the initial assertion saw `node_modules` in `TestProject::all_files()` even with `.gitignore`; switching only the listing/discovery view to `FilesystemProject` proved the production walker excludes those paths before and after discovery.
- Observation: strict Clippy currently fails before checking Bifrost source because Cargo reports its freshly built `cc` build dependency as incompatible with the same displayed Homebrew `rustc 1.96.0`; this reproduces in both the workspace target and a fresh `scripts/with-isolated-cargo-target.sh` target.
  Evidence: the isolated command stops in `crates/bifrost-analysis/build.rs:17` with `E0514`, names `/private/tmp/bifrost-cargo-target.../libcc...rlib`, and then removes that isolated target.

## Decision Log

- Decision: model each selected npm module entry point as one `ResolvedDependency` containing exactly its package manifest and declaration artifact.
  Rationale: package metadata, exports routing, and declaration bytes jointly determine each public module API, while the coordinator's generic artifact limit remains applicable and static export subpaths activate independently by exact module name.
  Date/Author: 2026-08-02 / Codex
- Decision: only exact, local evidence activates an npm pack: a lockfile record, package manifest identity, and a declaration path contained by the corresponding installed package must agree on package name and version.
  Rationale: an arbitrary directory named like a package, an unpinned manifest, or a same-name dependency from another install must be incomplete coverage, never a modeled target.
  Date/Author: 2026-08-02 / Codex
- Decision: parse declarations directly with tree-sitter TypeScript and create typed semantic facts; do not add a TypeScript compiler subprocess or source-text parser.
  Rationale: this retains Bifrost's bounded offline behavior and reuses the repository's structural parser while avoiding compiler-equivalent inference outside the issue scope.
  Date/Author: 2026-08-02 / Codex
- Decision: publish no partial replacement overlay after discovery, parsing, or activation fails. Keep diagnostics/profile data and preserve the preceding active set.
  Rationale: a partial external API must be explicit and must never make an absent answer look authoritative.
  Date/Author: 2026-08-02 / Codex
- Decision: follow the landed JVM adapter and source-pack producer shape; do not add a new workspace initialization lifecycle or per-analyzer catalog ownership in this issue.
  Rationale: #1150 and #1152 already supply and validate the shared producer, catalog, preparation, activation, overlay, and navigation seams. #1349 is the npm discovery and TypeScript declaration producer adaptation of those seams.
  Date/Author: 2026-08-02 / Codex

## Outcomes & Retrospective

Milestones 1 and 2 are complete. Root npm `package-lock.json` and `npm-shrinkwrap.json` files with a version-two/three `packages` table now resolve exact installed package name/version evidence into one dependency per declaration entry point. Discovery supports `types`, `typings`, static `exports` type targets, conventional `index.d.ts`, scoped packages, and `@types` import-name mapping. It rejects version/name disagreement, unsafe or escaped paths, wildcard/ambiguous exports, missing declarations, malformed/oversized metadata, and cancellation with explicit incomplete diagnostics. The declaration producer structurally emits deterministic module/type/member/signature/hierarchy facts for supported exported and ambient TypeScript syntax, and its adapter requires the exact manifest-plus-declaration artifact shape. Shared catalog preparation, activation, overlay proof, and measurement work remains.

## Context and Orientation

All paths are relative to the repository root. A semantic-model pack is a typed, validated representation of declarations that are not normal project files. `crates/bifrost-analysis/src/analyzer/semantic_model/producer.rs` defines an exact external artifact, its production request, bounded producer limits, and producer diagnostics. `crates/bifrost-analysis/src/analyzer/semantic_model/dependency.rs` reads resolved artifacts once under byte/count limits, hashes their bytes with normalized evidence and producer limits, reuses or installs a generated pack through `SemanticPackCatalog`, and returns activation evidence. The catalog stores validated immutable pack data; the activation runtime turns compatible evidence into a generation-local overlay. The overlay is what the search, definition, hierarchy, signature, and reference paths query.

`crates/bifrost-analysis/src/analyzer/jvm/external.rs` and `crates/bifrost-analysis/src/analyzer/csharp/external.rs` are the patterns for discovery plus a `DependencyPackAdapter`. `crates/bifrost-analysis/src/analyzer/jvm/jdk_artifact.rs` and `crates/bifrost-analysis/src/analyzer/jvm/scala_artifact.rs` are the closest producer patterns: they parse source declarations into shared semantic facts, then generic overlay consumers provide navigation. `crates/bifrost-analysis/src/analyzer/typescript/mod.rs`, `crates/bifrost-analysis/src/analyzer/javascript/mod.rs`, and the shared `crates/bifrost-analysis/src/analyzer/js_ts/` directory own TypeScript/JavaScript parsing, imports, hierarchy, and `tsconfig` path aliases.

An npm declaration entry point is a `.d.ts`, `.d.mts`, or `.d.cts` file selected from an installed package's `types` or `typings` field or an applicable static `exports` branch. An `@types/foo` package is the type package for `foo`; it is selected only when its own exact lockfile/manifest evidence exists and the package's declaration entry point is unambiguous. A source locator is an external-model URI and range recorded in the semantic fact so navigation can identify the declaration without pretending it is a project file.

## Plan of Work

### Milestone 1: create an exact, bounded npm discovery contract

Extend `AnalyzerConfig` in `crates/bifrost-analysis/src/analyzer/config.rs` with a `JsTsDependencyDiscoveryConfig`. It must default to metadata-only local discovery, provide explicit package-root and lockfile paths for hosts that do not use normal workspace layout, and provide a small limits value for manifest bytes, lockfile bytes, packages, entry points, path depth, and diagnostics. Do not add an executable, network URL, registry cache, or install option.

Create `crates/bifrost-analysis/src/analyzer/js_ts/external.rs` and export its public adapter/discovery types from `crates/bifrost-analysis/src/analyzer/js_ts/mod.rs` and `crates/bifrost-analysis/src/analyzer/mod.rs`. Implement `resolve_js_ts_semantic_pack_dependencies(config, project, limits, cancellation) -> DependencyDiscoveryOutcome` with the same cancellation and bounded-diagnostic semantics as the JVM/C# resolvers. Discover exact local npm `package-lock.json` and `npm-shrinkwrap.json` version-two/three `packages` tables. Leave pnpm and Yarn formats outside this increment until their installed path/version evidence can be added with equivalent structural fixtures; never guess when a format cannot express a unique installed identity.

For each candidate, read a bounded `package.json` from the installed package directory and require exact agreement between lock evidence and its `name` and `version`. Resolve declaration files in this order: explicit `types`, then `typings`, then a non-conditional string declaration target from `exports`, then a conventional root `index.d.ts`. Respect scoped paths and package-local containment with `Path` operations. Treat conditional exports, path escapes, missing files, oversized manifests, malformed JSON/YAML, duplicate roots, and multiple equally applicable declaration targets as incomplete coverage. Retain package name, version, lockfile kind/path, package-root-relative declaration path, and route/field choice as normalized provenance. Convert selected files to `ResolvedDependencyArtifact` values with a new declaration artifact kind and an explicit declaration role. Sort packages and entry points by canonical package name/version/path before returning.

Add table-driven unit fixtures next to this module using `InlineTestProject`. Cover scoped dependencies, `@types`, `types`, `typings`, static `exports`, all supported lockfile shapes, duplicate nested installs, lock/manifest version disagreement, missing declaration file, path traversal, and cancellation. Every positive fixture must assert that `project.all_files()` is unchanged before and after discovery.

### Milestone 2: produce a deterministic TypeScript declaration pack

Add `TypeScriptDeclarationFile` to `ExternalArtifactKind` in `crates/bifrost-analysis/src/analyzer/semantic_model/producer.rs`. In `js_ts/external.rs`, define `TypeScriptDeclarationPackProducer` and `JsTsDependencyPackAdapter`. The adapter must use the shared coordinator, have a stable producer name/version, require the npm ecosystem, and reject a dependency whose selected artifact set is not exactly the package metadata plus contained declaration entries selected by discovery.

Use the repository's TypeScript tree-sitter grammar to parse each exact declaration artifact. Walk nodes iteratively and emit `AuthoredSemanticModelPack` facts for exported modules/namespaces, interfaces, classes, type aliases, functions, variables, constructors, methods, properties, overload signatures, type parameters, extends/implements relationships, explicit re-exports, declaration-merging participants, and proven `declare global` additions. Use semantic IDs built from package identity, module entry path, declaration kind, owner, and declaration name; use declaration ranges in external model URIs as locators. Maintain declaration order only until canonical compilation sorts facts; never use source text matching to infer an export, a type, or a route.

Constrain the producer with `ArtifactProducerLimits`: poll cancellation between files and declaration batches, cap parser nodes, declaration records, nesting/type-reference depth, source bytes, and diagnostics. A parse error, unsupported construct, conditional export, ambiguous merge, or unresolved re-export must lower completeness and give a bounded diagnostic. Do not emit a guessed declaration and do not examine `.ts`/`.js` implementation bodies.

Add producer-level tests in `js_ts/external.rs` that compare generated pack bytes for repeated runs and renamed-identical package roots, then assert changes to a declaration byte, package version, route, or selected `@types` package produce a new production identity. Add same-name near misses: an unexported declaration, the same type name in a non-selected nested package, a similarly named property on a different owner, an unsupported conditional export, and a global declaration without a supported ambient form must not produce a selectable fact.

### Milestone 3: prove the adapter through the existing shared overlay

Add an integration test under `tests/suite_semantic/` (and one `mod` entry in `tests/suite_semantic/main.rs`) that constructs an inline workspace with a lockfile, an installed declaration package, and a TypeScript consumer. Following `tests/suite_semantic/jvm_standard_library_pack.rs`, the test must call `resolve_js_ts_semantic_pack_dependencies`, pass the result to `prepare_discovered_dependency_semantic_packs`, compose exact evidence into `SemanticModelActivationRequest`, and activate it with `acquire_active_semantic_models`. Do not add a new `WorkspaceAnalyzer` lifecycle, default catalog, or language-specific overlay.

The test must prove `Project::all_files()` excludes `node_modules` and exercise the generic definition, symbol, source/signature, hierarchy, and reference entry points that the current overlay supports. It must also prove an exact lock/version match activates, a wrong version does not, a changed declaration regenerates only that package, and incomplete discovery cannot be composed into an authoritative empty activation request. Model locations must use `bifrost-model://` external URIs rather than project-relative dependency files.

### Milestone 4: measure and validate the operational contract

Add an ignored, reproducible measurement test under `tests/suite_semantic/` that builds a representative fixture at least twice. Record cold discovery/generation time, warm catalog activation time, generated pack bytes, retained overlay bytes, artifact/record counts, and a representative lookup latency. Store the captured machine-independent fixture parameters and observed results in `.agents/docs/` with the Bifrost commit. Do not accept a performance result after an error, cancellation, or partial coverage.

Run `cargo fmt`, the focused JS/TS external module tests, the semantic integration suite, and featureless strict Clippy through `scripts/with-isolated-cargo-target.sh`. Before finishing code changes, run the installed `bifrost.code-smells` policy pack and any named repository policy roots in one `run_policy` request; resolve findings or treat an unreliable result as failed validation. Update this ExecPlan's Progress, Surprises & Discoveries, Decision Log, Outcomes & Retrospective, and revision note at every milestone.

## Concrete Steps

From the repository root, use these commands after each corresponding milestone:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-analysis js_ts::external
    scripts/with-isolated-cargo-target.sh cargo test -p brokk-bifrost-analysis --test suite_semantic
    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings

The final policy command must use the Bifrost MCP `run_policy` tool against this worktree, selecting `bifrost.code-smells` and every repository policy root named by the project. A successful result has no findings and is not marked unreliable.

## Validation and Acceptance

Acceptance is demonstrated by an inline TypeScript workspace whose normal source imports a symbol from an installed, lockfile-proven package. The workspace file listing contains only the authored source and metadata files, not dependency declaration files. The real host initialization produces one complete generated/reused semantic pack with exact npm package/version/digest evidence. Public navigation finds the package declaration at a `bifrost-model://` URI, symbol search includes it, signatures retain overload information, hierarchy returns declared inheritance, and an external reference is visible where the overlay can model it.

Changing a declaration artifact byte causes regeneration only for its exact package. Changing the locked version, deleting the selected declaration, making a selected export conditional/ambiguous, exceeding a configured limit, or cancelling discovery must produce explicit incomplete diagnostics and no invented target. Warm activation reuses the verified catalog production and the measurement records its latency and retained bytes.

## Idempotence and Recovery

All discovery and parsing are read-only over the workspace and installed dependencies. The catalog may be reused safely because the coordinator validates canonical production identity, artifact digests, producer version, and schema before reuse. A failed parse, limit, cancellation, malformed lockfile, or corrupt catalog object must publish neither a complete new production nor a replacement active set; fix the fixture/input and rerun the same focused command. Do not delete `node_modules`, lockfiles, catalogs, or Cargo targets as part of this work.

## Artifacts and Notes

The implementation must add a concise `.agents/docs/` measurement report only after collecting the representative cold/warm data. It must name the fixture, exact Bifrost commit, command, platform, catalog mode, record/artifact counts, elapsed times, generated bytes, retained bytes, lookup latency, and completeness. The report is evidence, not a benchmark gate with machine-specific thresholds.

## Interfaces and Dependencies

At completion, these stable interfaces must exist:

    pub fn resolve_js_ts_semantic_pack_dependencies(
        config: &JsTsDependencyDiscoveryConfig,
        project: &dyn Project,
        limits: &DependencyPackLimits,
        cancellation: Option<&CancellationToken>,
    ) -> DependencyDiscoveryOutcome;

    pub struct JsTsDependencyPackAdapter;
    pub struct TypeScriptDeclarationPackProducer;

`ExternalArtifactKind` must include a declaration-file value. `JsTsDependencyPackAdapter` implements `DependencyPackAdapter`; `TypeScriptDeclarationPackProducer` implements `ExternalArtifactPackProducer`. Existing callers continue to own catalog selection and `SemanticModelActivationRequest` composition, exactly as they do for JVM packs; concrete language analyzers gain no catalog I/O and the project file set is unchanged.

Revision note (2026-08-02): Created the initial plan for issue #1349 after confirming the prerequisite exact-input coordinator and activation matcher are present.

Revision note (2026-08-02): Narrowed the plan after comparison with the merged #1150/#1152 implementation. #1349 now follows the existing JVM adapter/producer/overlay test shape and does not introduce speculative workspace initialization or per-analyzer catalog ownership.
