# Index exact Ruby gem APIs from RBS, RBI, and source declarations

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintain this document in accordance with `.agents/PLANS.md`. A contributor should be able to resume the work from this file and the repository alone.

## Purpose / Big Picture

After this change, a Ruby project can provide exact, passive dependency evidence for the gems selected by Bundler and Bifrost will turn the corresponding `.gem` archives into deterministic semantic API packs. Those packs make library classes, modules, methods, overloads, aliases, mixins, and singleton methods available to the same definition, hover, signature, hierarchy, symbol, and reference features that already understand workspace Ruby source. The feature remains offline and safe: Bifrost reads only caller-approved files, never executes Ruby, Bundler, Sorbet, Steep, gem hooks, or generators, and never searches broad gem caches.

The behavior is demonstrated by the consolidated semantic integration suite. A fixture supplies a lockfile digest and an exact local `.gem` path containing representative RBS, RBI, and ordinary Ruby declarations. The tests prepare and activate a dependency pack, assert navigation from workspace code into the dependency declarations, prove deterministic output across input order, and show bounded partial diagnostics for dynamic or malformed declarations. The fixture dependency files must not appear in `Project::all_files`.

## Progress

- [x] (2026-08-02 16:49Z) Inspected the issue, prerequisites, current issue branch, semantic-pack infrastructure, existing Ruby analyzer, and official `ruby-rbs` owned AST surface; selected a passive exact-evidence design.
- [x] (2026-08-02 16:49Z) Recorded the approved implementation as this self-contained ExecPlan.
- [x] (2026-08-02 16:58Z) Added Ruby dependency evidence configuration, Ruby gem artifact vocabulary, and ordered Ruby mixin facts to the shared semantic model; regenerated the checked-in schema and passed all 24 semantic-model pack tests.
- [x] (2026-08-02 17:25Z) Implemented exact lockfile/archive evidence validation, approved-root enforcement, bounded nested `.gem` archive ingestion without extraction, and initial typed RBS projection.
- [ ] Project RBS, RBI, and ordinary Ruby declaration sources into deterministic semantic facts and merge their origins.
- [ ] Activate Ruby dependency packs in navigation without adding dependency artifacts to workspace files.
- [ ] Add end-to-end fixtures, behavior tests, performance measurements, and user-facing configuration documentation.
- [ ] Run formatting, focused tests, strict featureless clippy, repository policy checks, and specialist review; fix all confirmed findings.

## Surprises & Discoveries

- Observation: The shared semantic model already has a generic dependency discovery, artifact production, compilation, catalog, activation, and overlay pipeline. Ruby should add a narrow ecosystem adapter rather than a second pack system.
  Evidence: `crates/bifrost-analysis/src/analyzer/semantic_model/dependency.rs` defines `ResolvedDependency`, `DependencyPackAdapter`, and `prepare_dependency_packs`, while `overlay.rs` handles activated packs.

- Observation: The Ruby analyzer already preserves the semantic distinction between `include`, `prepend`, and `extend`, but the authored pack model currently exposes only `Extends`, `Implements`, and `UsesTrait`, and canonical compilation sorts hierarchy facts without an explicit declaration ordinal.
  Evidence: `crates/bifrost-analysis/src/analyzer/ruby/declarations.rs` and `mixins.rs` model the three Ruby relations; `crates/bifrost-analysis/src/analyzer/semantic_model/model.rs` defines the smaller public vocabulary.

- Observation: A RubyGems `.gem` is a tar archive containing a compressed `data.tar.gz`; streaming the two archive layers permits bounded, cancellation-aware reads without extracting attacker-controlled paths to disk.
  Evidence: The selected implementation uses the existing Rust `flate2` dependency plus the `tar` crate and accepts only regular-file archive entries.

- Observation: The official `ruby-rbs` Rust crate supplies typed AST wrappers for classes, modules, interfaces, aliases, mixins, attributes, methods, overloads, and structured types. The wrappers borrow a native parser allocation rather than owning independent nodes, but still provide the structured boundary this implementation needs.
  Evidence: `ruby-rbs` 0.3.0 compiled successfully on this worktree; `SignatureNode` owns the native parser lifetime and its typed child nodes cannot outlive it.

- Observation: RubyGems versions are not always SemVer, for example `1.2.3.pre`, while the catalog's optional `CatalogCoordinate.version` is a SemVer value.
  Evidence: The discovery test binds `1.2.3.pre` exactly in normalized provenance and the dependency ID, leaves the optional SemVer field absent, and still binds generated selection to the exact lockfile and archive digests.

## Decision Log

- Decision: Require typed `RubyDependencyApiEvidence` supplied through `AnalyzerConfig` instead of discovering installed gems or invoking Bundler.
  Rationale: Exact lockfile digest, Ruby version, platform, gem coordinate, checksum, and archive path make selection reproducible, offline, bounded, and free of executable build hooks. This also prevents broad cache scans.
  Date/Author: 2026-08-02 / Codex

- Decision: Use the official `ruby-rbs` 0.3.0 high-level typed parser for RBS and the existing tree-sitter Ruby grammar for RBI and ordinary Ruby source.
  Rationale: Both inputs stay structurally parsed. The repository explicitly forbids regexes, delimiter scanning, and source-text mini-parsers where an AST can carry the answer.
  Date/Author: 2026-08-02 / Codex

- Decision: Stream `.gem` contents in memory and never extract them.
  Rationale: Only declarations are needed. Avoiding filesystem extraction eliminates path traversal and cleanup concerns while allowing strict outer-entry, inner-entry, expanded-byte, record, and cancellation limits.
  Date/Author: 2026-08-02 / Codex

- Decision: Preserve Ruby mixin kind and declaration order in the shared hierarchy fact model.
  Rationale: Ruby lookup semantics distinguish `prepend`, `include`, and singleton-class `extend`, and order changes method precedence. Collapsing these facts would make an exact API pack semantically misleading.
  Date/Author: 2026-08-02 / Codex

- Decision: Merge equivalent declarations with primary-origin precedence RBS, then RBI, then ordinary gem source, while retaining contradictory declarations as explicit ambiguity and emitting bounded diagnostics.
  Rationale: Signature files are the intended API contract, but reopening is ordinary Ruby behavior and conflicting evidence must not be silently discarded. Stable precedence and stable sorting make output independent of archive entry order.
  Date/Author: 2026-08-02 / Codex

- Decision: Encode archive member locations as digest-qualified logical paths rather than host absolute paths.
  Rationale: Pack identity and navigation must be reproducible across machines and must not expose or depend on an approved archive's local location.
  Date/Author: 2026-08-02 / Codex

## Outcomes & Retrospective

Milestones 1 and 2 are complete. The public analyzer configuration can carry exact Ruby dependency evidence, `.gem` is a first-class external artifact, and semantic packs can represent Ruby's three distinct mixin operations with an optional declaration ordinal. Discovery now reads only configured files, enforces canonical approved roots, verifies lockfile and optional archive SHA-256 values, and preserves exact non-SemVer gem versions. The nested archive reader never extracts files and enforces cancellation, entry-count, compressed-byte, expanded-byte, UTF-8, and portable-path boundaries. Initial RBS projection proves overloaded methods, singleton methods, aliases, attributes, superclass facts, and ordered mixins. The implementation still needs cross-entry origin merging, RBI/source projection, adapter/catalog integration, overlay behavior, and end-to-end proof.

## Context and Orientation

The repository is a Rust workspace. The relevant crate is `crates/bifrost-analysis`. A semantic API pack is a deterministic, serializable description of external types and members which Bifrost can activate as an overlay above the workspace's own semantic model. An overlay means external declarations participate in lookup without becoming ordinary project source files.

`crates/bifrost-analysis/src/analyzer/config.rs` contains per-language analyzer configuration. Existing Rust, JVM, C#, and JavaScript/TypeScript sections show how exact dependency evidence enters the analyzer. Add a Ruby section there rather than passing paths through process-global environment variables.

`crates/bifrost-analysis/src/analyzer/semantic_model/producer.rs` defines artifact kinds, producer limits, exact bounded file reads, and producer diagnostics. `dependency.rs` converts discovered dependency artifacts into compiled packs. `model.rs` is the authored semantic vocabulary, `compiler.rs` canonicalizes and validates it, and `overlay.rs` exposes activated records to language analyzers. `schemas/semantic-model-pack-v1.schema.json`, or the actual schema path found beside these modules, must stay synchronized with any serialized vocabulary change.

`crates/bifrost-analysis/src/analyzer/ruby/` is the existing workspace Ruby analyzer. `declarations.rs` extracts classes, modules, methods, aliases, visibility, singleton methods, and mixin relations from tree-sitter nodes. `mixins.rs` and `hierarchy.rs` compute Ruby lookup relationships. `crates/bifrost-analysis/src/analyzer/usages/get_definition/ruby.rs`, `get_type/ruby.rs`, and `usages/ruby_graph.rs` serve navigation and reference analysis. The dependency implementation must reuse these structured concepts and must not interpret Ruby through regular expressions or string splitting.

RBS is Ruby's structured signature language. RBI is Sorbet's Ruby-syntax interface format. RBS will be parsed by `ruby-rbs`; RBI will be parsed as Ruby and only a finite, explicitly tested set of Sorbet DSL calls will be recognized. Unsupported metaprogramming remains partial and produces diagnostics. Ordinary `.rb` files inside a gem may contribute declarations already expressible by the existing tree-sitter extractor, but Bifrost never executes the source.

Exact evidence means the caller names the files and identity facts Bifrost may trust: a Bundler lockfile path and SHA-256 digest, Ruby version, platform, and per-gem name, version, source, optional checksum, and `.gem` archive path. Paths are resolved relative to the project root and canonicalized. The discovery step verifies supplied digests and coordinates; it does not recursively search sibling directories, `$HOME`, a gem cache, or the network.

## Plan of Work

Milestone 1 extends the shared contracts. In `config.rs`, add `RubyAnalyzerConfig`, `RubyDependencyApiEvidence`, and a per-gem evidence type with the exact fields described above, then add `ruby` to `AnalyzerConfig` and its default. In `semantic_model/producer.rs`, add `RubyGemArchive`. In `semantic_model/model.rs`, add `MixinInclude`, `MixinPrepend`, and `MixinExtend`, plus an optional ordered position on `HierarchyFact`. Update all authored fact constructors, canonical sort keys, validation, serialization schema, and focused model/compiler tests. Existing ecosystems should serialize unchanged when the optional position is absent. This milestone is complete when shared-model tests demonstrate that two same-kind mixins retain declaration order and different Ruby mixin kinds do not collapse.

Milestone 2 implements exact discovery and safe archive access. Add `crates/bifrost-analysis/src/analyzer/ruby/dependency_discovery.rs` and expose it from `ruby/mod.rs`. Discovery reads only the configured lockfile and exact archives, verifies the expected lockfile digest, rejects duplicate or inconsistent gem coordinates, canonicalizes paths under the approved project root or explicit approved roots, and returns `ResolvedDependency` records with normalized provenance. Add `gem_artifact.rs` to open the outer tar, find `data.tar.gz`, decompress it through a counting reader, and visit only regular `.rbs`, `.rbi`, and selected `.rb` entries. Enforce existing byte and record limits plus explicit outer/inner entry limits, check cancellation between entries and parser units, reject unsafe or non-UTF-8 logical member paths, and never write archive data to disk. Tests create archives in a temporary directory, so repeated runs leave no residue.

Milestone 3 projects declarations. Add `rbs_artifact.rs` around the owned `ruby-rbs` AST and `rbi_artifact.rs` around tree-sitter Ruby. Convert namespaces, reopened classes/modules, singleton methods, visibility, attributes, method aliases, type aliases, overloads, and all three mixin operations into authored types and members. Render structured RBS types deterministically into the semantic model's existing `TypeRef` forms; do not parse types after rendering them. RBI support must recognize only concrete AST call shapes such as `sig`, `abstract!`, `interface!`, `type_member`, and ordinary class/module/method declarations that tests require. Dynamic calls, computed constant paths, `method_missing`, and unrecognized DSLs produce a partial pack with bounded diagnostics rather than invented declarations.

Add `external.rs` containing `RubyDependencyPackAdapter`. It groups archive entries by fully qualified Ruby name, merges reopened scopes, preserves overloads and aliases, deduplicates equivalent facts, and assigns stable origin precedence. Contradictory facts remain separate enough for lookup to report ambiguity, and the adapter emits a diagnostic containing all relevant logical archive locations. Sort every unordered map at the pack boundary. The pack's identity incorporates lockfile digest, Ruby version, platform, gem coordinate, archive digest, adapter version, and normalized declaration content.

Milestone 4 connects overlays to Ruby behavior. Register Ruby discovery and its adapter alongside existing ecosystem adapters at the semantic-pack preparation call site. Extend Ruby definition, hover/type, hierarchy, symbol, and usage resolution only where a behavior test demonstrates that generic overlay support is insufficient. Workspace declarations win over dependency packs. Dependency declarations are queryable by their logical locators, but `.gem` members and the archive itself never enter `Project::all_files`. A missing signature, dynamic construct, corrupt archive, or conflicting origin must be visible as partial/ambiguous rather than silently falling back to source-text matching.

Milestone 5 proves the user outcome. Add `tests/suite_semantic/ruby_dependency_semantic_pack.rs` and one `mod ruby_dependency_semantic_pack;` line in `tests/suite_semantic/main.rs`. Build compact `.gem` fixtures at test runtime with RBS, RBI, and Ruby entries covering reopened types, instance and singleton methods, attributes, aliases, overloads, `include`/`prepend`/`extend` order, equivalent duplicate origins, contradictory origins, unsafe archive paths, byte/entry limits, cancellation, dynamic near misses, and two input orderings with identical compiled bytes. Assert definition, hover/signature, hierarchy, symbol search, and reference behavior from workspace Ruby code. Assert the dependency files are absent from `Project::all_files`.

Record cold and warm elapsed time, peak artifact bytes, declaration count, and compiled-pack size for a representative fixture in `.agents/docs/issue-1351-ruby-pack-measurement-2026-08-02.md`. This evidence is a bounded regression baseline, not a claim about all gems. Update the existing published semantic-pack or Ruby configuration documentation with the passive evidence fields, safety boundary, unsupported dynamic behavior, and a minimal configuration example.

Milestone 6 validates and reviews the result. Run format, focused tests, featureless strict clippy in the repository cleanup wrapper, and one policy request selecting `bifrost.code-smells` plus every executable repository policy root named by repository instructions. Treat a policy `finding` as review work and `unreliable` as failed validation. The guided issue workflow then runs specialist review for security, correctness, architecture, tests, and code quality; confirmed findings are fixed and all focused validation is rerun. Do not enable `nlp` for this task-scoped gate.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/2f40/bifrost` on the already checked-out issue branch. Before each milestone, run:

    git status --short --branch

After edits, run the narrowest relevant tests, then:

    cargo fmt --all -- --check
    git diff --check

For the shared model milestone, use focused library test filters discovered from the edited modules, for example:

    cargo test -p brokk-bifrost-analysis semantic_model

For discovery and production, run:

    cargo test -p brokk-bifrost-analysis ruby_gem_artifact
    cargo test -p brokk-bifrost-analysis ruby_dependency

For observable integration behavior, run:

    cargo test --test suite_semantic ruby_dependency_semantic_pack

For the final task-scoped lint gate, use the automatically cleaned isolated target directory:

    scripts/with-isolated-cargo-target.sh cargo clippy -p brokk-bifrost-analysis --all-targets -- -D warnings

Do not add `--features nlp` to routine testing. Update this section with exact passing test counts and any changed commands as the implementation reveals the final test names. Commit each independently passing milestone on the current branch with a multiline message explaining the behavior and why the design is safe. Stage only files changed for that milestone; never use `git add -A`.

## Validation and Acceptance

Acceptance is behavioral. With valid evidence and a local `.gem`, preparation produces a complete or explicitly partial pack without spawning a process or accessing the network. Two runs with the same bytes but different archive entry order produce byte-identical compiled packs. Changing the lockfile digest, platform, Ruby version, gem version, or archive digest changes selection or produces a bounded diagnostic instead of reusing a stale pack.

From a workspace Ruby call to a gem API, get-definition returns the dependency declaration's stable digest-qualified locator; hover/type returns the declared signature; symbol search finds dependency classes/modules/methods; hierarchy preserves the exact `prepend`, `include`, and `extend` order; and reference analysis connects workspace calls to the external member when resolution is supported. A workspace declaration with the same name has precedence. The archive path and its members never appear in `Project::all_files`.

RBS and RBI examples prove reopened classes/modules, singleton methods, attributes, aliases, overloads, and conflicting declarations. Near-miss fixtures prove that computed constants, unsupported DSL calls, malformed signatures, unsafe paths, oversized archives, and cancellation do not create speculative facts. Instead the outcome is partial or cancelled with bounded diagnostics. No test depends on Ruby, Bundler, Sorbet, Steep, or network availability.

The final focused tests, format check, strict featureless clippy, repository policy selection, and specialist review must all pass. Record exact results in `Progress`, `Surprises & Discoveries`, and `Artifacts and Notes` before declaring the plan complete.

## Idempotence and Recovery

All discovery and production operations are read-only with respect to user dependencies. Tests create temporary archives through the shared temporary-project facilities and drop them automatically. The archive reader never extracts files, so interruption cannot leave a half-populated directory. Compiled pack installation uses the existing catalog's content-addressed behavior and may be safely retried.

If a milestone fails, leave its unchecked progress item split into completed and remaining work. Re-run the focused test after correcting the root cause. If the `ruby-rbs` native parser cannot build on a supported target, stop that milestone, capture the exact compiler evidence in `Surprises & Discoveries`, and evaluate another official structured RBS parser; do not replace it with source-text parsing. If a semantic-model schema change invalidates existing fixtures, update fixtures through the normal compiler/serializer path and confirm older ecosystem behavior rather than hand-editing opaque generated bytes.

Use `scripts/with-isolated-cargo-target.sh` for isolated clippy so temporary build output is removed even on interruption. Do not remove unrelated `target` directories or user changes. Before any commit, inspect `git diff --name-only` and stage only the plan's files.

## Artifacts and Notes

The issue branch began from:

    93ad83a2 Fix master CI: PoolSafeMemo::get was test-only but query_indexes_warm calls it from the lib

The design-phase repository inspection found these reusable contracts:

    AnalyzerConfig -> per-language passive evidence
    ResolvedDependency -> exact artifacts plus normalized provenance
    DependencyPackAdapter -> authored pack production
    compile_pack -> canonical compiled pack
    SemanticModelOverlay -> activated external declarations

Add concise passing-test transcripts, policy results, measurement rows, and any changed file inventory here as milestones complete. Do not paste large logs.

Milestone 1 validation:

    cargo test -p brokk-bifrost-analysis semantic_model --lib
    test result: ok. 16 passed; 0 failed; 1968 filtered out

    cargo test --test suite_semantic semantic_model_pack::
    test result: ok. 24 passed; 0 failed; 613 filtered out

The second command includes `ruby_mixin_hierarchy_retains_declaration_order`, `checked_in_json_schema_matches_rust_model`, and the checked-in golden artifact test.

Milestone 2 validation:

    cargo test -p brokk-bifrost-analysis analyzer::ruby::dependency_discovery::tests --lib
    test result: ok. 2 passed; 0 failed

    cargo test -p brokk-bifrost-analysis analyzer::ruby::gem_artifact::tests --lib
    test result: ok. 2 passed; 0 failed

    cargo test -p brokk-bifrost-analysis analyzer::ruby::rbs_artifact::tests --lib
    test result: ok. 2 passed; 0 failed

The pinned `ruby-rbs` and `tar` dependencies also passed `cargo check -p brokk-bifrost-analysis --lib` after Cargo resolved their locked transitive dependencies.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/config.rs`, the final public configuration should have this shape, adjusted only when repository naming conventions require it:

    pub struct AnalyzerConfig {
        // existing fields
        pub ruby: RubyAnalyzerConfig,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct RubyAnalyzerConfig {
        pub dependency_api_evidence: Vec<RubyDependencyApiEvidence>,
    }

    pub struct RubyDependencyApiEvidence {
        pub lockfile_path: PathBuf,
        pub lockfile_sha256: String,
        pub ruby_version: String,
        pub platform: String,
        pub approved_archive_roots: Vec<PathBuf>,
        pub gems: Vec<RubyGemApiArtifact>,
    }

    pub struct RubyGemApiArtifact {
        pub name: String,
        pub version: String,
        pub source: String,
        pub checksum: Option<String>,
        pub gem_archive_path: PathBuf,
    }

`ExternalArtifactKind` must include `RubyGemArchive`. `HierarchyKind` must include `MixinInclude`, `MixinPrepend`, and `MixinExtend`. `HierarchyFact` must carry an optional non-negative declaration ordinal whose absence preserves existing ecosystem behavior and whose presence participates in canonical ordering and semantic hashing.

Add `ruby-rbs = "0.3.0"` as an exact compatible high-level parser dependency and `tar` using the workspace's normal dependency style. Continue using the existing `flate2` Rust backend. Disable unnecessary default features where the crates support doing so without breaking the official parser. Commit resulting `Cargo.lock` changes with the dependency milestone.

`ruby::dependency_discovery` must expose a function consistent with existing ecosystem discovery functions, accepting project root, Ruby config, limits, and optional `CancellationToken`, and returning `DependencyDiscoveryOutcome`. `ruby::external::RubyDependencyPackAdapter` must implement `semantic_model::DependencyPackAdapter`. Archive parsing helpers accept byte/entry/depth limits and return authored facts plus bounded `ProducerDiagnostic` values; they must not expose unbounded iterators over decompressed input.

All logical source locations must use a stable form such as `gem+sha256:<archive-digest>!/<normalized-member-path>` and never an absolute host path. The exact prefix may change to match existing locator helpers, but its digest and normalized member components are required and tests must assert cross-root stability.

Revision note (2026-08-02): Created the initial self-contained execution plan after live issue, prerequisite, repository, dependency, and analyzer inspection. It records the user-approved exact-evidence and structured-parser design so implementation can proceed milestone by milestone without relying on conversation history.

Revision note (2026-08-02 16:58Z): Marked the shared-contract milestone complete and recorded its exact test evidence. This update keeps the living plan aligned with the committed public configuration, schema vocabulary, and ordered-mixin behavior.

Revision note (2026-08-02 17:25Z): Marked exact discovery and bounded archive ingestion complete, corrected the RBS parser ownership description from design research, and recorded the non-SemVer selection boundary and passing focused tests.
