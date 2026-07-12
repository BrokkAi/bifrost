# Make persisted symbol startup lazy and content-correct

This ExecPlan is a living document maintained according to `.agents/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds.

## Purpose / Big Picture

Opening a warm persisted workspace must finish without reconstructing every declaration in memory or reparsing Go files merely to recover package identity. After this change, a second open of a large clean workspace performs no source parses, full file-state hydration, or combined definition-index construction before a targeted symbols request. Single-language and multi-language analyzers retain the same public definition and usage results, and Go blobs reused at different paths produce correct path-dependent canonical import paths from one persisted content-dependent package-clause fact.

## Progress

- [x] (2026-07-13) Validated issue #677 against current `master` and mapped `WorkspaceAnalyzer`, `MultiAnalyzer`, `DefinitionLookupIndex`, `TreeSitterAnalyzer`, `QueryResolver`, and Go qualifier persistence.
- [x] (2026-07-13) Isolated the raw Go package-clause persistence fix.
- [x] (2026-07-13) Add content-dependent parsed-state qualifier storage and remove Go source parsing from row hydration.
- [x] (2026-07-13) Prototyped and rejected lazy Arc-backed index shards because they merely defer full SQLite materialization until a graph query.
- [x] (2026-07-13) Add a lazy batch support boundary and migrate Go forward definition resolution to an owned, query-shaped provider backed by exact SQL definitions and bounded file hydration.
- [x] (2026-07-13) Add adapter-opt-in persisted lookup projections and migrate direct C# forward definition resolution to indexed exact/normalized/type/package/member queries without constructing the legacy definition index.
- [x] (2026-07-12) Migrate Rust forward definition resolution to exact FQN, same-file identifier, and exact owner/member queries without constructing the legacy definition index.
- [ ] Migrate C# inherited-member, candidate-signature/return-type, global-using, and `get_type_by_location` paths off the remaining explicit legacy fallbacks.
- [ ] Migrate remaining symbols resolvers from `DefinitionLookupIndex` to owned, query-shaped analyzer operations backed by indexed SQL candidate reads.
- [x] (2026-07-13) Add index-build/full-scan counters plus warm multi-language, blob-reuse, sibling-module, and bounded-hydration regressions for the Go vertical slice.
- [x] (2026-07-12) Pass the complete 427-case definition suite, both Rust usage-graph suites, all analyzer-persistence tests, and the local serde-json-rs benchmark for the Rust provider slice.
- [x] (2026-07-12) Complete repository gates after guided-review fixes; usagebench passed 110/110 at the implementation checkpoint and all actionable review findings have been incorporated.
- [x] (2026-07-13) Pass formatting, all-target/all-feature clippy, focused Go/persistence tests, and the complete `nlp,python` suite.
- [x] (2026-07-13) Measure schema-v9 cold population and warm exact forward/inverse resolution on `aws__aws-sdk-go-v2`.

## Surprises & Discoveries

- Observation: Current `WorkspaceAnalyzer::build_filtered` already returns `WorkspaceAnalyzer::Single` for exactly one selected language, so the single-language production path does not pass through `MultiAnalyzer::new`.
  Evidence: `src/analyzer/workspace.rs` matches `delegates.len()` and directly stores the sole `AnalyzerDelegate`.

- Observation: Multi-language construction still calls every delegate's `all_declarations` immediately and builds a copied combined `DefinitionLookupIndex`.
  Evidence: `src/analyzer/multi_analyzer.rs::MultiAnalyzer::new` calls `DefinitionLookupIndex::from_declarations(delegates.values().flat_map(...all_declarations()))`.

- Observation: Exact definition lookup, which backs the normal `get_symbol_sources` path, is already an indexed SQL query and does not require `DefinitionLookupIndex`.
  Evidence: `TreeSitterAnalyzer::definitions` delegates to `sql_definitions_vec`, which selects candidate rows by persisted short name before applying adapter normalization.

- Observation: Graph-heavy definition and usage resolution still accepts `&DefinitionLookupIndex` broadly and therefore materializes a language's full persisted definition index when that support object is first requested.
  Evidence: `DefinitionBatchContext::new` and the usage graph resolvers retain a `DefinitionLookupIndex`; replacing that contract with bounded store-backed lookup operations is a larger follow-up than removing eager workspace construction.

- Observation: Go forward definition lookup can avoid the full index using only exact FQN, same-file identifier, direct-owner-child, and workspace-package existence queries. Exact FQNs already use indexed SQLite reads; owner children hydrate only files containing an exact owner; package existence is checked by import-path/module-root inversion and a bounded target-directory inventory.
  Evidence: `AnalyzerGoDefinitionProvider` in `src/analyzer/usages/get_definition/go.rs` implements those operations without calling `definition_lookup_index` or `all_declarations`.

- Observation: `DefinitionBatchContext` itself was an eager trigger even for resolvers that did not need the support index.
  Evidence: Its constructor called `analyzer.definition_lookup_index()` before reading the request language. It now stores a `OnceLock` fallback initialized only by non-migrated language dispatch.

- Observation: The existing Go workspace graph preparsed every analyzed Go file on the first batch lookup, even though forward resolution only needs the current file's tree and its bounded import namespace.
  Evidence: The forward path now calls `definition_import_namespaces(file)` and `resolve_go_reference_with_namespaces` with the already parsed request tree; the obsolete whole-workspace preparse entrypoints were removed while usage scanning retains its candidate-scoped graph.

- Observation: Exact SQL lookup still called the nonpersisted path-synthetic union, which enumerated every live path even for adapters such as Go that never synthesize path-derived modules.
  Evidence: `LanguageAdapter::has_path_synthetic_module_units` now defaults false and only JavaScript, TypeScript, and Python opt in, allowing other adapters to return an empty union before taking a live snapshot.

- Observation: Go intentionally stores empty `code_units.content_qualifier` and `blob_meta.content_package`, then `GoAdapter::hydrate_content_qualifier` reads and parses the entire source file for every resolved candidate row.
  Evidence: `src/analyzer/go/adapter.rs` returns `String::new()` from both storage hooks and constructs a tree-sitter parser in the hydration hook.

- Observation: A canonical Go import path is not blob content. The same bytes can appear at multiple live paths and must resolve to different canonical packages, while the declared `package foo` or `package foo_test` clause is content-dependent and can safely be stored once per blob.
  Evidence: `canonical_go_package_name` combines the declared package's external-test suffix with the nearest live `go.mod` and the file's live directory.

- Observation: C# fully-qualified declaration names are content-stable, but this is not a property shared by all adapters.
  Evidence: Schema-v10 lookup projections are nullable and populated only when `LanguageAdapter::persist_content_stable_lookup_keys` opts in; C# opts in while Go and path-synthetic module languages retain no persisted FQN projection.

- Observation: Normalized C# owner names are not declaration identities. A nested `N.Outer$Inner` and a top-level `N.Outer.Inner` normalize to the same selector spelling.
  Evidence: Member queries now try the indexed exact owner first and only fall back to the normalized owner when no live exact child exists. `ClassRangeIndex` retains the exact enclosing `CodeUnit` so it does not discard this distinction before the query.

- Observation: Rust forward definition resolution only reads exact FQNs, same-file identifiers, and named members beneath an exact owner, and Rust currently contributes no lookup-only units outside its declaration set.
  Evidence: `src/analyzer/usages/get_definition/rust.rs` uses only `fqn` and `file_identifier`; the shared trait-associated resolver can replace direct-child enumeration with exact `{owner}.{name}` lookup, while only JavaScript currently calls `ParsedFile::add_definition_lookup_unit`.

## Decision Log

- Decision: Reject immutable Arc-backed `DefinitionLookupIndex` shards.
  Rationale: They avoid a second copied workspace map but still hydrate every persisted declaration into memory when the first graph-heavy symbols request asks for a delegate index. That is deferral, not correct use of SQLite.
  Date/Author: 2026-07-13 / Codex

- Decision: Introduce an owned-result, query-shaped definition provider for symbols resolvers.
  Rationale: Exact FQN, normalized FQN, identifier, owner/member, file/identifier, type/package, and package-prefix operations can fetch bounded candidates using the persisted short-name and identifier indexes, hydrate only live matches, and merge dirty state. Multi-language lookup can fan out those owned queries without constructing a combined workspace index.
  Date/Author: 2026-07-13 / Codex

- Decision: Make the legacy batch definition index a lazy fallback, and route Go through a language-specific provider first.
  Rationale: This establishes a complete vertical slice without forcing a cross-language resolver rewrite in one checkpoint. Independent index-build and full-declaration-scan counters prevent the lazy fallback from silently regressing Go.
  Date/Author: 2026-07-13 / Codex

- Decision: Keep exact symbols lookup on the existing bounded `definitions` SQL path and test that it does not initialize the composite definition index.
  Rationale: Deferring the full index is only useful if common symbols requests do not immediately force it. This establishes that boundary without claiming that graph-heavy usage analysis is store-backed yet.
  Date/Author: 2026-07-13 / Codex

- Decision: Persist a generic content-dependent qualifier in `ParsedFile`/`FileState`; for Go it is the raw package-clause identifier, while other adapters keep their existing package qualifier.
  Rationale: Storage hooks need the content-only fact at write time. Canonical Go package identity remains path-dependent and is recomposed only when a row is attached to a live path.
  Date/Author: 2026-07-13 / Codex

- Decision: Bump Go's analyzer epoch salt.
  Rationale: Existing Go rows contain empty qualifiers and cannot be migrated correctly without source syntax. Rebuilding only Go blobs is the safe migration.
  Date/Author: 2026-07-13 / Codex

- Decision: Persist exact FQN, normalized FQN, and package/simple-type lookup projections only for adapters whose names are intrinsic to blob contents.
  Rationale: This gives C# indexed candidate reads without reintroducing path-dependent identity corruption for Go or path-synthetic module languages. Nullable projections make the capability explicit in storage instead of pretending every language has the same identity model.
  Date/Author: 2026-07-13 / Codex

- Decision: Keep unresolved C# initializer/member-return and hierarchy paths as explicit legacy fallbacks until candidate-scoped signatures, supertypes, and global imports are persisted and queryable.
  Rationale: Direct typed receivers and `var x = new Foo()` are now bounded, but removing the remaining fallback before its structured replacement exists regresses valid `var x = field` and factory-return resolution. Tests and the plan must not overstate the migration boundary.
  Date/Author: 2026-07-13 / Codex

- Decision: Give Rust a focused owned-result provider instead of expanding one cross-language provider to mirror every `DefinitionLookupIndex` operation.
  Rationale: Rust can be migrated completely with three bounded query shapes, while JavaScript/TypeScript lookup-only units and the remaining languages' package, normalized-name, and prefix semantics need different structured operations. A broad interface now would obscure which implementations remain workspace-wide.
  Date/Author: 2026-07-12 / Codex

- Decision: Bind forward Rust queries to the concrete `RustAnalyzer`, cache owned results for multi-reference request batches, and cap public definition batches at 100 references.
  Rationale: Delegating through `MultiAnalyzer::definitions` would apply other languages' normalization rules and could reintroduce path-wide work through non-Rust adapters. Request-scoped positive and negative caches preserve the old batch index's reuse property without retaining workspace-sized state, while single-reference requests avoid cache insertion overhead and the limit bounds unique adversarial queries consistently with `get_type_by_location`.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

The first Go forward-definition vertical slice and the direct C# and Rust forward-definition slices are implemented. A warm persisted multi-language Go regression resolves an imported package member whose import-path tail differs from its declared package name, with zero warm-build parse events, zero delegate/composite definition-index builds, and zero full declaration scans. The corresponding C#+Python regression resolves `var service = new Service(); service.Run()` with the same zero-index/zero-scan guarantees, and the Rust+Python regression resolves a serde-shaped `value.Value.Number` enum-variant reference with those same guarantees. C# stale-blob package existence and nested-vs-dotted owner collisions have public regressions. A sibling-module Go regression proves the workspace path index is built once and package-clause metadata is read without full file-state hydration. On the 25,617-file AWS SDK Go checkout, the one-time schema-v9 population completed in 132.05 seconds at 3,839,280 KiB peak RSS; the identical warm one-site run completed in 10.41 seconds at 401,928 KiB. An exact internal `types.S3Location` forward-plus-inverse probe completed in 10.51 seconds at 402,828 KiB and returned an exact consistent hit. C# candidate signatures, supertypes, global usings, and `get_type_by_location`, plus remaining Java, JavaScript/TypeScript, PHP, Python, Ruby, and Scala definition-provider migrations, are pending.

## Context and Orientation

`WorkspaceAnalyzer` in `src/analyzer/workspace.rs` builds one tree-sitter delegate per detected language. A `MultiAnalyzer` in `src/analyzer/multi_analyzer.rs` routes calls across two or more delegates. A `DefinitionLookupIndex` in `src/analyzer/definition_lookup_index.rs` is an immutable set of lookup maps used by language resolvers. Each persisted `TreeSitterAnalyzer` stores content-addressed declaration rows in SQLite and resolves them against the current live path snapshot through `src/analyzer/store/query.rs::QueryResolver`.

Go declarations use canonical import paths such as `github.com/aws/aws-sdk-go-v2/service/s3`. That value depends on both source content and the file's path beneath its nearest `go.mod`. The raw package clause such as `package s3` depends only on source content. Persisting the canonical path in a blob row would be wrong when identical bytes are reused at another path; persisting the raw clause and recomputing against each live path is correct.

## Plan of Work

First extend parsed and hydrated file state with a content-dependent qualifier. Change the language-adapter storage hook so writing a code-unit row can use that qualifier. Set Go's qualifier from the tree-sitter `package_clause`, store it in code-unit and blob metadata rows, and make Go hydration call `canonical_go_package_name(file, raw_qualifier)` without reading source or constructing a parser. Bump only the Go epoch salt so old empty rows are discarded and rebuilt.

Then add an owned-result definition-query surface to the analyzer contract. Implement persisted tree-sitter operations with indexed `code_units(lang, short_name)` and `code_units(lang, identifier)` candidate queries, live-path expansion, adapter normalization, and dirty/nonpersisted unions. Migrate `DefinitionBatchContext` and forward symbols usage resolvers away from borrowed `DefinitionLookupIndex` maps. Keep inherently whole-workspace operations such as Scala inverse/global indexing explicit and measurable rather than hiding their cost behind a lazy index. `MultiAnalyzer` will fan out bounded delegate queries and merge sorted, deduplicated results.

For the completed Rust slice, keep the query contract in `src/analyzer/usages/rust_graph/resolver.rs` so forward resolution and existing usage-graph callers share the same semantic operations. The analyzer-backed implementation in `src/analyzer/usages/get_definition/rust.rs` queries only the concrete Rust delegate for exact FQNs and one file's declarations, preventing other languages' normalization rules or path-synthetic work from entering a Rust lookup; the legacy `DefinitionLookupIndex` implements the same contract for graph callers. `DefinitionBatchContext` owns this provider and enables its positive/negative caches for multi-reference request batches. Single-reference requests query the concrete analyzer directly without populating request-local maps. Named trait members use exact `{owner}.{name}` queries and retain the existing parent/kind proof filters.

Build a generated persisted multi-language workspace twice, assert the warm build emits zero parse events and full declaration scans, then issue exact definition and representative forward usage queries and assert the scan count remains zero. Add a same-Go-blob/two-path regression with distinct canonical packages, an external-test package regression, and public single/multi analyzer definition and usage parity. Reuse existing persistence and inline-project harnesses.

Finally run the repository gates and benchmark the real warm Go corpus. The benchmark must use the release binary or a dedicated ignored measurement test, record cold build time, warm open time, targeted query time, and peak RSS, and confirm the warm open reaches the query with zero parse events. Do not add a resident map proportional to workspace declarations.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost`.

Run focused tests while implementing:

    cargo test --test analyzer_persistence
    cargo test --test analyzer_sql_query_parity
    cargo test --test multi_analyzer_test
    cargo test --test analyzer_query_parity
    cargo test --test go_analyzer_parity

Run final gates:

    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features -- -D warnings

Build release measurement artifacts and run the warm corpus benchmark against the existing clone at `/mnt/T9/repo-clones/aws__aws-sdk-go-v2`. Capture `/usr/bin/time -v` or the repository's measurement-test output for cold build, warm open, targeted query, and maximum resident set size.

## Validation and Acceptance

A generated persisted workspace must parse on the cold build and report zero parse events on the second build. Exact definition and representative forward usage queries must not enumerate or materialize all persisted declarations, and must return the same symbol identities as direct single-language analyzers. Any inherently global inverse operation must be explicit and separately bounded/measured. A source-identical Go file placed beneath two different module-relative directories must produce two correct canonical package FQNs from one content blob, without a hydration parse.

The real Go corpus warm open must complete in a practical time and bounded RSS rather than saturating one core for hours at multi-gigabyte memory. Public definition and usage tests must remain green for both single- and multi-language workspaces.

## Idempotence and Recovery

All tests and benchmark commands are repeatable. The Go epoch bump invalidates only Go analyzer rows; rerunning a cold build repopulates them transactionally. Existing user worktree files are read-only during measurement. If a benchmark is interrupted, rerun it against the same clone; persisted rows already written remain reusable.

## Artifacts and Notes

The integrated Go query-provider checkpoint passed `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, the complete `cargo test --features nlp,python` suite, all 35 focused Go definition tests, all 16 canonical-FQN tests, all six persistence tests, and the identical-blob/two-live-path store regression.

The direct C# query-provider checkpoint passed all 425 cross-language `get_definition_test` cases, all 43 definition-selector cases, all analyzer persistence tests, all 33 analyzer-store tests, all eight cache-schema tests, and `cargo clippy --all-targets --all-features -- -D warnings`. Its warm multi-language regression proves direct object-created receiver lookup does not build either definition index or scan all declarations; separate public regressions prove stale complete blobs are filtered by the live snapshot and exact nested owners are not merged with normalized dotted-name collisions.

The Rust query-provider checkpoint passed all 427 cross-language `get_definition_test` cases, all 108 authoritative Rust usage tests, all 19 Rust usage-graph tests, and all nine analyzer-persistence tests. Its serde-shaped enum-variant regression resolved with zero warm parses, zero definition-index builds, and zero full declaration scans. The exact local `serde-json-rs` benchmark retained the expected `value.Value.Number` result and changed measured median from 8.830 ms on `018ff6d1` to 8.651 ms at the initial provider checkpoint. Guided-review memoization initially moved two hot local reruns to 9.5 ms, so caching was limited to multi-reference batches; two final hot reruns measured 9.0 and 9.1 ms. The optimization's primary acceptance is removing workspace-sized construction, not claiming this small local corpus delta as a stable speedup. Usagebench passed all 110 planned cases from both isolated checkpoint `fc58f468` and final reviewed code commit `aaa3a342091972d258e3878d9b78c0e7201fd897`. Guided review added concrete-Rust delegate isolation, bounded multi-reference result caching, a 100-reference public limit, a cross-language normalized-FQN collision regression, and shared warm-persistence test scaffolding. The resulting diff passed formatting, warning-as-error all-target/all-feature clippy, the complete `cargo test --features nlp,python` suite, and focused definition, persistence, and MCP tests.

Real-corpus commands used the release `bifrost_reference_differential` binary against `/mnt/T9/repo-clones/aws__aws-sdk-go-v2` at repository head `91eca463daf932474778dc4a984c41ecfcd9dc3c`. The cold and warm sampled records are `/tmp/bifrost-go-677-smoke.jsonl` and `/tmp/bifrost-go-677-warm.jsonl`; the resolved exact record is `/tmp/bifrost-go-677-warm-internal2.jsonl` for `service/gamelift/api_op_UpdateScript.go` bytes `2856..2866`.

## Interfaces and Dependencies

The symbols resolver contract gains owned-result definition queries for exact/normalized names, identifiers, owner members, files, types, and packages. `TreeSitterAnalyzer` implements them using indexed store reads; `MultiAnalyzer` merges delegate results. Rust's current slice uses `RustDefinitionProvider::{fqn,file_identifier,members_for_owner_name}` with an analyzer-backed implementation for forward queries and a `DefinitionLookupIndex` implementation for existing usage-graph paths. Existing `DefinitionLookupIndex` remains available only for paths not yet migrated and is not treated as an acceptable persisted symbols backend.

`ParsedFile` and `FileState` gain a content-dependent qualifier string. `LanguageAdapter::storage_content_qualifier` receives that fact when persisting units. `GoAdapter` persists the raw package clause and hydrates canonical package names solely through `canonical_go_package_name`; it must not read source or instantiate tree-sitter in hydration.

Revision note (2026-07-12): recorded the completed Rust forward-definition vertical slice, its language-specific provider decision, focused zero-index and usagebench evidence, and the guided-review hardening so the plan remains restartable from current `master`.
