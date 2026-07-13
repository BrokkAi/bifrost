# Make persisted symbol startup lazy and content-correct

This ExecPlan is a living document maintained according to `.agents/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must remain current while implementation proceeds.

## Purpose / Big Picture

Opening a warm persisted workspace must finish without reconstructing every declaration in memory or reparsing Go files merely to recover package identity. After this change, a second open of a large clean workspace performs no source parses, full file-state hydration, combined definition-index construction, or other workspace-sized derived-index construction before any supported `get_definition` or `get_type_by_location` request. Single-language and multi-language analyzers retain the same public definition and type results, and Go blobs reused at different paths produce correct path-dependent canonical import paths from one persisted content-dependent package-clause fact. Inverse usage scans remain explicit global operations; they must not be reached from a forward definition or type request.

## Progress

- [x] (2026-07-13) Validated issue #677 against current `master` and mapped `WorkspaceAnalyzer`, `MultiAnalyzer`, `DefinitionLookupIndex`, `TreeSitterAnalyzer`, `QueryResolver`, and Go qualifier persistence.
- [x] (2026-07-13) Isolated the raw Go package-clause persistence fix.
- [x] (2026-07-13) Add content-dependent parsed-state qualifier storage and remove Go source parsing from row hydration.
- [x] (2026-07-13) Prototyped and rejected lazy Arc-backed index shards because they merely defer full SQLite materialization until a graph query.
- [x] (2026-07-13) Add a lazy batch support boundary and migrate Go forward definition resolution to an owned, query-shaped provider backed by exact SQL definitions and bounded file hydration.
- [x] (2026-07-13) Add adapter-opt-in persisted lookup projections and migrate direct C# forward definition resolution to indexed exact/normalized/type/package/member queries without constructing the legacy definition index.
- [x] (2026-07-12) Migrate Rust forward definition resolution to exact FQN, same-file identifier, and exact owner/member queries without constructing the legacy definition index.
- [x] (2026-07-13) Migrate C# inherited-member, candidate-signature/return-type, global-using, and `get_type_by_location` paths off the remaining explicit legacy fallbacks.
- [x] (2026-07-13) Migrate all remaining forward definition/type resolvers from the legacy index to owned, query-shaped analyzer operations backed by indexed SQL candidate reads.
- [x] (2026-07-13) Add index-build/full-scan counters plus warm multi-language, blob-reuse, sibling-module, and bounded-hydration regressions for the Go vertical slice.
- [x] (2026-07-12) Pass the complete 427-case definition suite, both Rust usage-graph suites, all analyzer-persistence tests, and the local serde-json-rs benchmark for the Rust provider slice.
- [x] (2026-07-12) Complete repository gates after guided-review fixes; usagebench passed 110/110 at the implementation checkpoint and all actionable review findings have been incorporated.
- [x] (2026-07-13) Pass formatting, all-target/all-feature clippy, focused Go/persistence tests, and the complete `nlp,python` suite.
- [x] (2026-07-13) Measure schema-v9 cold population and warm exact forward/inverse resolution on `aws__aws-sdk-go-v2`.
- [x] (2026-07-13) Replace every forward definition and type resolver use of the legacy index with bounded persisted candidate queries for every supported language.
- [x] (2026-07-13) Keep Scala `ProjectTypes`, C++ global visibility support, and other whole-workspace graph helpers out of forward definition/type dispatch; retain them only for explicit inverse usage analysis.
- [x] (2026-07-13) Add warm persisted definition/type regressions for every supported language, including generated unrelated files and stale/dirty/path-dependent state.
- [x] (2026-07-13) Add a shared bounded lookup facade, persistently query lookup-only JS/TS assignment declarations by short name, and fan out deterministic owned results through `MultiAnalyzer`.
- [x] (2026-07-13) Move Java, PHP, Python, Ruby, JavaScript/TypeScript, and C++ forward definition dispatch onto the bounded facade; C++ include visibility now remains request-scoped instead of retaining a global definition index.
- [x] (2026-07-13) Reproduce and review the post-migration Scala failures: 47 focused Scala cases pass and three fail on class/companion identity or explicit-import precedence; the nine existing persistence tests pass but cover only Go, C#, and Rust forward requests.
- [x] (2026-07-13) Replace the language-agnostic forward facade with an internal, request-scoped, language-bound query session and remove request-time path-synthetic workspace enumeration.
- [x] (2026-07-13) Replace Scala's string-only forward resolver with typed class/singleton resolution and candidate-scoped persisted ancestry; prove no forward path constructs `ProjectTypes`.
- [x] (2026-07-13) Persist OID-validated path projections for JavaScript, TypeScript, and Python modules, refresh them during reconciliation, and remove Python's eager workspace module map.
- [x] (2026-07-13) Make empty candidate-name queries return no rows, batch prefix validation, and add request counters for path scans and Scala `ProjectTypes` construction.
- [x] (2026-07-13) Pass all 436 definition tests, all 14 analyzer-persistence tests, 50 focused Scala definition/type tests, and structured-supertype unit tests after the typed Scala milestone.
- [x] (2026-07-13) Complete warm persisted definition/type coverage for every migrated language, including path-derived modules, dirty Scala owner overlays, stale Scala owner blobs, and unrelated generated files.
- [x] (2026-07-13) Rename the legacy index and its public trait hook to `GlobalUsageDefinitionIndex` / `global_usage_definition_index`, preserving it only for explicitly global diagnostics and inverse usage paths.
- [x] (2026-07-13) Complete the clean warm definition matrix for C++, C#, Go, Java, JavaScript, TypeScript, PHP, Python, Ruby, Rust, and Scala, plus the supported C#/Go/Java/JS/TS/Rust/Scala type matrix, with a 32-file unrelated hydration sentinel.
- [x] (2026-07-13) Close matrix-discovered Java import, Ruby semantic-facts, C# factory-return, and Rust import/export route leaks without weakening the zero-global-work assertions.
- [x] (2026-07-13) Repair cache migration-v2 tests and benchmark profiling assertions so they encode the new path projection and require forward definition profiles to avoid the global usage index.
- [x] (2026-07-13) Restore bounded Scala wildcard-import resolution for top-level package members as well as object members; the complete LSP click-around regression now passes.
- [x] (2026-07-13) Pass 436 definition tests, 35 persistence tests, 18 cache migration tests, all-target/all-feature clippy, formatting, and the complete `nlp,python` gate under the macOS CI linker configuration.
- [x] (2026-07-13) Make asynchronous unified-cache GC snapshot eligible rows before its Git reachability walk, preventing an in-flight cold-build GC from deleting dirty/stale blobs written by a concurrent warm build; the 35-case persistence suite passes 20 consecutive stress runs.

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

- Observation: JS/TS member assignments can be intentionally absent from the ordinary declaration surface while remaining valid forward-resolution targets.
  Evidence: `JsAssignmentSymbolSurface::DefinitionLookupOnly` populates `ParsedFile::definition_lookup_units`; name-bounded persisted candidate reads must include that membership bit and still validate each hydrated live path.

- Observation: The current Scala forward rewrite conflates a class, its `$` companion object, and a missing explicit import into one optional FQN string.
  Evidence: `cargo test --test get_definition_test scala_ -- --nocapture` reports 47 passes and three failures: `scala_instance_member_prefers_inherited_member_over_companion_object` returns `app.Child$.value`, `scala_missing_imported_type_annotation_does_not_fall_back_to_same_package_type` returns `app.Child.local`, and `scala_singleton_typed_receiver_method_prefers_object_definition` returns `app.Settings.value`.

- Observation: Scala forward lookup can still reach the global `ProjectTypes` graph even though its main resolver accepts bounded queries.
  Evidence: `scala_enclosing_member_shadows_bare_call` calls `type_hierarchy_provider().get_direct_ancestors`; `ScalaAnalyzer` implements that operation by calling `resolve_direct_ancestors`, which initializes `project_types()`.

- Observation: An absent persisted Scala supertype row currently means both "this owner has no parents" and "facts were unavailable", causing the forward resolver to parse an owner source file after a bounded lookup miss.
  Evidence: `scala_owner_source_ancestor_member_units` falls through from `raw_supertypes_of` to `get_source`, `parse_scala_tree`, and an AST walk whenever no inherited member was found, including clean owners with no parents.

- Observation: The current generic bounded FQN query still performs hidden workspace work for path-synthetic languages and can perform a full declaration scan for malformed or empty lookup keys.
  Evidence: `sql_definition_candidates_vec` calls `declaration_candidate_rows_for_langs` when `definition_candidate_short_names` is empty and always unions `sql_nonpersisted_workspace_declarations_vec_matching`; that helper iterates `LiveSnapshot::all_paths()` for JavaScript, TypeScript, and Python.

- Observation: Python constructs another workspace-sized derived index during analyzer construction.
  Evidence: `PythonAnalyzer::from_inner` eagerly calls `build_python_module_code_units`, which iterates `inner.all_files()` and retains an `Arc<HashMap<String, CodeUnit>>` before any forward request.

- Observation: The installed default Cargo/Rust compiler and `clippy-driver` binaries have incompatible LLVM patch versions on this machine, so the nominal clippy command reports E0514 before checking repository code.
  Evidence: the default compiler reports LLVM 22.1.2 while the Homebrew compiler and clippy driver report LLVM 22.1.6; running the identical all-target/all-feature clippy gate with `/opt/homebrew/bin/cargo` and `/opt/homebrew/bin/rustc` succeeds cleanly in an isolated target directory.

- Observation: Generated unrelated files exposed four forward paths that the focused language suites could not reveal: Java exact imports still consulted the global import index, Ruby eagerly built all semantic facts even for a constant lookup, C# factory return inference initialized global callable facts, and Rust import resolution initialized `RustUsageIndex` and hydrated every Rust file.
  Evidence: the expanded persistence harness failed the global-index/full-scan/hydration counters for each path before the fixes and now passes all 33 clean warm regressions with every request below the 32-file hydration sentinel.

- Observation: A wildcard Scala import can target either a singleton owner (`Syntax.*`) or a package containing top-level declarations (`support.*`); owner-child lookup alone cannot represent the latter because a package is not a `CodeUnit`.
  Evidence: the full feature gate exposed `milestone_4_scala_extension_trait_click_around`; bounded exact lookup of `support.helper` plus candidate owner-child lookup restores both forms without enumerating the package.

- Observation: Adding the path-projection migration advanced the unified cache to version 2 and intentionally invalidated analyzer blob rows, but the cache tests still described the version-1 baseline as the current schema.
  Evidence: the first feature-enabled gate failed the migration suite; current-schema validation now applies both migrations, future-migration fixtures include migration 2, and all 18 cache tests pass.

- Observation: Exact-first C# owner lookup resolves an additional valid reference inside a partial generic type that the prior exact-plus-normalized lookup discarded as ambiguous with the nongeneric type.
  Evidence: `csharp_graph_distinguishes_generic_and_nongeneric_constructor_owners` now finds the generic object initializer and `RestException<T>.Read` body, while all 66 C# usage tests prove the nongeneric initializer remains excluded.

- Observation: The first dirty/stale Scala regressions were intermittently erased by an older analyzer's asynchronous GC, not by Scala resolution. GC computed reachability before the warm analyzer wrote its new blob, then swept the newly inserted row because the sweep enumerated rows after the reachability walk.
  Evidence: the 35-case persistence suite failed within three stress repetitions before the fix. GC now stores its eligible OID/language keys in disk-backed temporary tables before walking Git and sweeps only that snapshot; 20 consecutive suite repetitions pass.

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

- Decision: Treat all public forward definition and type lookup paths as the issue #677 completion boundary; retain `DefinitionLookupIndex` only for explicitly global inverse usage analysis.
  Rationale: A lazy index is still an unbounded persisted mirror when a common symbols request initializes it. Forward resolution must instead use candidate-shaped SQL queries and request-scoped source trees, while inverse graph analysis may remain explicit about its whole-workspace cost.
  Date/Author: 2026-07-13 / Codex

- Decision: Bind forward Rust queries to the concrete `RustAnalyzer`, cache owned results for multi-reference request batches, and cap public definition batches at 100 references.
  Rationale: Delegating through `MultiAnalyzer::definitions` would apply other languages' normalization rules and could reintroduce path-wide work through non-Rust adapters. Request-scoped positive and negative caches preserve the old batch index's reuse property without retaining workspace-sized state, while single-reference requests avoid cache insertion overhead and the limit bounds unique adversarial queries consistently with `get_type_by_location`.
  Date/Author: 2026-07-12 / Codex

- Decision: Keep C++ include closure construction request-scoped and use its already hydrated visible declarations for qualified/member selection.
  Rationale: The include closure is necessary C++ visibility information for the requested file, while retaining a second global `DefinitionLookupIndex` inside it silently defeats bounded forward lookup.
  Date/Author: 2026-07-13 / Codex

- Decision: Bind forward lookup sessions to an explicit language scope and keep the capability crate-internal instead of adding more methods to the public `IAnalyzer` trait.
  Rationale: A request already knows its source language. Explicit scopes prevent unrelated delegate normalization and path work, preserve deliberate Scala/Java and JavaScript/TypeScript interoperability, and avoid public wrapper boilerplate. A request-local positive/negative cache recovers batch reuse without retaining workspace-sized state.
  Date/Author: 2026-07-13 / Codex

- Decision: Store path-derived synthetic module identities in a separate workspace-path projection, never in content-addressed blob declaration rows.
  Rationale: JavaScript, TypeScript, and Python module identities depend on the live path. An indexed path projection can be refreshed from already enumerated live paths and queried by candidate FQN without scanning every path per request or corrupting identical blobs mounted at different paths.
  Date/Author: 2026-07-13 / Codex

- Decision: Model Scala forward owners as class or singleton identities and model missing explicit imports as a terminal resolution outcome.
  Rationale: Suffix manipulation after an untyped name lookup cannot express the distinction between `Child`, the term `Child`, and `Child.type`; it also cannot preserve the rule that a matching but missing explicit import blocks same-package fallback. Typed outcomes make member precedence mechanical rather than heuristic.
  Date/Author: 2026-07-13 / Codex

- Decision: Persist a structured Scala supertype lookup path alongside its raw source spelling.
  Rationale: Forward ancestry needs the base type identity but must neither split Scala type syntax by delimiters nor reparse a clean owner source on a warm request. The declaration extractor already has the tree-sitter node and can persist both facts safely.
  Date/Author: 2026-07-13 / Codex

- Decision: Validate path projections against both the current live blob OID and the adapter-derived live identity before returning them.
  Rationale: Workspace-relative module identities are safe to index only while attached to the exact live path/blob pair that produced them. OID and identity validation makes stale rows harmless and keeps dirty files in the bounded live overlay.
  Date/Author: 2026-07-13 / Codex

- Decision: Treat callable signatures, Ruby mixin/ancestor facts, and Rust re-export routes as owner/module candidates in forward resolution rather than reusing their global inverse indexes.
  Rationale: Each request already identifies the receiver owner or imported module. Hydrating that owner, reading its persisted signature/supertype facts, and following only its manifest/re-export edges preserves semantics while making unrelated source files unreachable from the request.
  Date/Author: 2026-07-13 / Codex

## Outcomes & Retrospective

The request-scoped forward query layer and typed Scala forward resolver are complete. A forward batch carries an explicit language scope and positive/negative owned-result caches; it does not expose new public `IAnalyzer` methods or fan out to unrelated delegates. JavaScript, TypeScript, and Python synthetic module identities live in OID-validated workspace-path projections, so exact module queries no longer enumerate all live paths and Python no longer constructs an eager workspace module map. Scala distinguishes class and singleton owners, treats a missing explicit import as terminal, persists structured supertype lookup paths, walks only candidate owner facts iteratively, and resolves wildcard imports through exact package-member candidates or bounded singleton children. The legacy index is explicitly named `GlobalUsageDefinitionIndex` and remains reachable only from global diagnostics and inverse usage analysis.

The final local gates pass: 436 definition tests, 35 persistence tests, 18 cache migration tests, the complete Scala LSP click-around regression, formatting, warning-as-error all-target/all-feature clippy, and the complete feature-enabled workspace suite. The persistence matrix covers every supported definition language and every type-enabled language, asserts zero warm parses, full declaration scans, global-index builds, Scala `ProjectTypes` builds, and request-time path scans, and keeps candidate hydration below a 32-file unrelated sentinel. The requested AWS rerun cannot be performed in this worktree because `/mnt/T9/repo-clones/aws__aws-sdk-go-v2` is not mounted; the prior schema-v9 artifacts remain the latest real-corpus evidence and this environmental limitation does not weaken the deterministic bounded-work regressions.

## Context and Orientation

`WorkspaceAnalyzer` in `src/analyzer/workspace.rs` builds one tree-sitter delegate per detected language. A `MultiAnalyzer` in `src/analyzer/multi_analyzer.rs` routes calls across two or more delegates. A `DefinitionLookupIndex` in `src/analyzer/definition_lookup_index.rs` is an immutable set of lookup maps used by language resolvers. Each persisted `TreeSitterAnalyzer` stores content-addressed declaration rows in SQLite and resolves them against the current live path snapshot through `src/analyzer/store/query.rs::QueryResolver`.

Go declarations use canonical import paths such as `github.com/aws/aws-sdk-go-v2/service/s3`. That value depends on both source content and the file's path beneath its nearest `go.mod`. The raw package clause such as `package s3` depends only on source content. Persisting the canonical path in a blob row would be wrong when identical bytes are reused at another path; persisting the raw clause and recomputing against each live path is correct.

## Plan of Work

First extend parsed and hydrated file state with a content-dependent qualifier. Change the language-adapter storage hook so writing a code-unit row can use that qualifier. Set Go's qualifier from the tree-sitter `package_clause`, store it in code-unit and blob metadata rows, and make Go hydration call `canonical_go_package_name(file, raw_qualifier)` without reading source or constructing a parser. Bump only the Go epoch salt so old empty rows are discarded and rebuilt.

Then add an owned-result definition-query surface behind a crate-internal, request-scoped session bound to explicit languages. Implement persisted tree-sitter operations with indexed exact/normalized FQN, short-name, identifier, owner/member, package/type, and prefix candidates plus live-path validation and dirty unions. A separate indexed workspace-path projection supplies JavaScript, TypeScript, and Python synthetic modules without persisting path-derived identities in blob rows or iterating all live paths during a request. Remove the public `IAnalyzer::bounded_*` additions, make `MultiAnalyzer` route only the requested delegates without Rayon fan-out, and cache positive and negative owned results for each public batch.

For Scala forward resolution, introduce a typed owner identity that distinguishes an instance class from its singleton companion and a name result that distinguishes a missing explicit import from an ordinary miss. Resolve names in ordered tiers: explicit import, wildcard import, current package or enclosing type, then built-ins. Normal annotations select the plain class; `.type` and AST-proven term/object receivers select the `$` object. Read each exact owner's signatures, trait marker, and structured supertype facts from its one hydrated `FileState`, then walk ancestors iteratively with a visited-FQN set. Direct instance members win, followed by the nearest inherited members, AST-gated companion dispatch, and finally applicable extensions. Every Scala forward helper, including shadow checks and type lookup, must use this provider and must not call `TypeHierarchyProvider`, `project_types`, or a descendant index.

For the completed Rust slice, keep the query contract in `src/analyzer/usages/rust_graph/resolver.rs` so forward resolution and existing usage-graph callers share the same semantic operations. The analyzer-backed implementation in `src/analyzer/usages/get_definition/rust.rs` queries only the concrete Rust delegate for exact FQNs and one file's declarations, preventing other languages' normalization rules or path-synthetic work from entering a Rust lookup; the legacy `DefinitionLookupIndex` implements the same contract for graph callers. `DefinitionBatchContext` owns this provider and enables its positive/negative caches for multi-reference request batches. Single-reference requests query the concrete analyzer directly without populating request-local maps. Named trait members use exact `{owner}.{name}` queries and retain the existing parent/kind proof filters.

Build generated persisted multi-language workspaces twice, assert the warm build emits zero parse events, then issue representative definition and type requests while asserting zero full declaration scans, global definition-index builds, Scala `ProjectTypes` builds, and request-time live-path scans. Record targeted full-hydration counts and prove unrelated generated files remain untouched. Cover the Scala class/companion failures, imports, inheritance, extensions, dirty overlays, stale blobs, and multi-reference parity, then complete the same warm matrix for every migrated language.

Finally run the repository gates and benchmark the real warm Go corpus. The benchmark must use the release binary or a dedicated ignored measurement test, record cold build time, warm open time, targeted query time, and peak RSS, and confirm the warm open reaches the query with zero parse events. Do not add a resident map proportional to workspace declarations.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/a8f0/bifrost`.

Run focused tests while implementing:

    cargo test --test analyzer_persistence
    cargo test --test get_definition_test scala_
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

The real Go corpus warm open must complete in a practical time and bounded RSS rather than saturating one core for hours at multi-gigabyte memory. Public definition and usage tests must remain green for both single- and multi-language workspaces. Scala acceptance additionally requires that an instance `Child` resolves inherited `Base` members even when `object Child` exists, `Child.type` resolves only the singleton object, a missing explicit import never falls back to a same-package type, and neither definition nor type lookup initializes `ProjectTypes`.

## Idempotence and Recovery

All tests and benchmark commands are repeatable. The Go epoch bump invalidates only Go analyzer rows; rerunning a cold build repopulates them transactionally. Existing user worktree files are read-only during measurement. If a benchmark is interrupted, rerun it against the same clone; persisted rows already written remain reusable.

## Artifacts and Notes

The integrated Go query-provider checkpoint passed `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, the complete `cargo test --features nlp,python` suite, all 35 focused Go definition tests, all 16 canonical-FQN tests, all six persistence tests, and the identical-blob/two-live-path store regression.

The direct C# query-provider checkpoint passed all 425 cross-language `get_definition_test` cases, all 43 definition-selector cases, all analyzer persistence tests, all 33 analyzer-store tests, all eight cache-schema tests, and `cargo clippy --all-targets --all-features -- -D warnings`. Its warm multi-language regression proves direct object-created receiver lookup does not build either definition index or scan all declarations; separate public regressions prove stale complete blobs are filtered by the live snapshot and exact nested owners are not merged with normalized dotted-name collisions.

The Rust query-provider checkpoint passed all 427 cross-language `get_definition_test` cases, all 108 authoritative Rust usage tests, all 19 Rust usage-graph tests, and all nine analyzer-persistence tests. Its serde-shaped enum-variant regression resolved with zero warm parses, zero definition-index builds, and zero full declaration scans. The exact local `serde-json-rs` benchmark retained the expected `value.Value.Number` result and changed measured median from 8.830 ms on `018ff6d1` to 8.651 ms at the initial provider checkpoint. Guided-review memoization initially moved two hot local reruns to 9.5 ms, so caching was limited to multi-reference batches; two final hot reruns measured 9.0 and 9.1 ms. The optimization's primary acceptance is removing workspace-sized construction, not claiming this small local corpus delta as a stable speedup. Usagebench passed all 110 planned cases from isolated checkpoint `fc58f468`, reviewed pre-rebase code commit `aaa3a342091972d258e3878d9b78c0e7201fd897`, and post-rebase commit `69c9d25cd14432dd22dc13d947d8c818369daf65`. Guided review added concrete-Rust delegate isolation, bounded multi-reference result caching, a 100-reference public limit, a cross-language normalized-FQN collision regression, and shared warm-persistence test scaffolding. The resulting diff passed formatting, warning-as-error all-target/all-feature clippy, the complete `cargo test --features nlp,python` suite, and focused definition, persistence, and MCP tests.

Real-corpus commands used the release `bifrost_reference_differential` binary against `/mnt/T9/repo-clones/aws__aws-sdk-go-v2` at repository head `91eca463daf932474778dc4a984c41ecfcd9dc3c`. The cold and warm sampled records are `/tmp/bifrost-go-677-smoke.jsonl` and `/tmp/bifrost-go-677-warm.jsonl`; the resolved exact record is `/tmp/bifrost-go-677-warm-internal2.jsonl` for `service/gamelift/api_op_UpdateScript.go` bytes `2856..2866`.

## Interfaces and Dependencies

The completed forward interface is crate-internal and request-scoped. It exposes explicit language scopes and owned queries for exact/normalized FQNs, file identifiers, owner members, package/simple types, packages/prefixes, and path-derived modules. `TreeSitterAnalyzer` implements these operations using indexed store reads; multi-language sessions merge only explicitly requested delegates. Rust's current slice uses `RustDefinitionProvider::{fqn,file_identifier,members_for_owner_name}` with an analyzer-backed implementation for forward queries and a global index implementation for existing usage-graph paths. The legacy workspace index is renamed to communicate that it belongs to explicit global usage analysis and is not an acceptable persisted symbols backend. Scala's forward provider exposes typed class/singleton owners plus complete owner facts; inverse Scala usage analysis retains `ProjectTypes` unchanged.

`ParsedFile` and `FileState` gain a content-dependent qualifier string. `LanguageAdapter::storage_content_qualifier` receives that fact when persisting units. `GoAdapter` persists the raw package clause and hydrates canonical package names solely through `canonical_go_package_name`; it must not read source or instantiate tree-sitter in hydration.

Revision note (2026-07-12): recorded the completed Rust forward-definition vertical slice, its language-specific provider decision, focused zero-index and usagebench evidence, and the guided-review hardening so the plan remains restartable from current `master`.

Revision note (2026-07-13): recorded the three reproduced Scala semantic regressions and the remaining hidden workspace work, then expanded the final milestones to use typed Scala owners, structured persisted supertype facts, language-bound request sessions, and indexed path-derived module projections. This revision prevents a narrow companion fallback from being mistaken for completion of issue #677.
