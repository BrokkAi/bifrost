# Keep Rust semantic tokens responsive

This ExecPlan is a living document. It must be maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

VS Code asks the Bifrost language server for semantic tokens to colour declarations and references. Before this change, a Rust token request can repeatedly validate every indexed Rust file in SQLite and can run on the server's single request loop. In a medium workspace that makes unrelated editor features, including `bifrost/runeIr`, appear hung for minutes. After this work, one token request reuses its live-file and Rust declaration parses, can be cancelled, and runs in the existing bounded worker pool so the request loop remains available for Rune IR, hover, and other requests.

## Progress

- [x] (2026-07-17 00:00Z) Fetched `origin`, inspected issue #850, current branch state, and the semantic-token, Rust resolution, query-cache, and LSP worker code paths.
- [x] (2026-07-17 00:00Z) Extend the analyzer query cache so one active query computes the complete live analyzed-file list at most once.
- [x] (2026-07-17 00:00Z) Share `RustTypeLookupCache` through a complete definition lookup batch and add a regression test for repeated nested Rust field resolution.
- [ ] Run semantic tokens in the cancellable LSP worker path (completed: worker and cancellation plumbing; remaining: behavioural coverage for concurrent Rune IR/cancellation and full validation).
- [x] (2026-07-17 00:00Z) Extend batch-local lookup state to the other high-frequency targets: JS/TS shares imports, path aliases, and receiver syntax facts; Go shares package and import namespaces by reference; Scala shares package and import facts. Added focused regression coverage for each target.

## Surprises & Discoveries

- Observation: Request-scoped caching already exists but only covers per-file OIDs, file state hydration, and prepared syntax.
  Evidence: `src/analyzer/tree_sitter_analyzer.rs` defines `QueryReadCache` with `live_oids`, `file_states`, and `prepared_syntax`; `analyzed_live_files()` still calls `parsed_blob_keys_at_generations` each time.
- Observation: Semantic token reference resolution is already batched, but the Rust resolver makes a fresh parsed-declaration cache for each member candidate.
  Evidence: `src/lsp/handlers/semantic_tokens.rs` calls `resolve_definition_batch_with_source`; `src/analyzer/usages/get_definition/rust.rs::resolve_rust` constructs `RustTypeLookupCache::default()` locally.
- Observation: The LSP already has a bounded, cancellable worker mechanism used by references and RQL queries.
  Evidence: `src/lsp/server.rs` owns `RequestJobs`, receives `$/cancelRequest`, snapshots the overlay, and runs workers with a cloned `WorkspaceAnalyzer`.
- Observation: The machine cannot link the Python-enabled test build because its Python symbols are unavailable to the linker.
  Evidence: `cargo test --features nlp,python ...` reaches Rust compilation, then fails with unresolved `_Py*` symbols from `pyo3` during dynamic-library linking.
- Observation: all-features Clippy currently fails before crate analysis because Cargo's dependency metadata was produced by a different build of the same Rust release.
  Evidence: both isolated and worktree-target `cargo clippy --all-targets --all-features -- -D warnings` stop with `E0514` for third-party `.rmeta` files; the compiler reports 1.96.0 in both cases but treats the metadata as incompatible.

## Decision Log

- Decision: Cache the sorted, deduplicated `Vec<ProjectFile>` in `QueryReadCache`, rather than weakening SQLite integrity checks or adding a global cache.
  Rationale: the existing `AnalyzerQueryScope` defines a request-consistent lifetime and clears on the outermost scope exit; keeping the integrity condition intact preserves stale-store detection between requests.
  Date/Author: 2026-07-17 / Codex
- Decision: Add `RustTypeLookupCache` to `DefinitionBatchContext` and pass it explicitly to Rust resolution.
  Rationale: semantic tokens already turn all references in a document into one batch. The existing cache is mutable, request-local, and exactly represents the declaration parsing that should be shared without making it cross-request state.
  Date/Author: 2026-07-17 / Codex
- Decision: Model semantic tokens after the existing cancellable request workers, with an overlay snapshot and the two-job limit.
  Rationale: this protects the main LSP loop and gives standard `$/cancelRequest` semantics without adding an unbounded thread path or changing the token protocol.
  Date/Author: 2026-07-17 / Codex
- Decision: Generalize only the per-document facts that are reconstructed for every definition candidate, keeping result and AST-node caches request-local to their existing providers.
  Rationale: JS/TS import binding, alias configuration, and receiver syntax indexing; Go package/import namespaces; and Scala package/import facts are immutable for a file during a definition batch. Sharing them removes repeated setup without extending tree-node lifetimes or turning mutable provider caches into global state.
  Date/Author: 2026-07-17 / Codex

## Outcomes & Retrospective

The request-local live-file cache, batch-local Rust declaration cache, and cancellable semantic-token worker are implemented. The same batch boundary now avoids repeated JS/TS, Go, and Scala resolver setup for a document. Focused featureless compile and regression coverage pass; all-features lint/test validation remains blocked by the local Rust metadata mismatch and the separately recorded Python linker limitation. The expected outcome is that semantic token correctness is unchanged while repeated workspace validation and language-specific resolver setup are eliminated within a request and other LSP requests remain responsive.

## Context and Orientation

`src/lsp/server.rs` reads JSON-RPC requests on one LSP loop. Most requests currently execute synchronously in `handle_request`; references and RQL query execution are exceptions that reserve a bounded `RequestJobs` slot, clone the workspace with an immutable overlay snapshot, and send their response from a worker thread. The client may cancel a reserved job with the standard `$/cancelRequest` notification.

`src/lsp/handlers/semantic_tokens.rs` reads the current document, emits declaration tokens, collects tree-sitter reference candidates, and resolves all unresolved candidates through `resolve_definition_batch_with_source`. A semantic token is a small protocol record that tells the editor where a named declaration or reference appears and which style to apply.

`src/analyzer/usages/get_definition/mod.rs` owns `DefinitionBatchContext`, the reusable state for every batch of definition lookups. Its Rust branch dispatches to `src/analyzer/usages/get_definition/rust.rs`, which performs structured AST-based receiver and type inference. `RustTypeLookupCache` stores a parsed declaration source by `ProjectFile`; it must remain local to the batch because its tree nodes borrow the cached source.

The same context now owns immutable per-file facts for the other targets where semantic tokens may resolve many references in one document. JS/TS uses a shared `ImportBinder`, `AliasResolver`, and receiver syntax index; Go lends cached package and import namespaces to its structured resolver; Scala reuses package and import facts to construct its forward name resolver. These values are still scoped to one definition batch.

`src/analyzer/i_analyzer.rs::AnalyzerQueryScope` marks one top-level analyzer request. `TreeSitterAnalyzer` maintains `QueryReadCache` for that lifetime. Its `analyzed_live_files()` implementation in `src/analyzer/tree_sitter_analyzer.rs` filters the live filesystem snapshot to the adapter language and asks the SQLite analyzer store which `(OID, language)` entries are complete at the active generation. That SQLite query performs intentional integrity validation and is expensive for hundreds of files, so only the result—not the validation rules—should be memoized for the active scope.

`tests/bifrost_lsp_server.rs` drives the real LSP binary via `tests/common/lsp_client.rs`. It is the appropriate end-to-end home for a test that sends semantic tokens and another LSP request without waiting for the first response. Rust definition-batch unit tests live beside `src/analyzer/usages/get_definition/mod.rs`; analyzer query-cache tests live beside `src/analyzer/tree_sitter_analyzer.rs`.

## Plan of Work

First, extend `QueryReadCache` with an optional analyzed-live-files value. Clear it with the other request-local values in both outermost `begin` and final `end`. Add a helper that returns a clone only when a query is active and records the result only while active. Change `TreeSitterAnalyzer::analyzed_live_files()` to use that helper after computing its existing sorted, deduplicated vector. Add a test that establishes one `AnalyzerQueryScope`, invokes the broad file enumeration repeatedly, and proves the store-presence enumeration runs once; after the scope ends, a new request must recompute.

Second, give `DefinitionBatchContext` a `RustTypeLookupCache`. Change the Rust resolution boundary so `resolve_rust` receives `&mut RustTypeLookupCache` rather than creating one itself. Thread the context cache through all existing definition-batch entry points without changing their public result shape. Add a Rust fixture with repeated member references that require return-type or field type lookup, and assert the batch still resolves every reference while declaration source parsing occurs once per owner file. If the existing cache has no test counter, add a narrow test-only counter at the cache boundary rather than timing the test.

Third, make `semantic_tokens::handle` accept a `CancellationToken` and return `Result<SemanticTokensResult, RequestCancelled>`. Check cancellation before costly stages and use `resolve_definition_batch_with_source_and_cancellation` for the candidate batch. In `src/lsp/server.rs`, route `SemanticTokensFullRequest::METHOD` before the synchronous dispatch and implement a semantic-token worker using the same reserve/snapshot/cancellation/response lifecycle as references. It must release the job ID and slot on every exit, return `RequestCanceled` if cancelled, and preserve all existing token responses for non-cancelled work. Add an integration test that sends a semantic-token request without reading its response, immediately sends Rune IR, and proves the Rune response is available before the token response; also add cancellation coverage if a deterministic slow token fixture can be built without wall-clock-sensitive assertions.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/8581/bifrost`.

1. Implement the cache and Rust batch changes, then run:

        cargo fmt --check
        cargo test --features nlp,python analyzer::tree_sitter_analyzer::tests::
        cargo test --features nlp,python analyzer::usages::get_definition::tests::

   The focused tests must show the new scope/batch regression tests passing.

2. Implement the LSP worker and integration test, then run:

        cargo test --features nlp,python --test bifrost_lsp_server semantic_tokens

   The existing language, overlay, unsupported-file, and Go-budget token tests must pass along with the new responsiveness test.

3. Run the Rust quality gates with isolated temporary artifacts:

        cargo fmt
        scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
        scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

## Validation and Acceptance

The focused cache test must demonstrate that multiple calls to `analyzed_live_files()` inside one `AnalyzerQueryScope` issue one complete store-presence validation, and a later scope does not reuse stale state. The Rust batch test must demonstrate that repeated references remain correct and reuse parsed declaration state. The LSP test must demonstrate that a pending semantic-token request does not stop `bifrost/runeIr` from being handled. Existing token classifications must remain unchanged, and a cancelled request must return the LSP request-cancelled error rather than a token result.

## Idempotence and Recovery

The cache is cleared automatically when the final nested query scope ends, so rerunning the same request never carries data into a later analyzer generation. Worker setup reserves its request ID before spawning; spawn failures must remove the reservation and return a normal internal-error response. Focused tests create temporary projects and can be rerun safely. The isolated Cargo helper removes its target directory on every normal, failed, or interrupted completion.

## Artifacts and Notes

Issue #850's observed production-like reproduction reports a 131,896 ms `semanticTokens/full` request followed by a 17 ms Rune IR request. The implementation must avoid adding a source-text fallback: token candidates, Rust resolution, and the cache remain tree-sitter/analyzer-store based.

## Interfaces and Dependencies

At completion, `QueryReadCache` in `src/analyzer/tree_sitter_analyzer.rs` must retain an optional `Vec<ProjectFile>` for the active `AnalyzerQueryScope` and expose private clone/retain helpers. `DefinitionBatchContext` in `src/analyzer/usages/get_definition/mod.rs` must own:

    rust_type_cache: RustTypeLookupCache

The Rust resolver in `src/analyzer/usages/get_definition/rust.rs` must accept that cache by mutable reference:

    pub(super) fn resolve_rust(..., cache: &mut RustTypeLookupCache) -> DefinitionLookupOutcome

The semantic token handler must accept `&CancellationToken` and return a cancellation-aware result. The LSP server must use its existing `RequestJobs`, `ActiveRequestIds`, `WorkspaceAnalyzer::clone_with_project`, `RequestContext`, and `finish_cancellable_request` interfaces; no new runtime or thread pool dependency is needed.

Plan created on 2026-07-17 after diagnosing issue #850; updated after implementing the Rust caches/worker plumbing and the corresponding JS/TS, Go, and Scala batch-state reuse, with local all-features and Python-linker validation limitations recorded for a future rerun.
