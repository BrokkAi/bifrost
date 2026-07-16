# Surface analyzer-store and watcher initialization failures

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost currently treats some failures as ordinary empty states. If a persisted SQLite analyzer query fails, definition and usage tools can report that nothing was found. If the operating-system file watcher cannot start, a service configured for automatic updates can continue without observing later file changes. These responses look healthy even though the workspace is degraded.

After this change, persisted-store opening and query failures will reach the tool or initialization boundary with their original context, and a service configured to watch files will fail construction or workspace activation when its watcher cannot start. Successful empty lookups, analyzers that do not support a capability, and deliberate `UpdateStrategy::Manual` operation will remain valid. A failed workspace activation will leave the previous workspace usable. The behavior will be observable through deterministic tests that inject storage and watcher failures rather than relying on host-specific permissions or watcher exhaustion.

## Progress

- [x] (2026-07-16 14:06Z) Fetched `origin`, confirmed the issue branch is clean and identical to `origin/master`, and read issue #695 and its current comments.
- [x] (2026-07-16 14:06Z) Diagnosed the current analyzer and watcher paths, including the July 14 change that made failed lazy-index builds retryable without making them reportable.
- [x] (2026-07-16 14:06Z) Ran the focused stale-generation lazy-index test and confirmed that current behavior returns empty fallbacks while leaving the `OnceLock` values unset.
- [x] (2026-07-16 14:06Z) Chose request-context error reporting for resultless analyzer compatibility methods, fallible persisted workspace construction, and fallible watcher-backed session construction.
- [x] (2026-07-16 14:28Z) Implemented per-request analyzer failure contexts, preserved retryable lazy-index fallbacks while recording their errors, made persisted workspace construction fallible, and propagated construction errors through runtime callers.
- [x] (2026-07-16 14:28Z) Added healthy-miss, unsupported-analyzer, stale direct-definition, stale lazy-index, and broken-cache-path coverage. The isolated `nlp,python` analyzer-persistence suite passes all 39 tests with the required macOS PyO3 dynamic-lookup flags.
- [x] (2026-07-16 14:29Z) Committed the reviewed analyzer/store milestone as `88bb1d3a` (`fix: surface persisted analyzer failures`).
- [x] (2026-07-16 14:36Z) Replaced optional watcher state with explicit disabled/active state, injected watcher startup per service, made eager/lazy/deferred session assembly fallible, retained lazy/deferred failures, and made workspace activation transactional.
- [x] (2026-07-16 14:36Z) Passed five deterministic watcher-failure tests, all 12 service unit tests, both real polling-watcher tests, and all six activation integration tests; the linked-worktree activation tests required access to the primary checkout's shared `.brokk` cache.
- [x] (2026-07-16 14:37Z) Committed the reviewed watcher/session milestone as `70bcb14c` (`fix: fail watcher-backed session startup`).
- [x] (2026-07-16 15:01Z) Closed every reportable SearchTools boundary over the analyzer query context and added a real multi-language service regression proving stale definition and symbol-search queries return `Internal` instead of false-empty success.
- [x] (2026-07-16 15:01Z) Fixed the specialist-review findings: serialized concurrent lazy initialization, recorded the remaining store-backed search/declaration/hydration failures, and propagated analyzer epoch-publication failures instead of panicking. Both reviewing agents confirmed no high or critical findings remain in those scopes.
- [x] (2026-07-16 15:01Z) Passed `cargo fmt --all`, `cargo check --all-targets`, the deterministic epoch-publication regression, both analyzer failure-boundary tests, and all 15 `searchtools_service::` unit tests.
- [x] (2026-07-16 15:41Z) Passed isolated `cargo clippy --all-targets --all-features -- -D warnings` and the complete `cargo test --features nlp,python` suite. The full suite required external host access for process-spawn, uv-cache, GPG, and linked-worktree tests; its final isolated run exited successfully and removed its target.
- [x] (2026-07-16 15:41Z) Passed `cargo fmt --all -- --check` and `git diff --check`, inspected the final changed-file list and issue diff, and confirmed only issue-plan and implementation files remain modified for the final checkpoint.
- [x] (2026-07-16 15:41Z) Committed the reviewed final milestone on the issue branch after all gates passed.
- [x] (2026-07-16 16:19Z) Guided review found that broadcasting a store failure to every overlapping context could fail an unrelated request and expose another request's symbol or path. Replaced shared query caches with lightweight request-local analyzer clones, retained single-flight successful merged indexes without publishing failed builds, and added deterministic overlap, cache-reuse, failed-publication, and concurrent-first-use regressions.
- [x] (2026-07-16 16:29Z) Passed all 17 SearchTools service unit tests, the focused multi-analyzer tests, `cargo fmt --all -- --check`, `git diff --check`, isolated warnings-denied all-target/all-feature clippy, and the complete isolated `cargo test --features nlp,python` suite. Final architecture and operational re-review found no remaining actionable issues.

## Surprises & Discoveries

- Observation: The issue's original poisoned-cache description is no longer exact.
  Evidence: `TreeSitterAnalyzer::try_global_usage_definition_index_handle` now sets its `OnceLock` only after a successful `Result`, and `stale_lazy_index_builds_return_fallback_without_poisoning_once_locks` proves a failed build is retryable. The surrounding compatibility accessor still discards the `StoreError` and returns an empty fallback.

- Observation: Direct definition queries still erase storage errors independently of the lazy global index.
  Evidence: `TreeSitterAnalyzer::sql_definition_candidates_vec` calls `candidates.ok()?`, and `IAnalyzer::definitions` exposes the resulting `None` as an empty iterator.

- Observation: Persistent store creation has an earlier silent degradation path not called out in the issue's suggested starting points.
  Evidence: `tree_sitter_analyzer.rs::store_context` calls `AnalyzerStore::open_for_workspace(root).or_else(|_| AnalyzerStore::open_in_memory())`, so an unusable workspace cache silently changes persistence semantics.

- Observation: The original watcher ExecPlan deliberately allowed startup failure and relied on explicit refresh.
  Evidence: `.agents/plans/project-change-watcher-execplan.md` describes the watcher as optional runtime state. Issue #695 supersedes that decision for `UpdateStrategy::WatchFiles` because a watching service must not present itself as automatically current when startup failed.

- Observation: Bifrost's structured code-intelligence MCP tools were not exposed in this Codex session.
  Evidence: diagnosis and planning used `rg`, exact source reads, focused tests, blame, and git history instead of `search_symbols` and `scan_usages_by_location`.

- Observation: On this macOS host, `cargo test --features nlp,python` requires dynamic lookup for PyO3 extension-module symbols.
  Evidence: the first isolated run failed at link time on unresolved `_Py*` symbols. Repeating it with `RUSTFLAGS='-Clink-arg=-undefined -Clink-arg=dynamic_lookup'` and `BIFROST_SEMANTIC_INDEX=off` linked and passed all 39 analyzer-persistence tests. This matches existing repository ExecPlan guidance for the same host.

- Observation: The shell initially resolved a non-rustup compiler whose metadata was incompatible with cached dependencies, and an interrupted isolated clippy build exhausted the filesystem.
  Evidence: the first clippy attempt failed with Rust `E0514`; pinning `PATH` to `/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin` fixed the toolchain mismatch. `scripts/cleanup-bifrost-tmp.sh --apply --include-unmanaged` then removed reviewed stale build targets and restored more than 40 GiB before validation resumed.

## Decision Log

- Decision: Report analyzer storage failures through an explicit context owned by each top-level query instead of changing every best-effort `IAnalyzer` method to return `Result`.
  Rationale: Empty results are legitimate for unsupported analyzers and successful misses, while converting the entire analyzer trait and hundreds of semantic call sites would obscure the narrow failure boundary. A query context preserves existing internal APIs but prevents the service from returning a successful false-empty response after any affected store access failed.
  Date/Author: 2026-07-16 / Codex

- Decision: Give every SearchTools query a lightweight analyzer clone with independent request caches and record failures only in contexts registered on that clone.
  Rationale: Sharing active contexts across concurrent requests could fail a healthy request and disclose another request's symbol or path in the error. Clones continue sharing immutable runtime state and successfully published indexes, while request caches remain isolated so Rayon-backed work stays concurrent without cross-request attribution. Multi-analyzer merged-index construction checks the local request context before publishing, preventing a degraded request from poisoning the shared cache without rebuilding the whole index on every healthy request.
  Date/Author: 2026-07-16 / Codex

- Decision: Keep the existing empty lazy-index fallback only as an internal compatibility value, while recording its underlying error and leaving the `OnceLock` unset.
  Rationale: This retains the retry behavior added by generation-aware storage work and avoids a broad trait migration. The service-level query context ensures the fallback cannot escape as a successful tool response.
  Date/Author: 2026-07-16 / Codex

- Decision: Treat persistent store-open failure as part of issue #695 and remove the persistent-to-memory fallback.
  Rationale: Changing from a requested persisted analyzer to an in-memory analyzer is the same unobservable degraded-state problem. Transient builders remain intentionally in-memory and successful.
  Date/Author: 2026-07-16 / Codex

- Decision: Represent an installed session watcher as either `Disabled` or `Active`, with no installed `Failed` state.
  Rationale: `Manual` is a valid disabled mode. Under `WatchFiles`, failure to start the watcher should prevent session construction, so an installed watching session is always capable of observing changes.
  Date/Author: 2026-07-16 / Codex

- Decision: Fully construct a replacement workspace session before changing the active session or root.
  Rationale: Workspace activation is a transaction from the user's perspective. If analyzer-store opening or watcher startup fails, the previous snapshot, watcher, semantic indexer, and root must remain usable.
  Date/Author: 2026-07-16 / Codex

- Decision: Inject watcher startup through a per-service function object in tests.
  Rationale: A per-instance dependency can fail eager, lazy, deferred, and activation paths deterministically without relying on platform watcher limits or global mutable hooks that race under parallel tests.
  Date/Author: 2026-07-16 / Codex

- Decision: Serialize lazy workspace construction under the existing pending-build mutex.
  Rationale: Exactly one concurrent first request must publish the service's initialization outcome. Releasing the mutex before construction allowed a successful session and a retained failure to race, poisoning an otherwise usable service.
  Date/Author: 2026-07-16 / Codex

- Decision: Keep LSP analyzer scopes best-effort while isolating every overlapping SearchTools query through a request-local analyzer clone.
  Rationale: This issue's reportable contract is the SearchTools service boundary; LSP callers remain best-effort. Request-local clones preserve concurrent and Rayon-backed analysis while ensuring only the query that observes a degraded store can fail at the service boundary.
  Date/Author: 2026-07-16 / Codex

## Outcomes & Retrospective

Milestone 1 prevents persisted analyzer construction from silently degrading to memory and retains the failed database path in its error. Store-backed definition, path-module, global-definition-index, and usage-facts compatibility paths record their first `StoreError` in every active request context without poisoning their retryable lazy cells. Healthy missing symbols and unsupported analyzers still return empty results without an error.

Milestone 2 makes every production `WatchFiles` session contain a successfully started watcher. Eager construction fails immediately; lazy and deferred construction retain the failure so repeated calls remain explicit; manual construction never invokes the starter. Activation now builds the analyzer, starts the candidate watcher, and prepares semantic state before replacing the session and root. An injected activation failure leaves both the old root and a real `list_symbols` query intact.

Milestone 3 closes the main tool dispatch, direct code-query, refreshed symbol-source, and semantic snapshot paths over one shared request context. Store failures from definition lookup, symbol search, declaration scans, hierarchy lookup, file/import hydration, and lazy derived indexes now reach that boundary. Analyzer epoch publication is fallible through every persisted language wrapper, and concurrent lazy service startup publishes exactly one outcome. Guided review identified and fixed cross-request failure attribution: SearchTools requests now use isolated query caches, while successfully built immutable indexes remain shared and single-flight and failed merged-index builds remain local and retryable. Final specialist re-review found no actionable issue. Formatting, warnings-denied all-feature clippy, and the complete `nlp,python` suite pass. All three milestones and the review follow-up are complete on the issue branch.

## Context and Orientation

`src/analyzer/store/mod.rs` owns `AnalyzerStore` and `StoreError`. Store methods already return `Result<T, StoreError>` with SQLite, filesystem, Git, deserialization, and stale-generation context. The information is lost above this layer.

`src/analyzer/tree_sitter_analyzer.rs` implements store-backed analyzer operations. `QueryReadCache` currently tracks a nesting depth plus request-lived OID and hydrated-file caches. The resultless `IAnalyzer` compatibility surface lives in `src/analyzer/i_analyzer.rs`; concrete language wrappers forward its query lifecycle methods to their inner `TreeSitterAnalyzer`. `src/analyzer/multi_analyzer.rs` fans lifecycle calls out to all active language delegates, and `src/analyzer/workspace.rs` is the service-facing wrapper.

A query context in this plan means a thread-safe object created for one top-level tool or LSP request. It remembers the first analyzer storage error observed while that request is active. SearchTools creates a lightweight analyzer clone per request, so each tree-sitter analyzer keeps only contexts using that request's cache. When a store-backed compatibility method must return an empty fallback, it records the contextualized `StoreError` into the active context on that clone. LSP callers may continue to use best-effort results, but `SearchToolsService` must inspect the context before returning a successful tool response.

`src/searchtools_service.rs` owns `SearchToolsService`, `WorkspaceSession`, `WorkspaceQueryScope`, and `UpdateStrategy`. A `WorkspaceSession` currently stores `watcher: Option<ProjectChangeWatcher>`. `maybe_start_watcher` maps `ProjectChangeWatcher::start` through `.ok()`, so `None` represents both deliberate manual mode and failed automatic startup. `assemble_session` is consequently infallible, and that assumption reaches eager, transient, lazy, deferred, and workspace-activation paths.

`src/project_watcher.rs` already returns contextual errors for watcher creation, configuration, and per-path registration. No change to the public watcher behavior is required; the service must stop discarding those errors.

## Plan of Work

### Milestone 1: Surface persisted analyzer failures

Add `AnalyzerQueryContext` in `src/analyzer/i_analyzer.rs`. It should own a mutex-protected first `StoreError`, expose crate-internal record and inspect methods, and be shareable through `Arc`. Change `IAnalyzer::begin_query` and `end_query` to accept the same shared context. Default implementations remain no-ops, which preserves legitimate unsupported and empty analyzers. Update `AnalyzerQueryScope`, `WorkspaceAnalyzer`, `MultiAnalyzer`, and every language wrapper that currently forwards the no-argument lifecycle methods.

In `TreeSitterAnalyzer`, replace `QueryReadCache::depth` with explicit active contexts or add an adjacent context collection while preserving the existing nested cache lifetime. Beginning a query registers the context and clears request caches only on the first active context; ending it removes that exact context using `Arc::ptr_eq` and clears caches when none remain. SearchTools must clone the workspace analyzer at the request boundary so overlapping requests do not share this cache. Add a helper that attaches the operation name to a `StoreError` and records the first failure into the active context.

Make the internal definition candidate family result-bearing: `sql_definition_candidates_vec`, `sql_definitions_vec`, and `sql_bounded_definitions_vec` should return `Result<Vec<CodeUnit>, StoreError>` rather than using `Option` for both failure and absence. The resultless `IAnalyzer::definitions` adapter may retain an empty compatibility fallback only after recording the error. Apply the same explicit match-and-record behavior to `global_usage_definition_index_handle` and `usage_facts_index_handle`; do not initialize their `OnceLock` values on failure. Audit the store-backed helpers used by these three families and replace only equivalent `StoreError`-to-empty conversions. Do not convert parsing, filesystem discovery, unsupported-language behavior, or semantic best-effort resolution into storage failures.

Make `persistent_store_context` return `Result<AnalyzerStoreContext, StoreError>` and remove its fallback to `AnalyzerStore::open_in_memory`. Change `WorkspaceAnalyzer::build_persisted` and `build_persisted_with_progress` to return results. Propagate contextual failures through `src/searchtools_service.rs` and other runtime callers such as the LSP server, commit analysis, and reference differential binary. Update test-only builder call sites with explicit `expect` or `?`. Keep `default_store_context`, `WorkspaceAnalyzer::build`, and other explicitly transient construction paths in-memory.

Milestone acceptance is a deterministic stale-generation query whose compatibility method returns its temporary fallback internally but whose query context contains the original store failure, with both lazy `OnceLock` values still unset. A healthy missing symbol and an unsupported or zero-language workspace must complete with an empty result and no recorded error. A Git workspace whose `.brokk` path is a regular file must make persisted workspace construction fail with contextual storage information instead of silently selecting memory storage.

After focused tests pass, update this ExecPlan and commit only the plan and analyzer/store files changed for this milestone. The commit message body should explain why request contexts were chosen over a repository-wide `Result` migration.

### Milestone 2: Make watcher-backed sessions fallible and activation transactional

In `src/searchtools_service.rs`, define a private `SessionWatcher` with `Disabled` and `Active(ProjectChangeWatcher)` variants. Replace `WorkspaceSession.watcher: Option<_>` with this type and update `apply_watcher_delta` to do nothing only for `Disabled`.

Store a watcher starter on each `SearchToolsService`, using an `Arc<dyn Fn(Arc<dyn Project>) -> Result<ProjectChangeWatcher, String> + Send + Sync>` or an equivalently small private trait. Production constructors install `ProjectChangeWatcher::start`; unit tests can install a closure that returns a distinctive error and optionally increments an `AtomicUsize`.

Replace `maybe_start_watcher` with a result-bearing helper. `UpdateStrategy::Manual` must return `Ok(SessionWatcher::Disabled)` without calling the starter. `UpdateStrategy::WatchFiles` must call the starter and return `Active` or a contextual error. Change `assemble_session` to return `Result<WorkspaceSession, String>` and propagate it through eager and transient constructors, `new_manual_for_project`, lazy `ensure_ready`, and the deferred build thread. Deferred and lazy failures should be retained in `build_error` so repeated requests remain explicit rather than hanging or constructing a watcherless session.

Refactor `handle_activate_workspace` to build the persisted analyzer, watcher, and semantic state for a candidate `WorkspaceSession` before replacing the existing session or root. Start the watcher before the semantic indexer so watcher failure cannot leave an orphan background indexer. Map startup failure to an internal service error that includes the underlying `ProjectChangeWatcher::start` context. Keep invalid workspace paths as invalid-parameter errors. Only after the candidate is complete should the method replace the session, update the root, and close the old semantic state.

Milestone acceptance requires injected watcher failure tests for eager, lazy, deferred, and activation paths. Manual construction must succeed with the same failing starter, prove the starter was not invoked, and remain queryable. Failed activation must leave `get_active_workspace`, `active_workspace_root`, and a real query pointed at the previous workspace. Existing real polling-watcher success tests remain the platform integration proof.

After focused tests pass, update this ExecPlan and commit only the plan and service/watcher files changed for this milestone. The commit body should explain the explicit disabled-versus-active state and transactional activation rule.

### Milestone 3: Close every reportable boundary and complete repository gates

Give `WorkspaceQueryScope` an `Arc<AnalyzerQueryContext>` and a consuming `finish` operation. `finish` should preserve any handler error already returned; otherwise it should turn a recorded store failure into `SearchToolsServiceError::internal` with the operation and underlying `StoreError` text. `Drop` remains responsible for unregistering the context on early returns and panics.

Route the main `call_tool_output` dispatch, the special `get_symbol_sources` retry path, semantic snapshot queries, and the direct code-query result entry point through `finish`. Add a service behavior test that invalidates a test analyzer generation, invokes a real definition- or usage-facing tool, and observes an internal error rather than a successful empty payload. Add multi-language coverage proving that one delegate's error reaches the shared workspace context. Do not change successful no-match response shapes.

Run focused tests, formatting, all-target/all-feature clippy, and the complete `nlp,python` test suite. Inspect `git diff --check`, the final changed-file list, and the diff against `origin/master`. Perform a specialist review over the complete issue diff as required by the guided-issue workflow; triage and fix every critical or high finding before considering the implementation complete. Update the living sections of this plan with exact commands and outcomes, then commit the reviewed final milestone without staging unrelated files.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/8480/bifrost`.

First implement and validate the analyzer/store milestone:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --lib stale_lazy_index_builds
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test analyzer_persistence

Then implement and validate watcher-backed sessions:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --lib searchtools_service::tests
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test project_change_watcher_test

Finally run the repository gates:

    cargo fmt --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    git diff --check
    git status --short

Focused test filters may be refined to exact new test names as implementation proceeds. Record those names and their passing output in `Progress` and `Artifacts and Notes`. The full suite must include `--features nlp,python`; a featureless `cargo test` is not an acceptable final gate.

## Validation and Acceptance

Acceptance is behavioral.

A deterministic persisted-store open failure must make persisted workspace construction fail with the original storage context. It must never create a healthy-looking in-memory substitute. Explicit transient construction must still work.

A deterministic persisted query failure must make a real tool call return an internal error containing the underlying `StoreError` context. The same failure must not initialize the global definition or usage-facts `OnceLock`. A later successful build remains possible on a fresh valid query. Healthy queries with no matches and analyzers without the relevant capability must still return their existing successful empty responses.

An injected watcher startup failure must fail every `WatchFiles` construction mode: eager construction immediately, lazy construction on its first query, deferred construction through readiness, and workspace activation at the activation call. Repeated accesses after deferred or lazy failure must report the stored failure. Manual mode must remain successful and must not call the watcher starter.

Failed workspace activation must leave the prior workspace and watcher installed. The active-root API and a real symbol query must continue to observe the old workspace. Successful activation and existing real watcher change-detection tests must continue to pass.

Formatting, all-target/all-feature clippy with warnings denied, all focused tests, and the complete `nlp,python` test suite must pass. No unrelated files may be staged or committed.

## Idempotence and Recovery

All tests use temporary workspaces and per-service injected dependencies, so they are safe to repeat and parallelize. Use `scripts/with-isolated-cargo-target.sh` for builds that need isolation; it removes its target directory on success, failure, or interruption. Do not create manually named Cargo target directories under `/tmp` or `/private/tmp`.

The implementation should be additive until each call site compiles: introduce the query context before changing lifecycle signatures, introduce result-bearing persisted builders before removing the fallback, and introduce `SessionWatcher` plus the starter before making `assemble_session` fallible. If a milestone fails partway, keep the uncommitted files, update `Progress` with the exact stopping point, and rerun the focused command after repair. Do not use `git reset --hard` or discard unrelated worktree changes.

During implementation, commit only after each milestone's focused validation and post-milestone review. Stage files explicitly by name. If a later milestone exposes a design flaw, revise this ExecPlan's `Decision Log` before changing course.

## Artifacts and Notes

The analyzer milestone proof is:

    test analyzer::tree_sitter_analyzer::tests::stale_lazy_index_builds_return_fallback_without_poisoning_once_locks ... ok
    test analyzer::tree_sitter_analyzer::tests::stale_definition_query_records_failure_while_healthy_miss_does_not ... ok
    test analyzer::workspace::tests::unsupported_analyzer_query_remains_a_healthy_empty_result ... ok
    test persisted_build_reports_cache_open_failure ... ok
    test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

The feature-enabled persistence command that passes on this macOS host is:

    env RUSTFLAGS='-Clink-arg=-undefined -Clink-arg=dynamic_lookup' BIFROST_SEMANTIC_INDEX=off scripts/with-isolated-cargo-target.sh cargo test --features nlp,python --test analyzer_persistence

The watcher milestone proof is:

    cargo test --lib watcher_startup_tests
    test result: ok. 5 passed; 0 failed; 0 ignored

    cargo test --lib searchtools_service::
    test result: ok. 12 passed; 0 failed; 0 ignored

    cargo test --test project_change_watcher_test
    test result: ok. 2 passed; 0 failed; 0 ignored

    cargo test --test searchtools_service activate_workspace
    test result: ok. 6 passed; 0 failed; 0 ignored

The final service-boundary and initialization proof is:

    cargo test --lib searchtools_service::
    test result: ok. 15 passed; 0 failed; 0 ignored

    test analyzer::tree_sitter_analyzer::tests::persisted_epoch_publication_failure_is_returned_from_analyzer_construction ... ok
    test searchtools_service::analyzer_failure_boundary_tests::multi_language_store_failure_replaces_false_empty_tool_success ... ok
    test searchtools_service::watcher_startup_tests::concurrent_lazy_first_use_publishes_one_session_outcome ... ok

The final repository gates are:

    env PATH=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin:$PATH scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile; exit 0

    env PATH=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin:$PATH RUSTFLAGS='-Clink-arg=-undefined -Clink-arg=dynamic_lookup' BIFROST_SEMANTIC_INDEX=off scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    Doc-tests brokk_bifrost: ok; command exit 0; isolated target removed

The source proof for watcher failure erasure is:

    UpdateStrategy::WatchFiles => ProjectChangeWatcher::start(project).ok(),
    UpdateStrategy::Manual => None,

Replace these artifacts during implementation with the new focused test names and short passing transcripts.

## Interfaces and Dependencies

No new external dependency is required. Reuse `StoreError`, `ProjectChangeWatcher`, `SearchToolsServiceError`, `Arc`, `Mutex`, and the existing workspace/query lifecycle.

In `src/analyzer/i_analyzer.rs`, provide a crate-internal context with this conceptual interface:

    pub(crate) struct AnalyzerQueryContext { ... }

    impl AnalyzerQueryContext {
        pub(crate) fn record(&self, error: StoreError);
        pub(crate) fn error(&self) -> Option<StoreError>;
    }

    pub trait IAnalyzer {
        fn begin_query(&self, context: Arc<AnalyzerQueryContext>) {}
        fn end_query(&self, context: &Arc<AnalyzerQueryContext>) {}
        ...
    }

Exact visibility may be adjusted to satisfy the public trait's visibility rules, but the context must not become a user-facing protocol type.

In `src/analyzer/tree_sitter_analyzer.rs`, the internal definition candidate methods must return `Result<Vec<CodeUnit>, StoreError>`. The compatibility trait methods may retain their existing resultless signatures only while recording failures into the active request context.

In `src/analyzer/workspace.rs`, persisted builders must return `Result<WorkspaceAnalyzer, StoreError>` or a repository-standard contextual wrapper that retains `StoreError`. Transient builders remain infallible except for their existing project setup boundaries.

In `src/searchtools_service.rs`, provide these conceptual private types and results:

    enum SessionWatcher {
        Disabled,
        Active(ProjectChangeWatcher),
    }

    type WatcherStarter = Arc<
        dyn Fn(Arc<dyn Project>) -> Result<ProjectChangeWatcher, String> + Send + Sync
    >;

    fn assemble_session(...) -> Result<WorkspaceSession, String>;

`WorkspaceQueryScope::finish` must accept the handler's `Result<ToolOutput, SearchToolsServiceError>` and return the same type after checking the analyzer context, or use an equivalent generic helper that cannot accidentally skip the check.

Revision note (2026-07-16): Created this ExecPlan after validating issue #695 against current `origin/master`. It records the partial July 14 retryability fix, brings persistent-store opening into the failure-surfacing scope, and chooses explicit analyzer query contexts plus fallible watcher-backed sessions so implementation can preserve legitimate empty and manual states.
