# Analyze exact Git tree snapshots for `analyze_diff`

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain it under `.agents/PLANS.md`.

## Purpose / Big Picture

`analyze_diff` compares commits, Git tree snapshots, and the live checkout. Review clients can compare two exact Git trees captured at a boundary, including files that were untracked at the time, without later checkout, index, or attributes changes affecting immutable comparisons. A host launches Bifrost with a trusted private Git object store and passes only object IDs through the tool interface; the real CLI test demonstrates that a tree-to-tree comparison ignores destructive later worktree changes.

## Progress

- [x] (2026-07-27 00:00Z) Read repository execution-plan and implementation instructions; inspected the current diff engine and service call path.
- [x] (2026-07-27 00:00Z) Implemented one resolved endpoint model, trusted alternate ODB configuration, bare immutable repository path, and private snapshot export.
- [x] (2026-07-27 00:00Z) Added public-path snapshot-tree/alternate/immutability tests and focused Unix permission coverage.
- [x] (2026-07-27 00:00Z) Validated milestone 1 with `cargo fmt --check`, `git diff --check`, all-feature clippy, and the current `diff_analysis_test` suite after fixing needless borrows at the `diff_metadata` and `RevisionImage::materialize` call sites.
- [x] (2026-07-27 00:00Z) Added `--diff-snapshot-object-dir PATH`, launch-time absolute-path/directory validation, and mode guards that restrict it to one-shot `--tool` and MCP server launches.
- [x] (2026-07-27 00:00Z) Threaded the trusted directory into one-shot and stdio MCP `SearchToolsService` construction before the MCP service is wrapped in `Arc`.
- [x] (2026-07-27 00:00Z) Updated `analyze_diff` schema/help and the published CLI/MCP documentation without adding a tool argument for a filesystem path.
- [x] (2026-07-27 00:00Z) Added real-binary CLI coverage for inaccessible alternate trees, immutable tree results after live-worktree mutation, and an incompatible-mode rejection; ran focused CLI, diff, MCP, and service tests.
- [x] (2026-07-27 00:00Z) Ran final `cargo fmt --check`, `git diff --check`, and `cargo clippy --all-targets --all-features -- -D warnings` successfully.
- [x] (2026-07-27 00:00Z) Review pass: replaced the tautological `large_callsite_symbols` assertion with a fixture that actually trips the callsite cap, added the missing added-file assertions, de-degenerated the add/delete fixture, and corrected the stale `RevisionImage` doc comment.
- [x] (2026-07-27 00:00Z) Covered the last unexercised endpoint combination: a tree `base` with no `target`, which resolves a snapshot-only object through the alternate while diffing against the live working tree.

## Surprises & Discoveries

- Observation: The current base endpoint is an `Oid` interpreted only as a commit, while only the target can be a worktree.
  Evidence: `src/diff_analysis.rs` resolves `base_oid` through `resolve_commit` and `diff_metadata` calls `find_commit(base_oid)`.
- Observation: Opening the live Git directory as bare alone did not prevent libgit2's tree diff from honoring a staged or working-tree `.gitattributes` change.
  Evidence: `analyze_diff_tree_endpoints_are_immutable_and_require_an_explicit_base` changed from `loc_changed: 2` to `loc_changed: 0` after `*.go -diff` was written and staged. The isolated repository avoids the live Git directory's index and attributes entirely while using the original objects only as an ODB alternate.
- Observation: the current `diff_analysis_test` suite reports 17 tests, despite the earlier milestone handoff describing 18.
  Evidence: `BIFROST_SEMANTIC_INDEX=off cargo test --test diff_analysis_test` reported `17 passed; 0 failed`.
- Observation: `Option::map_or(service, |dir| service.with_...(dir))` cannot express an optional consuming builder because it moves `service` into both the eager default and closure.
  Evidence: Rust emitted E0382 during the first CLI test build; an explicit `match` compiles and preserves the consuming builder semantics.
- Observation: the immutable endpoint test initially changed `.gitattributes` and then staged it before its only rerun, leaving the worktree-only metadata path unproven.
  Evidence: the test now compares the original result once after the unstaged attributes write and again after `git add`; both comparisons pass.
- Observation: `assert!(result["large_callsite_symbols"].is_array())` proved nothing. `DiffAnalysisResult::large_callsite_symbols` is a `Vec`, so it serializes as an array even when truncation never runs.
  Evidence: the assertion passed against a fixture with two trivial functions and zero callsites. The test now generates 1200 calls to one callee — above `analyzer::usages::inverted_edges::MAX_CALLSITES` (1000) — and asserts a notice for `Target` whose `total_callsites` exceeds its reported `limit`.
- Observation: a small add/delete fixture can be swallowed by git's rename detection, hiding the very statuses a test means to prove.
  Evidence: with `delete.go` = `package sample\nfunc DeletedUntracked() {}` and `added.go` = `package sample\nfunc Added() {}`, `find_similar` paired them as `{"old_path":"delete.go","path":"added.go","status":"renamed"}`, so no file carried status `added`. This is correct Git similarity behavior, not an engine defect — the introduced symbol `sample.Added` was still reported correctly. The fixture now gives the two files clearly dissimilar bodies, so the intended `old.go`→`new.go` rename still fires while add and delete stay distinct.

## Decision Log

- Decision: Resolve each explicit spelling by peeling to a commit before trying to peel to a tree.
  Rationale: A commit is also peelable to its tree. Tree-first resolution would lose commit identity and produce an incorrect `tree:` endpoint label.
  Date/Author: 2026-07-27 / Eitri.
- Decision: Keep the snapshot object directory out of `AnalyzeDiffParams`; carry it in a non-deserializable `DiffAnalysisOptions` and immutable `SearchToolsService` builder configuration.
  Rationale: MCP arguments are untrusted and must never select an arbitrary host filesystem object database.
  Date/Author: 2026-07-27 / Eitri.
- Decision: For two immutable endpoints, create a private empty bare repository and attach both the source repository's `objects` directory and any configured snapshot directory as ODB alternates.
  Rationale: A bare handle opened on the live Git directory still shares that directory's index and attributes. A newly initialized bare repository has neither a worktree nor an index; it can resolve committed and snapshot objects through explicit alternates without consulting live metadata.
  Date/Author: 2026-07-27 / Eitri.
- Decision: Restrict `--diff-snapshot-object-dir` to `--tool` and MCP server modes.
  Rationale: These are the only launch surfaces that create a `SearchToolsService` able to dispatch `analyze_diff`; LSP, REPL, saved-query, policy, and skill-install modes do not need or safely consume this trusted object-store configuration.
  Date/Author: 2026-07-27 / Eitri.
- Decision: Canonicalize the configured snapshot path and reject absent or non-directory paths before a tool or MCP service starts.
  Rationale: A trusted launch configuration must not depend on later process working-directory interpretation or leave a server that fails only when a request reaches `analyze_diff`.
  Date/Author: 2026-07-27 / Eitri.
- Decision: Apply `SearchToolsService::with_diff_snapshot_object_dir` before `Arc::new` in `run_stdio_server`.
  Rationale: The object store is immutable host configuration for the server lifetime, not mutable request state; requests cannot change it once the shared service exists.
  Date/Author: 2026-07-27 / Eitri.
- Decision: Assert immutable tree comparisons after both unstaged and staged `.gitattributes` mutations.
  Rationale: The private bare repository must avoid both live worktree configuration and index-derived metadata, and the two independent assertions prove each boundary.
  Date/Author: 2026-07-27 / Eitri.

## Outcomes & Retrospective

Both milestones are implemented and validated. The engine resolves commit-or-tree endpoints through isolated immutable repositories when appropriate, and the CLI/MCP hosts can attach a trusted snapshot object directory only at launch. The public schema and documentation describe the unified endpoint contract without adding a path argument. The main lesson is that object reachability and snapshot immutability are separate concerns: alternates make private objects visible, while the private bare repository prevents live index and attributes metadata from affecting a comparison.

## Context and Orientation

`src/diff_analysis.rs` is the complete semantic diff engine. It obtains Git changes, exports changed endpoint files into temporary directories, builds throwaway analyzers, and returns serialized file and symbol effects. A Git tree is an immutable directory snapshot stored as a Git object; a commit points at a tree and may have parents. `src/searchtools_service.rs` deserializes MCP-style tool arguments and dispatches `analyze_diff`, so it is the trust boundary for host configuration. `tests/diff_analysis_test.rs` exercises the public service call path. Part 2 will update the CLI and MCP launch surfaces, but it must not add a path field to the tool arguments.

## Plan of Work

Milestone 1 replaces the asymmetric commit/worktree endpoint model with commit, tree, and worktree variants. Explicit endpoint resolution uses libgit2 object peeling, preserves commit labels, and rejects blobs and other unsuitable objects. Defaulting stays compatible for worktree and commit targets, while a target-only tree errors because it has no parent. `DiffAnalysisOptions` owns an optional trusted `PathBuf`; opening a repository validates and attaches the alternate object database before revision resolution.

When both endpoints are immutable, milestone 1 creates a freshly initialized private bare repository in a temporary directory. It attaches the source repository's `commondir()/objects` directory and any configured snapshot objects directory as object-database alternates, then uses that private repository for `diff_tree_to_tree` and blob export. `commondir()` is essential for linked worktrees: their `.git` is a file pointing at worktree-specific metadata, while the shared Git objects live in the common Git directory. The private repository has no live worktree or index, so neither can affect the result. Otherwise the engine retains worktree-with-index behavior. Tree and commit materialization both export regular blobs from their resolved tree. Unix exports create every temporary directory with mode `0700` and every blob with mode `0600`. The service receives a consuming `with_diff_snapshot_object_dir(PathBuf)` builder so process startup can configure it later without threading constructor arguments.

Milestone 1 adds public-path integration tests that create unreachable tree objects in a separate Git objects directory and prove interval semantics, alternate attachment, endpoint labels, bad-object errors, immutability against live content and attributes, and large results. A unit test observes export permissions while the temporary directory exists.

Milestone 2 adds `--diff-snapshot-object-dir PATH` only at trusted launch boundaries. The hand-written CLI parser lists it in `option_requires_value`, parses it beside `--root`, and validates/canonicalizes it only after rejecting incompatible dispatch modes. One-shot `run_tool` passes the optional absolute directory to `SearchToolsService::with_diff_snapshot_object_dir`. `run_stdio_server` accepts `Option<PathBuf>` and applies the builder to each deferred or unbound service before `Arc::new`; the compatibility launcher callers pass `None`. The schema/help and published docs describe commit-or-tree endpoint resolution, tree labels, target-only-tree rejection, immutable-pair isolation, and the launch-only snapshot-store requirement without ever adding a filesystem path property to `AnalyzeDiffParams`.

## Concrete Steps

Work from `/mnt/optane/bifrost-1191-mj-e2e`. Milestone 1 edits `src/diff_analysis.rs` and `src/searchtools_service.rs`. Milestone 2 edits `src/bin/bifrost.rs`, `src/mcp_common.rs`, the three compatibility MCP launchers, `src/mcp_slopcop.rs`, both published documentation pages, and `tests/bifrost_tool_cli.rs`. Run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test diff_analysis_test
    BIFROST_SEMANTIC_INDEX=off cargo test --lib diff_analysis
    BIFROST_SEMANTIC_INDEX=off cargo test --test bifrost_mcp_server
    BIFROST_SEMANTIC_INDEX=off cargo test --lib searchtools_service
    cargo fmt --check
    git diff --check
    cargo clippy --all-targets --all-features -- -D warnings

Each test command must report success. The real CLI test creates two trees in an unreachable objects directory, mutates the worktree afterward, proves the configured invocation reports the captured tree labels and symbols, then proves the same invocation without the launch flag fails. If a validation fails, record the exact failure in this plan's discoveries before changing the implementation.

## Validation and Acceptance

The public `SearchToolsService::call_tool_output("analyze_diff", ...)` path accepts explicit commit/tree endpoint pairs and reports full commit hashes or `tree:<full oid>` labels. A target-only tree explains that it has no parent and needs an explicit base. A tree available only through a configured alternate fails without configuration and works with it. Repeating an immutable tree comparison after changing the checkout, index, and `.gitattributes` serializes identically. The real `bifrost --tool analyze_diff` process accepts the trusted directory, while `--lsp` rejects it with an error naming both flags. Existing worktree and commit behavior remains covered by the original integration tests.

## Idempotence and Recovery

The tests create disposable temporary repositories and object directories. Re-running commands is safe. The engine's revision directories are removed on drop; if a test aborts, remove only the exact `bifrost-analyze-*` directory it reports after inspecting it. Do not delete repository files or alter Git branches to recover.

## Artifacts and Notes

The required engine interface after milestone 1 is:

    pub struct DiffAnalysisOptions { pub snapshot_object_dir: Option<PathBuf> }
    pub fn analyze_diff_at_root(root: &Path, params: AnalyzeDiffParams, options: &DiffAnalysisOptions) -> Result<DiffAnalysisResult, String>
    pub fn analyze_diff(analyzer: &dyn IAnalyzer, params: AnalyzeDiffParams, options: &DiffAnalysisOptions) -> Result<DiffAnalysisResult, String>
    pub fn SearchToolsService::with_diff_snapshot_object_dir(self, dir: PathBuf) -> Self

## Interfaces and Dependencies

Use `git2` 0.20's `Repository::odb` and `Odb::add_disk_alternate` after each object-access repository handle is opened. For immutable endpoints use `Repository::init_bare` in a private temporary directory, add `discovered.commondir().join("objects")` as the normal repository alternate, then add the configured snapshot alternate. Convert configured paths with `Path::to_str`; reject non-UTF-8 paths with an error naming the path rather than using a lossy conversion. Use `Object::peel_to_commit` followed by `Object::peel(ObjectType::Tree)` for object classification. On Unix use `std::os::unix::fs::PermissionsExt`; guard permission code with `#[cfg(unix)]` so Windows builds retain normal behavior.

Plan revision (2026-07-27): recorded implemented engine decisions and the attribute-isolation discovery; milestone 2 remains the intentionally deferred launch and documentation work.

Plan revision (2026-07-27): completed milestone 2 launch wiring, schema/help, documentation, and real-binary CLI tests; recorded the actual 17-test current diff suite and the E0382 validation discovery. Final static checks remain pending.

Plan revision (2026-07-27): added the missing worktree-only `.gitattributes` assertion, reran the immutable-tree test, and reran final formatting, whitespace, and all-feature clippy checks successfully; the plan is complete.
