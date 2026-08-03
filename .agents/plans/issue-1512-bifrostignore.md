# Exclude generated code from analysis with `.bifrostignore`

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Maintain this document in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost currently analyzes every supported-language file that belongs to its workspace, including files tracked by Git even when `.gitignore` matches them. That correctness rule prevents broad Git ignore patterns from accidentally hiding real source, but it also forces Bifrost to parse tracked generated artifacts that provide no useful code intelligence. In this repository, two generated Tree-sitter `parser.c` files account for several seconds of cold startup.

After this change, a repository can add `.bifrostignore` files using Gitignore syntax. Matching files remain visible to file-level tools such as `find_filenames` and `list_files`, but analyzer-backed tools, semantic indexing, and policies do not parse or index them. An explicit one-shot CLI `--sources` selection still wins. Bifrost itself will dogfood the feature by excluding the vendored Scala and Kotlin generated parser sources, and the behavior will be documented on the public website.

## Progress

- [x] (2026-08-03 09:00Z) Diagnosed the current workspace-listing, analyzer-inventory, watcher, CLI, MCP, and documentation paths.
- [x] (2026-08-03 09:10Z) Confirmed that generated `parser.c` files must remain checked in because `crates/bifrost-analysis/build.rs` compiles them directly during ordinary Cargo builds.
- [x] (2026-08-03 09:28Z) Implemented analysis-only `.bifrostignore` matching for filesystem and multi-root projects while preserving explicit file sets.
- [x] (2026-08-03 09:36Z) Made root and nested `.bifrostignore` edits trigger full watcher-driven re-analysis without forwarding ignored source edits.
- [x] (2026-08-03 09:38Z) Added behavior-focused project, service, file-tool, explicit-source, multi-root, and watcher tests.
- [x] (2026-08-03 09:39Z) Added Bifrost's own two-line `.bifrostignore`.
- [x] (2026-08-03 09:42Z) Published canonical workspace-scope documentation and linked it from CLI, MCP, and LSP pages; updated CLI help and MCP tool descriptions.
- [ ] (2026-08-03 09:50Z) Run final validation (completed: formatting; 21 project unit tests; 11 watcher unit tests; 8 project ignore integration tests; 4 watcher integration tests; end-to-end service test; CLI-help smoke; MCP descriptor tests; docs check/build/link check with 0 diagnostics and 5,860 valid internal links; remaining: policy checks, cold-start timing comparison, final review).

## Surprises & Discoveries

- Observation: The worktree became attached to the pre-existing issue branch after diagnosis, so creating the separately proposed `dave/issue-1512-bifrostignore` branch would duplicate work.
  Evidence: `git status --short --branch` reports `1512-support-bifrostignore-exclude-tracked-vendoredgenerated-code-from-analysis-while-keeping-it-visible-to-file-level-tools` tracking the matching origin branch at commit `15b7af64c`.

- Observation: The current issue branch is based directly on the cold-start improvement from issue #1507 and is two unrelated commits behind `origin/master`.
  Evidence: `git log HEAD..origin/master` lists only #1510 and #1509 changes in value-flow and taint conformance tests.

- Observation: A cold rmcp `search_symbols` call during diagnosis took 22.43 seconds and completed successfully.
  Evidence: The exact request searched for the project inventory symbols named in issue #1512; the delay is consistent with the generated-parser cold-build cost owned by this issue.

- Observation: Watching a nested `.bifrostignore` file directly is not sufficient because editors may replace or recreate the file, invalidating an inode-based watch.
  Evidence: The watcher now watches each relevant configuration directory non-recursively and the polling regression removes and recreates `vendor/.bifrostignore` successfully.

- Observation: A configuration-directory watch also observes sibling source changes, so event classification needs an analysis-ignore predicate separate from `is_gitignored`.
  Evidence: `Project::is_bifrostignored` keeps matching paths in `all_files` while `classify_project_path` drops their source events; the watcher regression edits `vendor/generated.rs` and observes no delta.

## Decision Log

- Decision: Preserve `Project::all_files` and `Project::is_gitignored` semantics and apply `.bifrostignore` only to `Project::analyzable_files`.
  Rationale: File-level tools consume the whole-workspace listing and must keep seeing ignored files, while code-intelligence tools consume analyzer delegates built from the analyzable inventory.
  Date/Author: 2026-08-03 / Codex

- Decision: Keep `FileSetProject` exempt from `.bifrostignore`.
  Rationale: `FileSetProject` represents explicit one-shot `--sources` and explicit tool file selections; explicit user requests should override ambient workspace configuration.
  Date/Author: 2026-08-03 / Codex

- Decision: Use the `ignore` crate's Gitignore matcher rather than source-text parsing or custom glob interpretation.
  Rationale: The repository already depends on `ignore`, and the feature promises Gitignore syntax including nested configuration and negation. Reusing its parser preserves those semantics across platforms.
  Date/Author: 2026-08-03 / Codex

- Decision: Publish a canonical workspace-scope page and link it from interface-specific docs.
  Rationale: `.bifrostignore` affects MCP, LSP, CLI, library analysis, semantic indexing, and policies, so describing it only in CLI help would make the feature difficult to discover and misleadingly interface-specific.
  Date/Author: 2026-08-03 / Codex

- Decision: Watch the workspace root and each existing nested ignore-file directory non-recursively, in addition to the existing minimal recursive source roots.
  Rationale: This observes configuration creation, replacement, removal, and recreation without recursively watching ignored generated trees or collapsing the optimized watcher roots to the workspace root.
  Date/Author: 2026-08-03 / Codex

- Decision: Add `Project::is_bifrostignored` with a default false implementation and delegate it through filesystem, multi-root, and overlay projects.
  Rationale: The watcher must ignore source events seen only because it watches a configuration directory, while `is_gitignored` must retain its established file-inventory meaning.
  Date/Author: 2026-08-03 / Codex

## Outcomes & Retrospective

The implementation milestone is complete: project inventory, multi-root delegation, watcher behavior, explicit file-set precedence, end-to-end file-tool visibility, Bifrost's dogfood configuration, CLI/MCP descriptions, and public documentation are present and pass focused validation. Broader validation, policy checking, timing evidence, and final review remain.

## Context and Orientation

`crates/bifrost-analysis/src/analyzer/project.rs` defines the `Project` abstraction. `Project::all_files` is the complete file-level workspace view, while `Project::analyzable_files(language)` selects source files for a language analyzer. `FilesystemProject` walks a real workspace. Its `collect_workspace_files` helper honors Git ignore files during the walk and then deliberately unions every file from the Git index back into the result. `FileSetProject` represents an explicit fixed selection. `MultiRootProject` combines filesystem roots. `OverlayProject` supplies unsaved editor content while delegating file membership.

`crates/bifrost-mcp/src/project_watcher.rs` watches directories containing analyzed files. Ordinary file events produce an incremental delta. Configuration or ambiguous events can set `requires_full_refresh`, which rebuilds analyzer state. The watcher also invalidates the shared workspace-listing cache used by `find_filenames` before classifying changed paths.

`crates/bifrost-mcp/src/searchtools_service.rs` exposes analyzer-backed and file-level tools through one service. The file-level `find_filenames` fast path consumes the cached `all_files` listing without waiting for analyzer construction. This separation is why `.bifrostignore` must not change the listing.

The public documentation site is under `docs/src/content/docs/` and its navigation is declared in `docs/astro.config.mjs`. CLI help text lives in `src/bin/bifrost.rs`. MCP tool descriptions for `find_filenames` and `list_files` live in `crates/bifrost-mcp/src/mcp_extended.rs`.

## Plan of Work

First, add a small analysis-ignore matcher beside the project inventory code in `crates/bifrost-analysis/src/analyzer/project.rs`. It will discover the root `.bifrostignore` and relevant nested `.bifrostignore` files, compile them with `ignore::gitignore::GitignoreBuilder`, and test candidate paths using the library's parent-aware match operation. `FilesystemProject::analyzable_files` will apply this matcher after selecting the language extension. The matcher may be cached, but `invalidate_cached_file_listing` must clear it so watcher-driven refresh sees configuration edits. `MultiRootProject::analyzable_files` will ask each child `FilesystemProject` for its filtered inventory and translate results into the common multi-root coordinate system. `FileSetProject` and `OverlayProject` retain their existing explicit/delegating behavior.

Second, update `crates/bifrost-mcp/src/project_watcher.rs`. Register a non-recursive watch on the workspace root in addition to the existing minimal recursive analyzed-directory watches, unless the root is already recursively watched. This observes creation and deletion of the root `.bifrostignore` without turning the optimized watcher into a recursive whole-repository watcher. Existing recursive analyzed-directory watches observe relevant nested files. Any event whose project-relative basename is `.bifrostignore` will set `requires_full_refresh`; the existing early invalidation clears listing and matcher caches before the refresh.

Third, add behavior-focused coverage. Extend the consolidated project tests to prove a tracked ignored source remains in `all_files` but leaves `analyzable_files`, nested patterns and negation work, `is_gitignored` keeps its old meaning, explicit `FileSetProject` files remain analyzable, and multi-root projects apply root-local configuration. Add a service-level scenario that builds an analyzer, verifies `search_symbols` omits an ignored declaration while `find_filenames` and `list_files` still report its path, removes the pattern, refreshes, and verifies the declaration returns. Add watcher tests for root creation, modification, removal, nested configuration, and full-refresh classification.

Fourth, create the repository-root `.bifrostignore` with the two vendored parser source directories. These are required Cargo build inputs and remain tracked; only Bifrost's code-intelligence inventory excludes them.

Fifth, create `docs/src/content/docs/workspace-scope.md` as the canonical user-facing explanation and add it to `docs/astro.config.mjs`. Link it from `docs/src/content/docs/cli.md`, `docs/src/content/docs/mcp.md`, and `docs/src/content/docs/lsp.md`. Update `src/bin/bifrost.rs` help text and the `find_filenames` and `list_files` descriptors in `crates/bifrost-mcp/src/mcp_extended.rs` so installed binaries expose the same contract.

Finally, format and validate the focused featureless Rust surfaces, build and link-check the docs, run the repository's code-smell policy pack, and compare a cold analyzer build before and after the root `.bifrostignore`. Do not enable the `nlp` feature for this task because the change does not touch semantic-search implementation and routine NLP builds consume substantial disk.

## Concrete Steps

Work from the repository root `/Users/dave/.codex/worktrees/5c69/bifrost`.

Inspect and edit the project inventory, watcher, tests, help, descriptors, and public docs named above. Apply changes incrementally and keep this plan's living sections current.

Run formatting and focused tests:

    cargo fmt
    cargo test --test suite_mcp_cli -- filesystem_project_gitignore
    cargo test --test suite_analyzers -- project_change_watcher_test
    cargo test --test suite_symbols -- bifrostignore

Run any unit-test filters added in `crates/bifrost-analysis/src/analyzer/project.rs` or `crates/bifrost-mcp/src/project_watcher.rs` with package-qualified `cargo test` commands. The expected result is that every new test passes and the existing focused suites report no regression.

Validate the public documentation:

    cd docs
    npm run check
    npm run build

Return to the repository root before Rust or policy commands.

Run the installed Bifrost policy surface once the code changes are complete, selecting `bifrost.code-smells` and every executable repository policy root explicitly named by repository configuration. A `finding` must be reviewed or fixed; an `unreliable` result is a validation failure.

For the timing comparison, use an ephemeral cache or an isolated copy/configuration so the before and after runs do not share analyzer persistence. Record the exact command, revision, cache state, and elapsed time in this plan rather than claiming the issue's estimated improvement as measured fact.

## Validation and Acceptance

Acceptance is behavioral. In a temporary Git repository, add and track `src/visible.rs` and `vendor/generated.rs`, then add `.bifrostignore` containing `vendor/`. A Bifrost service over that root must return `visible` but not `generated` from `search_symbols`. `find_filenames` for `generated.rs` and `list_files` for `vendor` must still return `vendor/generated.rs`. Removing the ignore pattern and forcing a refresh must make `generated` searchable without restarting the process.

A one-shot service built with `FileSetProject` over `vendor/generated.rs` must still return its declaration. Two filesystem roots with different `.bifrostignore` files must each apply their own patterns after paths are mapped into `MultiRootProject`'s common root.

Creating, changing, renaming, or deleting a root or relevant nested `.bifrostignore` while a polling watcher is active must yield a delta with `requires_full_refresh == true`. Ordinary source edits must remain incremental.

The public documentation build and link checker must succeed, and the rendered navigation must contain a Workspace Scope page explaining the visibility split and explicit-selection precedence. CLI help and MCP tool descriptions must use the same semantics.

## Idempotence and Recovery

The implementation is source-only and can be retried safely. Tests use temporary directories and must not mutate the working repository's Git index. If matcher construction fails because a `.bifrostignore` is invalid or unreadable, propagate an `io::Error` from `analyzable_files` rather than silently widening analysis. If a watcher event cannot be classified, preserve the existing conservative full-refresh fallback.

Do not delete the generated parser files. Do not rewrite Git history, switch away from the active issue branch, or stage unrelated files. Temporary Cargo targets must use `scripts/with-isolated-cargo-target.sh` when isolation is required so cleanup is automatic.

## Artifacts and Notes

The repository's intended dogfood file is:

    crates/bifrost-analysis/vendor/tree-sitter-scala/src/
    crates/bifrost-analysis/vendor/tree-sitter-kotlin/src/

The generated parsers are approximately 34 MiB and 32 MiB and are compiled directly by `crates/bifrost-analysis/build.rs`. They are not candidates for deletion until compatible published grammar crates replace Bifrost's private Scala fixes and temporary Kotlin snapshot.

## Interfaces and Dependencies

Use the existing `ignore = "0.4.24"` dependency in `crates/bifrost-analysis/Cargo.toml`. Do not add a glob parser, regex fallback, or source-text mini parser. The analysis matcher belongs with `FilesystemProject` in `crates/bifrost-analysis/src/analyzer/project.rs` and must expose no new public API unless tests require a stable behavior-level entry point.

`Project::all_files`, `Project::analyzable_files`, `Project::is_gitignored`, and `Project::invalidate_cached_file_listing` are the load-bearing interfaces. At completion, the first remains the file-tool inventory, the second is the analysis inventory, the third still means an on-disk file absent from `all_files`, and the fourth invalidates both workspace-listing and `.bifrostignore` matcher caches for filesystem projects.

Plan revision note (2026-08-03 09:50Z): Recorded the broader focused Rust and clean public-doc validation results before the implementation checkpoint. Policy checking, timing evidence, and final review remain.
