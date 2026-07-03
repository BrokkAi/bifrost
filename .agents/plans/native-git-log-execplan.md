# Use native git log for Git relevance scoring

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

`most_relevant_files` currently spends several seconds scoring recent Git co-changes on large repositories because Bifrost asks libgit2 to construct and scan one tree diff per commit. A user querying related files should not wait several seconds for history scoring when native Git can stream the same `git log --name-status -M50` information in a single process. After this change, the Git relevance path will prefer a native `git` CLI backend for bulk changed-path collection, while preserving Bifrost's scoring formula and rename canonicalization rules.

## Progress

- [x] (2026-04-23 10:40Z) Profiled same-directory Ghidra `most_relevant_files` and identified `relevance::git.score_commits` as about 3.5 seconds, with almost all time in per-commit changed-path extraction.
- [x] (2026-04-23 10:43Z) Compared Brokk's `GitDistance` implementation and confirmed Brokk parallelizes per-commit scoring, while native `git log --name-status -M50 -n 1000` streams Ghidra's changed paths in about 51 ms.
- [x] (2026-04-23 10:55Z) Implemented a native Git log parser and routed `related_files_by_git` through it.
- [x] (2026-04-23 10:59Z) Removed the libgit2 changed-path fallback and converted tests/diagnostics away from direct libgit2 changed-path helpers.
- [x] (2026-04-23 11:18Z) Removed active external-repo tests that replayed commit changes and rename canonicalization directly; public `most_relevant_files` tests now own the regression surface.
- [x] (2026-04-23 11:25Z) Validated with `cargo check`, `cargo test --lib`, targeted `most_relevant_files` tests, and a Ghidra same-directory profile.

## Surprises & Discoveries

- Observation: libgit2 rename detection is not the expensive part of Bifrost's current Git scoring.
  Evidence: profiling reported `change_ms=3497.3` for 1000 commits but `find_similar_ms=28.1`.
- Observation: native Git is only fast when invoked once for the whole window.
  Evidence: `git log --format='commit %H' --name-status -M50 -n 1000` took about 51 ms on the Ghidra clone, while 1000 separate `git diff-tree` commands took about 6710 ms.
- Observation: merge commits need explicit first-parent diff output in native Git.
  Evidence: `git show --name-status` for Ghidra commit `b211a07...` emitted no paths, while `git show --name-status --diff-merges=first-parent` emitted the expected modified file.

## Decision Log

- Decision: Make native `git log --name-status -M50 --diff-merges=first-parent --root -z` the primary changed-path backend for Git relevance.
  Rationale: This keeps Git's native rename threshold behavior while replacing 1000 per-commit diff setups with one streaming process.
  Date/Author: 2026-04-23 / Codex.
- Decision: Keep libgit2 `changed_repo_paths_for_commit` and `recent_commit_ids` in place.
  Rationale: Existing tests exercise these helpers directly, and they provide a fallback if the native command fails unexpectedly.
  Date/Author: 2026-04-23 / Codex.
- Decision: Superseded the fallback decision and removed the libgit2 changed-path path for Git relevance.
  Rationale: The user pointed out that tests should exercise Bifrost's live path instead of a different low-level surface. Native `git log` is now the single changed-path collection backend for this scorer; libgit2 remains only for repository discovery, tracked-file checks, and blob reads needed by rename safety.
  Date/Author: 2026-04-23 / Codex.
- Decision: Continue applying Bifrost's extra rename safety filter to native `R` records.
  Rationale: The parity contract says accepted native rename labels must pass compact filename and token-overlap checks; native Git provides the label but not that extra filter.
  Date/Author: 2026-04-23 / Codex.
- Decision: Remove active tests that assert by manually replaying native Git changes and rename canonicalization on external repositories.
  Rationale: Those tests duplicated scorer business logic at the wrong layer. The normal regression surface should call `most_relevant_files` or `related_files_by_git`; ignored diagnostics may still inspect internals when explicitly requested.
  Date/Author: 2026-04-23 / Codex.

## Outcomes & Retrospective

The implementation replaced the serial libgit2 changed-path loop with one native `git log` stream for this scorer. On the Ghidra same-directory profile with 32 seed files, `relevance::related_files_by_git` dropped from about 3630 ms to 201 ms. `relevance::git.score_commits` is now about 32 ms; the native command and parser bucket, including rename safety blob reads, is about 167 ms. Total CLI time for that case dropped from about 9017 ms to 6209 ms, and the dominant remaining rank cost is import graph construction/reverse lookup.

Validation completed:

    cargo check
    cargo test --lib
    cargo test --test most_relevant_files rename_history_is_canonicalized_to_current_paths
    cargo test --test most_relevant_files consolidation_commit_does_not_merge_deleted_file_history_into_new_file
    cargo test --test most_relevant_files no_git_fallback_uses_import_page_ranker
    cargo test --test most_relevant_files missing_seed_files_are_reported
    cargo test --test most_relevant_files git_results_are_filled_with_import_ranking_when_needed
    cargo build --release --bin most_relevant_files

Ghidra same-directory profile after the change:

    n,total_ms,open_ms,build_ms,rank_ms,git_ms,git_recent_ms,git_score_ms,imports_ms,graph_ms,reverse_lookup_ms
    2,5440.8,186.3,1650.0,2921.6,197.2,161.9,32.4,2724.2,2711.9,1705.6
    4,5494.6,175.3,1591.3,3022.7,194.1,161.1,30.9,2828.4,2815.0,1779.9
    8,5562.6,182.2,1587.3,3083.1,198.8,164.0,32.3,2884.1,2871.2,1859.1
    16,5803.8,178.4,1614.8,3293.2,197.8,164.2,31.3,3095.0,3081.5,2025.9
    32,6209.1,179.1,1634.3,3701.9,201.4,166.7,32.4,3499.9,3483.6,2413.9

## Context and Orientation

The Git relevance scorer lives in `src/relevance.rs`. `most_relevant_project_files` first asks `related_files_by_git` for co-change candidates, then fills remaining slots through import relevance. `related_files_by_git` currently discovers a repository with `GitProjectContext::discover`, asks `recent_commit_ids` for the most recent 1000 commits, and then loops serially over those commits calling `changed_repo_paths_for_commit`.

`changed_repo_paths_for_commit` uses libgit2 to diff a commit's first parent against the commit tree, detect renames at a 50 percent threshold, and return `CommitChange { paths, renames }`. `paths` are repository-relative paths changed in the commit. `renames` are old-to-new repository-relative rename edges accepted by Bifrost's safety checks. The scorer feeds those rename edges into `RenameCanonicalizer`, which maps historical paths to current paths before converting them to `ProjectFile`.

The native Git command should produce the same shape of data in one process. `git log --name-status -M50 -z` emits each changed file's status and path. Rename entries use a status such as `R100` followed by old path and new path. `--diff-merges=first-parent` makes merge commits report the diff against the first parent, matching the libgit2 helper. `--root` makes the root commit list all files, matching libgit2's diff from an empty tree.

## Plan of Work

First, extend `GitProjectContext` in `src/relevance.rs` with the repository root path so native `git -C <repo_root>` can be executed even when the analyzed project root is a subdirectory of the repository. Add a method that runs `git log --topo-order --format=format:%x1e%H --diff-merges=first-parent --root -M50 --name-status -z -n <limit>` and parses the byte stream into a `Vec<CommitChange>`.

Second, implement parser helpers in `src/relevance.rs`. Split records on ASCII record separator `0x1e`, parse the first 40 bytes as the commit id, then parse NUL-separated name-status tokens. For `A`, `M`, and `D`, push the new or old path using the same path choices as `changed_repo_paths_for_commit`. For `R...`, use old and new paths, run the existing rename replacement, compact-stem, and token-overlap safety checks via libgit2 blob lookups for that one commit, and either accept the new path plus rename edge or treat the old and new paths as ordinary changed paths.

Third, change `related_files_by_git` so the scoring loop consumes the new `Vec<CommitChange>` instead of finding each commit and diffing it serially. If the native command cannot run or exits unsuccessfully, return the error to the caller; `most_relevant_project_files` already treats Git scoring failure as no Git results and continues to import relevance. Do not keep a libgit2 changed-path fallback for this scorer.

Finally, add focused tests for the parser if practical and run the existing Git relevance tests. Re-profile Ghidra same-directory `most_relevant_files` with `BIFROST_TIMING=1` to verify the Git bucket improves.

## Concrete Steps

Work from `/home/jonathan/Projects/bifrost`.

Run formatting and checks after the edit:

    cargo fmt
    cargo check
    cargo test --test most_relevant_files missing_seed_files_are_reported no_git_fallback_uses_import_page_ranker rename_history_is_canonicalized_to_current_paths
    cargo test --lib relevance::tests::rename_history_is_canonicalized_to_current_paths

Rebuild and profile the CLI:

    cargo build --release --bin most_relevant_files
    env BIFROST_TIMING=1 target/release/most_relevant_files --root /home/jonathan/Projects/brokkbench/clones/NationalSecurityAgency__ghidra <same-directory seed files>

## Validation and Acceptance

The implementation is acceptable when `cargo check` passes, the targeted Git relevance tests pass, and a same-directory Ghidra profile shows `relevance::git.score_commits` substantially below the previous about 3.5 seconds. If the native command is unavailable, Git scoring may fail internally and the caller should continue with import relevance through the existing `unwrap_or_default` behavior.

## Idempotence and Recovery

The code changes are local to `src/relevance.rs` unless a new unit test is added elsewhere. Running the validation commands is safe to repeat. If the parser produces incorrect parity results, revert only the routing in `related_files_by_git` to the libgit2 loop while keeping parser tests for diagnosis.

## Artifacts and Notes

Important profile evidence before the change:

    relevance::git.score_commits processed_commits=1000 find_commit_ms=0.7 change_ms=3497.3 canonicalize_ms=38.0
    git-counters commits_scanned=1000 commits_with_churn=139 A=855 D=75 R=62 C=0 native_rename_candidates=62 find_similar_ms=28.1
    git_log_name_status_ms=51 bytes=327669 lines=4614

## Interfaces and Dependencies

This change intentionally depends on a `git` executable on `PATH` for changed-path collection in this scorer. No Cargo dependency is added. The existing `git2` crate remains in use for repository discovery, HEAD tracked-file checks, and reading old/new blobs for the extra rename safety filter.

At the end of the change, `src/relevance.rs` should contain a native collection method on `GitProjectContext` with a signature equivalent to:

    fn recent_commit_changes(&self, limit: usize) -> Result<Vec<CommitChange>, GitLogError>

and `related_files_by_git` should score over `CommitChange` values rather than opening and diffing each commit in its main loop.

Revision note 2026-04-23: Initial plan created after profiling and Brokk comparison showed the per-commit libgit2 diff loop is the Git relevance bottleneck.

Revision note 2026-04-23: Updated after user feedback to remove the libgit2 changed-path fallback and avoid tests that duplicate scorer business logic through lower-level helper calls.
