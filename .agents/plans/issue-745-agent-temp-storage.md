# Prevent agent validation from leaking temporary storage

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md` from the repository root. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must stay current as work proceeds.

## Purpose / Big Picture

Agent-driven validation sometimes needs a fresh Cargo target directory so stale artifacts or a mismatched Rust toolchain cannot affect a check. Today agents create named directories such as `/private/tmp/bifrost-clippy-577`, but Cargo never removes them, so repeated checks can consume the host's disk. After this change, agents can run a command through one helper that creates a unique target directory and removes it on success, failure, or interruption. Operators can also inspect and safely remove old Bifrost temporary directories, while reference-differential smoke runs can explicitly avoid changing the repository's persistent analyzer cache.

The behavior is observable without a large build: run the isolated-target helper around a shell command that writes into `$CARGO_TARGET_DIR`, then observe that the directory is gone. Run the cleanup command without `--apply` and observe a dry-run; add `--apply` and observe that only stale, inactive, non-retained `bifrost-*` directories disappear. Run the reference-differential CLI with `--cache-mode ephemeral` and observe that it completes without creating `.brokk/bifrost_cache.db`.

## Progress

- [x] (2026-07-14T11:42Z) Synced the existing issue branch and inspected the issue, agent guidance, Cargo validation examples, reference-differential CLI, workspace constructors, and current tests.
- [x] (2026-07-14T11:42Z) Chose the safety contracts for managed-directory markers, stale cleanup, and cache-mode defaults.
- [x] (2026-07-14T11:48Z) Added the clean-on-exit isolated Cargo target helper and behavior tests, including success, failure, interruption, and deliberate retention.
- [x] (2026-07-14T11:48Z) Added the dry-run-by-default stale-directory cleanup command and safety tests for prefix, age, PID, open directory, retained marker, and symlink boundaries.
- [x] (2026-07-14T11:48Z) Added explicit persisted and ephemeral reference-differential cache modes, preserving persisted mode as the default.
- [x] (2026-07-14T11:48Z) Updated `AGENTS.md` with the commands and the smoke-versus-campaign cache policy.
- [x] (2026-07-14T11:53Z) Ran shell syntax checks, formatting, 11 focused integration tests, strict all-feature Clippy in a clean pinned-toolchain target, a manual helper smoke, and the final safety diff review.
- [x] (2026-07-14T12:30Z) Ran the requested five-perspective guided review against `origin/master` and queued all seven deduplicated findings.
- [x] (2026-07-14T12:45Z) Hardened managed-directory provenance, ownership/inode revalidation, quarantine deletion, process-group shutdown, Linux timestamp probing, age bounds, and deletion-error reporting; removed duplicated root policy and CLI fixtures.
- [x] (2026-07-14T13:02Z) Re-ran 16 focused tests, strict all-feature Clippy, shell syntax and diff checks, then obtained post-fix security and operational APPROVE verdicts with no remaining high- or medium-severity findings.

## Surprises & Discoveries

- Observation: plain `WorkspaceAnalyzer::build` already uses an in-memory SQLite analyzer store, even for a Git worktree, while `WorkspaceAnalyzer::build_persisted` opens `.brokk/bifrost_cache.db`.
  Evidence: `src/analyzer/workspace.rs` selects `default_store_context` or `persistent_store_context`; `src/analyzer/tree_sitter_analyzer.rs` maps the former to `AnalyzerStore::open_in_memory()`.
- Observation: the existing reference-differential CLI always selects the persisted constructor for both one-repository and corpus runs.
  Evidence: `run_engine` in `src/bin/bifrost_reference_differential.rs` unconditionally calls `WorkspaceAnalyzer::build_persisted`.
- Observation: the repository has historical ExecPlans with manually named `/private/tmp/bifrost-*` target directories but no lifecycle helper or cleanup script.
  Evidence: `rg` finds examples in `.agents/plans/issue-575-incremental-lsp-text-synchronization.md`, `.agents/plans/issue-577-lsp-semantic-tokens.md`, and `.agents/plans/issue-584-shared-cache-liveness.md`; `scripts/` has no matching helper.
- Observation: the Bifrost code-intelligence skills were installed, but their advertised MCP tools were not callable in this session.
  Evidence: the available tool inventory exposed the GitHub connector but no `search_symbols`, `get_summaries`, or `get_symbol_sources` tool, so repository exploration used narrow `rg` and source reads instead.
- Observation: the ordinary strict Clippy command selected Homebrew Rust against Rustup-built shared artifacts and failed with `E0514`, even though both compilers report version 1.96.0.
  Evidence: the first run reported incompatible metadata for 30 dependencies. Pinning `PATH` to `/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin` and running Clippy through `scripts/with-isolated-cargo-target.sh` passed in 1 minute 29 seconds, after which the helper removed `/private/tmp/bifrost-cargo-target.jCvDMA`.
- Observation: a failed BSD-style `stat -f '%m'` probe can still emit GNU filesystem-status output before the GNU fallback runs.
  Evidence: GNU `gstat` returned status 1 but printed a filesystem report followed by the fallback epoch, producing a nonnumeric multiline timestamp. The shared helper now captures and validates each dialect separately and tries GNU first.
- Observation: macOS `lsof +D` can print a matching open directory while returning status 1.
  Evidence: the open-directory regression showed the holder process in `lsof` output but the original status-only check treated the directory as inactive. Cleanup now requests field output and treats any nonempty result as active before interpreting status.

## Decision Log

- Decision: use a unique `mktemp -d` target under `BIFROST_TMP_ROOT` when set, `/private/tmp` when available, and `${TMPDIR:-/tmp}` otherwise, with a direct-child PID marker and an explicit retained marker.
  Rationale: `mktemp` is available on macOS and Linux and removes naming collisions. Markers let cleanup distinguish active helper-owned output and intentionally retained output without guessing from directory names.
  Date/Author: 2026-07-14 / Codex.
- Decision: make stale cleanup dry-run by default, restrict candidates to direct non-symlink directories named `bifrost-*`, require a minimum age, skip live marker PIDs and retained markers, and use `lsof` to reject other active directories.
  Rationale: deletion must be conservative. If inactivity cannot be proved because `lsof` is unavailable, apply mode will skip the candidate instead of weakening the safety promise.
  Date/Author: 2026-07-14 / Codex.
- Decision: expose `--cache-mode persisted|ephemeral` on both reference-differential subcommands and keep `persisted` as the default.
  Rationale: campaign runs benefit from warm, resumable cache state; one-off smoke runs should leave repository storage untouched. Both workspace behaviors already exist, so the CLI should select rather than invent a third store implementation.
  Date/Author: 2026-07-14 / Codex.
- Decision: update `AGENTS.md` rather than rewrite historical ExecPlan evidence.
  Rationale: old plans record commands that were actually run. New repository-wide guidance prevents recurrence while preserving the accuracy of those living records.
  Date/Author: 2026-07-14 / Codex.
- Decision: automatic apply requires an exact `bifrost-cargo-target.*` name, a versioned managed marker matching the basename/current UID, and current-UID ownership; historical unmarked directories require `--include-unmanaged`.
  Rationale: prefix, age, and one activity snapshot do not prove that a directory belongs to this helper. The explicit legacy option retains recovery capability without making unrelated Bifrost worktrees automatic deletion targets.
  Date/Author: 2026-07-14 / guided-review fix batch.
- Decision: apply mode records device/inode/owner, revalidates immediately before moving the candidate to a same-root quarantine name, verifies the moved inode, checks activity again, then deletes.
  Rationale: moving and revalidating the checked inode closes the pathname-replacement window and prevents a newly substituted active directory from being passed to `rm -rf`.
  Date/Author: 2026-07-14 / guided-review fix batch.
- Decision: the isolated command runs in its own process group, and interruption signals the group with a bounded grace period followed by `KILL`; ordinary completion also terminates surviving descendants before cleanup.
  Rationale: direct-child supervision is insufficient for Cargo/rustc/linker trees and can either delete live output or hang forever on a signal-ignoring child.
  Date/Author: 2026-07-14 / guided-review fix batch.

## Outcomes & Retrospective

Completed initially on 2026-07-14, then reopened for the requested guided-review fix batch. The isolated helper now supervises the complete command process group rather than only one PID, bounds interruption, and retains rather than deleting if the group cannot be stopped. Cleanup is dry-run by default, automatically applies only to helper-managed/current-UID targets, atomically quarantines the validated inode, and requires explicit opt-in for historical unmarked directories. The differential CLI still defaults to persisted behavior and offers an ephemeral in-memory mode that leaves `.brokk/bifrost_cache.db` absent. All seven guided-review findings were applied and verified; the post-fix security and operational reviews both returned APPROVE with no remaining high- or medium-severity findings.

Validation passed: `bash -n` for all three scripts; `cargo fmt --check`; `cargo test --test temp_storage_scripts --test bifrost_reference_differential_cli` with 16 tests passed; a manual clean-on-exit smoke; `git diff --check`; and `cargo clippy --all-targets --all-features -- -D warnings` through the isolated helper with a pinned Rustup toolchain. The final review strengthened the active marker to include the child PID as well as the helper PID, covering a helper killed before it can clean up while Cargo remains alive, and separately verified the process-tree and deletion-safety regressions.

## Context and Orientation

Cargo places compiled dependencies and other build artifacts in `target/`, or in the directory named by the `CARGO_TARGET_DIR` environment variable. An isolated target is a fresh external directory used to prevent one validation command from reusing existing artifacts. External targets are not owned by the worktree and Cargo does not delete them.

`scripts/` holds repository maintenance helpers. The new `scripts/with-isolated-cargo-target.sh` will own the complete lifecycle of one unique external target. The new `scripts/cleanup-bifrost-tmp.sh` will inspect or remove older candidates. `tests/temp_storage_scripts.rs` will execute both scripts as black boxes against temporary roots, so the test never scans or deletes the machine's real temporary directory.

`src/bin/bifrost_reference_differential.rs` parses `run-repo` and `run-corpus`, constructs a `FilesystemProject`, builds a `WorkspaceAnalyzer`, then compares forward definition lookup with inverse usage results. A persisted workspace writes the unified SQLite cache below the repository's `.brokk` directory. An ephemeral workspace uses an in-memory SQLite store that disappears when the process exits. `tests/bifrost_reference_differential_cli.rs` exercises the binary through its public command-line boundary.

`AGENTS.md` is the repository-wide instruction surface for future agent sessions. It will tell agents to use the helper instead of manually assigning a named `CARGO_TARGET_DIR`, explain how to intentionally retain a target, require a dry-run before applying stale cleanup, and distinguish ephemeral smoke runs from persisted campaigns.

## Plan of Work

First add `scripts/with-isolated-cargo-target.sh`. It rejects an empty command, creates a `bifrost-cargo-target.XXXXXX` directory with `mktemp`, writes a versioned ownership marker plus shell/direct-child PIDs, exports `CARGO_TARGET_DIR`, and runs the requested command in a dedicated process group. Exit removes the exact target only after the process group is gone. Signal traps stop the group with bounded escalation before using the same cleanup path. `BIFROST_KEEP_TARGET=1` replaces deletion with a keep marker after removing the active marker.

Next add `scripts/cleanup-bifrost-tmp.sh`. It accepts `--apply`, `--include-unmanaged`, `--older-than-hours N`, and a testable `--tmp-root PATH`; default age is 24 hours and root selection lives in `scripts/lib/bifrost-tmp.sh`. It enumerates only direct `bifrost-*` directories, never follows symlinks, and skips retained, live, young, foreign-owned, or open candidates. Automatic apply requires helper provenance. Apply revalidates identity, quarantines by same-root rename, revalidates and rechecks activity, and only then deletes. Failed deletion is reported nonzero and remaining data is restored when possible.

Then extend the reference-differential parser with a small `CacheMode` enum. The default and `persisted` value call `WorkspaceAnalyzer::build_persisted`; `ephemeral` calls `WorkspaceAnalyzer::build`. The choice is operational and does not change differential sampling or the completion fingerprint. Help text will state which mode suits smoke versus resumable runs. Add a CLI test proving ephemeral mode completes and leaves no `.brokk/bifrost_cache.db`; retain the existing default-path coverage and assert that it still creates the persisted cache.

Finally update `AGENTS.md`, format the Rust code, run focused behavior tests, run `cargo clippy --all-targets --all-features -- -D warnings`, and inspect the complete diff for unsafe path handling, accidental persistence changes, or undocumented behavior.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/6ec9/bifrost` on the existing `745-prevent-storage-leaks-on-agentic-temp-directories` branch.

1. Add the plan, scripts, and script integration test. Run:

       cargo test --test temp_storage_scripts

   Expect every helper lifecycle, dry-run, apply, prefix, age, active, retained, and symlink case to pass.

2. Add the CLI cache mode and tests. Run:

       cargo test --test bifrost_reference_differential_cli

   Expect the tiny persisted and ephemeral runs to complete, with only persisted mode creating `.brokk/bifrost_cache.db`.

3. Update guidance and run repository checks:

       cargo fmt
       cargo clippy --all-targets --all-features -- -D warnings

   Expect formatting to make no further changes on a second run and Clippy to exit successfully with no warnings.

4. Exercise the helper manually with a no-build command:

       scripts/with-isolated-cargo-target.sh sh -c 'test -d "$CARGO_TARGET_DIR"'

   Expect stderr to identify a unique target followed by its cleanup, and expect the printed directory not to exist afterward.

## Validation and Acceptance

The isolated helper is accepted when success and nonzero command exits preserve the child status while removing the target, interruption removes it after stopping the direct child, and `BIFROST_KEEP_TARGET=1` retains it with no active marker and with a keep marker.

The cleanup command is accepted when its default invocation changes nothing; `--apply` removes only old matching directories proven inactive; unrelated names, symlinks, young directories, live PIDs, open directories, and retained directories survive. A missing activity probe must produce a skip in apply mode rather than a deletion.

The reference-differential change is accepted when existing invocations remain persisted by default, `--cache-mode persisted` is equivalent, `--cache-mode ephemeral` completes with the same report shape without creating the unified cache file, invalid values fail clearly, and help explains the policy.

The overall change is accepted when both focused integration test targets, `cargo fmt`, and strict all-feature Clippy pass.

## Idempotence and Recovery

Both scripts are repeatable. The helper deletes only the exact path returned by its own `mktemp` call. Retaining a target is explicit and leaves a marker that the cleanup command always respects. The cleanup command is non-mutating unless `--apply` is present, and repeated apply runs simply find fewer candidates. Tests use `--tmp-root` with `tempfile` directories and never touch the host temporary root.

If a helper process is killed with an untrappable signal such as `SIGKILL`, its active marker contains a dead PID after the child exits. A later cleanup run can remove the directory after the minimum age and inactivity checks. If `lsof` is unavailable, install it or inspect and remove the directory manually; the script will not guess.

Switching cache mode is safe because both caches contain derived analyzer data. Ephemeral mode discards its in-memory database at process exit. Persisted mode remains the default and can warm or resume later campaign runs.

## Artifacts and Notes

The implementation adds two executable shell scripts, one Rust integration test for their observable behavior, a narrow CLI enum and parser option, this ExecPlan, and repository agent guidance. It adds no dependency and does not introduce a second cache format.

## Interfaces and Dependencies

`scripts/with-isolated-cargo-target.sh COMMAND [ARG ...]` must export a unique `CARGO_TARGET_DIR` to the command and support `BIFROST_KEEP_TARGET=1` and `BIFROST_TMP_ROOT=PATH`.

`scripts/cleanup-bifrost-tmp.sh [--apply] [--include-unmanaged] [--older-than-hours N] [--tmp-root PATH]` must be dry-run by default. It depends only on shell utilities available on macOS and Linux plus `lsof` for apply-time activity proof. `scripts/lib/bifrost-tmp.sh` owns shared root selection and portable stat helpers.

In `src/bin/bifrost_reference_differential.rs`, define a private `CacheMode` with `Persisted` and `Ephemeral`, parse it from `--cache-mode`, and pass it to `run_engine`. No library API changes are needed.

Plan created on 2026-07-14 for issue #745. It records the conservative cleanup boundary and preserves persisted differential behavior by default.

Plan updated on 2026-07-14 after implementation and review to record completed behavior, validation evidence, the mixed-toolchain discovery, and the child-PID safety hardening.

Plan updated again on 2026-07-14 after guided review to record seven queued findings, the provenance/process-group redesign, and the post-fix validation still required.

Plan finalized on 2026-07-14 after all seven findings were fixed, 16 focused tests and strict Clippy passed, and the post-fix security and operational reviewers approved the result.
