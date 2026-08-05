# Release Bifrost 0.8.22

This ExecPlan is a living document. Maintain it in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

This work publishes Bifrost 0.8.22 from a fixed release-candidate branch. The release uses one validated commit for the Rust crates, command-line archives, Python packages, agent packages, and VS Code extension. A successful pushed `v0.8.22` tag starts the repository Release workflow.

## Progress

- [x] (2026-08-05 06:54Z) Created and pushed `dave/v0.8.22-rc` from `origin/master` commit `809464f1cfba290f2326d3cfa13fede3caa26d29`.
- [x] (2026-08-05 06:54Z) Confirmed a clean worktree, current remote state, release rules, and 433 GiB of free disk space.
- [x] (2026-08-05 06:57Z) Ran the baseline `bifrost.code-smells` policy pack; it completed reliably with 295 existing findings.
- [x] (2026-08-05 06:59Z) Changed the source version to 0.8.22 and synchronized all release metadata.
- [x] (2026-08-05 07:01Z) Regenerated and validated agent and editor bundles; all 116 plugin tests passed after locked dependencies were installed.
- [x] (2026-08-05 08:01Z) Corrected release-gate portability, toolchain selection, exact dependency pins, cache path handling, and the REPL process budget.
- [x] (2026-08-05 08:44Z) Passed the full pre-push gate: 8,422 featureless tests, doctests, and all-feature workspace clippy.
- [x] (2026-08-05 09:17Z) Passed all comprehensive `nlp,python` executable tests and matching-toolchain doctests.
- [x] (2026-08-05 09:18Z) Ran the final code-smell pack. It completed reliably with the unchanged 295 baseline findings and no findings in changed files.
- [ ] Commit and push the validated release candidate.
- [ ] Synchronize the version change to `master` as required by the release process.
- [ ] Tag the validated RC commit as `v0.8.22` and push the tag.
- [ ] Observe the Release workflow and report publication status.

## Surprises & Discoveries

- Observation: The worktree started detached at `cbf7536ef`, which was not an ancestor of current `origin/master`.
  Evidence: `git rev-list --left-right --count HEAD...origin/master` returned `5 63` before RC branch creation.

- Observation: `scripts/pre-push-gate.sh` stopped on macOS before compilation because it used the GNU-only `df --output=avail` option.
  Evidence: macOS `df` returned `unrecognized option --output=avail` immediately after the format check.

- Observation: Release metadata synchronization did not update exact internal Bifrost dependency pins in Cargo manifests.
  Evidence: Cargo rejected `brokk-bifrost-analysis v0.8.22` because it still required `brokk-bifrost-core =0.8.21`.

- Observation: The local PATH selected rustup-managed `cargo` and `rustc`, but Homebrew `rustdoc` with incompatible crate metadata.
  Evidence: doctests and the isolated clippy build failed with E0514. `rustc` had commit `ac68faa20`, while the selected tool paths came from two installations.

- Observation: The REPL test that timed out under the concurrent gate passed alone in 18.09 seconds.
  Evidence: nextest run `f397526b-7d2d-44f6-94ec-5a5341d3ff10` passed its one selected test.

- Observation: The same REPL test exceeded its fixed 30-second process budget again in the comprehensive suite, after it produced the complete expected output and `bye`.
  Evidence: The test failed at the child timeout, while an adjacent query test took more than 60 seconds under the same concurrent load.

- Observation: `cargo clippy` selected Homebrew `cargo-clippy` and `clippy-driver` because the rustup proxy directory did not contain those commands.
  Evidence: `command -v cargo-clippy` and `command -v clippy-driver` returned `/opt/homebrew/bin`, while `rustup which` returned matching tools in the active sysroot.

- Observation: A cache reader opened the noncanonical `/var` spelling after the writer created the database through canonical `/private/var`.
  Evidence: SQLite `SQLITE_OPEN_NOFOLLOW` rejected the read-only open. The focused test failed at the reader open with `unable to open database file`.

- Observation: The documented comprehensive command also selected Homebrew `rustdoc` after all executable suites passed.
  Evidence: Its final doctest phase reported E0514 for rustup-built dependencies. The doctest passed when `RUSTDOC` named the active rustup sysroot tool.

## Decision Log

- Decision: Use `origin/master` commit `809464f1cfba290f2326d3cfa13fede3caa26d29` as the release branch point.
  Rationale: The user requested a new RC branch without naming an older stable commit. The canonical release process requires a fixed commit from `master`, and this was the fetched current tip.
  Date/Author: 2026-08-05 / Codex

- Decision: Run the full release gate with all features.
  Rationale: Release validation is one of the stated cases that requires comprehensive `nlp,python` coverage.
  Date/Author: 2026-08-05 / Codex

- Decision: Read available disk space with POSIX `df -Pk` and convert its KiB value to GiB in the shell.
  Rationale: The project supports Windows and Unix-like systems. The gate must work on macOS and Linux without GNU-specific `df` options.
  Date/Author: 2026-08-05 / Codex

- Decision: Make `release-version.mjs sync` update exact internal Bifrost dependency pins in all released Cargo manifests.
  Rationale: The documented workflow tells the operator to edit only the workspace version and run this script. The script must produce a buildable workspace.
  Date/Author: 2026-08-05 / Codex

- Decision: Pin `RUSTC` and `RUSTDOC` to the same Rust sysroot at gate start when the caller did not set them.
  Rationale: Cargo artifacts and doctests must use compiler tools from one installation. The settings remain overridable for controlled environments.
  Date/Author: 2026-08-05 / Codex

- Decision: Put the selected Rust sysroot first in PATH during the gate.
  Rationale: Cargo subcommands such as clippy must come from the same toolchain as rustc and rustdoc.
  Date/Author: 2026-08-05 / Codex

- Decision: Canonicalize only the cache database parent before read-only SQLite opens.
  Rationale: This removes ancestor symlink aliases such as macOS `/var` while preserving `SQLITE_OPEN_NOFOLLOW` protection for the database file itself.
  Date/Author: 2026-08-05 / Codex

- Decision: Increase the REPL process-test budget from 30 seconds to 120 seconds.
  Rationale: This test checks command behavior, not latency. The repository nextest configuration separately detects and stops real hangs.
  Date/Author: 2026-08-05 / Codex

## Outcomes & Retrospective

The release is in progress. This section will record the final tag, workflow run, publication results, and any recovery work.

## Context and Orientation

`Cargo.toml` contains `[workspace.package].version`, the single source of truth. `node scripts/release-version.mjs sync` copies that value into committed agent, editor, package, and documentation metadata. The RC branch is `dave/v0.8.22-rc`. The release tag is `v0.8.22`. Pushing that tag starts `.github/workflows/release.yml`.

The release process requires all RC fixes and version projections to exist on `master`. Therefore, after validation and an RC commit, apply the release preparation commit to `master`, push `master`, and return to the RC branch before tagging its validated commit.

## Plan of Work

First run the installed `bifrost.code-smells` policy pack against the unchanged branch. Then edit only the workspace version in `Cargo.toml` and run the version synchronization script. Regenerate Codex and Amp skill bundles. Run all release metadata checks and package tests.

Run the repository pre-push gate. It performs formatting, featureless workspace tests, doctests, and all-feature workspace clippy checks. Run comprehensive tests through the uv Python 3.12 environment with `--features nlp,python`. Use the isolated Cargo target helper for large validation when applicable, so it removes temporary artifacts.

Run the same policy selection after all changes. Review the diff and commit only the release files and this ExecPlan with a multiline checkpoint message. Push the RC branch. Apply the same release preparation commit to `master`, push it, return to the RC branch, and confirm commit identity. Create the annotated `v0.8.22` tag on the validated RC commit and push the tag. Monitor the resulting Release workflow through its validation and promotion result.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/710d/bifrost`.

Use the Bifrost MCP `run_policy` tool with `policy_packs` set to `bifrost.code-smells`, `evaluation_date` set to `2026-08-05`, and `fail_on` set to `warning`.

Set `[workspace.package].version` in `Cargo.toml` to `0.8.22`, then run:

    node scripts/release-version.mjs sync
    node scripts/release-version.mjs check
    node scripts/generate-codex-skill-bundle.mjs
    node scripts/generate-amp-skill-bundle.mjs
    node scripts/check-codex-plugin-manifest.mjs
    node --test plugins/bifrost-agent/test/*.test.mjs

Run the release validation commands documented by the repository. Record exact pass or failure output in this plan.

After validation, commit and push the RC changes. Synchronize the same commit to `master`. Then run:

    git tag -a v0.8.22 -m "Release v0.8.22"
    git push origin refs/tags/v0.8.22

Use GitHub CLI commands to locate and monitor the Release workflow for the pushed tag.

## Validation and Acceptance

The synchronized metadata check must report success. Plugin manifest checks and Node tests must pass. The pre-push gate and comprehensive `nlp,python` tests must complete without failures. The final policy run must complete reliably and add no findings to the recorded baseline.

The local RC branch and `origin/dave/v0.8.22-rc` must name the same validated commit. The release preparation change must also exist on `origin/master`. The annotated `v0.8.22` tag must name the RC commit. GitHub must show the Release workflow for this tag. Publication status must come from that workflow, not an inference from the tag push.

## Idempotence and Recovery

Version synchronization and bundle generation are safe to repeat. Validation commands are safe to repeat. Do not move or recreate the release tag after publication starts. If a workflow job fails, use GitHub's rerun-failed-jobs action on the same workflow run. If a new run is necessary, dispatch the same tag. Do not use a different branch, commit, or tag for partial-release recovery.

## Artifacts and Notes

Initial RC commit:

    809464f1cfba290f2326d3cfa13fede3caa26d29

Initial workspace version:

    version = "0.8.21"

## Interfaces and Dependencies

The release uses `scripts/release-version.mjs` for version projection, the generated bundle scripts for agent artifacts, `scripts/pre-push-gate.sh` for the main Rust gate, uv with Python 3.12 for PyO3-linked tests, and `.github/workflows/release.yml` for publication. No application API changes are part of this release preparation.

Plan update note: Created the plan at release start to record the branch point, required validation, master synchronization, immutable tagging, and workflow monitoring. Updated it after validation found macOS disk checks, Cargo pin synchronization, mixed Rust toolchain, cache path, and test-budget defects.
