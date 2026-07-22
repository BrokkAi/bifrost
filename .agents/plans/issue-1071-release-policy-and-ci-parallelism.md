# Consolidate release policy and shorten continuous integration

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current as work proceeds. This document is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost currently encodes the meaning of a release tag and its relationship to Cargo, Python, editor, and plugin metadata in several shell and JavaScript implementations. The binary and wheel workflows also duplicate the complete Rust notice-generation job. This makes releases harder to test locally and allows independently triggered publishing workflows to disagree about the release they are publishing.

After this work, one repository command will validate or synchronize every version projection, and all three release workflows will obtain a validated tag and version through the same reusable workflow. A second milestone will shorten pull-request feedback: inexpensive policy failures will stop the expensive jobs quickly, while Python and Rust platform tests will start together instead of placing the Python matrix after the full Rust matrix.

The observable result is that `node scripts/release-version.mjs check` succeeds locally only when Cargo, pyproject, and committed release projections agree. In GitHub Actions, the release workflows contain no inline Cargo/tag parsers, the two notice-producing release workflows call one shared job, the CI quick-policy job completes in under a minute, and Python jobs are no longer delayed until every Rust job completes.

## Progress

- [x] (2026-07-22 16:45Z) Inspected issue #1071, issue #1072, the release scripts, all release workflow dependency graphs, current branch protection/rulesets, and representative CI run timings.
- [x] (2026-07-22 16:45Z) Confirmed the clean current branch `1071-consolidate-release-workflow-policy-and-metadata-validation` is attached at the same commit as `origin/master` and its remote tracking branch.
- [x] (2026-07-22 16:56Z) Implemented the canonical release-version command and 11 focused/integration tests covering tag, manifest, projection, CRLF, and GitHub-output behavior.
- [x] (2026-07-22 16:56Z) Added reusable release-context and Rust-notice workflows and migrated the binary, crate, and wheel callers without changing their publishing boundaries.
- [x] (2026-07-22 17:18Z) Validated, reviewed, and checkpointed the release-policy milestone with focused tests, local tag/output smoke, projection idempotence, YAML parsing, `actionlint`, a direct-needs audit, and diff whitespace checks.
- [x] (2026-07-22 17:23Z) Replaced the serial repository-policy job with a quick gate plus parallel dependency-license and crate-package jobs.
- [x] (2026-07-22 17:23Z) Started Python and Rust matrices after the same quick gate while keeping each Rust target's clippy and tests together.
- [x] (2026-07-22 17:28Z) Validated and reviewed the final CI graph, including all local quick-gate commands, crate packaging, YAML parsing, `actionlint`, dependency audits, and diff checks; remote timing is intentionally deferred until an ordinary pushed CI run exists.

## Surprises & Discoveries

- Observation: The Bifrost MCP code-search tool is not bound to this desktop worktree.
  Evidence: `find_filenames` returned `Bifrost is not bound to a workspace`, so workflow/script navigation uses the skill's documented local `rg` fallback.

- Observation: The newly consolidated `repository policy` job is a slow serial lane, not a fast policy check.
  Evidence: master run `29938264614` spent 3 minutes 39 seconds installing license tools before the 12-second format check, then 2 minutes 47 seconds in crate packaging; the job lasted 7 minutes 48 seconds.

- Observation: Python has no artifact or data dependency on Rust despite `needs: rust`.
  Evidence: in successful run `29935145163`, all Python jobs checked out the repository, installed their own toolchain/cache, and started only after the slowest Rust matrix job ended. They added roughly 3 to 6 minutes to the workflow critical path.

- Observation: The broader Pi package suite is not currently runnable under the host's Node 24 even after `npm ci`.
  Evidence: 47 tests pass, while four unchanged suites fail resolving `@earendil-works/pi-ai/compat` from `@earendil-works/pi-coding-agent`. The release-version integration file itself passes in both the focused run and the broader invocation; CI pins Node 22.

- Observation: The system Ruby is 2.6, whose `YAML.load_file` does not accept the newer `aliases:` keyword.
  Evidence: the first generic syntax command failed on that argument; the compatible `YAML.load_file(path)` form parsed every workflow, and pinned `actionlint` 1.7.12 then validated their GitHub Actions semantics.

## Decision Log

- Decision: Deliver release consolidation and CI latency work as two milestones on the same issue branch.
  Rationale: The release command is exercised from CI policy, so coordinating the edits avoids temporary duplicated validation while retaining reviewable commits.
  Date/Author: 2026-07-22 / Codex and user.

- Decision: Keep issue #1072 out of this work.
  Rationale: Permissions, immutable Action pins, dependency-update automation, and workflow security tooling are a separate security-policy concern and should not be mixed into release semantics or timing changes.
  Date/Author: 2026-07-22 / Codex and user.

- Decision: Gate expensive CI jobs on a sub-minute policy job.
  Rationale: This adds a small delay to green runs but prevents platform runner expenditure when formatting or deterministic release metadata is already wrong.
  Date/Author: 2026-07-22 / Codex and user.

- Decision: Remove the Python-to-Rust dependency but keep clippy and tests together within each Rust target.
  Rationale: Python is independent and removes a measured tail. Separating clippy from tests would duplicate most target compilation for only a small additional wall-time improvement.
  Date/Author: 2026-07-22 / Codex and user.

- Decision: Use same-repository reusable workflows for release context and notice generation.
  Rationale: Release context is a job-level value shared across downstream jobs, while notice generation is already a complete job with its own runner and uploaded artifact. Reusable workflows preserve step-level logs and keep the callers declarative.
  Date/Author: 2026-07-22 / Codex.

## Outcomes & Retrospective

The release-policy implementation is locally complete. Eleven focused unit and subprocess tests pass; a real repository check, sync idempotence check, and tag/GitHub-output smoke pass; every workflow parses as YAML; the release jobs' direct output dependencies were audited; and `actionlint` 1.7.12 reports no findings. The only broad-suite caveat is the pre-existing Node 24 Pi dependency-resolution failure noted above; the affected release test passes independently and GitHub Actions uses Node 22. Remote release execution is deliberately deferred because these workflows publish artifacts.

The CI implementation is also locally complete. `quick-policy` contains only toolchain setup, formatting, the focused release-policy tests, and the read-only repository projection check. Every other CI job directly needs that gate, with Python and Rust becoming eligible at the same point. Dependency licenses and crate packaging are independent jobs; the latter reproduced the real package verification successfully at 8,199,282 bytes against its 10,000,000-byte budget. The matrix definitions, Rust clippy/test grouping, publishing surfaces, credentials, permissions, and Action versions are unchanged. A pinned final `actionlint` run reports no findings, and a programmatic graph audit confirms all non-gate jobs depend directly on `quick-policy`. The next ordinary pushed run will provide the remote wall-clock comparison to the 7-minute-48-second policy baseline and the previous Python tail; no workflow was dispatched from this implementation session.

## Context and Orientation

`Cargo.toml` is the committed version source. `pyproject.toml` must inherit that value through `project.dynamic = ["version"]` rather than declaring its own version. `scripts/sync-release-version.mjs` currently copies the Cargo version into literal JSON, README, and documentation projections. `scripts/check-release-version.mjs` checks one Cargo-versus-release value, while `scripts/resolve-release-tag.sh` separately parses a tag. Inline `grep` and `sed` implementations in `.github/workflows/publish-crate.yml` and `.github/workflows/publish-wheels.yml` repeat the same policy.

`.github/workflows/release.yml` builds and publishes binary, VS Code, agent-plugin, and Pi artifacts. `.github/workflows/publish-wheels.yml` builds and publishes Python distributions. `.github/workflows/publish-crate.yml` publishes the Rust crate. These remain separate callers because their build matrices, publishing credentials, environments, and retry boundaries are intentionally independent.

`.github/workflows/ci.yml` currently has one `repository-policy` job that installs two expensive license tools before formatting, release-script tests, and crate packaging. Its `python` matrix declares `needs: rust`, even though every Python job rebuilds independently with its own cache key.

A reusable workflow is a workflow file whose `on` section contains `workflow_call`; another workflow invokes it as one job. A caller may consume outputs only by listing the called job as a direct `needs` dependency. Therefore every release job that reads the validated tag or version must list `release-context` directly even if it already depends on another downstream job.

## Plan of Work

Milestone 1 introduces `scripts/release-version.mjs`. Its `check` command accepts optional `--tag` and `--github-output` options, validates the `v`-prefixed semantic version, scopes Cargo version extraction to the root `[package]` section, rejects a static pyproject project version, requires `version` in the pyproject dynamic list, and confirms every projection currently managed by the sync script. When all checks pass, it writes `tag` and `version` outputs if requested. Its `sync` command performs the current projection updates, preserving line endings and the rule that VS Code archive checksums are copied only when the canonical plugin release metadata already matches the Cargo version.

The old tag resolver, version checker, and sync command are removed. Their tests become one release-version suite, while `plugins/bifrost-agent/test/sync-release-version.test.mjs` continues to exercise the command as a subprocess on CRLF fixtures. `CONTRIBUTING.md` changes its pre-release and validation examples to `node scripts/release-version.mjs sync` and `node scripts/release-version.mjs check`.

Add `.github/workflows/release-context.yml` with one required string input named `tag` and two outputs named `tag` and `version`. It checks out that tag, sets up Node 22, and invokes the canonical check command with a GitHub output path. Add `.github/workflows/rust-notices.yml` with one required string input named `ref`; it performs the existing pinned Rust/cargo-about/fetch/generate/upload sequence and always publishes the existing `rust-third-party-licenses` artifact.

Migrate the three release callers. Each starts with `release-context`, passes `${{ inputs.tag || github.ref_name }}`, and checks out or names artifacts with the validated outputs. Binary and wheel workflows call the shared notice workflow after release context. Remove every repeated Resolve tag step and both inline manifest parsers. The wheel publication artifact-name guard uses the validated version output rather than stripping a tag again. The metadata synchronization job checks out master and invokes the same canonical command with the validated tag, preserving its guard against applying an older release to a newer master.

Milestone 2 replaces `repository-policy` with three jobs. `quick-policy` installs only Node and rustfmt, then runs formatting, release-version unit tests, and repository projection checking. `dependency-licenses` and `crate-package` both need `quick-policy` and execute the existing license/report and crate-package behavior independently. Every remaining job also needs `quick-policy`. The Pi matrix drops its redundant projection check. The Python matrix needs only `quick-policy`; the Rust matrix also needs only `quick-policy`. Existing matrix membership, features, cache keys, and `fail-fast: false` remain unchanged.

After each milestone, inspect the diff for accidental publishing, credential, permission, Action-version, or matrix changes. Update this document, stage only files owned by the milestone, and create a multiline checkpoint commit explaining the policy reason. Do not push or open a pull request without explicit user authorization.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/22e1/bifrost`.

For milestone 1, edit the release command, tests, documentation, and four workflow files. Then run:

    node --test scripts/release-version.test.mjs plugins/bifrost-agent/test/sync-release-version.test.mjs
    node scripts/release-version.mjs check
    npm test --prefix plugins/bifrost-agent
    ruby -e 'require "yaml"; Dir[".github/workflows/*.yml"].sort.each { |path| YAML.load_file(path); puts path }'
    git diff --check

After review, stage only the milestone-1 files and commit them with the ExecPlan checkpoint.

For milestone 2, edit `.github/workflows/ci.yml`, update the ExecPlan, and run:

    node --test scripts/release-version.test.mjs plugins/bifrost-agent/test/sync-release-version.test.mjs
    node scripts/release-version.mjs check
    cargo fmt --check
    scripts/check-crate-package.sh
    ruby -e 'require "yaml"; Dir[".github/workflows/*.yml"].sort.each { |path| YAML.load_file(path); puts path }'
    git diff --check

Review the final workflow graph and commit only the CI and updated plan files. If push authorization is later granted, inspect one resulting CI run to confirm Python and Rust jobs become eligible after the same quick gate and to compare wall-clock duration against the recorded baseline.

## Validation and Acceptance

The release-version test suite must cover tag input both as `v1.2.3` and `refs/tags/v1.2.3`, invalid or missing `v`, malformed semantic versions, Cargo mismatch, unrelated TOML version keys, pyproject static version rejection, missing dynamic inheritance, a drifted committed projection, CRLF-preserving sync, and output-file emission only after a successful check.

`node scripts/release-version.mjs check` must print a success message naming the Cargo version and make no repository changes. `sync` followed by `check` must be idempotent on a synchronized fixture. Searches must show no remaining `resolve-release-tag`, `check-release-version`, `sync-release-version`, inline `tag#v`, or inline Cargo `grep`/`sed` parser in release workflows.

The release workflow diff must leave platform matrices, artifact patterns, publishing actions, environments, permissions, secrets, and the ordering between validation, publication, smoke testing, and metadata synchronization unchanged except for the added early validation dependency.

The CI workflow must have a single short prerequisite path and then fan out. A quick-policy failure must skip expensive jobs. On a green run, license validation, crate packaging, Rust, Python, editor, plugin, and fixture jobs must all become eligible after quick policy. Python must not contain `needs: rust`. Rust clippy and tests must remain in the same target job.

## Idempotence and Recovery

The check command is read-only. The sync command compares serialized content before writing and can be run repeatedly; a second run must report that metadata is already synchronized. Fixture tests create and remove their own temporary directories. Reusable workflows do not publish anything by themselves; they only validate context or upload a notice artifact inside a caller run.

If a migration test fails, retain the old script until the new command reproduces the behavior, then remove it in the same milestone. Do not dispatch any release workflow for validation because successful jobs publish externally. Workflow syntax is validated locally, and full execution is observed only through ordinary CI or the next deliberately created release.

## Artifacts and Notes

The baseline timing evidence comes from GitHub Actions runs `29938264614` and `29935145163`. No branch-protection status checks currently depend on the `repository policy` job name; the active master ruleset only prevents deletion and non-fast-forward updates.

## Interfaces and Dependencies

`scripts/release-version.mjs` exposes these command-line forms:

    node scripts/release-version.mjs check [--tag TAG] [--github-output PATH]
    node scripts/release-version.mjs sync

It uses only Node built-ins and introduces no package dependency. Its importable functions cover tag normalization, Cargo package-version reading, pyproject inheritance validation, projection collection, check, and sync so unit tests exercise policy without shelling out.

`.github/workflows/release-context.yml` accepts `tag: string` and emits `tag: string` plus `version: string`. `.github/workflows/rust-notices.yml` accepts `ref: string` and emits the fixed Actions artifact `rust-third-party-licenses`. Neither reusable workflow accepts secrets or elevates permissions.

Revision note (2026-07-22): Initial implementation-ready plan recorded after live repository, issue, workflow, and Actions timing inspection.
