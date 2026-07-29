# Gate release publication behind one validated promotion DAG

This ExecPlan is a living document. Maintain it according to `.agents/PLANS.md`.

## Purpose / Big Picture

A `vX.Y.Z` tag currently starts three independent GitHub Actions workflow runs. That permits crates.io or PyPI publication before the command-line archives and agent-plugin package have completed their release checks. After this change, one `Release` workflow run captures the exact commit selected by the tag, builds and validates every artifact, and permits each external publication only after a single promotion-evidence job succeeds. Operators can inspect one summary to see completed targets and safely retry a failed job without changing source revisions.

## Progress

- [x] (2026-07-29 08:10Z) Inspected the clean issue branch, refreshed `origin`, and diagnosed the independent tag triggers.
- [x] (2026-07-29 08:25Z) Chose a parent-run artifact topology so reusable publishers download artifacts produced in the same workflow run.
- [x] (2026-07-29 08:50Z) Added immutable release-commit output, parent workflow concurrency, and commit-pinned checkouts.
- [x] (2026-07-29 08:50Z) Split build/validation jobs from publication, added the promotion-evidence gate, and made crate/wheel publishers reusable.
- [x] (2026-07-29 08:50Z) Added ordering fixture, CI invocation, release summary, and contributor documentation.
- [x] (2026-07-29 09:45Z) Ran focused and full quick-policy Node tests, release metadata validation, YAML parsing, whitespace validation, and the live tag guard against `origin`. The required Bifrost code-smell scan completed but is unreliable because five repository-wide performance rules exhausted their discovery budget; it reported no findings in this change's files.
- [x] (2026-07-29 10:25Z) Repaired the PR Quick Policy `zizmor` template-injection findings by environment-binding reusable-workflow inputs before shell execution. The local Actions audit reported no findings and the full quick-policy Node suite passed 41/41.

## Surprises & Discoveries

- Observation: GitHub Actions artifacts are shared between jobs in one workflow run, while separate workflow runs require an explicit run identifier and token. Reusable-workflow jobs execute as part of the caller's run, so the parent can build once and publishers can download those artifacts.
  Evidence: GitHub Actions artifact documentation states that artifacts share data between jobs in the same workflow run.
- Observation: the current `validation_ref` permits both agent-plugin smoke jobs to check out something other than the release tag.
  Evidence: `.github/workflows/release.yml` uses `inputs.validation_ref || needs.release-context.outputs.tag` at the two smoke checkouts.
- Observation: the installed Bifrost policy engine cancelled three full `bifrost.code-smells` evaluations instead of returning findings or a clean report.
  Evidence: every `run_policy` request on 2026-07-29 returned `policy evaluation cancelled` after approximately five seconds.
- Observation: `actions/checkout` can resolve an unqualified ref to a same-named branch before a tag.
  Evidence: post-implementation security review identified that a `vX.Y.Z` branch could otherwise become the exported release commit; the workflow now uses `refs/tags/<tag>` and compares `HEAD` to that tag's commit.
- Observation: a workflow-text fixture that searches the whole file can mistake the release-summary fan-in for the promotion gate.
  Evidence: architecture review showed that the first fixture would still pass if a prerequisite moved from `promotion-evidence` to `release-summary`; the fixture now extracts the exact job block.
- Observation: `zizmor` treats reusable-workflow inputs interpolated directly into `run:` as attacker-controllable code.
  Evidence: PR #1308 Quick Policy reported 11 code-injection findings in `.github/workflows/publish-crate.yml` and `.github/workflows/publish-wheels.yml`; moving the values into job environment variables made the repository audit clean.

## Decision Log

- Decision: Make `release.yml` the sole tag and manual-dispatch entrypoint; make registry publishers callable workflows only.
  Rationale: `needs` relations do not cross independent workflow runs, so this is the smallest topology that makes the ordering enforceable.
  Date/Author: 2026-07-29 / Codex
- Decision: Resolve the checked-out commit once in `release-context.yml` and pass that SHA to every source checkout.
  Rationale: a tag name can be retargeted after validation; a commit SHA cannot, which satisfies the exact-source requirement.
  Date/Author: 2026-07-29 / Codex
- Decision: Build wheel/sdist, crate package evidence, editor package, Pi package, and plugin smoke artifacts before the gate; publish them after it.
  Rationale: packaging is release evidence, not publication. This avoids rebuilding a differently validated artifact after a GitHub Release exists.
  Date/Author: 2026-07-29 / Codex
- Decision: Keep the existing release artifact names and add only `pi-package` and `vscode-package` workflow artifacts for the deferred attachment jobs.
  Rationale: stable artifact names preserve existing download contracts, while the two new names make package validation explicit and avoid attaching anything before the gate.
  Date/Author: 2026-07-29 / Codex
- Decision: Accept only an unqualified `vX.Y.Z` input and check out `refs/tags/<tag>` before exporting the immutable SHA.
  Rationale: an unqualified checkout can select a same-named branch before a tag, which would make a branch commit appear to be the release source.
  Date/Author: 2026-07-29 / Codex
- Decision: Keep the separate GitHub Pages documentation workflow outside this package-release promotion DAG.
  Rationale: issue #1274 explicitly scopes package and marketplace publishers and its existing docs contract permits a docs-only manual correction. The release fixture is therefore named to cover package publication only, rather than incorrectly claiming every repository workflow is a release child.
  Date/Author: 2026-07-29 / Codex
- Decision: Recheck the remote tag-to-commit binding at the promotion gate and immediately before every registry, Marketplace, or GitHub Release mutation.
  Rationale: a captured SHA alone cannot prevent a force-moved tag from receiving validated artifacts or being used as a registry release identity. `scripts/verify-release-tag-commit.sh` handles annotated and lightweight tags through `git ls-remote`.
  Date/Author: 2026-07-29 / Codex
- Decision: Split VS Code release-asset attachment from Marketplace publication.
  Rationale: one job result cannot report whether a partial failure occurred before or after the asset upload. Separate gated jobs make retry instructions and the release summary accurate.
  Date/Author: 2026-07-29 / Codex
- Decision: Bind `tag`, `version`, and `commit` reusable-workflow inputs into job-level environment variables and reference only quoted shell variables from `run:` scripts.
  Rationale: GitHub expression expansion occurs before the shell parses a script. The environment boundary avoids interpreting an input as shell syntax while preserving the validated immutable identity.
  Date/Author: 2026-07-29 / Codex

## Outcomes & Retrospective

The workflow now has one package-release entrypoint, captures an immutable tag commit, and waits for common build/package/smoke evidence before every scoped external publication. Security and intent reviews found and the implementation fixed tag shadowing/retargeting, unsafe reusable-input shell interpolation, and ambiguous VS Code partial-publication reporting. The focused release fixture passed 7/7 tests; the full quick-policy selection passed 41/41 tests; the local `zizmor` Actions audit reported no findings; `node scripts/release-version.mjs check`, Ruby YAML parsing, `git diff --check`, and a live `v0.8.7` remote-tag guard passed. The Bifrost policy MCP tools were not registered in the final task after the fix, so a fresh full-pack result could not be obtained; the earlier run was already unreliable from five repository-wide performance checks exhausting discovery budgets.

## Context and Orientation

`.github/workflows/release.yml` is the current binary and plugin release workflow. `.github/workflows/publish-crate.yml` and `.github/workflows/publish-wheels.yml` independently trigger from the same tag; that is the defect. `.github/workflows/release-context.yml` is already reusable and validates tag/version metadata, but it only exposes tag and version. `.github/workflows/rust-notices.yml` creates the notice artifact consumed by binary and wheel builds.

The parent workflow is the YAML file that owns the user-visible tag trigger. A reusable workflow is a YAML file with `on.workflow_call`; the parent invokes it as a job. A promotion gate is a no-side-effect job whose `needs` list expresses that all build, package, and smoke evidence succeeded. Artifacts are uploaded files that later jobs in the same workflow run download; callers and their reusable workflows share that run.

`scripts/github-actions-policy.test.mjs` demonstrates the lightweight `node:test` convention for workflow-text assertions. `.github/workflows/ci.yml` runs those tests in its `quick-policy` job. `CONTRIBUTING.md` documents the existing three-workflow fan-out and must describe the replacement process.

## Plan of Work

First extend `release-context.yml` so its validation job writes a `commit` output using the commit checked out from the validated tag. Update its public reusable-workflow outputs. In `release.yml`, remove `validation_ref`, add a non-cancelling concurrency group keyed by the supplied tag, and use `needs.release-context.outputs.commit` for every source checkout. Tag strings remain for displayed asset names and version checks.

Refactor `release.yml` into validation and publication phases. Preserve all existing binary matrices and Node/Rust checks. Add a crate package-check job and call a reusable wheel-build workflow before a new `promotion-evidence` fan-in job. Split VS Code and Pi packaging/test work from their release uploads, and move the second agent-plugin smoke before the gate because it tests an artifact rather than a GitHub Release. The existing GitHub Release and all jobs that write to GitHub, registries, or a marketplace must explicitly need the gate. A final `always()` summary will render every target outcome and exact safe recovery guidance.

Create `.github/workflows/build-wheels.yml` as a callable workflow containing the present wheel matrix and sdist jobs, with `tag`, `version`, and `commit` inputs. Change `publish-wheels.yml` to a callable publish-only workflow that downloads those artifacts, repeats its final version filename defense, and preserves `environment: release` and `id-token: write`. Change `publish-crate.yml` similarly; its package-content check runs once in the parent validation phase, while the child keeps only exact-commit checkout, trusted publishing, environment protection, and publication.

Add a focused Node test that reads the release YAML files and asserts the public safety contract: one tag/manual entrypoint, callable-only publishers, immutable identity inputs, the promotion-gate dependencies, platform matrices, OIDC/environment permissions, and an always-run release summary. Add it to `quick-policy`, preserve the general immutable-action-pin policy test, and update the contributor release instructions.

## Concrete Steps

Run from `/Users/dave/.codex/worktrees/6851/bifrost`:

    node --test scripts/release-promotion-workflow.test.mjs scripts/github-actions-policy.test.mjs
    node scripts/release-version.mjs check
    git diff --check

The first command must report all release-topology tests passing. The second must confirm current generated release metadata is consistent. The diff check must print nothing and exit zero. GitHub-hosted runner jobs cannot be executed locally; the fixture is the local proof that later YAML edits retain the graph contract.

## Validation and Acceptance

The completed fixture must demonstrate that a tag can trigger only `release.yml`, and that `publish-crate.yml` and `publish-wheels.yml` are callable only. It must demonstrate a `promotion-evidence` dependency before GitHub Release, crates.io, PyPI, VS Code Marketplace, and agent-plugin publication; each publisher receives the same tag, version, and commit. The checked-in YAML must retain all seven CLI targets, five wheel targets plus sdist, crate package validation, both plugin smoke checks, release environment protection, and trusted OIDC publishing. The summary must run after failures and give same-tag/same-commit retry instructions.

## Idempotence and Recovery

The workflow never uses a later branch head: all source checkouts use the captured SHA. Re-running failed jobs in the same workflow run reuses its artifacts. Re-dispatching the same tag starts a new run from the same captured commit and does not overlap another run for that tag because workflow concurrency does not cancel in progress. Operators must not retry a partial release with a different tag or ref; the summary says so explicitly.

## Artifacts and Notes

The parent consumes artifact names already used by the release jobs: `bifrost-<target>`, `bifrost-agent-package`, wheel artifacts `wheels-<target>`, and `sdist`. New editor and Pi package artifacts must have release-specific names to avoid collisions. Existing release attachments remain named with the validated tag.

## Interfaces and Dependencies

At completion, `release-context.yml` exposes string outputs `tag`, `version`, and `commit`. `build-wheels.yml`, `publish-wheels.yml`, and `publish-crate.yml` expose `on.workflow_call.inputs` named `tag`, `version`, and `commit`, all required strings. The caller jobs invoke them with the three outputs from `release-context`; no child resolves a moving tag ref itself. Publishers retain their job-level `environment: release` and `permissions.id-token: write` declarations.

Plan revision 2026-07-29: created from issue #1274 diagnosis before implementation so the workflow topology, retry model, and validation proof remain explicit.

Plan revision 2026-07-29: recorded the final review fixes, validation evidence, and incomplete policy result so a future contributor does not mistake the full-pack limitation for a pass.

Plan revision 2026-07-29: recorded the Quick Policy template-injection repair and its clean local Actions audit, plus the final-task Bifrost MCP registration failure.
