# Add impact-aware CI validation with a merge-queue full matrix

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It is maintained in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

Pull requests currently wait for the same cross-platform test matrix regardless of whether they change a Rust analyzer, an RQL policy, a VS Code grammar, or the agent plugin. After this work, every pull request still receives one CI workflow and an always-on baseline, but a checked-in classifier selects the smallest relevant validation set. Merge-queue commits and pushes to `master` always run the existing full matrix. The CI run’s Step Summary makes the decision and command durations observable.

## Progress

- [x] (2026-07-29 08:00Z) Inspected #1273, the clean issue branch, the current CI workflow, existing policy checks, and the live master ruleset.
- [x] (2026-07-29 08:00Z) Confirmed the user wants workflow-only delivery: expose the stable aggregation status but do not alter the master ruleset.
- [x] (2026-07-29 06:10Z) Added and tested the versioned classifier, checked-in path fixtures, and cross-platform timing wrapper.
- [x] (2026-07-29 06:10Z) Restructured CI around `ci-impact`, canonical all-feature Linux linting, selected host/policy jobs, merge-queue full selection, and `PR verification` aggregation.
- [x] (2026-07-29 06:10Z) Passed the Node policy suite, locked Actions security scan, YAML parsing, pinned actionlint, JavaScript syntax checks, Rust formatting, and whitespace validation.
- [x] (2026-07-29 06:10Z) Attempted the required built-in policy-pack MCP validation; the installed server exposes `run_policy` only and does not expose the required `list_policies` discovery tool, so this cannot be reported as a policy-pack pass.
- [x] (2026-07-29 06:20Z) Gated Rust-dependent and matrix-heavy selected jobs on lint while retaining direct Node-only feedback after `quick-policy`; the combined workflow suite passed 34 tests.
- [x] (2026-07-31 09:25Z) Added the missing generic PR fallback for ordinary Rust analyzer/tests, Python package/tests, Python bindings, policy/MCP integration tests, and external-fixture provenance while preserving full merge-queue/master selection and fail-closed unknown paths.

## Surprises & Discoveries

- Observation: The live `master` ruleset prevents deletion and non-fast-forward updates but has no required status checks.
  Evidence: `gh api repos/BrokkAi/bifrost/rulesets/18574277` returned only `deletion` and `non_fast_forward` rules.

- Observation: The existing full matrix contains five Rust targets and three Python targets, all behind `quick-policy`.
  Evidence: `.github/workflows/ci.yml` defines five Rust matrix entries and three Python matrix entries.

- Observation: The installed Bifrost MCP server is missing `list_policies`.
  Evidence: the available MCP surface contains `mcp__bifrost__run_policy` but no `mcp__bifrost__list_policies`; the policy-checking contract requires both tools before a clean policy result can be claimed.

- Observation: Deleted pull-request paths must participate in impact selection.
  Evidence: the first classifier command used `--diff-filter=ACMR`, which omitted deletions; it was corrected to `--diff-filter=ACMRD` and guarded by a classifier source test.

- Observation: The initial implementation never added the planned generic analyzer/test/build fallback, so any ordinary analyzer or Python path forced full mode.
  Evidence: applying the classifier to PR #1383 selected all twelve components; after adding the generic mappings, the same 55 paths select only Rust, Python, RQL runtime, MCP/LSP contracts, policy-pack, and VS Code validation.

## Decision Log

- Decision: Use a repository-owned Node classifier rather than a third-party changed-files Action.
  Rationale: Node is already installed by CI, the mapping needs focused fixture tests, and a local implementation avoids a second trust boundary.
  Date/Author: 2026-07-29 / Codex and user.

- Decision: Force full selection for unknown paths and failures to obtain the pull-request diff.
  Rationale: A classifier error must spend extra CI time rather than silently remove meaningful validation.
  Date/Author: 2026-07-29 / Codex and user.

- Decision: Leave branch/ruleset configuration out of this implementation.
  Rationale: The user selected workflow-only delivery after inspecting the live ruleset.
  Date/Author: 2026-07-29 / Codex and user.

- Decision: Treat deleted paths as ordinary changed paths rather than forcing all deletions to full mode.
  Rationale: A deletion of an RQL, host, editor, or plugin file has the same ownership as its modification, while unmapped deletions still force full validation.
  Date/Author: 2026-07-29 / Codex.

- Decision: Make canonical all-feature linting a prerequisite for Rust-dependent and matrix-heavy jobs, but not editor or agent-plugin Node checks.
  Rationale: A Clippy failure must stop expensive matrix allocation, while editor and plugin authors should retain feedback that does not depend on Rust linting.
  Date/Author: 2026-07-29 / Codex and user.

- Decision: Keep merge groups and `master` pushes full, but map ordinary pull-request Rust source/tests to the Rust matrix and Python package/tests to the Python matrix.
  Rationale: The user wants full post-merge validation while avoiding unrelated package, plugin, provenance, and license lanes on pull requests. Python binding changes select both matrices; policy/MCP integration tests and external fixtures retain their owning specialized checks plus Rust coverage. Cargo manifests, workflows, resources, build inputs, and unknown paths remain fail-closed full.
  Date/Author: 2026-07-31 / Codex and user.

## Outcomes & Retrospective

The implementation adds a versioned, fixture-tested impact classifier and a timing wrapper, then uses them to make the CI fast lane observable and safe. After adding generic Rust and Python pull-request mappings, the final combined Node suite passed 57 tests, locked zizmor reported no findings, and pinned actionlint reported no workflow diagnostics. YAML parsing, Rust formatting, release-version consistency, and whitespace validation also passed. Canonical all-feature lint now fails before any Rust-dependent or matrix-heavy selected job starts, while VS Code and agent-plugin checks retain direct quick-policy feedback. The built-in `bifrost.code-smells` pack completed in 4.5 seconds but returned `unreliable`: two whole-workspace policies exhausted their execution budgets, and the remaining findings are pre-existing and outside the three changed files. No clean policy result is claimed. A normal pushed PR is still needed to observe the GitHub-hosted timing summaries and a merge-queue run is needed to observe GitHub’s merge-group event.

## Context and Orientation

`.github/workflows/ci.yml` is the required repository CI workflow. It currently runs on every pull request and master push, starts with the short `quick-policy` job, and fans out to platform, packaging, editor, plugin, fixture, and license jobs. A GitHub Actions merge group is the temporary commit GitHub builds before a queued pull request is merged; it must run the full matrix because it can contain more than one pull request.

The new `scripts/ci-impact.mjs` is a Node command with no package dependencies. It compares a pull request’s base and head commits, classifies changed repository paths, writes boolean component outputs for Actions job conditions, and writes a human-readable summary. The new `scripts/ci-timing.mjs` wraps a check command, keeps its exit status, and records elapsed milliseconds in its job summary. The scripts’ Node tests and text fixtures live under `scripts/` so the path decisions are reviewable and executable without GitHub Actions.

## Plan of Work

First add the classifier and fixture tests. The classifier owns schema version `1`, a fixed set of component keys, and a default-full rule. It recognizes RQL/structural/policy work, code-intelligence runtime work, MCP work, LSP work, editor work, and agent-plugin work before applying the generic analyzer/test/build fallback. A merge queue or master push selects every component directly and does not depend on a diff. A failed pull-request diff likewise selects every component.

Next add the timing wrapper and rewrite CI around an always-running `ci-impact` job. `quick-policy`, Linux all-feature linting, and `PR verification` run on all events. Conditional jobs depend on both `ci-impact` and `quick-policy`; the classifier makes all existing components true in the full mode. Focused RQL, MCP, LSP, and policy jobs provide the fast checks selected by their specific paths. `PR verification` uses `always()` and fails when an always-on or selected job did not finish successfully.

Finally, wrap substantive check commands with the timing helper, add raw-workflow policy tests, and run the safe local validation commands. Do not dispatch the workflow or change GitHub ruleset settings; a normal pushed run is the production timing and merge-queue proof.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/747f/bifrost`.

    node --test scripts/ci-impact.test.mjs scripts/ci-timing.test.mjs scripts/ci-impact-workflow.test.mjs
    node --test scripts/github-actions-policy.test.mjs scripts/release-version.test.mjs plugins/bifrost-agent/test/sync-release-version.test.mjs
    bash scripts/check-github-actions-security.sh
    ruby -e 'require "yaml"; Dir[".github/workflows/*.yml"].sort.each { |path| YAML.load_file(path); puts path }'
    actionlint
    git diff --check

The first command proves the classifier fixtures and timing helper. The workflow policy test must prove the unconditional PR and merge-queue triggers. The security, YAML, actionlint, and whitespace commands must all exit successfully. A failed command is fixed and rerun; no CI workflow is manually dispatched because merge-queue behavior requires GitHub’s own event payload.

## Validation and Acceptance

The fixture test must show that a Cargo, workflow, unknown, or diff-error path selects every component; an RQL path selects runtime, MCP, LSP, policy-pack, and VS Code checks; runtime and host paths select their corresponding contracts; and editor/plugin paths do not expand to the full matrix. The workflow test must prove that `pull_request` has no `paths` filter, `merge_group` is enabled, canonical all-feature lint is always present, and the stable aggregation job validates selected result states.

After a normal PR run, its Step Summary must list schema version, classification mode, changed paths, selected components, and elapsed command timings. A merge-queue or master run must list full mode and every current Rust/Python platform job. The status is exposed as `CI / PR verification`; enabling it in a ruleset is an explicitly deferred repository-administration task.

## Idempotence and Recovery

The classifier and its tests are deterministic for a supplied path list. If Git history cannot supply a pull-request diff, the classifier deliberately returns full mode instead of retrying with an unsafe empty result. Re-running the local tests and static workflow validation does not modify source files. Reverting the workflow and scripts together restores the former unconditional full pull-request fan-out without touching external state.

## Artifacts and Notes

The classifier’s action interface uses one output per component plus `schema_version`, `mode`, and comma-separated `selected`. The aggregator consumes the boolean outputs and the downstream job results, so a skipped unselected job is acceptable but a skipped selected job is a failure. Step summaries are the timing record; GitHub Actions retains them alongside the command logs for later path-map refinements.

## Interfaces and Dependencies

`scripts/ci-impact.mjs` exports `SCHEMA_VERSION`, `COMPONENTS`, and `classifyChangeSet({ eventName, ref, changedPaths, diffFailed })`. The function returns the selected component set, mode, reasons, and changed paths. Its CLI accepts `--event`, `--ref`, `--base`, `--head`, `--output`, and `--summary`; it writes Actions outputs and a Markdown summary.

`scripts/ci-timing.mjs` accepts `--label LABEL -- command [args...]`. It runs the command without a shell, preserves the exit code, prints a machine-readable elapsed-millisecond line, and writes a Markdown timing row when `GITHUB_STEP_SUMMARY` is set. Both interfaces use only Node built-ins and the existing Git executable available in checkout jobs.

Revision note (2026-07-29): Created the implementation plan from the accepted #1273 design, the current CI workflow, and the user’s workflow-only ruleset decision.

Revision note (2026-07-29): Recorded the implemented classifier/workflow design, passing local validation, and the unavailable `list_policies` MCP validation surface.

Revision note (2026-07-29): Recorded final 33-test, zizmor, YAML, actionlint, formatting, and whitespace evidence after adding deleted-path coverage.

Revision note (2026-07-29): Added the lint dependency boundary requested during implementation and recorded 34-test, zizmor, YAML, actionlint, and whitespace validation.

Revision note (2026-07-31): Added the missing generic PR path mappings, kept merge-queue/master behavior unchanged, and used PR #1383 plus narrow analyzer, Python, binding, and external-fixture cases as behavior-focused regressions.

Revision note (2026-07-31): Recorded the 57-test validation result and the built-in policy pack's whole-workspace execution-budget limitation before publishing the follow-up PR.
