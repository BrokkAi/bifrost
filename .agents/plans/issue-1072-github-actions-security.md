# Harden GitHub Actions permissions and dependency provenance

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current as work proceeds. This document is maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost's validation and publishing workflows currently obtain permissions and third-party code through policies that are partly implicit. The live repository default gives `GITHUB_TOKEN` write access, while the pull-request CI workflow does not override it. Every external Action is referenced through a movable tag or branch, so an upstream tag move could change code that runs in CI or alongside release credentials without a Bifrost diff.

After this work, pull-request jobs will have only read access, publishing privileges will exist only on jobs that require them, external Actions will be immutable full commit hashes with readable release comments, and checkout credentials or webhook secrets will not remain available outside the steps that need them. The existing fast `quick-policy` job will run one deterministic zizmor security audit rather than adding another serial job. A contributor can prove the policy locally with one repository script and a generic Node test.

The user explicitly does not want Dependabot or Renovate update pull requests. Pin enforcement will therefore be automatic, while advancing a healthy pin will remain deliberate reviewed maintenance. The final handoff will also list the exact external Action repositories needed for GitHub's allowlist, comma separated in a Markdown block.

## Progress

- [x] (2026-07-22 19:42Z) Fetched issue #1072 and audited all eight workflows, event boundaries, permissions, external Actions, caches, secrets, reusable callers, and relevant history.
- [x] (2026-07-22 19:42Z) Confirmed live repository settings use default write permissions, allow all Actions, and do not require SHA pins.
- [x] (2026-07-22 19:42Z) Ran zizmor 1.28.0 against the unmodified workflows and grouped its medium/high findings: mutable Action refs, inherited permissions, persisted checkout credentials, and publishing cache reuse.
- [x] (2026-07-22 19:42Z) Agreed with the user to omit Dependabot/Renovate and enforce a pinned offline zizmor policy instead.
- [x] (2026-07-22 19:42Z) Re-synchronized branch `brokk/issue-1072-harden-github-actions-permissions` to `origin/master` at `38b3bedb` before implementation.
- [x] (2026-07-22 19:55Z) Resolved and verified the immutable commit corresponding to all nineteen currently selected external Action repositories and recorded readable upstream refs beside every pin.
- [x] (2026-07-22 19:55Z) Applied least-privilege permissions, credential isolation, Slack secret scoping, privileged-cache removal, setup-node cache disabling, and immutable Action pins across all eight workflows.
- [ ] Add the local/CI zizmor command, readable-pin policy test, and contributor-facing security documentation.
- [x] (2026-07-22 19:55Z) Validated Milestone 1 with zizmor, YAML parsing, release-policy tests, the benchmark workflow policy test, rustfmt, immutable-ref search, and diff checks.
- [ ] Validate the complete workflow surface and checkpoint each milestone.
- [ ] Run the five guided specialist reviews, triage findings, and prepare the reviewed branch for a pull request.

## Surprises & Discoveries

- Observation: The missing CI permission block is exploitable policy, not merely style.
  Evidence: the GitHub API reports `default_workflow_permissions: write`, and `.github/workflows/ci.yml` runs pull-request-controlled Cargo, npm, Node, and Python code without a `permissions` override.

- Observation: The repository source contains no immutable external Action reference.
  Evidence: zizmor reports `unpinned-uses` for the full workflow surface, and a line inventory finds only mutable aliases such as `@v6`, `@stable`, and `@release/v1`.

- Observation: One security scanner covers the issue without materially lengthening the quick gate.
  Evidence: a cold isolated installation and offline run of zizmor 1.28.0 completed in about five seconds. `--strict-collection` makes malformed inputs fail, and `--min-severity medium` focuses the gate on actionable findings.

- Observation: `actions/setup-node@v6` may enable package-manager caching without an explicit `cache` input.
  Evidence: its checked-in `action.yml` defines `package-manager-cache: true` by default when a package manager is declared. Publishing and deployment workflows must set that input to false, not merely remove explicit cache lines.

## Decision Log

- Decision: Use one enforced scanner, zizmor 1.28.0, in offline regular mode with strict collection and a medium-severity threshold.
  Rationale: zizmor directly detects the observed permission, pinning, credential-persistence, and cache-poisoning classes. Offline mode is deterministic and does not expose a token to the scanner. Actionlint remains an independent final validation rather than a second maintained CI dependency.
  Date/Author: 2026-07-22 / Codex and user.

- Decision: Do not add Dependabot, Renovate, a scheduled updater, or a custom pin-update bot.
  Rationale: the user prioritizes a quiet review queue. CI will reject mutable or malformed pins, while version comments and documented commands keep intentional manual updates reviewable. This deliberately changes the issue's original automatic-advancement criterion into automatic enforcement plus manual advancement.
  Date/Author: 2026-07-22 / user.

- Decision: Require each non-local `uses:` entry to pair a forty-character lowercase hexadecimal commit with a readable upstream ref comment.
  Rationale: zizmor proves immutability but does not require a human-readable version. A generic test can preserve this review surface without duplicating an exact Action list or order.
  Date/Author: 2026-07-22 / Codex.

- Decision: Remove caches from publication/deployment trust boundaries rather than suppressing cache-poisoning findings.
  Rationale: releases are infrequent, and accepting a slower trusted build is preferable to consuming artifacts that a lower-trust workflow might have populated. CI and benchmark caches remain because they do not feed a privileged publisher.
  Date/Author: 2026-07-22 / Codex.

- Decision: Leave repository-level Action settings unchanged during branch implementation.
  Rationale: changing default token permissions or enabling mandatory SHA pins is an external administrative mutation. The code change will make both settings safe to enable, then the final handoff will request separate authorization.
  Date/Author: 2026-07-22 / Codex.

## Outcomes & Retrospective

Milestone 1 is complete. All existing Action dependencies now execute at verified immutable commits; workflows default to read-only permissions; publishing OIDC is scoped to the crate publish job; and checkout credentials, release caches, setup-node caches, the benchmark Slack webhook, and the metadata-push token now follow their narrow trust boundaries. Zizmor reports no medium-or-higher findings, all eight YAML files parse, eleven release-policy tests and two benchmark-policy tests pass, rustfmt is clean, the mutable-ref search prints nothing, and `git diff --check` passes.

The first Rust test attempt exhausted the nearly full local disk during a cold compile. The repository cleanup helper removed only its reviewed older-than-24-hours Bifrost temporary candidates, skipped newer/live/open directories, and freed enough space for the unchanged command to pass. This was an environment limitation rather than a source failure. Milestone 2 and specialist review remain.

## Context and Orientation

GitHub Actions workflow files live under `.github/workflows/`. `ci.yml` handles pushes to `master` and pull requests; its `quick-policy` job is a short prerequisite for all expensive validation. `benchmark.yml` runs only on a schedule or manual dispatch and may notify Slack. `docs.yml` builds documentation on pull requests and deploys Pages only for trusted events. `release.yml`, `publish-crate.yml`, and `publish-wheels.yml` publish binaries, plugins, the Rust crate, and Python packages from validated release tags. `release-context.yml` and `rust-notices.yml` are local reusable workflows called by the publishers.

An Action is external code named by a `uses:` line such as `actions/checkout@v5`. A tag such as `v5` can move; a full forty-character Git commit hash cannot be changed without producing a different hash. A trailing comment records the reviewed human version while the executable reference remains immutable. Local reusable workflows use a repository path beginning with `./` and do not need a hash.

`GITHUB_TOKEN` is a per-job repository token created by GitHub. A workflow-level `permissions` block supplies a safe default, and a job-level block replaces that default for a job that publishes or deploys. `id-token: write` permits OpenID Connect, abbreviated OIDC, which lets crates.io, PyPI, or Pages exchange a short-lived identity for publishing access without a long-lived password.

`actions/checkout` normally saves its Git credential in repository configuration so later `git push` commands work. Most jobs never push, so they must set `persist-credentials: false`. The one metadata synchronization job that pushes to `master` will also disable persistence and provide `GH_TOKEN` only to the final commit/push step, where `gh auth setup-git` supplies an ephemeral credential helper.

Zizmor is a static analyzer for GitHub Actions. The new repository script will invoke the exact PyPI release `zizmor@1.28.0` through `uvx`, require parse/schema collection to succeed, report findings of medium severity or higher, and run offline. In CI, its GitHub output format creates annotations without needing Advanced Security or a writable security-events token.

## Plan of Work

Milestone 1 hardens the workflow trust boundaries. Resolve every currently selected symbolic Action ref against its authoritative upstream repository, verify the resulting commit, and replace all occurrences with the full hash plus an exact readable comment. Do not use this security change to upgrade Action majors. Add `contents: read` workflow defaults where missing and preserve the existing job-local `contents: write`, `pages: write`, and OIDC grants. Move crate OIDC to the publish job. Disable checkout credential persistence everywhere, then give only the metadata commit step an ephemeral `GH_TOKEN` credential helper.

In the same milestone, remove `Swatinem/rust-cache` from crate and binary publishing paths. Disable setup-node's automatic package-manager cache in docs and release jobs, including jobs that do not currently spell out a `cache` input. Keep caching in read-only CI and the scheduled benchmark. Move the Slack webhook out of `benchmark.yml`'s job environment: a trusted shell step should expose only a boolean availability output, payload preparation should use that output, and only the Slack Action should receive the webhook value. Extend `tests/benchmark_workflow_policy.rs` to protect that secret boundary without asserting unrelated workflow layout.

After Milestone 1, run the generic pin audit manually, YAML parsing, the benchmark policy test, and zizmor. Inspect the diff for accidental event, matrix, artifact, publishing, environment, or secret-name changes. Update this ExecPlan and create a checkpoint commit containing only the workflow hardening, benchmark policy test, and plan.

Milestone 2 makes the policy durable. Add `scripts/github-actions-policy.test.mjs`, whose repository test enumerates workflow YAML files, ignores local `./` references, and rejects any external `uses:` line that lacks a lowercase forty-character hash or a readable original-ref comment. Test its parser with representative valid and invalid lines rather than hard-coding current Actions. Add `scripts/check-github-actions-security.sh` as the single local entry point for the pinned offline zizmor invocation; it should emit GitHub annotations only when `GITHUB_ACTIONS=true`.

Pin `astral-sh/setup-uv` in `ci.yml`, install it in `quick-policy` with caching disabled, add the generic Node policy test to the existing inexpensive test invocation, and run the security script before expensive jobs fan out. Extend `SECURITY.md` with the immutable-reference rule, local command, manual reviewed-update policy, and narrowly justified publishing/deployment exceptions. Do not add `.github/dependabot.yml`.

After Milestone 2, run the full validation set, update the plan, and create a second checkpoint. Then compute the final diff from `origin/master` and run the guided security, duplication, intent, DevOps, and architecture reviewers in parallel. Fix validated findings, rerun affected checks, and checkpoint review remediation before publication.

## Concrete Steps

Run every command from `/Users/dave/.codex/worktrees/22e1/bifrost`.

Before editing, resolve each distinct external `owner/repository@ref` to a commit through the GitHub API or `git ls-remote`. Verify the hash belongs to the named repository and determine the most specific release tag that points to it. Replace repeated occurrences consistently. A representative result looks like:

    uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v5.0.0

For Milestone 1 validation, run:

    node --test scripts/release-version.test.mjs plugins/bifrost-agent/test/sync-release-version.test.mjs
    cargo test --test benchmark_workflow_policy
    ruby -e 'require "yaml"; Dir[".github/workflows/*.yml"].sort.each { |path| YAML.load_file(path); puts path }'
    uvx "zizmor@1.28.0" --offline --strict-collection --min-severity medium .
    git diff --check

The first three commands must pass. The initial zizmor baseline fails; after Milestone 1 it should report no medium-or-higher findings except a temporary failure for the still-unpinned setup-uv step if that step is added only in Milestone 2.

For Milestone 2 and final validation, run:

    node --test scripts/github-actions-policy.test.mjs scripts/release-version.test.mjs plugins/bifrost-agent/test/sync-release-version.test.mjs
    bash scripts/check-github-actions-security.sh
    cargo fmt --check
    cargo test --test benchmark_workflow_policy
    actionlint
    ruby -e 'require "yaml"; Dir[".github/workflows/*.yml"].sort.each { |path| YAML.load_file(path); puts path }'
    git diff --check

Also search for any surviving symbolic external reference:

    rg -n '^\s*uses:\s*[^./][^@]*@(?![0-9a-f]{40}(?:\s+#\s+\S+)?)' .github/workflows --pcre2

The search must print nothing. Do not dispatch release, crate, wheel, or Pages workflows as validation because successful executions publish externally.

## Validation and Acceptance

The implementation is accepted when a pull request executes `quick-policy` with `contents: read`, persistent checkout credentials disabled, no release secret, and a passing offline zizmor audit before any expensive job starts. The generic Node test must fail on a fixture using `actions/checkout@v5`, fail on a bare hash without a version comment, pass on a full hash with a readable comment, and ignore `./.github/workflows/release-context.yml`.

Every workflow must state a read-only default. Only jobs that create GitHub Releases or update release attachments, deploy Pages, request crates.io or PyPI OIDC, or synchronize generated metadata may elevate permissions. The crate validation job must not receive OIDC. The benchmark webhook must not exist in job-level environment state. Every checkout except no checkout at all must disable persisted credentials, including the metadata checkout; only its final push step receives `GH_TOKEN`.

Zizmor must collect the entire repository strictly and report zero findings at medium severity or above. Actionlint must report no workflow syntax, expression-type, dependency, or injection finding. The release-policy and benchmark-policy tests must remain green. The final diff must not change triggers, matrices, artifact names, release tags, publishing destinations, environment names, secret names, or application code.

## Idempotence and Recovery

All checks are read-only. Re-running the pin replacement is safe because identical upstream refs must map to identical hashes. If an upstream ref cannot be resolved or its commit cannot be tied to the named repository, stop for that Action rather than substituting a guessed hash.

The security script uses a versioned temporary `uvx` environment and does not write project dependencies. Zizmor runs without `--fix`, so it cannot edit workflows. If a broad scanner finding is a false positive, prefer changing the workflow to make the trust boundary explicit. Add a narrow documented suppression only when the behavior is demonstrably safe; never lower the global severity threshold merely to obtain green CI.

Release cache removal changes performance only and can be reversed by a reviewed cache design that proves untrusted runs cannot populate keys consumed by publishers. Repository-level Actions settings remain untouched until after this branch is merged and the user separately authorizes the external mutation.

## Artifacts and Notes

The unmodified offline zizmor 1.28.0 medium/high baseline grouped findings into four classes:

    artipacked             Medium   persisted checkout credentials
    cache-poisoning        High     caches feeding publishing/deployment paths
    excessive-permissions  Medium   inherited CI and workflow-wide crate OIDC
    unpinned-uses          High     mutable external Action references

The live GitHub settings at diagnosis time were:

    default_workflow_permissions: write
    allowed_actions: all
    sha_pinning_required: false

These settings are evidence for the branch changes, not permission to mutate repository administration.

## Interfaces and Dependencies

`scripts/check-github-actions-security.sh` is a Bash entry point with no arguments. It requires `uvx`, invokes exactly zizmor 1.28.0, runs offline with strict collection and a medium minimum severity, and selects `github` output format only inside GitHub Actions.

`scripts/github-actions-policy.test.mjs` uses Node built-ins only. It exports or locally tests a helper that classifies a single `uses:` line and runs one repository test over `.github/workflows/*.yml`. External refs must match a full lowercase hexadecimal commit and a nonempty readable comment; local refs beginning with `./` are exempt.

The only new CI dependency is `astral-sh/setup-uv`, itself pinned to a verified full commit with a readable version comment. No updater service, secret, new job, security-events permission, or package manifest entry is introduced.

Revision note (2026-07-22): Initial implementation-ready plan recorded after the live issue diagnosis, user approval of the no-bot policy, current zizmor baseline, and final pre-implementation synchronization with `origin/master`.
