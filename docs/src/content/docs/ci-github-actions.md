---
title: CI Gating with GitHub Actions
description: Run Bifrost policies in CI and show findings as pull-request annotations through GitHub code scanning.
---

Bifrost ships a reusable GitHub Action that runs static-analysis policies and uploads the SARIF report to GitHub code scanning. GitHub then shows each finding as a pull-request annotation and tracks alert lifecycle across runs.

## Quick start

Add one workflow file:

```yaml
name: bifrost-policies

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: BrokkAi/bifrost-policy-scan@v0
```

The default configuration installs the pinned Bifrost release, selects `bifrost.code-smells` from the host catalog, writes `bifrost-policy.sarif`, uploads it, and gates on the exit code. The [v0.13 external-content follow-up](#versioned-external-content-v013-follow-up) replaces the earlier embedded-pack assumption; acquisition failure is a failed gate, not a clean scan.

On most real code, some policies in the pack end `inconclusive`: `contradictory-condition`, for example, when it cannot decide a condition, and the Python absent-member policies when the Python standard-library pack is not active. The gate lists each inconclusive policy as a warning annotation and in the job summary, and it passes when no finding crosses `fail-on`. An inconclusive policy that reports nothing proves nothing, so read the warnings before you rely on that policy. A policy that fails, or a pack that fails to load, still fails the gate with exit `2`. [Scan a Codebase](/scan-a-codebase/) explains these cases and shows how to gate on selected policies.

## Versioning

Every Bifrost release publishes a matching `vX.Y.Z` tag of the action to [BrokkAi/bifrost-policy-scan](https://github.com/BrokkAi/bifrost-policy-scan), and that tag's `version` input defaults to the same Bifrost release. The action version and the binary it installs therefore stay in lockstep, including policy and RQL syntax compatibility. Pin an exact tag (for example `@v0.10.4`) for reproducible gates; the floating major tag (`@v0`) follows the newest release. The long form `BrokkAi/bifrost/.github/actions/policy-scan@vX.Y.Z` remains equivalent.

The `security-events: write` permission is required for the SARIF upload. Code scanning must be available on the repository.

## Exit codes

The gate distinguishes three results:

- `0` - clean. No finding crossed `fail-on`, and every policy gave a verdict. An `inconclusive` verdict counts: the run could not prove there is nothing more to find, which is common in static analysis. The job passes, and each inconclusive policy appears as a warning annotation and in the job summary.
- `1` - findings at or above the `fail-on` threshold, or an orphaned suppression record: an accepted suppression whose file the run analyzed but whose finding no longer exists. An orphaned record gives `1` even with `fail-on: never`. A finding from an inconclusive run gates too. The job fails and the findings appear as code-scanning alerts.
- `2` - unreliable. Part of the scan gave no verdict: the run stopped at its deadline, a report diagnostic is an error, report diagnostics were truncated, a policy run failed or was unsupported, an explicitly requested policy could not run, or a `proven_subset` run found nothing to gate. The job fails with a distinct message. Do not treat an unreliable run as clean, and do not lower `fail-on` to hide it. Read the report diagnostics instead.

These are the statuses [SlopCop](https://slopcop.com) gives the same report: `0` is its `clean`, with inconclusive policies listed but not counted as incomplete; `1` is its findings status; and `2` is its `incomplete`, a check that timed out, failed, or was unreliable.

Set `on-inconclusive: unreliable` to fail the job with exit `2` on any inconclusive run that gated no finding, as Bifrost before v0.14.4 did. The input passes `--on-inconclusive unreliable` to the CLI. A policy that declares `(on-unknown :verdict warn-unreliable)` or `(on-unknown :verdict fail-closed)` keeps its own handling under either value.

The [policy reference](/reference/policies/#exit-status) gives the complete exit-status rules.

## Scan error diagnostics

CLI-generated SARIF records the policy status in
`runs[].invocations[].exitCode`, with an `exitCodeDescription`. Status `1`
means the finding gate fired; it does not by itself mean the analyzer failed.
Unreliable analysis keeps `executionSuccessful: false`, including when an
explicit policy setting changes how an unknown verdict gates CI. An
`inconclusive` run is a verdict, so it keeps `executionSuccessful: true` and
is reported as a `warning` notification, unless `--on-inconclusive
unreliable` made the exit status 2.

Detailed diagnostic identifiers live in
`runs[].invocations[].toolExecutionNotifications[].descriptor.id`. Use these
stable identifiers for automation; message wording can change. There are two
kinds:

- A report diagnostic uses its canonical JSON diagnostic `code` as the
  identifier, for example `policy-load-failed`, `suppression-load-failed`, or
  `diff-base-unreliable`. The
  [report diagnostic codes](/reference/policies/#report-diagnostic-codes) table in the policy
  reference gives the meaning and next step for every code.
- A policy run whose completion is not `complete` adds one notification.
  `BIFROST_REPORT_DIAGNOSTICS_TRUNCATED` means some report diagnostics did not
  fit in the report.

| Completion | Notification ID | Meaning |
| --- | --- | --- |
| `proven_subset` | `BIFROST_POLICY_PROVEN_SUBSET` | Every retained finding is proven, but the run searched only part of the program. Reliable, not exhaustive. With no gated finding, the run exits `2`. |
| `proven_by_summary` | `BIFROST_POLICY_PROVEN_BY_SUMMARY` | The result rests on authored external procedure summaries. Reliable, not exhaustive. Exits `0` or `1`. |
| `inconclusive` | `BIFROST_POLICY_INCONCLUSIVE` | The run could not prove there is nothing more to find. Advisory: exits `0` or `1` on its findings. Exits `2` under `on-inconclusive: unreliable` unless the policy's `on-unknown` verdict says otherwise. |
| `not_run` | `BIFROST_POLICY_NOT_RUN` | A required capability was unavailable. Implicit pack/category/default selections do not affect the exit status; an explicit policy ID exits `2`. |
| `unsupported` | `BIFROST_POLICY_UNSUPPORTED` | The policy needs a capability that this analyzer lacks. Exits `2`. |
| `failed` | `BIFROST_POLICY_FAILED` | Evaluation failed. Exits `2`. |

The [completion states](/reference/policies/#completion-states) table in the
policy reference lists the reasons for each state.


Notifications also retain policy identity, completion reasons, and diagnostic
source details in `properties`. A notification can be advisory: its identifier
alone is not a failure verdict. An empty findings list under incomplete
coverage does not establish that the code is clean.

To inspect a downloaded report:

```bash
jq '.runs[].invocations[] | {exitCode, exitCodeDescription, executionSuccessful, toolExecutionNotifications}' bifrost-policy.sarif
```

The report-only library renderer omits process status because a report alone
does not contain the CLI threshold decision. Library callers with a
`PolicyBatchOutcome` can use `write_policy_sarif_for_outcome` to include it.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | pinned release tag | Bifrost release to install. Pin an exact tag for reproducible gates. The value `local` installs nothing: the action uses `target/release/bifrost`, then `target/debug/bifrost` from the checkout, then a `bifrost` on `PATH`. |
| `packs-source` | pinned public source | JSON repository/version and rules/semantic descriptor pins; optional digest-bound HTTPS inventory. See [versioned external content](#versioned-external-content-v013-follow-up). |
| `packs-token` | empty | Existing private repository read secret, restricted to trusted push or workflow-dispatch acquisition. When empty, the job's `github.token` authenticates API reads of a source outside the workflow's repository. |
| `packs-cache` | `true` | Restore and save verified external content for this source and actual engine profile. Disabled when `packs-token` is set. |
| `packs-offline` | `false` | Require verified cached external content without network access; a cache miss fails. |
| `policy-packs` | `bifrost.code-smells` | Space-separated pack IDs from the selected host catalog. When unset, the default applies only if you set no `policy-ids` or `policy-categories`. |
| `policy-ids` | empty | Space-separated policy IDs. |
| `exclude-policy-ids` | empty | Space-separated built-in policy IDs to skip after the selection inputs resolve. Each must be selected by them, and at least one policy must remain. |
| `policy-categories` | empty | Space-separated categories. |
| `policy-files` | empty | Space-separated workspace-relative `.rqlp` files. |
| `fail-on` | `warning` | Severity gate: `never`, `finding`, `note`, `warning`, or `error`. |
| `diff-base` | empty | Git revision to diff against. Only findings absent from that revision gate. |
| `full-evaluation` | `false` | Disable incremental evidence reuse and pass `--no-incremental` for a full evaluation. |
| `sarif-file` | `bifrost-policy.sarif` | SARIF output path, relative to `working-directory`. |
| `policy-timings` | `false` | Collect per-policy timings; requires a runner supporting `--policy-timings`. |
| `artifact-name` | empty | Upload the SARIF report as an artifact before gating; use a unique name per scan. |
| `upload` | `true` | Upload the SARIF file to code scanning. |
| `category` | `bifrost-policy` | Code-scanning category. Use one category per scan configuration. |
| `cache` | `true` | Restore and save the analyzer cache between runs. |
| `working-directory` | `.` | Workspace root to analyze, relative to the checkout. |

The four selection inputs become `--policy-pack`, `--policy-id`,
`--policy-category`, and `--policy-file` flags. When you leave `policy-packs`
unset, the action passes `bifrost.code-smells` only if you set no `policy-ids`
or `policy-categories`. This has these effects:

- Values within one input form a union. Different catalog selectors
  intersect. An explicit `policy-packs` value intersects with `policy-ids` and
  `policy-categories`: a `policy-ids` value outside those packs selects nothing,
  and the action fails. Its log names the `policy-packs`, `policy-categories`,
  and `policy-ids` values that matched nothing.
- To run a policy from another pack, set `policy-ids` or `policy-categories`
  and leave `policy-packs` unset.
- When the default pack applies, `policy-files` runs beside it. Set
  `policy-packs: ''` to run only your files.
- If `policy-packs` is `''` and every other selection input is empty, the run
  evaluates every pack in the selected catalog.
- Opt-in policies, such as the declared-storage family, run only when
  `policy-ids` names them.
- `exclude-policy-ids` removes policies after the selection inputs intersect,
  and it keeps every other member of the selected packs, including members
  added in later releases. For example, with the default pack,
  `exclude-policy-ids: bifrost.correctness.python-absent-member` runs the other
  code-smells policies. An excluded ID that the selection does not select, an
  unknown ID, and an exclusion that removes every policy each fail the run with
  exit status 2. This is a selection control, not a suppression: use
  `.bifrost/suppressions.json` for individual findings.

See [Policy selection](/reference/policies/#policy-selection) in the policy
reference.

The action exposes these outputs for later steps:

| Output | Meaning |
| --- | --- |
| `analyzer-cache-hit` | Whether an exact analyzer cache entry was restored; empty when caching is disabled. |
| `exit-code` | Raw bifrost policy exit code (0, 1, or 2). |
| `stderr-capture-code` | Status of the stderr log capture. `0` means the log was created and retained. |
| `sarif-file` | Path of the SARIF report, relative to the checkout. |
| `bifrost-bin` | Absolute path of the bifrost executable the run used. |
| `pack-selection-id` | Digest-bound external content selection identity, when acquisition ran. |
| `pack-cache-reused` | Whether an existing verified content selection was reused. This is not policy execution evidence. |

## Analyzer cache

With `cache: true`, the action restores and saves Bifrost's standard
`.bifrost/cache` store, the same store used by ordinary CLI and MCP scans. A
workspace nested in a checkout uses the primary Git repository root; a nested
Git repository uses its own root. The action sets `BIFROST_CACHE_DIR` to that
exact directory for the scan and clears an inherited `BIFROST_CACHE_ROOT`;
`cache: false` leaves both environment settings untouched. GitHub cache
snapshots are separated by runner OS, architecture, version, exact
compiled-input build identity, and working-directory identity.
Restore prefixes omit only the per-invocation suffix, so a snapshot from another
build or workspace is never restored. Bifrost still validates its schema and
analyzer epochs and keys stored content by Git blob identity.

GitHub cache entries are immutable. Each action invocation therefore uses a
fresh save key and can publish the cache state produced by its scan, even when
it restored a compatible earlier snapshot. Only a structurally valid SARIF
report with successful invocations, `complete` policy-run completion, and CLI
status `0` or `1` is saved. Reliable but non-exhaustive `proven_subset` and
`proven_by_summary` runs do not qualify. The qualification also checks execution
termination, report diagnostic completeness, and baseline qualification when
`diff-base` is set. Status `1` still represents a completed scan whose policy
gate found a violation; unreliable, malformed, or capture-failed runs do not
publish a snapshot.

Incremental evidence reuse is on by default, including for `diff-base` scans.
Set `full-evaluation: true` to pass `--no-incremental` and request a full
evaluation for comparison. The action forwards this existing CLI control; it
does not implement a separate slicing algorithm. A scan of the base branch
publishes policy units for that revision, so a later pull-request scan whose
`diff-base` is the same commit reuses them for its base evaluation when the
restored cache snapshot holds them; the SARIF run property `bifrost.incremental`
reports those counts as `base_units_reused` and `base_units_recomputed`.

The action logs execution, policy work, completeness, and incremental evidence
from its single SARIF scan. `policy-timings: true` adds per-policy timing details
and logs the runner's measured aggregate stage timings on stderr. Successful
canonical reports intentionally keep aggregate elapsed values at zero for
deterministic serialization; zero does not mean the scan did no work. For diff
scans, per-policy work describes the head evaluation. Aggregate stage timings
include baseline evaluation as `diff_base` when that phase is reached; the stderr
record then reports `scope: base_and_head` and `base_timing_included: true`.
`policy_work_scope` remains `head`. The retained stages show which phases were
measured; `base_and_head` does not imply that head evaluation ran if the request
stopped during baseline evaluation. Set `artifact-name` to retain the report and opt-in
stderr log even when the gate fails. This artifact upload is separate from code-scanning
upload and works for repositories without GitHub Code Security.

## New findings on pull requests

Code scanning compares the alerts from the pull-request analysis with the base branch and marks new alerts on the pull request. Upload from both the default branch and pull requests, with the same `category`, to get that comparison.

## Gate only on findings the pull request introduced

By default the gate fails on every finding, including pre-existing debt. To fail a pull request only on the findings it introduced, pass the pull request's base commit as `diff-base`. Bifrost then evaluates the same policies against that commit's content, classifies every finding as `new` or `persisting` by its stable finding identity, and computes the exit code from the new findings only. Each SARIF result carries the standard `baselineState` field (`new` or `unchanged`).

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: BrokkAi/bifrost-policy-scan@v0
        with:
          diff-base: ${{ github.event.pull_request.base.sha }}
```

The checkout must contain the base revision: `fetch-depth: 0` is the simple form, or fetch the base SHA explicitly. If the base revision does not resolve, the run exits `2` (unreliable) rather than silently gating on everything. If the base revision resolves but its evaluation reaches no verdict, the run degrades to full gating, reports a `diff-base-unreliable` diagnostic, and exits `2`, so a broken base can never hide new findings. A policy whose base run was only `inconclusive` gates every one of its head findings, including those that already existed, and reports a `diff-base-policy-unqualified` warning; it does not by itself make the run exit `2`.

With `cache` on, which is the default, the run stores what each policy concluded over the base revision and what every part of that evaluation read. A later run against the same base restores that cache, skips the base export and build, and recomputes only the parts of the pull request's tree whose inputs changed, so a pull-request run pays for its own change rather than for the whole base. `cache: 'false'` keeps nothing between runs, so every run evaluates both revisions in full. The report is the same either way: findings, identities, `baselineState` values, diagnostics, and the exit code do not depend on what the cache holds. Only the report's `incremental` section, which records what the run reused, and the run's own work counters differ.

Two identity limitations are accepted: a pure file rename re-keys every finding in the file (one `fixed` plus one `new`), and inserting an identical duplicate of an existing source slice above it under the same owner can shift the ordinal that distinguishes the duplicates and misclassify one pair. An edit also re-keys a finding when it changes the violating site's own source slice. For a typestate finding, an edit re-keys it when it changes the text of the declaration a locator sits in above that locator, the declaration path a locator names, or the policy's automaton. Adding a tracked object in another file does not. See [Gate Only On What The Change Introduced](/static-analysis-policies/#gate-only-on-what-the-change-introduced).

## Onboard a legacy repository with a committed baseline

`diff-base` narrows pull-request gates, but scheduled full runs and release gates still fail on every pre-existing finding. To accept the existing debt once and gate only on what appears afterwards, generate a baseline locally and commit it:

```bash
bifrost --root . --policy-pack bifrost.code-smells --accept-current
git add .bifrost/baseline.json
git commit -m "Accept existing bifrost.code-smells findings as the baseline"
```

`--accept-current` writes `.bifrost/baseline.json` from a completed run's strong finding identities under one batch-level reason; an unreliable run refuses to write and exits `2`. Every later CI run — full or `diff-base` — honors the committed document exactly as the CLI does: baselined findings stay in the report and the SARIF upload as accepted suppressions, stop gating, and are audited for drift (a policy edit) and staleness (a finding proven fixed). Keep the same selection (`policy-packs`, `policy-ids`, `policy-files`) in CI that you accepted locally, and regenerate explicitly when you intend to re-accept — the baseline never refreshes itself.

A recommended split for a legacy repository: pull requests gate with `diff-base` (findings the change introduced), while the scheduled full run and the release gate rely on the committed baseline (everything new since acceptance), burning the baseline down by fixing findings, which the audit then reports as stale entries to prune.

## Suppressions, scope, and baseline

The run honors the workspace's review files exactly as the CLI does: the suppression files `.bifrost/suppressions.json`, `.bifrost/suppressions.private.json`, and `.bifrost/suppressions.local.json`, read in that order; the scope file `.bifrost/policy-scope.json`; and the baseline `.bifrost/baseline.json`. The action has no input that overrides these paths. Accepted suppressions and baselined findings appear in the SARIF report as suppressed results. See [Static-Analysis Policies](/static-analysis-policies/) for how to use them and the [policy reference](/reference/policies/) for their formats and limits.

## Versioned external content (v0.13 follow-up)

The core engine has no default product rules. The updated action acquires rules
from a host-selected source and their exact semantic release dependency before
resolving `policy-packs`, `policy-ids` or `policy-categories` against that catalog.
A successful download or verified cache hit is not a clean scan or proof of
behavioral coverage. Policy results without a verdict retain the engine's exit
`2` contract and SARIF diagnostics.
Each invocation clears its SARIF and diagnostic output paths before binary or
content acquisition, so a failed acquisition cannot retain an earlier report.

The default public pin is rules `0.5.1`, descriptor SHA-256
`e607e5c360889805bf614ab05f96feda199f6ad3009d00f49158cd9f507ada6b`, with its semantic
dependency packs `0.6.0`, descriptor SHA-256 `dd8888f763f13732ede1f05a34c2bd205dad25705b3da967e9df949c14842570`.
Each Bifrost release requires the engine version that the action installs by
default to admit this exact pin before the release can ship. An action tag that
pins an older engine keeps the pin that it shipped with.

Set `packs-source` to a JSON object with a trusted GitHub `repository` URL,
exact semantic version `rules_version`, and the reviewed rules descriptor's
`manifest_sha256` plus `semantic_manifest_sha256` for its exact dependency descriptor. The repository must publish the existing `pack-release.json`
contract under `rules/vVERSION` and its exact semantic dependency under
`packs/vVERSION`. The wrapper pack identities remain `bifrost.public.rules` and
`bifrost.public.packs`; the policy catalog inside can define custom pack IDs.
The descriptor binds its clean source commit to the Git tag, indexes content
hashes, declares archive digests and pins its semantic dependency. The resolver
checks all declared schemas and capabilities against `bifrost pack-engine-profile`
from the actual scan binary, and requires qualified behavior before execution.
Before publishing a content cache, the action also reads the selected catalog
and rejects requirements absent from that actual profile.

```yaml
      - uses: BrokkAi/bifrost-policy-scan@v0
        with:
          packs-source: >-
            {"repository":"https://github.com/example/reviewed-packs",
             "rules_version":"1.2.3",
             "manifest_sha256":"REPLACE_WITH_REVIEWED_64_HEX_DESCRIPTOR_DIGEST",
             "semantic_manifest_sha256":"REPLACE_WITH_REVIEWED_64_HEX_DEPENDENCY_DIGEST"}
          policy-packs: my-reviewed-catalog
```

For a trusted HTTPS archive mirror, add `inventory_url` and `inventory_sha256`
to that object. The pinned inventory has `schema_version: 1` and a `releases`
array. Each record names `tag`, `tag_commit`, `prerelease`, `manifest_sha256`,
`manifest_url`, and `assets` mapping each declared archive filename to an object
with `url`. It must include the selected rules descriptor and its exact semantic
dependency. These are the existing release descriptors and tar.gz archive
contracts, not arbitrary source checkouts or raw policy folders. All descriptor
and archive URLs and redirects must remain on the inventory's HTTPS origin.
Repository sources permit only their GitHub API/release URLs and redirects to
GitHub's `release-assets.githubusercontent.com` or `objects.githubusercontent.com`
asset hosts. Authorization is sent only to the selected repository's GitHub API,
never to a redirect target. Without a credential, and always for the public
`BrokkAi/bifrost-packs` repository, descriptors and archives come from their
`github.com/.../releases/download/...` URLs, which GitHub's API rate limit does
not cover. The API asset form is used only for a credentialed read of another
repository, which may be private. Digests bind the content either way. Credentials, query strings and fragments are rejected
in configured URLs; transient signed GitHub asset redirects are never persisted.

An explicit `packs-source` takes precedence over caller-prepared roots and the
public pin. An invalid explicit selection fails without fallback. With no
explicit selection, a caller may supply both `BIFROST_OPEN_POLICY_PACK_ROOT` and
`BIFROST_OPEN_SEMANTIC_PACK_BUNDLE`; the engine validates those roots. A
policy-file-only scan with empty `policy-packs`, `policy-ids` and
`policy-categories` bypasses product acquisition. For example, set
`policy-packs: ''` and `policy-files: policies/team.rqlp`.

`packs-cache` defaults to `true` independently of the analyzer `cache` input.
The key binds the source/version/descriptor pin, the mirror inventory digest
when present, runner platform and full engine profile (build identity, model
set, schemas and capability contract). The saved suffix is the verified selection
ID, which also binds exact dependency descriptors and archive identities. Only
that source/profile prefix can restore; every restored descriptor, archive,
extracted file and selection receipt is reverified. Changes in source, version,
digests, dependencies or engine contracts invalidate reuse. Corrupt bytes fail
closed. Online runs refresh source descriptors; `packs-offline: true` forbids
network requests and fails on a missing verified selection. Negative selection
receipts never activate content and are never saved as successful content caches.
`pack-selection-id` and `pack-cache-reused` expose acquisition evidence separately
from policy results. Missing releases, authentication/404, network, malformed,
incompatible and unqualified content fail the action without manufacturing SARIF.

### GitHub API rate limits

Discovery lists the source's releases and tags through the GitHub API, then
reads each annotated release tag once to find its commit; lightweight tags
need no further request. Anonymous API requests share the runner IP address's quota of 60 an
hour, which pull-request scans on hosted runners can exhaust. When `packs-token`
is empty, the action therefore authenticates those reads with the job's
`github.token` on every event, pull requests from forks included. The job token
reads only the workflow's own repository and public ones, so the action uses it
only for a source outside the workflow's repository, where it can authenticate
public content only, and that content is still cached. The action does not send
it with a digest-bound HTTPS mirror, which makes no API requests, or on a GitHub
Enterprise Server, whose job token `api.github.com` does not accept.

A failed acquisition prints the receipt's failure class and message, for example
`Open-pack acquisition failed: unavailable (pack source rate limit reached)`.

### Private repositories

Use `packs-token: ${{ secrets.EXISTING_PACKS_READ_TOKEN }}` only in a trusted
`push` or explicitly approved `workflow_dispatch` workflow, with the immutable
reviewed action revision and source pin. The existing token needs **Contents:
read** on the selected source repository, including its releases. The caller's
`GITHUB_TOKEN` generally cannot read a different private repository. Repository
or protected-environment secrets are the supported mechanism; do not put tokens
in source URLs. This implementation creates no tokens, OAuth grants or persistent
credentials. If access is missing, a human must grant the existing credential
read access to that repository (and organization authorization if required), then
make it available as a secret to the trusted workflow/environment.

Private acquisition credentials are prohibited on all PR events, including
`pull_request_target`. Never run untrusted PR code in a privileged workflow.
The token is scoped to the acquisition step, withheld from the engine-profile
subprocess and policy execution, and absent from URLs, identities, receipts,
logs and SARIF. Authenticated content and its analyzer data are not saved to
Actions caches that a fork or PR could restore. Retained SARIF may still contain
private policy names or findings, so use the appropriate repository and artifact
access controls for those results.
