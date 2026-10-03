# Bifrost Policy Scan

Run [Bifrost](https://bifrost.brokk.ai) static-analysis policies in GitHub
Actions and upload the SARIF report to GitHub code scanning. Findings appear
as pull-request annotations, and the job gates on a strict exit-code
contract: `0` is clean, `1` is a policy gate failure (a finding at or above
the `fail-on` threshold or an orphaned suppression decision), and `2` is
unreliable — a run that could not prove its own completeness and
must never be treated as clean.

## Quick start

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

## Versioning

Each Bifrost release publishes a matching `vX.Y.Z` tag here, and that tag's
`version` input defaults to the same Bifrost release, so the action and the
binary it installs stay in lockstep — including policy and RQL syntax
compatibility.

`@v0` follows the newest release and is what the quick start above uses. Pin
an exact tag when a gate has to stay reproducible:

```yaml
      - uses: BrokkAi/bifrost-policy-scan@v0.10.4
```

The pinned example names the release this copy of the action was published
for, so it is always a tag that exists.

## Documentation

Inputs, outputs, diff-aware gating (`diff-base`), committed baselines for
legacy repositories, caching, and suppression formats are documented at
[CI Gating with GitHub Actions](https://bifrost.brokk.ai/ci-github-actions/).

Incremental policy evidence reuse is on by default, including for `diff-base`
scans. Set `full-evaluation: true` to pass `--no-incremental` and evaluate the
full request for comparison. The action forwards this existing Bifrost CLI
control and does not implement a separate slicing algorithm.

The `cache` input defaults to `true` and persists Bifrost's standard
`.bifrost/cache` analyzer store. A workspace nested in a checkout uses the
primary Git repository root; a nested Git repository uses its own root. GitHub
cache snapshots are scoped to runner OS, architecture, Bifrost version, exact
binary build identity, and working-directory identity. Each invocation saves
under a fresh immutable key after a qualified report, including when it
restored a compatible snapshot. Only exhaustive `complete` policy-run reports
publish cache snapshots; reliable but non-exhaustive `proven_subset` and
`proven_by_summary` reports do not.

The exit-code contract is strict: `0` is a clean completed scan, `1` is a
completed policy-gate failure, and `2` is unreliable and must never be treated
as clean.

## Source

This repository is a generated alias, synced on every release from the
canonical action at
[`BrokkAi/bifrost/.github/actions/policy-scan`](https://github.com/BrokkAi/bifrost/tree/master/.github/actions/policy-scan).
Do not open pull requests here; changes belong in
[BrokkAi/bifrost](https://github.com/BrokkAi/bifrost).
