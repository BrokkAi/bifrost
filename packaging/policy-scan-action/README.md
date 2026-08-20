# Bifrost Policy Scan

Run [Bifrost](https://bifrost.brokk.ai) static-analysis policies in GitHub
Actions and upload the SARIF report to GitHub code scanning. Findings appear
as pull-request annotations, and the job gates on a strict exit-code
contract: `0` is clean, `1` is findings at or above the `fail-on` threshold,
and `2` is unreliable — a run that could not prove its own completeness and
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
compatibility. Pin an exact tag (`@v0.10.4`) for reproducible gates; the
floating major tag (`@v0`) follows the newest release.

## Documentation

Inputs, outputs, diff-aware gating (`diff-base`), committed baselines for
legacy repositories, caching, and suppression formats are documented at
[CI Gating with GitHub Actions](https://bifrost.brokk.ai/ci-github-actions/).

## Source

This repository is a generated alias, synced on every release from the
canonical action at
[`BrokkAi/bifrost/.github/actions/policy-scan`](https://github.com/BrokkAi/bifrost/tree/master/.github/actions/policy-scan).
Do not open pull requests here; changes belong in
[BrokkAi/bifrost](https://github.com/BrokkAi/bifrost).
