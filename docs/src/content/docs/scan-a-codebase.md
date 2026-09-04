---
title: Scan a Codebase
description: Run a Bifrost policy scan from the terminal and read the human report, in about five minutes.
---

Bifrost's scan is a policy evaluation: the CLI indexes your workspace, runs
the selected static-analysis policies against the resulting code model, and
prints one report. There is no separate `scan` subcommand -- the scan is the
`--policy` family of flags on the `bifrost` binary, and the zero-configuration
form is one line:

```bash
bifrost --root /path/to/project --policy
```

This page walks that command over a small checked-in fixture and reads the
results. For the full flag reference see [CLI](/cli/), for the policy language
and execution model see
[Static-Analysis Policies](/static-analysis-policies/), and for running the
same scan as a pull-request gate see
[CI Gating with GitHub Actions](/ci-github-actions/).

## Get the fixture

Install Bifrost by following [Install Bifrost](/install/), or build the
current checkout with `cargo build --bin bifrost`. The tutorial project is
checked into the Bifrost repository:

```bash
git clone https://github.com/BrokkAi/bifrost.git
cd bifrost/docs/fixtures/scan-tutorial
```

It is a two-file Python tool that summarizes access-log lines. Both files
contain deliberate, realistic mistakes:

- `src/settings.py` deserializes operator input with `pickle` and evaluates a
  configuration expression with `eval`.
- `src/report.py` compiles the same regular expression on every loop
  iteration.

## Run the scan

```bash
bifrost --root . --policy
```

The first run indexes the workspace, so it takes longer than the reruns.
The report this prints is real output from the fixture above:

```text
[warning]  src/settings.py:12:12
    Replace dynamic evaluation with explicit parsing or dispatch

[warning]  src/settings.py:8:16
    Replace pickle deserialization with a data-only format

[note]  src/report.py:9:19
    Review whether this lexically nested regex compilation repeats per iteration

policy bifrost.security.java.servlet-parameter-to-jdbc diagnostic: [note; advisory] empty_selection: taint policy `bifrost.security.java.servlet-parameter-to-jdbc` bound no sink endpoint: its sink selectors matched no location in the scanned workspace, so this run reports zero findings vacuously rather than proving that no flow exists
policy bifrost.security.java.servlet-parameter-to-jdbc diagnostic: [note; advisory] empty_selection: taint policy `bifrost.security.java.servlet-parameter-to-jdbc` bound no source endpoint: its source selectors matched no location in the scanned workspace, so this run reports zero findings vacuously rather than proving that no flow exists
summary: 3 active findings; 0 suppressed findings; dependency packs: mode default; complete; ecosystems python; 17 complete policy runs
```

Each finding is one block: a severity, the `file:line:column` of the exact
expression, and the policy's remediation advice. Read the report bottom-up:

- The **summary line** is the contract for the whole run. It counts active
  findings, suppressed findings, the semantic dependency packs that were
  activated (here the Python ecosystem pack, selected automatically), and how
  many policies ran to completion. A policy that could not complete is never
  silently dropped: it changes the process status instead (see below).
- The **advisory diagnostics** are Bifrost being honest about vacuous
  results. A built-in Java taint policy matched nothing in this Python-only
  workspace, so its clean result proves nothing, and the report says so
  instead of letting the empty result masquerade as verified absence.
- The two `warning` findings gate the run by default; the `note` on the regex
  compilation is a review prompt and does not.

Add `--verbose` for policy IDs, suppression provenance, and the complete
finding records; add `--format json` or `--format sarif` for machine-readable
versions of the same canonical report.

## Fix the smells and re-run

`src/report.py` compiles its regex on every loop iteration. Hoist it to a
module constant:

```python
PATTERN = re.compile(r"^(?P<user>\w+) (?P<path>\S+) (?P<ms>\d+)$")


def summarize(lines):
    entries = []
    for line in lines:
        match = PATTERN.match(line)
```

In `src/settings.py`, replace `pickle.loads` with a data-only format
(`json.load`) and replace the `eval` call with explicit parsing of the one
comparison shape the tool actually supports.

Run the same command again. The vacuous-taint advisories repeat -- the
workspace still contains no Java -- and the summary line now ends in `clean`:

```text
summary: 0 active findings; 0 suppressed findings; dependency packs: mode default; complete; ecosystems python; 17 complete policy runs; clean
```

The findings are gone from the report because the code changed, not because
anything was suppressed or configured.

## Exit codes are the gate

The scan is designed to be scripted. `echo $?` after a run gives one of three
statuses:

| Status | Meaning |
| --- | --- |
| `0` | Every requested policy completed and no active unsuppressed finding met the `--fail-on` threshold. |
| `1` | Every requested policy completed and at least one active unsuppressed finding met the threshold. |
| `2` | The batch is unreliable -- a policy, suppression, schema, evaluation, or output failure. Never read status 2 as clean. |

The default threshold is `--fail-on warning`. The tutorial scan above exits
`1` while the two warnings are present (the regex `note` alone would not
gate) and `0` once they are fixed.

## Where to go next

- Select policies explicitly with `--policy-pack`, `--policy-category`, and
  `--policy-id`, or run your own `.rqlp` files with `--policy-file` --
  [CLI](/cli/).
- Gate pull requests on only the findings they introduce with
  `--diff-base` -- [CLI](/cli/#gate-only-on-new-findings---diff-base---no-incremental).
- Emit `--format sarif` and upload to GitHub code scanning with the reusable
  action -- [CI Gating with GitHub Actions](/ci-github-actions/).
- Accept a reviewed finding with a suppressions file instead of deleting the
  code -- [Static-Analysis Policies](/static-analysis-policies/).
- Write a policy of your own --
  [Build a Rule](/build-static-analysis-rule/).
