---
title: Scan a Codebase
description: Run a Bifrost policy scan from the terminal, read the human report, and gate on its exit status.
---

A Bifrost scan is a policy evaluation. The CLI indexes your workspace, runs
static-analysis policies against the code model, and prints one report. The
zero-configuration scan is one command:

```bash
bifrost scan /path/to/project
```

It runs the same policies as `bifrost --root /path/to/project --policy`, and it
also prints the identities of the built-in policy packs on stderr.

This page runs a scan over a small fixture, reads the report, and then gates on
selected policies. For every flag, see [CLI Reference](/reference/cli/). For
the policy language, see
[Static-Analysis Policies](/static-analysis-policies/). To run a scan as a
pull-request gate, see [CI Gating with GitHub Actions](/ci-github-actions/).

## Get the Fixture

Install Bifrost by following [Install Bifrost](/install/), or build the
current checkout with `cargo build --bin bifrost`. The tutorial project is in
the Bifrost repository:

```bash
git clone https://github.com/BrokkAi/bifrost.git
cd bifrost/docs/fixtures/scan-tutorial
```

It is a two-file Python tool that summarizes access-log lines. Both files
contain deliberate mistakes:

- `src/settings.py` deserializes operator input with `pickle` and evaluates a
  configuration expression with `eval`.
- `src/report.py` compiles the same regular expression on every loop
  iteration.

## Run the Scan

```bash
bifrost scan .
```

The first run indexes the workspace, so it takes longer than later runs.

The scan first writes the activated packs to stderr:

```text
builtin-policy-pack bifrost.code-smells@2.16.0 policies=30
builtin-policy-pack bifrost.correctness@0.1.0 policies=1
builtin-policy-pack bifrost.security@1.3.0 policies=29
builtin-policy-pack bifrost.effects@1.4.0 policies=10
builtin-policy-catalog sha256=5735bf4781e357fdfb69c6a36e490703021567a2d0b03e39121e34634e932628
bifrost scan: activated 4 built-in policy packs (71 policies shipped, 45 evaluated)
```

The versions and the digest depend on your Bifrost build. The per-pack counts
include opt-in policies, which a scan does not run; the summary line counts
only the policies the scan evaluates. The report on stdout starts like
this. The output below is shortened where it shows `...`: the real
**Analysis warnings** section has 46 lines, sorted by policy ID.

```text
3 findings | Analysis incomplete

Findings
  [warning] bifrost.correctness.dynamic-evaluation: Replace dynamic evaluation with explicit parsing or dispatch
    Location: src/settings.py:12:12
    Certainty: definite; proof: proven; completeness: complete

  [warning] bifrost.correctness.unsafe-deserialization: Replace pickle deserialization with a data-only format
    Location: src/settings.py:8:16
    Certainty: definite; proof: proven; completeness: complete

  [note] bifrost.performance.regex-compile-in-loop: Review whether this lexically nested regex compilation repeats per iteration
    Location: src/report.py:9:19
    Certainty: definite; proof: proven; completeness: complete


Analysis warnings
  bifrost.correctness.c-self-assignment [note; advisory] empty_selection: assertion policy `bifrost.correctness.c-self-assignment` observed no group for relational assertion `by-assignment-self-assignments` group `by-assignment`: its selection matched no row in the scanned workspace, so this run reports zero findings vacuously rather than proving the asserted condition holds
  bifrost.correctness.contradictory-condition [warning; run_incomplete] code_query/branch_relation_derivation_incomplete: contradictory_condition branch relation for src/report.py is incomplete: partial_procedure
  ...
  bifrost.correctness.contradictory-condition: inconclusive (capability_incomplete)
  ...
  bifrost.correctness.python-absent-member [warning; run_incomplete] code_query/semantic_capability_unsupported: python absent-member analysis requires an active Python declaration surface
  ...
  bifrost.correctness.python-absent-member: inconclusive (capability_incomplete)
  ...
  bifrost.correctness.python-absent-member-conditional: inconclusive (capability_incomplete)
  ...

Dependency models
  Coverage: complete
  Mode: default; ecosystems: python
  Details: --verbose or --format json
```

The scan exits with status 2, and stderr ends with
`bifrost: policy evaluation was incomplete or invalid; see the emitted report
for details`.

Read the report from the top:

- The **header line** counts active findings and says whether every policy
  completed. `Analysis incomplete` means at least one policy did not.
- Each **finding** names the policy ID, the policy's advice, the
  `file:line:column` of the exact expression, and how strong the proof is.
- **Analysis warnings** with `advisory` are honest notes about empty results.
  For example, a C or Go policy matched nothing in this Python-only workspace,
  so its empty result proves nothing. These notes do not change the exit
  status.
- Analysis warnings with `run_incomplete`, and the `inconclusive` lines, name
  policies that could not finish. Any such policy makes the exit status 2.
- **Dependency models** shows which semantic dependency packs were activated.
  Here the Python ecosystem was selected automatically.

Add `--verbose` for complete finding records, suppression provenance,
dependency-pack decisions, and policy audit details. Add `--format json` or
`--format sarif` for machine-readable versions of the same report.

## Why This Scan Is Incomplete

Three default policies cannot finish on this fixture:

- `bifrost.correctness.python-absent-member` and
  `bifrost.correctness.python-absent-member-conditional` report attribute
  accesses that no class declares. To prove that a member is absent, they need
  a complete declaration model of the Python standard library. The `bifrost`
  binary does not embed that model. It comes from the Python standard-library
  semantic pack, which activates only when the pack is installed and the
  project declares a CPython version, for example in `.python-version` or
  `pyproject.toml`. See [Semantic-Model Packs](/semantic-model-packs/).
- `bifrost.correctness.contradictory-condition` reports a condition that is
  always true or always false. It reports a complete result for a function only
  when its analysis of that function has no gaps and it can decide the value of
  every condition. The analysis of `summarize` has gaps (the report says
  `partial_procedure`), so the policy ends inconclusive. A condition on a value
  that the analysis cannot know, such as `if x is None:` on a function
  parameter `x`, also ends inconclusive.

Status 2 never means "no problems". It means that the report cannot support a
claim that the code is clean. The three findings above are still real and
proven.

## Gate on Selected Policies

To get a gate that can pass, select the policies you want to enforce. This
command runs the three policies that report findings on this fixture:

```bash
bifrost --root . \
  --policy-id bifrost.correctness.dynamic-evaluation \
  --policy-id bifrost.correctness.unsafe-deserialization \
  --policy-id bifrost.performance.regex-compile-in-loop
```

```text
3 findings | Analysis complete

Findings
  [warning] bifrost.correctness.dynamic-evaluation: Replace dynamic evaluation with explicit parsing or dispatch
    Location: src/settings.py:12:12
    Certainty: definite; proof: proven; completeness: complete

  [warning] bifrost.correctness.unsafe-deserialization: Replace pickle deserialization with a data-only format
    Location: src/settings.py:8:16
    Certainty: definite; proof: proven; completeness: complete

  [note] bifrost.performance.regex-compile-in-loop: Review whether this lexically nested regex compilation repeats per iteration
    Location: src/report.py:9:19
    Certainty: definite; proof: proven; completeness: complete


Analysis warnings
  None.

Dependency models
  Coverage: complete
  Mode: default; ecosystems: python
  Details: --verbose or --format json
```

Every selected policy completed, and two `warning` findings meet the default
`--fail-on warning` threshold, so this run exits 1. The `note` alone would not
fail the run.

You can also select by pack or category, for example
`--policy-category performance`. Repeating one selector widens the selection;
combining different selectors narrows it. See
[CLI](/cli/#explicit-policy-selection).

## Fix the Code and Run Again

`src/report.py` compiles its regular expression on every loop iteration.
Compile it once as a module constant:

```python
PATTERN = re.compile(r"^(?P<user>\w+) (?P<path>\S+) (?P<ms>\d+)$")


def summarize(lines):
    entries = []
    for line in lines:
        match = PATTERN.match(line)
```

In `src/settings.py`, replace `pickle.loads` with a data-only format such as
`json.load`. Replace the `eval` call with explicit parsing of the one
comparison shape that the tool supports.

Run the same selected-policy command again:

```text
0 findings | Analysis complete

Findings
  No findings reported.

Analysis warnings
  None.

Dependency models
  Coverage: complete
  Mode: default; ecosystems: python
  Details: --verbose or --format json
```

The run exits 0. The findings are gone because the code changed, not because
anything was suppressed or configured. `bifrost scan .` still exits 2 on the
fixed code, because the three policies described above still cannot finish.

## Exit Codes Are the Gate

The scan is designed for scripts. `echo $?` after a run gives one of three
statuses:

| Status | Meaning |
| --- | --- |
| `0` | Every requested policy completed, no active unsuppressed finding met the `--fail-on` threshold, and no suppression record is orphaned. |
| `1` | Every requested policy completed, and at least one active unsuppressed finding met the threshold or at least one suppression record is orphaned. |
| `2` | The run is unreliable: a policy was inconclusive, unsupported, or failed, or a suppression, schema, evaluation, output, or argument error occurred. Never read status 2 as clean. |

The default threshold is `--fail-on warning`. In this tutorial, `bifrost scan
.` exits 2 before and after the fix. The selected-policy command exits 1 while
the two warnings are present and 0 once they are fixed.

## Where to Go Next

- Select built-in policies with `--policy-pack`, `--policy-category`, and
  `--policy-id`, or run your own `.rqlp` files with `--policy-file`. See
  [CLI](/cli/).
- Gate pull requests on only the findings they introduce with
  `--diff-base`. See
  [CLI](/cli/#gate-only-on-new-findings---diff-base---no-incremental).
- Emit `--format sarif` and upload it to GitHub code scanning. See
  [CI Gating with GitHub Actions](/ci-github-actions/).
- Accept a reviewed finding with a suppressions file instead of deleting the
  code. See [Static-Analysis Policies](/static-analysis-policies/).
- Write your own policy. See
  [Build a Rule](/build-static-analysis-rule/).
