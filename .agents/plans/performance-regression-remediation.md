# Repair remaining benchmark regressions

This ExecPlan is a living document. Keep it in accordance with
`.agents/PLANS.md`.

## Purpose / Big Picture

The daily Benchmark action must report real performance regressions without
stale Serde name contracts. After this work, the remaining Click, Gin, C++,
query-code, and Serde location cases will either meet their existing budgets or
have a measured, reviewed replacement contract. The final strict Benchmark
action on this branch will show the result.

## Progress

- [x] (2026-08-06 14:20Z) Fixed and pushed the eight stale Serde name
  contracts to `master` in `6bdcda38c`.
- [x] (2026-08-06 14:35Z) Created this branch from `6bdcda38c` and recorded
  the failed Benchmark action `31104312306`.
- [ ] Profile and repair Click and Gin `scan_usages` regressions.
- [ ] Profile and repair shared C++ workspace, symbol search, and location
  regressions.
- [ ] Profile and repair cold `query_code` regressions.
- [ ] Profile and repair the Serde symbol-location regression.
- [ ] Run focused tests, policy validation, the strict Benchmark action, and
  open one pull request.

## Surprises & Discoveries

- Observation: eight failed Serde scenarios were stale expected names, not
  slow paths.
  Evidence: action `31104312306` returned `serde_json.value.Value.Number`
  where the manifest expected `value.Value.Number`.
- Observation: the remaining query-code failures are mainly cold requests.
  Evidence: Scala `exact-elem-class` took 25,673 ms first and 9.6 ms warm.
- Observation: Click and Gin share the `scan_usages` tool but use different
  language adapters.
  Evidence: Click increased from 2,469 ms to 9,524 ms; Gin increased from
  782 ms to 1,245 ms.

## Decision Log

- Decision: Keep all repairs in one branch and one pull request.
  Rationale: The user requested one combined review unit. Each repair remains
  independently tested before integration.
  Date/Author: 2026-08-06 / Codex.
- Decision: Do not promote the baseline during this work.
  Rationale: A baseline records accepted behavior. It must not hide a new
  regression before a cause is measured and reviewed.
  Date/Author: 2026-08-06 / Codex.
- Decision: Profile each language group before changing an implementation.
  Rationale: Similar action names do not prove a shared cause across language
  adapters.
  Date/Author: 2026-08-06 / Codex.

## Outcomes & Retrospective

Work is in progress. Record the repaired cases, remaining exceptions, action
links, and final benchmark comparison here before opening the pull request.

## Context and Orientation

`benchmark/targets.toml` defines pinned external repositories, tool scenarios,
and required output witnesses. `benchmark/baselines/ubuntu-latest.json` stores
the accepted Ubuntu timing report. The `bifrost_benchmark` binary runs each
tool against each pinned repository. The action compares warm medians against
the baseline and also checks that a first `query_code` request does not remain
too much slower than its warm requests.

Action `31104312306` ran at commit `0a9136fbe`. It found eleven remaining
measured regressions after removal of the stale Serde contracts. They divide
into four investigation groups: `scan_usages` on Click and Gin; C++ workspace
and symbol operations on fmt; cold `query_code` calls on Scala, Dapper,
Exposed, fmt, and Gson; and Serde `get_symbol_locations`.

The main implementation areas are `crates/bifrost-analysis` for language
analysis and stored facts, `crates/bifrost-mcp` for tool execution, and
`src/bin/bifrost_benchmark.rs` with `benchmark/` for measurement behavior.
Do not change the baseline unless a new result is intentionally accepted and
its reason is documented.

## Plan of Work

First, record a profiling run for each affected repository. Capture both the
first and warm request timings. Use the profile fields to identify the phase
that changed: workspace build, durable fact preparation, query compilation,
language resolution, or response rendering.

For Click and Gin, compare `scan_usages` candidate discovery and per-file scan
cost. Make a shared change only when both profiles show the same hot phase.
Otherwise, keep language-specific changes in their adapters and add a focused
behavior test for each.

For fmt, measure workspace creation, declaration collection, and
`get_symbol_locations` separately. Repair the earliest shared slow phase.
Preserve C++ lookup behavior with a focused fixture that proves the benchmark
symbol resolves.

For query-code, measure the first structural query and ten warm requests in
Scala first. Use the result to decide whether structural-fact preparation must
be lazy, cached, or bounded. Apply the same change to Dapper, Exposed, fmt,
and Gson only if their profiles use that path. Add tests that prove the first
request completes and warm reuse remains fast.

For Serde, trace the `value.to_value` symbol-location query. Correct the
canonical-name or stored-location cache path, not the timing threshold.

Integrate agent changes only after review, focused tests, formatting, and a
policy run. Run the strict Benchmark action on this branch before the pull
request. Report every remaining action failure in the pull-request body.

## Concrete Steps

From the repository root, run the profiler for one named repository:

    cargo run --release --bin bifrost_benchmark -- run \
      --manifest benchmark/targets.toml --repo <repository> --profile

Use the resulting report to select the affected test module. Run the smallest
test command that executes that module, then run `cargo fmt --check` and
`git diff --check`.

After all focused cases pass, dispatch the GitHub `Benchmark` workflow from
this branch with strict comparison enabled, profiling enabled, and normal
result reporting. Download its report artifact. The run must have no scenario
failures and no actionable regressions before opening the pull request.

## Validation and Acceptance

Acceptance requires these observable results:

- Each repaired repository benchmark returns successful scenarios.
- The known timing medians are no longer regressions against the checked-in
  baseline.
- The first `query_code` request satisfies its retained warm-request limit.
- Focused behavior tests pass for each changed analyzer path.
- `cargo fmt --check` and `git diff --check` pass.
- `run_policy` completes reliably or an existing issue records new timing
  evidence.
- The strict GitHub Benchmark action passes on this branch.

## Idempotence and Recovery

Profiling runs only write benchmark reports and reusable pinned repository
caches. They can be repeated. Do not edit the baseline to recover a failing
run. If an experiment harms another target, revert only that experiment and
retain its profile report in the plan decision log.

## Artifacts and Notes

The source comparison report is the `benchmark-31104312306` artifact from
GitHub action `31104312306`. Key values are Click `scan_usages` 9,524 ms,
Gin `scan_usages` 1,245 ms, fmt `workspace_build` 4,282 ms, and Scala first
`query_code` 25,673 ms.

## Interfaces and Dependencies

Do not add a new crate. Use the existing analyzer and MCP tool interfaces. A
repair must preserve the public JSON result format, complete/incomplete
metadata, and canonical fully qualified names. Add tests to the established
integration suites under `tests/`, not a new root test binary, unless process
isolation is required.

Plan created on 2026-08-06 because the user requested a multi-agent,
single-pull-request performance repair. It records the current action evidence
and the required integration order.
