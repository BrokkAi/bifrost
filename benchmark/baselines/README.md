# Blessed Baselines

`ubuntu-latest.json` is the intended blessed baseline for the scheduled benchmark workflow.

The first blessed Ubuntu baseline was promoted from the successful PR-path benchmark run on June 5, 2026 (`run-20260605T072813Z.json` from PR #172).

It is not written automatically. Promote it deliberately:

1. Run the benchmark workflow or a local `bifrost_benchmark run`.
2. Review the JSON artifact and confirm the scenario set and timings look healthy.
3. Copy that artifact to `benchmark/baselines/ubuntu-latest.json` in the same change that explains why the new baseline is valid.

Until that file exists, the daily workflow still runs the harness, uploads artifacts, and records that compare was skipped because no blessed Ubuntu baseline is checked in yet.
