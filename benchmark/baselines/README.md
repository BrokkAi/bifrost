# Blessed Baselines

`ubuntu-latest.json` is the intended blessed baseline for the scheduled benchmark workflow.

The first blessed Ubuntu baseline was promoted from the successful PR-path benchmark run on June 5, 2026 (`run-20260605T072813Z.json` from PR #172).

The current blessed Ubuntu baseline was promoted from the successful scheduled
benchmark run on July 1, 2026 (`run-20260701T104146Z.json` from Actions run
28511308801). The report had zero scenario failures across 71 scenarios. The
previous baseline flagged the sustained `fastroute-php scan_usages` timing
increase as a regression; this promotion accepts the current post-June 29
performance level and includes the Google Gson hierarchy scenarios added after
the June 22 baseline.

It is not written automatically. Promote it deliberately:

1. Run the benchmark workflow or a local `bifrost_benchmark run`.
2. Review the JSON artifact and confirm the scenario set and timings look healthy.
3. Copy that artifact to `benchmark/baselines/ubuntu-latest.json` in the same change that explains why the new baseline is valid.

Until that file exists, the daily workflow still runs the harness, uploads artifacts, and records that compare was skipped because no blessed Ubuntu baseline is checked in yet.
