# Blessed Baselines

`ubuntu-latest.json` is the intended blessed baseline for the scheduled benchmark workflow.

The first blessed Ubuntu baseline was promoted from the successful PR-path benchmark run on June 5, 2026 (`run-20260605T072813Z.json` from PR #172).

The July 1 blessed Ubuntu baseline was promoted from the successful scheduled
benchmark run (`run-20260701T104146Z.json` from Actions run
28511308801). The report had zero scenario failures across 71 scenarios. The
previous baseline flagged the sustained `fastroute-php scan_usages` timing
increase as a regression; this promotion accepts the current post-June 29
performance level and includes the Google Gson hierarchy scenarios added after
the June 22 baseline.

The issue #503 LSP click-around baseline PR promotes the successful pull-request
benchmark run on July 7, 2026 (`run-20260707T132443Z.json` from Actions run
28868473877). The report had zero scenario failures across the same 10
repositories and 71 scenarios. Comparing that artifact against the July 1
baseline reported broad timing slowdown, including 23 threshold-crossing
scenarios and environment variance across all 10 repositories. This promotion is
intentional: the PR establishes a fresh comparison point after the relation-heavy
LSP fixture sweep and its analyzer fixes, so future scheduled runs compare
against the reviewed July 7 artifact instead of carrying the older July 1 timing
floor forward.

The July 9 blessed Ubuntu baseline was promoted from the successful scheduled
benchmark run (`run-20260709T104007Z.json` from Actions run 29011660435). The
report had zero scenario failures across the same 10 repositories and 71
scenarios. Comparing that artifact against the July 7 baseline reported 24
threshold-crossing improvements and one remaining threshold-crossing regression;
this promotion registers the broad analyzer-performance improvements as the new
comparison point without changing the regression detector.

It is not written automatically. Promote it deliberately:

1. Run the benchmark workflow or a local `bifrost_benchmark run`.
2. Review the JSON artifact and confirm the scenario set and timings look healthy.
3. Copy that artifact to `benchmark/baselines/ubuntu-latest.json` in the same change that explains why the new baseline is valid.

Until that file exists, the daily workflow still runs the harness, uploads artifacts, and records that compare was skipped because no blessed Ubuntu baseline is checked in yet.
