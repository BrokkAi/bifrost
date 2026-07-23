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

The July 15 blessed Ubuntu baseline (`run-20260715T120808Z.json`, Bifrost commit
`e3860e0b5d50e8b82bb963569d4c5a170b9d977c`) had zero scenario failures across
the same 10 repositories and 76 scenarios. It was checked in by commit
`0d12e86f982c734d8caf446e42990b02fec0b997`; the originating Actions run was not
recorded in the repository.

The issue #920 query-regression baseline is promoted from the complete full
manual benchmark artifact on July 22, 2026 (`run-20260722T214543Z.json` from
Actions run 29959610518, Bifrost commit
`ba488b66a840356ed946f19d2d81e2960c84d7f2`). The harness had zero scenario
failures across the same 10 repositories and 92 scenarios, including all 16 new
`query_code` cases with stable result cardinalities and no query diagnostics.
The artifact also passes strict comparison against itself, including the
dual-arm first-to-warm retention invariant. A provisional artifact from run
29956839833 was rejected as an unusually fast sample after two current-head
replays produced 27 and 21 timing flags against it. The promoted artifact has no
regressions when compared with either the immediately preceding current-head
artifact from run 29958615453 or the earlier representative artifact from run
29955662059. The cold-retention comparator also applies its ordinary 50 ms
absolute noise floor to the 10x ratio gate, retaining the original eager-build
failure while ignoring 1-11 ms boundary jitter. This promotion deliberately
establishes the reviewed final-head post-#920 floor so subsequent strict runs
exercise the new query correctness, cache-path, and timing contracts instead of
treating all 16 cases as absent from the baseline.

The July 23 post-sync issue #920 refresh is promoted from the exact-branch
artifact `run-20260723T005928Z.json` from Actions run 29970021643 at Bifrost
commit `180e7b5dd4eb83d9a0936caa4aa3d56e617003b2`. All 92 scenarios succeeded,
including all 16 `query_code` cases, and the workflow reported no regression
against the prior blessed baseline. The artifact has no threshold crossings in
either comparison direction against exact-head run 29968367834 and passes strict
comparison against itself. Run 29966995969 was rejected because its broadly
faster runner produced 30 threshold crossings when a representative replay was
compared against it; blessing that sample would have manufactured regressions
across unrelated languages. This refresh includes the Rust analysis-epoch fix,
the Scala relative-import changes, and the O(1) lazy-LRU/SearchTools cache work
from current master, so future comparisons use the current persisted-store and
cache contracts.

It is not written automatically. Promote it deliberately:

1. Run the benchmark workflow or a local `bifrost_benchmark run`.
2. Review the JSON artifact and confirm the scenario set and timings look healthy.
3. Copy that artifact to `benchmark/baselines/ubuntu-latest.json` in the same change that explains why the new baseline is valid.

Until that file exists, the daily workflow still runs the harness, uploads artifacts, and records that compare was skipped because no blessed Ubuntu baseline is checked in yet.
