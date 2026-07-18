# Reference-differential N=1 campaign summary

## Result

The eleven-language N=1 campaign completed its repository runs, exhaustive disagreement triage, and fixes for every recurring genuine family that passed the campaign filing threshold. Raw `missing` is not a defect count: the final records deliberately retain wrong-forward identities, declaration/reference frontier differences, and isolated structured limitations so that the reports remain auditable rather than being tuned to zero.

Chromium was the longest leg, but it converged. Comparable full C++ runs reduced raw missing classifications from 421 to 79, then 33, and finally 23. The final `07ad79f6` run reproduced the same 105,604-file inventory, 10,000-site sample, 4,147 forward resolutions, and 1,897 target groups; it completed all 1,000 inverse queries in 1,808.4 seconds. Ten #921 redeclaration sites moved to consistent and no new missing key appeared. The terminal 23 rows are seven isolated genuine structured omissions, each below the recurrence threshold, plus sixteen invalid-forward or declaration artifacts. No recurring unfixed C++ family remains.

This is evidence of compounding progress rather than unbounded whack-a-mole: fixes repeatedly removed multi-site semantic families, the full scoreboard shrank by 94.5% from the first accepted Chromium baseline, the run stopped hitting its former inverse blocker, and post-fix memory stayed below the established boundary instead of returning to the earlier multi-GiB amplification. The remaining Chromium work has low marginal return and should not delay other analyzer priorities unless one of the isolated shapes recurs in another corpus or production report.

## Final N=1 records

| Language | Selected repository | Sampled | Forward resolved | Consistent | Editor-only | Unproven | Inconclusive | Raw missing | Runtime | Terminal interpretation |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| C | `RMerl__asuswrt-merlin.ng` | 10,000 | 3,144 | 762 | 0 | 297 | 8,940 | 1 | 529.9s | One incompatible multi-project `mp_int` forward artifact; zero genuine residual defects. |
| C++ | `chromium__chromium` | 10,000 | 4,147 | 1,241 | 24 | 39 | 8,673 | 23 | 1,808.4s | Seven isolated structured omissions and sixteen non-actionable artifacts; no recurring family. |
| C# | `Azure__azure-powershell` | 10,000 | not retained | 1,858 | 3 | 30 | 8,109 | 0 | not retained | Zero actionable findings in the durable closure record. |
| Go | `aws__aws-sdk-go-v2` | 10,000 | 3,332 | 921 | 0 | 7 | 8,946 | 126 | 219.1s | All residuals have incompatible focus/target or wrong-owner forward identities. |
| Java | `googleapis__google-cloud-java` | 10,000 | 2,680 | 1,030 | 38 | 42 | 8,768 | 122 | 993.2s | All residuals are invalid class identities or owner/receiver-focus artifacts. |
| JavaScript | `nodejs__node` | 10,000 | 3,674 | 1,005 | 80 | 114 | 8,781 | 20 | 38.5s | Recurring genuine families fixed; retained rows were triaged as non-terminal/artifact boundaries. |
| PHP | `moodle__moodle` | 10,000 | 3,776 | 1,379 | 0 | 0 | 8,621 | 0 | 116.3s | Zero raw missing in the clean closure run. |
| Python | `googleapis__google-cloud-python` | 10,000 | 3,712 | 1,166 | 0 | 0 | 8,828 | 6 | 110.8s | One wrong receiver and five post-rebind wrong-import forward identities. |
| Rust | `biomejs__gritql` | 10,000 | 1,549 | 1,758 combined consistent/editor-only | not retained separately | not retained | not retained | 268 | not retained | Every recurring genuine family was reduced, fixed, and exact-validated; historical split telemetry was not preserved in the plan handoff. |
| Scala | `JetBrains__intellij-scala` | 10,000 | 2,723 | 994 | 182 | 0 | 8,691 | 133 | 391.5s | Recurring hierarchy, companion/infix, lexical, and follow-on families fixed; retained rows exhaustively triaged. |
| TypeScript | `elastic__kibana` | 10,000 | 2,594 | 1,085 | 26 | 10 | 8,879 | 0 | 108.1s | Zero raw missing in the final clean run. |

The two `not retained` cells are historical reporting limitations, not unexecuted runs: the C# and Rust closure records were completed and accepted, but their ephemeral raw JSONL files no longer exist in the current workspace and the living plan did not preserve those individual telemetry fields. The durable semantic outcomes, fixing commits, tests, production witnesses, issue closures, and the other recorded counts remain in the ExecPlan.

## Fix and verification outcome

The campaign issue ledger and per-family evidence are recorded chronologically in [reference-differential-corpus.md](../../plans/reference-differential-corpus.md). Each accepted recurring defect has a structured behavior reduction, a root-cause implementation on pushed `master`, focused coverage, proportionate complete gates, an exact production witness, and a closed assigned issue. The final C++ implementation is `07ad79f6`; all-feature Clippy and the complete `nlp,python` local suite passed, and GitHub Actions run `29649023842` passed all fourteen jobs.

The final Chromium record is `/tmp/cpp-n1-07ad79f6.jsonl`. It pins Bifrost `07ad79f6c8cd807b1a6815fe0648d82d612b8d39` and Chromium `e52675fe3e05dd0e3be9d7e0375240d175ed3db5`, both clean. Its one expected file exclusion is the explicit 7.27 MiB source-size limit; no candidate limit or inverse target limit invalidates the terminal partition.
