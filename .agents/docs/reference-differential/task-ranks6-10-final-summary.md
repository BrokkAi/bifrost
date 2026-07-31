# Task-ranked repositories six through ten: final campaign summary

The distinct ranks-six-through-ten expansion is complete for all eleven
`tasks.py` languages. Selection used
`tasks.task_repos(tasks.SFT_PREDICATES, langs=[LANG])`, stable descending task
counts with selector-order tie preservation, and slice `[5:10]`.
`SFT_PREDICATES` is the required selector path that excludes repositories in
`large-repos.csv`. The runner received each selected slug explicitly; no
rank-one-through-five record was reused as a new-rank envelope.

The accepted evidence contains 55 completed repository envelopes and 520,969
sampled sites. It queried 40,252 inverse target groups. Configured target caps
account for 8,197 skipped groups and 14,369 affected sites, all classified
inconclusive rather than missing. There are no file errors or
candidate-limit exclusions in an accepted envelope.

| Language | Bifrost acceptance head | Sampled sites | Queried targets | Raw missing | Actionable |
| --- | --- | ---: | ---: | ---: | ---: |
| C | `d9df6f92` | 50,000 | 3,908 | 0 | 0 |
| C++ | `5e17ecf5` | 49,908 | 2,905 | 44 | 0 |
| C# | `179336c7` | 50,000 | 4,133 | 0 | 0 |
| Go | `05b11b6c` | 50,000 | 5,000 | 0 | 0 |
| Java | `05b11b6c` | 50,000 | 4,880 | 0 | 0 |
| JavaScript | `c1362371` | 33,454 | 1,273 | 0 | 0 |
| TypeScript | `05b11b6c` | 50,000 | 3,169 | 0 | 0 |
| PHP | `05b11b6c` | 50,000 | 4,053 | 0 | 0 |
| Rust | `61acff24` | 40,458 | 3,603 | 0 | 0 |
| Scala | `f5d7ba67` | 50,000 | 4,362 | 1 | 0 |
| Python | `d3a3e9b6` | 47,149 | 2,966 | 72 | 0 |

The 117 raw residuals are fully audited, not silently subtracted. C++ has 44
rows from the already checked-in declaration, type-owner, self-owner, and
honestly unproven link-unit partition. Python has 72 rows from the previously
audited module/import-collision partition in Keras and websockets. Scala has
one Guardian Grid import whose forward target group contains two physical
`lib.elasticsearch.ElasticSearch` declarations from independent application
modules; inverse lookup correctly refuses to assign the import to either
physical declaration without build-module evidence. The exact Scala replay
and its nonactionable disposition are pinned by the manifest's missing-ledger
checksum.

## Issue and publication closure

Every legitimate finding was searched, assigned to `jbellis` before product
edits, fixed through structured analyzer logic, tested locally, pushed
directly to `origin/master`, replayed on its repository, and closed before
the next depth-first repository began. A final live GitHub audit found zero
open `FIRD:` issues. The audit covers C/C++ issues from #1165 through #1226,
Python through #1225/#1229, C# #1261/#1263-#1267/#1293, Go #1269-#1271,
JavaScript #1276/#1277/#1313, Rust #1278-#1283/#1375/#1403, and Scala
#1284-#1292/#1316/#1379-#1382/#1385-#1386/#1409/#1414. Provisional Scala
#1422 is closed `NOT_PLANNED`: review proved the witness is the intentional
physical-replica ambiguity described above, and no code was accepted for it.
Go #1272 is likewise closed without product edits because it duplicated an
existing owner.

The final Scala code head `f5d7ba67` passed formatting, strict
all-target/all-feature Clippy, focused regressions, and the featureless Cargo
suite's substantive tests. On the final merged-head gate, two C# wall-clock-
budget tests exhausted their time budget only under the loaded 1,443-test usage
suite; both passed immediately when rerun exactly and serially. Earlier fixing
heads received the corresponding local gates recorded in the ExecPlan and
language summaries. Cargo and Bifrost used normal
repository storage outside the sandbox at niceness 10; no Cargo target was
redirected into `/tmp`.

## Durable evidence

The machine-readable campaign manifest is
`task-ranks6-10-final-manifest.jsonl`. It pins all 55 repository ranks, task
counts, repository heads, language acceptance heads, fingerprints, aggregate
counters, raw artifact paths and SHA-256 values, and Scala's missing ledger.
The C record delegates per-envelope fingerprints to its referenced durable
manifest; the other language records pin their shared run fingerprint directly.
The previously checked-in C, C++, and Python summaries remain authoritative
for their exhaustive residual ledgers. Once this compact evidence is
published, the large raw artifacts under `/mnt/optane/tmp/bifrost-fird/` are
disposable and should be removed as the campaign's final cleanup step.
