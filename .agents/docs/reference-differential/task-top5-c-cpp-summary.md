# Task-ranked C and C++ reference differential

## C milestone

The task-ranked C leg is complete. Selection used `tasks.task_repos(tasks.SFT_PREDICATES, langs=["c"])`, so `not_overlarge=True` applied the required `large-repos.csv` exclusion, followed by an exact `(-task_count, repo_slug)` sort. The literal top five were preserved even though `bernardladenthin__BitcoinAddressFinder` has no eligible C implementation files; rank-six `aws__s2n-tls` was audited as a labeled supplement rather than silently replacing it.

The accepted runner was built from clean, published Bifrost head `7c1a16e063fe8e8accaadf86fe667daeff9a67d7`; its SHA-256 is `c16b4cc0e478bf34651750fd1b4c27ef777fc5b6374aae430afa07e1fb47d5a0`. Every record used fingerprint `830e9a0f239fcaa3e8f0a0b9d7831aa8f3ca8917a6b39e24d70e84cb601223d6`, 1,000 files, 10,000 sites, 250,000 candidates per file, 4 MiB sources, 1,000 target groups and usage files per target, 100,000 usages, seed zero, and eight workers.

| Scope | Repository | Tasks | Files | Sampled | Resolved | Consistent | Unproven | Inconclusive | Missing | Runtime |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| top 5 | `roseteromeo56-cb-id__go-ethereum` | 105 | 18 | 10,000 | 353 | 233 | 0 | 9,767 | 0 | 883.2s |
| top 5 | `rui314__chibicc` | 77 | 9 | 10,000 | 6,291 | 3,659 | 0 | 6,341 | 0 | 224.8s |
| top 5 | `libgit2__libgit2` | 60 | 326 | 10,000 | 3,403 | 1,101 | 0 | 8,899 | 0 | 911.9s |
| top 5 | `bernardladenthin__BitcoinAddressFinder` | 42 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0.2s |
| top 5 | `jerryscript-project__jerryscript` | 41 | 272 | 10,000 | 2,947 | 1,222 | 0 | 8,778 | 0 | 910.8s |
| rank-6 supplement | `aws__s2n-tls` | 39 | 186 | 10,000 | 4,021 | 1,698 | 2 | 8,300 | 0 | 107.6s |

The literal top-five artifact contains 40,000 sites across 625 audited files: 12,994 forward-resolved, 6,215 consistent, 33,785 inconclusive, and zero editor-only, unproven, or missing. It queried all 1,579 target groups and has zero file errors, candidate-limit exclusions, skipped targets, or target truncations. The supplement brings the substantive C total to 50,000 sites across 811 files and 2,283 fully queried targets: 7,913 consistent, two honestly unproven, 42,085 inconclusive, and zero missing or actionable residuals.

Raw top-five evidence is `/mnt/optane/tmp/reference-differential/c-task-top5-7c1a16e0.jsonl` (SHA-256 `edcdd5efe199a1b5c4c6dda9867c9c58bafbd41a14d929d1a8b614db4ec6091b`) with log SHA-256 `17bf34157e786093366168a5ad56bbf88090dd17c9e4fdc53d35093407891094`. Supplemental evidence is `/mnt/optane/tmp/reference-differential/c-task-rank6-s2n-7c1a16e0.jsonl` (SHA-256 `8a5616a86ee66ee757324612649fabd9e5c7f6bab2b6918d2d7daa51000765d6`) with log SHA-256 `7319b9eb9f0f021de8d3859ab159afcfdfc02c687f9bad52994afb84e2420f37`.

Two legitimate defects were found and fixed during this task-ranked C leg:

- #996 removed cross-target macro cursor contention and replay thrash. Clean production runs then completed all 666 Libgit2 and 332 JerryScript targets instead of stalling with workers serialized behind one shared cursor.
- #997 made public definition lookup reject every repeated C/C++ declarator. Eight former raw residuals—one Libgit2 secondary local and seven Chibicc typedef names—now return structured `no_definition`/`declaration_or_import_site`, with zero missing. The aggregate SHA-256 over the eight exact-proof checksum lines is `a5b074c5a6a6c7b4501890b0851c9e18c7f9876372b6199dfa11399ad738459d`.

Issues #996, #997, and the previously fixed C issues #924 and #928 are closed with production evidence. Formatting, all-target/all-feature Clippy, the complete `cargo test --features nlp,python` suite, and final merge-proportionate focused suites passed locally. An independent audit reproduced every acceptance counter and found no discrepancy. C is complete.

## C++ milestone

The task-ranked C++ leg is complete. Selection used the same fully filtered `tasks.task_repos(tasks.SFT_PREDICATES, langs=["cpp"])` result and exact `(-task_count, repo_slug)` ordering. The measured C/C++ top fives have zero overlap because `tasks.py` canonicalizes multi-language repositories to one preferred language; no alternate selector was substituted. Rank-four `ljharb__qs` has no eligible C++ files and remains an honest selector-faithful zero-file record.

The accepted runner was built from clean, published Bifrost head `a328a6737872ee7111d90123325bc9234469f6e5`; its SHA-256 is `ab487fddcebfc10144462d5dc4eff50ace7890f5e5618cd03779a7a109b9a7d5`. Every record used fingerprint `66cb273e6100c85ca23f1044e5b62b50ba38bc72bbcb85b127aa0050c8053283`, 1,000 files, 10,000 sites, 50,000 candidates per file, 4 MiB sources, 1,000 target groups and usage files per target, 100,000 usages, seed zero, and eight workers.

| Rank | Repository | Tasks | Files | Sampled | Resolved | Consistent | Editor-only | Unproven | Inconclusive | Missing | Runtime |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | `esphome__esphome` | 151 | 1,000 / 2,643 | 10,000 | 4,048 | 1,095 | 66 | 139 | 8,699 | 1 | 1,141.6s |
| 2 | `cloudflare__circl` | 68 | 7 / 7 | 1,035 | 236 | 192 | 0 | 33 | 806 | 4 | 0.4s |
| 3 | `PJK__libcbor` | 32 | 26 / 26 | 1,234 | 469 | 210 | 0 | 4 | 1,020 | 0 | 0.7s |
| 4 | `ljharb__qs` | 32 | 0 / 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0s |
| 5 | `apache__qpid-proton` | 27 | 271 / 271 | 10,000 | 5,152 | 2,492 | 41 | 163 | 7,259 | 45 | 282.8s |

The five records contain 22,269 sampled sites across 1,304 audited files: 9,905 forward-resolved, 3,989 consistent, 107 editor-only, 339 unproven, 17,784 inconclusive, and 50 raw missing. The explicit 1,000-target cap is fully accounted for: 2,067 of 3,134 target groups were queried, 1,067 were skipped, and 1,562 affected sites were marked inconclusive rather than missing. There were zero file errors or candidate-limit exclusions. The corpus took 23:46 wall time and peaked at 668,512 KiB RSS.

Every one of the final 50 raw rows was rerun at its exact path and byte range with ephemeral cache. All 50 completed at clean Bifrost and repository heads with one sampled site, one reproduced `missing`, and zero file errors. Their coordinate set is byte-for-byte identical to the preceding clean-head 51-row audit after removing the now-fixed `LwIPSocketImpl` row. The final disposition is exhaustive:

- ESPHome's sole row, `vl53l0x_sensor.cpp:477..490`, is a declaration-sampler leak in the existing #969 family; inverse declaration exclusion is correct.
- Qpid-proton's 45 rows are differential batch-target parity artifacts. Exact public targeted queries retain the sites, so the MCP/Rust/Python symbols behavior is correct.
- Circl's four rows are Go/Plan 9 assembly fragments in `fq_amd64.h` recovered as C++; forward identity is wrong and inverse omission is correct.

Thus the final corpus has zero actionable residuals. The aggregate SHA-256 over the 50 exact JSONL checksum lines is `0d91e2fc335abb9b5cdc36ff747c6ba5bac676e8d92cdd175d366a16f71ac0b1`; the canonical sorted coordinate/classification ledger hashes to `73f03c3ebaf4eec9309716056f27574ef22470bccc4302ed93b6bba3f377341f`. Raw corpus evidence is `/mnt/optane/tmp/reference-differential/cpp-task-top5-a328a673.jsonl` (SHA-256 `9f24069919aeb414decd1074278d2a93913c76fc0039f1f2d4bd580b14a93276`) with log SHA-256 `93f427e258bb44ea8120c34a4eff28b67fe844de0b3c97154fb472efaaffecfa`.

The task-ranked baseline exposed seven legitimate C++ issue families. The combined structured fix stack `d9dfbb4f` resolved #940 and #1000 through #1005; `4c9cea6b` resolved #1010 by measuring same-file preprocessor stability from declaration to reference. All 78 baseline product witnesses and the seven guarded `LwIPSocketImpl` self-type roles cleared in exact production probes. The public MCP renderer may exclude class-internal sites as declaration-contained, but the Rust/Python inverse engine no longer loses them. Earlier assigned C++ issues #925 through #932 were also validated on the final head; #932's QGIS witnesses remain honest exact `unproven` hits because the generated header needed for macro proof is absent.

Formatting, all-target/all-feature Clippy, 142 C++ graph tests, and the complete serialized `cargo test --features nlp,python` suite passed on final clean head `a328a673`. All source fixes are published to `origin/master`. Evidence comments were posted and assigned issues #925 through #932 (with #928 already closed), #940, #1000 through #1005, and #1010 are closed as completed.
