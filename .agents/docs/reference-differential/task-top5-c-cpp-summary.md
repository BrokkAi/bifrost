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

Issues #996, #997, and the previously fixed C issues #924 and #928 are closed with production evidence. Formatting, all-target/all-feature Clippy, the complete `cargo test --features nlp,python` suite, and final merge-proportionate focused suites passed locally. An independent audit reproduced every acceptance counter and found no discrepancy. C is complete; C++ remains in progress.
