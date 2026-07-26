# Task-ranked C reference differential

The task-ranked C top-ten leg is complete. Selection used
`tasks.task_repos(tasks.SFT_PREDICATES, langs=["c"])`, so the selector's
`not_overlarge=True` predicate applied the required `large-repos.csv`
exclusion. Repositories were then ordered by descending task count with stable
slug tie-breaking and passed to the runner as ten explicit `--repo` arguments.
An independent Oldskool audit reproduced the selector, task counts, exclusion
path, clone heads, and final accounting without a discrepancy.

The accepted runner was built from clean, published Bifrost head
`d9df6f92e8104f311d7954764dcf5ff9bee627af`; its SHA-256 is
`58fd8e9522f782adf4468a62a9a2e4f173f58a2c1f0be8814f270e04f3816189`.
Cargo used the normal repository target outside the sandbox, and every Cargo
and Bifrost process ran at niceness 10.

| Rank | Repository | Tasks | Files | Sampled | Resolved | Targets | Consistent | Unproven | Inconclusive | Missing | Runtime |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | `python-pillow__Pillow` | 159 | 86 / 86 | 10,000 | 3,032 | 207 / 207 | 710 | 5 | 9,285 | 0 | 40.7s |
| 2 | `roseteromeo56-cb-id__go-ethereum` | 105 | 18 / 18 | 10,000 | 1,507 | 134 / 134 | 238 | 6 | 9,756 | 0 | 400.2s |
| 3 | `rui314__chibicc` | 77 | 9 / 9 | 10,000 | 6,493 | 504 / 504 | 3,779 | 0 | 6,221 | 0 | 142.2s |
| 4 | `libgit2__libgit2` | 60 | 326 / 326 | 10,000 | 3,643 | 796 / 796 | 1,249 | 13 | 8,738 | 0 | 3,712.3s |
| 5 | `bernardladenthin__BitcoinAddressFinder` | 42 | 0 / 0 | 0 | 0 | 0 / 0 | 0 | 0 | 0 | 0 | 0.9s |
| 6 | `jerryscript-project__jerryscript` | 41 | 272 / 272 | 10,000 | 3,098 | 371 / 371 | 805 | 37 | 9,158 | 0 | 412.4s |
| 7 | `aws__s2n-tls` | 39 | 186 / 186 | 10,000 | 4,833 | 947 / 947 | 2,331 | 20 | 7,649 | 0 | 164.5s |
| 8 | `nanomsg__nng` | 32 | 205 / 205 | 10,000 | 5,209 | 1,000 / 1,407 | 2,057 | 47 | 7,896 | 0 | 274.8s |
| 9 | `CESNET__libyang` | 31 | 106 / 106 | 10,000 | 4,005 | 590 / 590 | 1,280 | 6 | 8,714 | 0 | 311.9s |
| 10 | `dovecot__core` | 27 | 1,000 / 1,410 | 10,000 | 3,988 | 1,000 / 1,507 | 1,235 | 4 | 8,761 | 0 | 88.1s |

The accepted ten records contain 90,000 sampled sites across 2,208 audited
files: 13,684 consistent, 138 honestly unproven, 76,178 inconclusive, zero
editor-only, and zero missing. They queried 5,549 of 6,463 distinct target
groups. The configured 1,000-target cap accounts for all 914 skipped groups and
1,610 affected sites, which were marked inconclusive rather than missing.
Every forward-status and classification partition sums exactly to its sampled
site count. All records have clean Bifrost and repository heads, all consistent
sites carry exact inverse ranges, and the accepted set has zero file errors or
candidate-limit exclusions.

The primary ten-repository run used fingerprint
`df6de3a3117ce1e8af4c802de9144a4c452315a8006be965ee4df8aa6ba230b2`,
50,000 candidates per file, 1,000 files, 10,000 sites, 4 MiB sources, 1,000
target groups and usage files, 100,000 usages, seed zero, and eight workers. It
finished in 1:42:58, used 555% aggregate CPU, peaked at 1,169,380 KiB RSS, and
exited zero.

Its only scope caveat was a configured candidate-limit exclusion for
go-ethereum's generated `precomputed_ecmult.c`. That record was not accepted.
The same clean head was rerun at the previously proven 250,000-candidate
ceiling, fingerprint
`830e9a0f239fcaa3e8f0a0b9d7831aa8f3ca8917a6b39e24d70e84cb601223d6`.
The replacement sampled all 18 files and 153,269 structured candidates,
completed all 134 selected inverse targets in 400.2 seconds, and has zero file
errors, truncation, missing, or actionable residuals.

BitcoinAddressFinder is an honest selector-faithful zero-file envelope. Its
pinned clone contains no `.c` or `.cpp` files: the C-family-looking resources
are eight headers and ten OpenCL `.cl` files inside a predominantly Java
project. The differential runner therefore correctly reported zero eligible
C translation units. This is a corpus bucketing fact, not a Bifrost defect, and
the literal fifth-ranked repository was not silently replaced.

Issue #1165 was the one legitimate C campaign defect. The accepted
name-bounded structured prefilter eliminated target-specific lexical resolution
for impossible C/C++ type references while preserving direct, qualified,
template, indexed-alias, parser-alias, inherited, unresolved, and cyclic
possibilities. The exact pushed-head Libgit2 replay completed all 796 targets;
the formerly pathological `git_diff` query and every historical broad-tail
struct completed. Issue #1165 is closed with that production evidence.

Repository-wide publication also exposed three independent gate defects:
stale PHP and Ruby same-owner expectations (#1169 and #1170) and concurrent
fresh-cache migration admission (#1173). All were assigned to `jbellis` before
work, fixed or reconciled with current master, published, and closed.
Formatting, `git diff --check`, all-target/all-feature Clippy with warnings
denied, and the complete normal-permission
`cargo test --features nlp,python` matrix passed on the integrated source,
including symbols MCP/CLI, LSP, C/C++ usages, and cache concurrency coverage.

Raw primary evidence is
`/mnt/optane/tmp/bifrost-fird/c-task-top10-d9df6f92.jsonl` (SHA-256
`3d95511365731723151082d7261f7f3cfdf858bfb18d25d13013509b33d80167`)
with log SHA-256
`9d00dfbd510c9a5da5fd82f2cc365e54c61e8d64bbc4c82cb76c62ecea7ac44d`.
The accepted go-ethereum replacement is
`/mnt/optane/tmp/bifrost-fird/c-go-ethereum-d9df6f92-candidates250k.jsonl`
(SHA-256
`08ca756f58585af32226a43d54defe3f20713fbd459f4c16fa3db750979d88b2`)
with log SHA-256
`b047c6fe28c114e04c7df9982bef30eddae4ed7e9ebd0bc1cb6166d796c074d7`.
These raw artifacts remain only until the final 110-envelope reconciliation;
obsolete diagnostics are removed as soon as their durable hashes and decisions
are committed.
