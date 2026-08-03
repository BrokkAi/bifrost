# Task-ranked C repositories eleven through twenty

The distinct C ranks-eleven-through-twenty leg is complete. Selection used the
live `tasks.SFT_PREDICATES` path, which applies the required
`large-repos.csv` exclusion, followed by stable descending qualifying-task
count. Every selected slug was passed explicitly to the runner; no top-ten
repository was substituted or reused.

The final certification runner was built from clean, published Bifrost head
`f8e5022da6ee854e95ccb331d52448cd21f36217`; its SHA-256 is
`043580a821a4a68fae4ee864b54d2e84df69a86e70bf0efc23ace085b2c7c436`.
Cargo and Bifrost used normal repository storage outside the sandbox, and all
campaign processes ran at niceness 10.

| Rank | Repository | Tasks | Files | Sampled | Targets | Consistent | Unproven | Inconclusive | Missing | Runtime |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 11 | `trifectatechfoundation__sudo-rs` | 24 | 0 / 0 | 0 | 0 / 0 | 0 | 0 | 0 | 0 | 0.7s |
| 12 | `raphw__byte-buddy` | 24 | 1 / 1 | 176 | 4 / 4 | 8 | 0 | 168 | 0 | 4.6s |
| 13 | `LMCache__LMCache` | 24 | 0 / 0 | 0 | 0 / 0 | 0 | 0 | 0 | 0 | 4.6s |
| 14 | `DaveGamble__cJSON` | 23 | 6 / 6 | 5,291 | 115 / 115 | 768 | 38 | 4,485 | 0 | 1.2s |
| 15 | `unicorn-engine__unicorn` | 23 | 258 / 258 | 10,000 | 697 / 697 | 1,407 | 10 | 8,583 | 0 | 71.0s |
| 16 | `igraph__igraph` | 22 | 958 / 958 | 10,000 | 684 / 684 | 1,256 | 24 | 8,720 | 0 | 22.4s |
| 17 | `libuv__libuv` | 20 | 120 / 120 | 10,000 | 512 / 512 | 1,015 | 21 | 8,964 | 0 | 4.5s |
| 18 | `Mbed-TLS__mbedtls` | 19 | 59 / 59 | 10,000 | 214 / 214 | 494 | 30 | 9,476 | 0 | 8.6s |
| 19 | `ClusterLabs__pacemaker` | 19 | 248 / 248 | 10,000 | 952 / 952 | 1,648 | 63 | 8,289 | 0 | 60.4s |
| 20 | `getvictor__fleet-edr` | 18 | 2 / 2 | 392 | 5 / 5 | 52 | 0 | 340 | 0 | 0.4s |

The accepted records contain 55,859 sampled sites across 1,652 audited files
and 1,484,401 structured candidates. They queried every one of 3,183 distinct
inverse target groups: 6,648 sites are consistent, 186 are honestly unproven,
49,025 are inconclusive, and none are editor-only or missing. There are no
file errors, candidate-limit exclusions, skipped or truncated targets, or
configured-limit failures. Every accepted Bifrost and repository worktree is
recorded clean. The exhaustive residual ledger is therefore the empty byte
sequence, SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Two selector-faithful repositories have no C translation unit. `sudo-rs` is a
Rust project with one header, and LMCache has C++/CUDA sources but no `.c`
file. Their zero-file envelopes are corpus-bucketing facts rather than Bifrost
defects; neither was silently replaced.

The primary final run used fingerprint
`df6de3a3117ce1e8af4c802de9144a4c452315a8006be965ee4df8aa6ba230b2`
and the standard 50,000-candidate ceiling. Its Unicorn record hit that ceiling
in one generated file and is explicitly rejected. The accepted Unicorn
replacement used the previously proven 250,000-candidate fingerprint
`830e9a0f239fcaa3e8f0a0b9d7831aa8f3ca8917a6b39e24d70e84cb601223d6`;
it audited all 258 files and 651,656 candidates with zero exclusions or
missing rows.

## Findings and fixes

Three tickets were involved. Unicorn's broad inverse run exposed mutable
shared-cache contention (#1433); the fix made immutable source/file-state
snapshots lock-free and the final supplement completed in 71.0 seconds with
zero missing rows. Libuv exposed the one correctness defect: a C translation
unit admitted a `__cplusplus`-only overload during both forward candidate
expansion and inverse argument filtering (#1465). Translation-unit dialect is
now applied at the shared structured visibility boundary, and the final libuv
envelope is 1,015 consistent with zero missing. The strict publication gate
also found an unused production `PoolSafeMemo::get` surface (#1467); upstream
independently landed the same test-only restriction while the branch was in
flight, so the merge retained that version. All three issues were assigned
only to `jbellis`, are closed, and their fixing history is on `origin/master`.

Pacemaker's shared eight-worker run initially made the broad
`pcmk__resource` target appear to spend 27.8 seconds in flight. An isolated
ephemeral exact control completed that inverse phase in 0.9 seconds and the
whole run in 2.1 seconds, showing shared-run scheduling/CPU overlap rather
than a single-call product regression. Independent oldskool repository and
issue-history reviews found no additional legitimate symptom in Mbed TLS,
Pacemaker, Fleet EDR, or the other clean repositories.

Implementation commits received focused C/C++ tests, formatting, the broad
featureless Cargo suite, and strict all-target/all-feature Clippy. The broad
suite's sole failure was an unrelated C# wall-clock budget assertion under
the loaded suite; the exact test passed immediately in isolation. The final C
certification itself is clean and requires no CI wait.

## Durable evidence

The machine-readable manifest is
`.agents/docs/reference-differential/c-task-ranks11-20-f8e5022d.jsonl`.
The primary raw JSONL is
`/mnt/optane/tmp/bifrost-fird/c-task-ranks11-20-final-f8e5022d.jsonl`
(SHA-256
`d4203223c79d150575dbf4ce29121a3e60140b47bbe9536d6eb9b8316689ba0c`),
with log SHA-256
`1c79edd0440b61eb430d6e89b1ae802a139ba8db7ddb870b66797b6fb28a8206`.
The accepted Unicorn replacement is
`/mnt/optane/tmp/bifrost-fird/c-r15-unicorn-final-supplement-f8e5022d.jsonl`
(SHA-256
`fa008e0ac8c894a2724b319c6add41376f1238758f6ef138ef2a1129bb89e35f`),
with log SHA-256
`874f8ab13f8e9fe4e1182e950052d279779d4de2b83bcba3a79e98eb8cc6b511`.
Raw campaign artifacts remain under `/mnt/optane/tmp/bifrost-fird/` until the
final 110-envelope reconciliation and cleanup.
