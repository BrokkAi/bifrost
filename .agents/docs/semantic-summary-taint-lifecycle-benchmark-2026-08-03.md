# Production semantic-summary taint lifecycle baseline - 2026-08-03

This report records the first hosted release baseline for issue #824's production semantic-summary taint route. The machine-readable aggregate is `semantic-summary-taint-lifecycle-benchmark-2026-08-03.json` in this directory. It was produced by [GitHub Actions run 30817764139](https://github.com/BrokkAi/bifrost/actions/runs/30817764139); no CI threshold is enabled.

## Outcome

All seven inline scale cases completed the real production route for nine fresh processes each. Rounds zero and one were discarded and rounds two through eight were retained, yielding 49 deterministic samples from 63 processes.

Every retained case proved:

- cold semantic-model acquisition was `built` and warm generation-scoped acquisition was `cached`;
- warm and production catalog candidate/load hits and misses were all zero;
- exact relevant summary binding retained the declared dependency closure;
- all source/sink observations stayed in one compatible batch and one propagation solve;
- retained standalone, JSON CodeQuery, RQL, and policy projections preserved deterministic result and policy checksums.

The aggregate passed exact case/round membership, provenance, stable retained-size/count, checksum, cache-accounting, and one-solve validation. Thresholds remain an empty array.

## Protocol and provenance

The branch dispatched the existing `Benchmark` workflow with the semantic-summary taint lifecycle opt-in and `full` campaign:

    scripts/run-semantic-summary-taint-lifecycle-benchmarks.sh full

- Run: `30817764139`, successful in 1h 4m 55s.
- Bifrost commit: `868f92fed0617fc16f73983966e3e46d62577bd5`, clean tracked checkout.
- Benchmark source SHA-256: `1ab68dcc7e8938f359943b240701c72df09443123a7ce924ebc40dfc9043f101`.
- Crate/profile: `brokk-bifrost 0.8.19`, release.
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`.
- Host: Linux x86_64, four logical CPUs.
- Timer: monotonic wall time from `std::time::Instant`.
- Artifact: `semantic-summary-taint-lifecycle-30817764139`, retained by Actions for 14 days.

## Release baseline matrix

Times are milliseconds. p50/p95 use nearest-rank selection across seven retained rounds.

| Case | Summaries | Depth | Sources | Sinks | Production p50 | Production p95 | Binding p95 | Propagation p95 | RSS p95 MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `inline_s1_d1_src1_sink1` | 1 | 1 | 1 | 1 | 4.966 | 5.051 | 2.195 | 1.220 | 109.80 |
| `inline_s16_d1_src1_sink1` | 16 | 1 | 1 | 1 | 4.955 | 6.313 | 2.879 | 1.364 | 110.03 |
| `inline_s64_d1_src1_sink1` | 64 | 1 | 1 | 1 | 4.844 | 4.884 | 2.121 | 1.145 | 109.91 |
| `inline_s16_d4_src1_sink1` | 16 | 4 | 1 | 1 | 8.635 | 8.927 | 3.981 | 3.209 | 109.77 |
| `inline_s16_d8_src1_sink1` | 16 | 8 | 1 | 1 | 14.616 | 14.827 | 6.556 | 6.430 | 109.83 |
| `inline_s1_d1_src4_sink4` | 1 | 1 | 4 | 4 | 22.068 | 22.549 | 6.648 | 8.105 | 109.84 |
| `inline_s1_d1_src16_sink16` | 1 | 1 | 16 | 16 | 168.545 | 172.193 | 44.199 | 88.256 | 124.17 |

The summary-count axis holds relevant dependency depth at one. Catalog compile/registration p95 increased from 0.601 ms at one summary to 1.586 ms at 16 and 2.984 ms at 64, while the production route stayed near five milliseconds because exact selection retained one summary.

Dependency depth produced the expected phase-specific growth: production p95 rose from 5.051 ms at depth one to 8.927 ms at depth four and 14.827 ms at depth eight. Binding p95 rose from 2.195 to 3.981 to 6.556 ms, and propagation p95 rose from 1.220 to 3.209 to 6.430 ms.

Source/sink scaling retained one solve while increasing observations. Production p95 was 5.051 ms for 1x1, 22.549 ms for 4x4, and 172.193 ms for 16x16. The retained report grew from two findings, two witnesses, and 24 steps to 32 findings, 19 witnesses, and the configured 1,024-step witness limit.

## Single-case phase detail

The 1-summary, depth-1, 1-source, 1-sink case is the reference production route.

| Phase | p50 ms | p95 ms |
|---|---:|---:|
| Workspace build | 14.211 | 14.473 |
| Catalog model compile and registration | 0.544 | 0.601 |
| Cold model resolution | 0.646 | 0.660 |
| Warm generation-scoped acquisition | 0.012 | 0.013 |
| Production route total | 4.966 | 5.051 |
| Plan discovery and exact summary binding | 2.104 | 2.195 |
| Compatible batch planning | 0.041 | 0.046 |
| Propagation | 1.214 | 1.220 |
| Finding and witness reconstruction | 0.020 | 0.021 |
| Initial retained standalone projection | 0.428 | 0.437 |
| Repeated retained projection | 0.402 | 0.449 |
| JSON CodeQuery projection | 0.915 | 0.941 |
| RQL projection | 0.878 | 0.897 |
| Policy projection | 0.129 | 0.132 |
| Policy JSON rendering | 0.143 | 0.154 |

Its retained estimates were invariant at 13,528 plan bytes, 53,511 report bytes, 5,878 witness bytes, and 44,892 semantic-artifact bytes. Peak RSS was 109.58 MiB p50 and 109.80 MiB p95. The canonical result checksum was `f0367dff707e0be94d393ce9dbcf9961867871e63aa0539b07ba6066a94b2acf`; the canonical policy checksum was `6e97ced3673732007f1847129f4c7716789c716be0ec6ce2f02d0b368fdfcd88`.

Catalog accounting was one cold hit, zero cold misses, then zero warm and production hits or misses. This proves that warm target selection and exact summary binding do not return to catalog candidate/load SQL. `acquire_active_semantic_models` still reads `PRAGMA data_version` to detect external catalog mutation; the zero figure deliberately excludes that correctness check.

## Historical smoke

Before the hosted campaign, a three-process macOS arm64 debug smoke established protocol correctness. Its 1x1 production route measured 48.226 ms p50 and 69.514 ms p95, with peak RSS of 61.64 MiB p50 and 61.72 MiB p95. Those figures are retained here only as historical development evidence; they are not comparable to or part of the Linux release baseline now stored in the machine aggregate.

## Pinned realistic fixture design

The checked contract is `.agents/docs/semantic-summary-taint-realistic-fixture-2026-08-03.json`. It pins Spring PetClinic to `f182358d02e4a68e52bdbabf55ca7800288511e7`, roots analysis at `OwnerController.findPaginatedForOwnersLastName(int, String)`, and models `OwnerRepository.findByLastNameStartingWith(String, Pageable)` as parameter zero to normal return.

The contract remains `designed_not_available`. Before it becomes runnable, the exact Spring Data JPA version and dependency artifact digest, compiled semantic pack, and source-backed policy must be pinned and reviewed. The realistic case is not represented by this inline release baseline.

## Threshold decision

No threshold is added from a single hosted campaign. The checked data establishes the release baseline and phase-specific variance shape. A follow-up campaign should confirm repeatability before proposing separate limits for activation, binding, propagation, reconstruction, and projection; a single end-to-end threshold would hide which production phase regressed.
