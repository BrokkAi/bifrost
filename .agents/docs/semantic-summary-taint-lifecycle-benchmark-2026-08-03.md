# Production semantic-summary taint lifecycle benchmark - 2026-08-03

This report records the first focused baseline for issue #824's production semantic-summary taint route. It is a three-process debug-profile smoke, not a decision-grade release campaign and not a CI gate. The machine-readable aggregate is `semantic-summary-taint-lifecycle-benchmark-2026-08-03.json` in this directory.

## Outcome

The inline fixture completed through the real production route in every retained process. Catalog registration and activation selected one exact Java procedure summary. The first generation-scoped model acquisition was `built`; the second was `cached`. Production policy evaluation added zero catalog loads or misses, bound exactly the one relevant summary, compiled one compatible policy batch, ran one set-oriented propagation solve, retained two findings and two witnesses, and projected the same retained evidence through direct standalone projection, schema-v7 JSON CodeQuery, RQL, and policy output.

No hard threshold is proposed from this smoke. Three debug samples are sufficient to prove the protocol and expose phase-specific variance, but not to set release-performance limits. In particular, the third sample made plan discovery and binding the widest observed source of production-route variance; that is a reason to retain phase boundaries, not evidence for a regression threshold.

## Protocol and provenance

Command, from the Bifrost repository root:

    scripts/run-semantic-summary-taint-lifecycle-benchmarks.sh smoke

The runner launched three fresh test processes for `inline_s1_d1_src1_sink1` and aggregated all three. `BIFROST_SEMANTIC_INDEX=off` was set. The fixture contains one source, one sink, one external method, and one exact parameter-to-normal-return procedure summary. The policy uses `require-model`; therefore a missing activation or binding cannot silently degrade into optimistic propagation.

- Bifrost base commit: `0ad7dc17d5cc8c95e6d7136f2baa5220ff756bff`, with the benchmark changes uncommitted as requested.
- Benchmark source SHA-256: `1ab68dcc7e8938f359943b240701c72df09443123a7ce924ebc40dfc9043f101`.
- Crate/profile: `brokk-bifrost 0.8.19`, debug test profile.
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`.
- Host: macOS arm64, 10 logical CPUs.
- Timer: monotonic wall time from `std::time::Instant`.
- Samples: three fresh processes, no discarded warmups. The full protocol retains rounds two through eight after two warmups.

## Focused smoke results

Times are milliseconds. p95 is nearest-rank; with three samples it is the observed maximum and must not be read as a stable tail estimate.

| Phase | p50 ms | p95 ms |
|---|---:|---:|
| Workspace build | 51.769 | 62.400 |
| Catalog model compile and registration | 6.345 | 7.801 |
| Cold model resolution | 4.752 | 6.393 |
| Warm generation-scoped acquisition | 0.137 | 0.428 |
| Production route total | 48.226 | 69.514 |
| Plan discovery and exact summary binding | 14.048 | 22.600 |
| Compatible batch planning | 0.251 | 0.295 |
| Propagation | 5.671 | 9.197 |
| Finding and witness reconstruction | 0.143 | 0.282 |
| Initial retained standalone projection | 8.561 | 13.433 |
| Repeated retained projection | 7.939 | 8.733 |
| JSON CodeQuery projection | 12.727 | 14.822 |
| RQL projection | 11.585 | 12.137 |
| Policy projection | 1.437 | 1.686 |
| Policy JSON rendering | 1.900 | 3.376 |

Retained estimates were invariant: 13,528 plan bytes, 53,511 report bytes, 5,878 witness bytes, and 44,892 semantic-artifact bytes. The report retained two findings, two witnesses, and 24 witness steps. Process peak RSS was 61.64 MiB p50 and 61.72 MiB p95; it is a whole-process peak, not an allocation estimate for the retained result.

The canonical standalone result checksum was `f0367dff707e0be94d393ce9dbcf9961867871e63aa0539b07ba6066a94b2acf`; the canonical policy-finding checksum was `6e97ced3673732007f1847129f4c7716789c716be0ec6ce2f02d0b368fdfcd88`. Both were invariant across processes after removing projection-scoped identifiers while preserving stable semantic identities.

Catalog accounting was one cold hit, zero cold misses, then zero warm and production hits or misses. This proves that warm target selection and exact summary binding do not return to catalog candidate/load SQL. `acquire_active_semantic_models` still reads the catalog cache identity (`PRAGMA data_version`) to detect external catalog mutation; the zero figure is deliberately about per-call model lookup/hydration SQL, not that correctness check.

## Declared scaling campaign

The full runner declares seven inline cases and nine fresh processes per case, discarding rounds zero and one and retaining seven deterministic rounds:

- summary count 1, 16, and 64 at dependency depth 1;
- dependency depth 1, 4, and 8 with enough unrelated summaries to hold total count separately;
- source/sink count 1, 4, and 16 while retaining one compatible policy batch and one propagation solve.

Dependency cases include exact external descriptors for every retained dependency. Each relevant summary also has a direct parameter-to-return transfer, while call effects force the binder to retain the declared dependency closure. Focused development probes passed for depth 4, depth 8, four source/sink pairs, and sixteen source/sink pairs. The probes confirmed bound-summary counts of 4 and 8 respectively and one propagation solve at every endpoint scale. They are validation probes, not retained performance samples.

Aggregation requires exact case/round membership in `full` mode, stable provenance, stable dimensions, stable retained sizes and counts, invariant canonical result and policy checksums, one compatible solve, and zero warm catalog loads. It reports nearest-rank p50/p95 for every phase and peak RSS. Thresholds remain an empty array until a reviewed release-profile full campaign establishes variance.

## Pinned realistic fixture design

The checked contract is `.agents/docs/semantic-summary-taint-realistic-fixture-2026-08-03.json`. It pins Spring PetClinic to `f182358d02e4a68e52bdbabf55ca7800288511e7`, roots analysis at `OwnerController.findPaginatedForOwnersLastName(int, String)`, and models `OwnerRepository.findByLastNameStartingWith(String, Pageable)` as parameter zero to normal return.

The contract status is `designed_not_available`. Before it becomes runnable, the exact resolved Spring Data JPA version and dependency artifact SHA-256 must be frozen, the compiled semantic pack must be reviewed and hashed, and the source-backed policy must prove retained-report/JSON/RQL/policy equivalence. The local pinned repository checkout also currently contains an untracked `.DS_Store`. The realistic case therefore remains outside the runnable inline matrix; this session did not modify the external checkout or claim realistic-fixture measurements.

## Threshold decision

No CI or interactive threshold is added. The next authorized evidence run should use the full release-profile inline protocol, compare p50 and p95 per phase, and only then propose phase-specific thresholds with allowance for the observed variance. The realistic fixture should receive its own baseline after its contract becomes `ready`. A single end-to-end wall-time limit would hide whether activation, binding, propagation, reconstruction, or projection regressed and is intentionally not introduced.
