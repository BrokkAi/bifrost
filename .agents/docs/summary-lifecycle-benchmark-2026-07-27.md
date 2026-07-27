# Reusable-summary lifecycle benchmark, 2026-07-27

## Decision

Do not add SQLite persistence for semantic, protocol, or taint summaries in issue #823. All three candidates remain bounded in-memory artifacts. Their current Rust representations have no versioned portable DTO that can reconstruct and apply an equivalent summary in a fresh process, so the evidence classification is `insufficient_evidence` even where a diagnostic-envelope lower bound passes every performance gate.

This is a measured no-go decision, not a claim that serialization is slow. A future persistence proposal must first define a packed DTO that preserves the complete key, canonical rows and effects, completeness, invalidation behavior, and application semantics. It must then rerun this benchmark with `exact_equivalence=true` and compare actual artifact hydration rather than diagnostic-envelope parsing.

## Provenance and method

- Bifrost baseline: `ab8b90f3d8b47ecce840d81ab0831954506048fe` (reviewed Milestone 3, rebased onto `origin/master` at `105f2448`). The tracked worktree was dirty with the Milestone 4 plan/report edits, and the exact benchmark test plus runner sources were identified independently by SHA-256 `42da21894ef907893c7fcda9e28a7fdfd337396ad7425ca30f0d06c6137f1847`.
- Toolchain and host: Rust 1.96.0, release profile, macOS/aarch64, 10 logical CPUs.
- Runner: `scripts/run-summary-lifecycle-benchmarks.sh`.
- Sampling: nine fresh build processes and nine fresh hydration processes per case; rounds 0 and 1 were discarded, leaving seven samples per mode and case. Reported values are medians.
- Semantic cases: one complete empty transfer summary per generated or source file. The 512-entry generated TypeScript case measures summary-container scaling. Inline TypeScript and Java exercise one-entry behavior. External cases use at most 512 source files from the pinned repositories.
- Protocol case: a real complete Java typestate projection with two rows and one observed effect, built under one stable benchmark fixture root so the complete artifact validity key is identical across fresh processes.
- Taint case: a real dependency-closed two-procedure Java transfer repository with seven rows and 38 policy-neutral observations, also built under stable current/changed fixture roots. The changed-source solve used to prove invalidation runs only after rebuild time and rebuild RSS have been captured.
- Same-process reuse: 100 exact repository lookups per build process; the table reports the median time for one complete lookup pass.
- Invalidation: every build performs a lookup with a changed context or source revision and requires an exact miss.
- Fresh-process lower bound: the build process writes a 384–406-byte JSON diagnostic envelope containing branding, completeness, counts, retained bytes, stable validity checksum, and result checksum. The hydration process parses and validates that envelope. It cannot reconstruct or apply a summary, so `exact_equivalence` is false for every row.
- Pinned VS Code revision: `19e0f9e681ecb8e5c09d8784acaa601316ca4571` (512 TypeScript/TSX files sampled).
- Pinned Spring PetClinic revision: `f182358d02e4a68e52bdbabf55ca7800288511e7` (49 Java files).
- Both external worktrees were required to be clean and at their exact revisions before the runner started. Each sample enumerated only paths tracked by the pinned Git tree, rejected non-regular files, and revalidated the exact HEAD and tracked-tree cleanliness before and after reading the selected sources; ignored or untracked build output cannot enter the sample.
- Aggregation required the exact seven-case matrix, one build and one hydrate record for each retained round 2–8, complete artifacts, identical full provenance, matching sizes/counts/checksums, successful reuse hits, and exact invalidation misses. Duplicate, missing, mixed-source, or mixed-toolchain records are rejected.
- Protocol and taint result checksums structurally hash the complete validity keys and every canonical row, effect/observation, function, and evidence value. The fixed fixture roots avoid weakening those keys merely to normalize temporary mount churn.

The shared `evaluate_artifact_promotion` gate ran with its predeclared defaults:

- hydration speedup at least 30%
- hydration saving at least 50 ms
- hydration/rebuild peak RSS ratio at most 1.10
- serialized/hydrated bytes ratio at most 2.0
- build-and-write/rebuild time ratio at most 1.25
- absolute write overhead at most 250 ms

## Median results

All sizes are bytes and all times are milliseconds. “Perf gate” is the result of all six performance gates before the independently required exact-equivalence check.

| Candidate | Dataset | Artifacts | Rows | Effects/observations | Rebuild | In-memory reuse | Build + write | Diagnostic hydrate | Rebuild RSS | Hydrate RSS | Retained | Serialized | Perf gate | Final decision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| semantic | generated TypeScript 512 | 512 | 0 | 0 | 1.682 | 0.0324 | 1.930 | 0.0621 | 12,992,512 | 7,979,008 | 1,310,572 | 402 | fail: <50 ms saved | insufficient evidence |
| semantic | inline TypeScript | 1 | 0 | 0 | 0.049 | 0.000079 | 0.212 | 0.0340 | 8,503,296 | 7,979,008 | 2,534 | 390 | fail: speed, saving, write ratio | insufficient evidence |
| semantic | inline Java | 1 | 0 | 0 | 0.048 | 0.000064 | 0.218 | 0.0453 | 8,503,296 | 7,962,624 | 2,561 | 384 | fail: speed, saving, write ratio | insufficient evidence |
| semantic | VS Code TypeScript | 512 | 0 | 0 | 126.733 | 0.0630 | 126.903 | 0.0375 | 17,367,040 | 7,979,008 | 1,349,350 | 404 | pass | insufficient evidence |
| semantic | Spring PetClinic Java | 49 | 0 | 0 | 64.056 | 0.0030 | 64.212 | 0.0342 | 9,256,960 | 7,979,008 | 133,094 | 406 | pass | insufficient evidence |
| protocol | inline Java | 1 | 2 | 1 | 10.140 | 0.000308 | 10.211 | 0.0360 | 20,365,312 | 7,962,624 | 10,429 | 385 | fail: <50 ms saved | insufficient evidence |
| taint | inline Java | 2 | 7 | 38 | 11.030 | 0.0137 | 11.321 | 0.0344 | 20,742,144 | 7,979,008 | 278,501 | 384 | fail: <50 ms saved | insufficient evidence |

Every retained sample was complete, every exact in-memory lookup hit, every changed-validity lookup missed, and result/validity checksums were stable across build and hydration processes. The canonical result checksums were:

- semantic generated TypeScript: `810027b12c0d4424ff292ecba5289ebea853d83fce83251fd6e17b697de0197c`
- semantic inline TypeScript: `e80d7e56be5511bb73ccf15def4b9da3c609f25e68b6cf260fe25709f5c4cec2`
- semantic inline Java: `27c9592788338c0ef943ad34c17fcaec90c6b46c75e03c6f3f5343af06773580`
- semantic VS Code: `a0370ad02df523d6d3c705a4d0b51911d3a09e07d7741156a73b67fbe97e4360`
- semantic Spring PetClinic: `d4d41275f25992a5fbaa7fe4f0cca4bae4e988a6f3a513276978f4e4b989c27b`
- protocol inline Java: `4da691e45978d442392eab99cf29cbefa9704c160fe602076841e11211800ddc`
- taint inline Java: `c4004c2b163c8e03e08cf385c7042153c0d4e0412cedc9b0f0c226f27378b185`

## Interpretation

The VS Code and Spring PetClinic semantic cases demonstrate why the equivalence requirement matters. Parsing their 404-byte and 406-byte envelopes is more than 99% faster than collecting pinned source content and constructing the in-memory summary entries, and both pass all six numeric gates, but the envelopes contain none of the transfer relation needed by a caller. Treating either lower bound as a persistence win would be a false positive.

The other cases also lack equivalence and fail at least the absolute 50 ms saving gate. The one-entry inline semantic cases additionally fail the speedup or build-and-write ratio gates because fixed serialization overhead is larger than summary construction. Protocol and taint construction are measurably heavier, but still save only 10.1 ms and 11.0 ms respectively against the non-equivalent envelope lower bound.

No candidate authorizes a migration, an `AnalyzerStore` API, startup hydration, or background writes. The safe issue #823 outcome is the reviewed in-memory repositories plus this reproducible benchmark and explicit promotion boundary.
