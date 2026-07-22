# Issue #918 Milestone 2 CodeQuery measurement

This note records the optimized evidence used to complete Milestone 2 of
`.agents/plans/issue-918-query-planning-execution.md`. The benchmark is a
deterministic synthetic microbenchmark. It validates the profile schema, cache
lifecycle attribution, scaling, and optimistic overlap headroom. It does not
measure real parallel execution and does not select a production scheduling
threshold or a SQL-backed graph representation.

## Configuration and provenance

The decision run used:

- Apple M4, macOS arm64, 10 logical processors;
- Rust 1.96.0 and an optimized `release` build;
- analyzer parallelism 1;
- 16 files per branch at the small scale and 128 files per branch at the large
  scale;
- eight alternating profiled/unprofiled same-analyzer iterations per mode and
  two rounds with reversed scale and case order;
- maximum result count 1,000, maximum 20,000 scanned files, 128 MiB scanned
  source, 2,000,000 fact nodes, and 50,000 pipeline rows;
- physical execution `sequential_recursive` and headroom model
  `ideal_perfect_overlap_projection`.

Both final rounds fingerprinted the exact measured dirty tree as
`e3bde61241359dadbb59bdd9f72c4c7c39e1fb549d2fc823472959dcc6f582b7`.
The dirty-tree base was the Milestone 1 checkpoint
`6ed62746efa5803f89dcd93f5213cafbc3e77a78`. The benchmark records the full
compiler, OS, CPU, configuration, query, work, cache, raw-sample, result-digest,
and profile payload in its versioned JSON line.

The commands were:

    BIFROST_SEMANTIC_INDEX=off BIFROST_CODE_QUERY_BENCH_ROUND=0 \
      cargo test --release --lib code_query_execution_profile_measurement -- --ignored --nocapture
    BIFROST_SEMANTIC_INDEX=off BIFROST_CODE_QUERY_BENCH_ROUND=1 \
      cargo test --release --lib code_query_execution_profile_measurement -- --ignored --nocapture

Each invocation emits one line prefixed
`BIFROST_CODE_QUERY_EXECUTION_BENCHMARK=` with format
`bifrost_code_query_execution_benchmark/v1`.

## Large-scale timing results

Times are profiled same-analyzer medians in milliseconds, followed by median
absolute deviation. `Profile delta` is the median of paired profiled versus
unprofiled percentage differences. `Headroom` is the median idealized request
saving if two complete, distinct, non-sharing branches overlap perfectly while
set self-time and rendering remain unchanged and scheduler cost is zero.

| Case | Round 0 median / MAD | Round 1 median / MAD | Profile delta r0 / r1 | Headroom r0 / r1 |
| --- | ---: | ---: | ---: | ---: |
| identical exact union | 2.561 / 0.004 | 2.531 / 0.004 | -0.13% / +0.22% | ineligible |
| distinct exact union | 5.043 / 0.011 | 5.038 / 0.009 | +0.11% / +0.04% | 49.73% / 49.80% |
| identical broad union | 3.683 / 0.010 | 3.787 / 0.006 | -0.33% / +0.07% | ineligible |
| distinct broad union | 20.441 / 0.024 | 20.602 / 0.033 | +0.22% / -0.07% | 14.40% / 14.35% |
| identical shared-reference union | 57.101 / 0.223 | 58.155 / 0.991 | +0.22% / -0.77% | ineligible |
| distinct shared-import union | 4.537 / 0.004 | 4.576 / 0.004 | +0.20% / +0.00% | ineligible |

The small distinct exact case projected 48.48% and 48.43% headroom across the
two rounds. The small distinct broad case projected 39.48% and 40.30%. Across
all 24 case-round observations, paired profiling delta ranged from -0.77% to
+1.91%; the largest positive observation was the smallest identical exact
case. The large cases remained between -0.77% and +0.22%.

These values are not evidence that a parallel implementation will achieve the
projection. They omit dispatch, contention, CPU saturation, and dependency
waiting, and record wall time rather than per-request CPU time. Milestone 4
must measure the real bounded sequential and parallel operators before choosing
a policy.

## Cache and work contracts

The benchmark asserts these behaviors, rather than merely printing counters:

- A cold identical exact union performed one structural-facts extraction, one
  complete seed-result build, and one complete sibling hit. A same-analyzer
  later request performed one seed-path structural-facts memory hit and no
  extraction or persisted hydration.
- A cold distinct exact union performed two seed builds and two structural-facts
  extractions with no request-local seed hit. A later request saw two
  structural-facts memory hits.
- The large identical shared-reference union performed one complete inbound
  reference build and one complete sibling hit. It replayed 512 pre-filter
  cached payload items and examined 512 references. The separate provider delta
  showed 257 cold extractions and zero same-analyzer-later extractions.
- The large distinct shared-import union performed one complete reverse-import
  build and one sibling hit, replaying 128 relevant incoming entries. Building
  the shared graph resolved exactly 130 files and 256 import edges.
- Typed incomplete call-relation diagnostics make both call-cache builds and
  replays incomplete even when the lower result is not flagged truncated or
  cancelled. Likewise, unsupported import entries remain reusable cache hits
  but are incomplete in both forward and reverse cache profiles. Focused
  regressions cover these non-timing cases.
- Every profiled operator and request reported `peak_concurrency = 1`, zero
  dependency wait, and zero scheduling overhead. Those zeroes describe the M2
  serial executor; they are not measurements of a scheduler that does not yet
  exist.

Cold means the first request against a freshly constructed analyzer. Warm means
a later request against the same analyzer generation. Import and reference
relations are request-local in M2, so they rebuild for each request and are
shared only between sibling branches inside that request. This benchmark does
not exercise a persisted close/reopen lifecycle.

## Ordinary-path M1 comparison

A temporary integration harness using only public `execute_with_limits` APIs
was applied unchanged to the M1 checkpoint and the M2 tree, then removed before
the checkpoint. It built 128-file-per-branch TypeScript and Java fixtures,
warmed each query once, and recorded four alternating optimized rounds of 12
samples for six query shapes. Every M1 and M2 result count, completion status,
and SHA-256 result digest matched.

| Case | M1 combined median | M2 combined median | M2 delta |
| --- | ---: | ---: | ---: |
| identical exact union | 2.561 ms | 2.590 ms | +1.14% |
| distinct exact union | 5.122 ms | 5.215 ms | +1.82% |
| identical broad union | 3.755 ms | 3.797 ms | +1.13% |
| distinct broad union | 20.777 ms | 20.904 ms | +0.61% |
| identical shared-reference union | 60.125 ms | 59.935 ms | -0.32% |
| distinct shared-import union | 4.624 ms | 4.693 ms | +1.49% |

The combined medians contain 48 samples per revision and case. One M2 round of
the distinct broad case was a 23.24% timing outlier; the other three round
deltas were -0.43%, -0.79%, and +2.45%. The combined result and the reversed
rounds do not support treating that transient as a regression, but the small
positive deltas on several cheap paths should remain visible when Milestone 4
measures scheduler break-even costs.

## Decision

M2 establishes enough structured evidence to design the next experiments, but
not enough to publish a threshold. Exact independent seed branches expose a
large optimistic overlap ceiling, while broad high-output branches retain much
more serial merge and rendering work. Shared-reference and shared-import cases
prove that branch independence cannot be inferred from syntax alone: executing
them concurrently without a complete-value single-flight layer would duplicate
or contend on prerequisite construction.

Milestone 3 should therefore establish exact dependency keys and complete-value
single-flight before Milestone 4 introduces real parallel union. The synthetic
fixtures nominate reference traversal and import topology for later real-repo
measurement, but do not select or reject a SQL-to-memory representation. CPU
duration, RSS/retained bytes, persisted reopen behavior, asymmetric branches,
high-fanout repositories, and actual scheduler contention remain unmeasured.
