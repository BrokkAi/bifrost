# Issue #918 Milestone 4: bounded scheduling and measured union policy

## Scope and retained design

Milestone 4 adds a request-local bounded scheduler and a real
`ParallelUnion` physical operator without changing the public CodeQuery
surface. The scheduler dispatches only dependency-ready tasks, uses two scoped
workers, never lets an operator recursively enqueue work, and returns task
results in authored dependency order. A ready/release gate prevents branch
work from overlapping worker-setup accounting. Fallible spawning aborts and
releases already-created workers, while a panicking branch marks the fair
budget coordinator failed and wakes every waiter before unwinding.

The retained parallel operator is deliberately narrow: one root union with
exactly two distinct direct seed dependencies. Nested unions, shared seeds,
stepped branches, intersections, exceptions, and derived-layer traversals stay
on their existing sequential operators. Forced selection is available only to
internal tests and the ignored benchmark. Production `Auto` remains
sequential because the corrected A/B did not establish a stable cold-and-warm
crossover.

Each branch executes with isolated request-local caches and an authored branch
identity. Results, diagnostics, provenance, cache observations, and operator
observations are folded in authored order. The parent still folds telemetry
from every completed worker after cancellation, even when public partial
output stops at the first authored cancelled branch.

## Fair budgets and cancellation

The existing sequential executor reserves a fair share of each remaining
global budget for every authored branch, then lets later branches use unused
earlier capacity. The parallel operator preserves that contract with one
synchronized coordinator covering scanned files, source bytes, fact/reference
work, and pipeline/provenance work. Branch zero cannot borrow capacity reserved
for branch one. Branch one waits only when it requests capacity that depends on
branch zero's eventual unused share; once branch zero finishes, it receives
the same roll-forward allowance as authored sequential execution. Admission
happens before scan, fact, or row work is committed.

The parallel operator accepts live cancellation tokens; cancellation itself is
not a shape rejection. Production `Auto` remains serial because of the measured
policy below, not because a token exists. Running seed loops and budget waiters
observe the shared token. A scheduler task that sees cancellation before
invoking its closure still invokes the closure to construct the dependency's
typed cancellation-safe result, so the profile names this event
`tasks_observed_cancelled_before_start` rather than claiming the task was
skipped. Pre-cancelled top-level requests still return before planning or
dispatch.

Focused parity tests compare complete results, diagnostics, work, and detailed
evidence for fair roll-forward and true global-budget exhaustion. Additional
tests cover cancellation-bearing parallel execution, cancellation and worker
failure while a later branch waits for budget admission, unsafe-shape serial
fallback, rooted-path safety, bounded concurrency, and deterministic scheduler
result order.

## Corrected benchmark contract

The ignored release harness emits
`bifrost_code_query_parallel_execution_benchmark/v4`. Its timing schema is
candidate-neutral so Auto comparisons are not mislabeled as parallel work.
Every timed request includes analyzer query-scope setup and cleanup. Cold
baseline and candidate analyzers read the same source files but use separate
temporary durable stores, preserving structural-snapshot encoding and SQLite
writes without cross-strategy hydration. The harness asserts equal positive
extraction counts and zero hydrations on both cold sides. Warm pairs alternate
order on one analyzer after an untimed extracting warmup and assert zero later
extractions and hydrations.

Every pair asserts exact public-result, work, and detailed-evidence parity.
The final measurements used release mode, Rust 1.96.0, an Apple M4 with ten
logical processors, two scheduler workers, eight warm pairs per case, and
workspace sizes of 257, 513, and 1,001 TypeScript files. `distinct_exact_union`
scans one file per branch; `distinct_broad_union` scans 128, 256, or 500 files
per branch.

An earlier prototype appeared to justify exact parallelism at 257 files. Review
found that its cold analyzers shared one persistence root and that it omitted
the production query-scope lifecycle. The first strategy could persist facts
for the second, and Auto cold ran after both. That evidence and the threshold
derived from it were discarded before checkpointing.

## Final reversed-order evidence

Times below are milliseconds. Cold has one pair; warm shows medians and
candidate wins out of eight. Positive percentages favor forced parallel.
Stable case identity reverses the cold order: exact runs parallel first and
broad runs sequential first in round 12, with the opposite order in round 13.

| Round | Workspace | Shape | Cold sequential / parallel | Cold change | Warm sequential / parallel | Warm change | Wins |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 12 | 257 | exact | 4.597 / 9.001 | -95.80% | 5.361 / 9.459 | -76.44% | 0/8 |
| 13 | 257 | exact | 10.558 / 10.252 | +2.90% | 5.952 / 8.559 | -43.80% | 1/8 |
| 12 | 513 | exact | 16.612 / 16.946 | -2.01% | 15.684 / 25.430 | -62.14% | 1/8 |
| 13 | 513 | exact | 36.146 / 22.976 | +36.44% | 31.705 / 19.476 | +38.57% | 5/8 |
| 12 | 1,001 | exact | 16.647 / 31.457 | -88.96% | 22.798 / 35.798 | -57.02% | 0/8 |
| 13 | 1,001 | exact | 142.964 / 38.171 | +73.30% | 26.796 / 50.630 | -88.94% | 2/8 |
| 12 | 257 | broad | 47.622 / 44.388 | +6.79% | 34.340 / 37.236 | -8.43% | 0/8 |
| 13 | 257 | broad | 329.183 / 69.796 | +78.80% | 233.110 / 112.244 | +51.85% | 6/8 |
| 12 | 513 | broad | 104.182 / 91.845 | +11.84% | 80.580 / 83.848 | -4.06% | 3/8 |
| 13 | 513 | broad | 513.850 / 297.272 | +42.15% | 386.303 / 151.409 | +60.81% | 8/8 |
| 12 | 1,001 | broad | 841.686 / 428.313 | +49.11% | 222.465 / 402.767 | -81.05% | 1/8 |
| 13 | 1,001 | broad | 877.218 / 619.713 | +29.35% | 782.926 / 329.696 | +57.89% | 8/8 |

Exact cold results changed sign at all three scales after the order reversal;
exact warm medians also changed sign at 513 files and otherwise remained
negative with only isolated pair wins. Broad warm medians were negative at all
three scales in round 12 and positive at all three in round 13. Absolute
timings varied by several multiples under system load even though every result,
work record, cache contract, and source fingerprint stayed equal. There is no
current production cache-state or cardinality estimator that can distinguish
these regimes before doing the work. Promoting a machine-local cutoff would
therefore be speculative.

Auto selected no parallel operator in either final round. Its sequential
candidate timings serve only as a policy-overhead/noise control; they are not
parallel measurements.

## Decision

Retain the bounded scheduler, independent physical alternative, fair-budget
coordinator, cancellation behavior, structured scheduler profile, parity
tests, and reproducible A/B harness. Keep production Auto sequential. This is
a measured negative scheduling policy, not a claim that parallel unions can
never win. A future selector needs stable evidence across cold and warm states,
an observable pre-execution cache/cardinality signal, and concurrent-request
load coverage before it can promote a parallel shape.

No bitmap-backed set representation was added because this milestone did not
identify a stable dense identity domain. No explain/profile field was exposed
through MCP, RQL, CLI, Python, or editor surfaces; that remains Milestone 5.

## Commands and validation

Final benchmark rounds:

```sh
BIFROST_SEMANTIC_INDEX=off \
BIFROST_CODE_QUERY_PARALLEL_BENCH_SIZES=128,256,500 \
BIFROST_CODE_QUERY_BENCH_ITERATIONS=8 \
BIFROST_CODE_QUERY_BENCH_ROUND=12 \
cargo test --release --lib \
  analyzer::structural::execution::benchmark::code_query_parallel_execution_measurement \
  --no-default-features -- --ignored --exact --nocapture --test-threads=1

# Repeat with BIFROST_CODE_QUERY_BENCH_ROUND=13 to reverse case/order parity.
```

Final validation passed 11 execution/scheduler tests with 2 ignored benchmarks
registered, all 85 structural-query tests, all 46 structural-search tests, all
73 CodeQuery pipeline tests, both corrected release benchmark rounds,
formatting, strict pinned-toolchain all-target/all-feature Clippy, and
`git diff --check`. The full `nlp,python` executable suite passed as well: the
library reported 1,505 passed and 6 ignored, followed by every integration
binary. On this macOS host the initial doctest invocation mixed rustup `rustc`
artifacts with Homebrew `rustdoc`; the zero-example doctest passed when both
tools were explicitly pinned to rustup 1.96.0:

```sh
RUSTDOC=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/rustdoc \
RUSTC=/Users/dave/.rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/rustc \
RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup' \
BIFROST_SEMANTIC_INDEX=off \
rustup run 1.96.0 cargo test --features nlp,python
```
