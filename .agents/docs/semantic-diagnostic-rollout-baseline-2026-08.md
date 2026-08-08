# Semantic diagnostic rollout baseline, August 2026 (#1628)

This is the measured baseline before any decision about default enablement. It
is evidence, not a gate. No latency threshold exists yet: #1628 reserves that
for team review of these numbers.

Unrecognized-symbol diagnostics stay opt-in. Nothing in this document changes a
default.

The campaign procedure for real projects is
`.agents/docs/semantic-diagnostic-rollout-runbook.md`. This document is the
offline in-repo floor that campaign starts from.

## What produced these numbers

Command, once per fixture:

    cargo build --features release-tooling --bin bifrost_benchmark
    ./target/debug/bifrost_benchmark rollout \
        --fixture-id tests/fixtures/<fixture> \
        --fixture-root tests/fixtures/<fixture> \
        --configuration-id default-analyzer-config

The harness is `src/benchmark/semantic_diagnostic_rollout_harness.rs`. It
performs what an LSP session performs:

1. Build the analyzer over the fixture.
2. Select the ecosystems whose languages the workspace analyzes, by the same
   rule the LSP host uses.
3. Activate dependency packs once against a fresh ephemeral catalog. This is
   the cold activation sample.
4. Run one diagnostic request per analyzable file. This is the cold series.
5. Run the same requests again against the same published proof. This is the
   warm series.
6. Build a fresh analyzer generation, which starts with no published proof, and
   re-activate it against the now-populated catalog. This is the warm
   activation sample, and the per-file requests that follow it are the refresh
   series.

The artifact is then aggregated, validated against the #1712 schema, and
rendered. A run that produced an invalid artifact would fail rather than
report.

## Pins

- Bifrost revision: `325a4ea5f30926669839952db121c59b1222cf9a`, clean tree.
- Fixture revision: the same commit. Every fixture is in-repo, so the commit
  that contains the harness also pins the fixture content.
- Configuration: `default-analyzer-config`, that is `AnalyzerConfig::default()`
  with default `DependencyPackLimits` and default `SemanticModelRuntimeLimits`.
  Each run's configuration SHA-256 also covers the selected ecosystems and the
  measured file list, so a fixture that gains a file produces a different
  configuration hash rather than a silently different comparison.
- Active packs: none, on every fixture. Under `AnalyzerConfig::default()` no
  fixture declares dependency evidence a resolver can turn into a pack, so
  every run activates a complete but empty model set. That is the honest state
  of an offline in-repo fixture, and it is why these activation numbers are a
  floor rather than a full-cost measurement.
- Host: Linux 5.15, debug build (`cargo build`, not `--release`). Debug numbers
  overstate wall-clock latency relative to a shipped build. Treat them as
  relative signals across fixtures, not as absolute product latency.
- One run per fixture, no repetition, so there is no variance estimate.

## Activation

| Fixture | Ecosystem | Cold host ms | Warm host ms | Result | Max catalog SQL |
|---|---|---:|---:|---|---:|
| `testcode-py` | Python | 0.437 | 0.263 | ready | 0 |
| `testcode-go` | Go | 0.551 | 0.272 | ready | 0 |
| `testcode-java` | Jvm | 15.595 | 18.141 | ready | 0 |
| `testcode-rs` | Cargo | 0.445 | 0.269 | ready | 0 |
| `testcode-ts` | Npm | 0.555 | 0.335 | ready | 0 |
| `testcode-ruby` | Ruby | 0.519 | 0.294 | ready | 0 |
| `testcode-cs` | DotNet | 0.523 | 0.445 | ready | 0 |

Every activation reached `ready`, so every run published proof and requested a
diagnostic refresh.

The JVM row is the only activation costing more than a millisecond, and it does
not improve when warm. Its cost is the default-on metadata discovery walk plus
the `$JAVA_HOME` standard-library probe, neither of which the catalog caches.
Every other ecosystem is sub-millisecond because its resolver finds no evidence
to read under default configuration.

Activation runs on a background worker and never on a request path, so these
numbers bound a background cost, not a user-visible one.

## Diagnostics

Per-file request latency in milliseconds. Cold is the first read of each file;
warm re-reads the same files against the same published proof; refresh is the
first read after a fresh generation re-activates.

| Fixture | Files | Cold p50 | Cold p95 | Warm p50 | Warm p95 | Refresh p50 | Refresh p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `testcode-py` | 43 | 1.959 | 5.792 | 0.549 | 2.997 | 1.935 | 5.798 |
| `testcode-go` | 7 | 0.475 | 19.848 | 0.195 | 1.576 | 0.497 | 18.385 |
| `testcode-java` | 26 | 1.374 | 3.852 | 0.304 | 1.385 | 1.367 | 3.797 |
| `testcode-rs` | 2 | 7.756 | 16.058 | 3.438 | 6.718 | 7.058 | 14.993 |
| `testcode-ts` | 21 | 2.512 | 10.043 | 1.536 | 7.091 | 2.569 | 10.007 |
| `testcode-ruby` | 17 | 0.625 | 5.628 | 0.400 | 1.347 | 0.620 | 5.277 |
| `testcode-cs` | 6 | 4.137 | 543.734 | 2.414 | 540.098 | 6.580 | 542.398 |

Every measured request issued zero catalog SQL statements, which is the
invariant that keeps a diagnostic request read-only against the pack catalog.

Read the percentiles with the sample count in view. Nearest-rank p95 over two
to seven samples is the slowest single file, not a distribution.

Three observations to carry into review:

- Warm is consistently two to four times faster than cold, and refresh tracks
  cold rather than warm. This is expected, and it is why cold and warm are
  separate series: a new analyzer generation rebuilds the per-generation
  structures the collectors read, so the first request after any workspace
  update pays cold cost again. Refresh, not cold, is what an editing session
  pays repeatedly.
- `testcode-cs` has one file at roughly 540 ms that does not improve when warm.
  It is the largest single latency in the baseline by two orders of magnitude,
  and it is the first thing to profile before any default-enablement decision.
  It is below the five-second threshold that `CLAUDE.md` makes an automatic
  product-regression report, so no issue is filed here; it is recorded as the
  named follow-up for review.
- `testcode-go` cold p95 of about 19 ms against a p50 of 0.5 ms is one slow
  file out of seven, not a broad cost.

## Correctness signals

| Fixture | Status | Errors per pass | Absent proofs | Suppressions |
|---|---|---:|---:|---|
| `testcode-py` | incomplete | 19 | 57 | `missing_dependency_discovery` 213 |
| `testcode-go` | incomplete | 0 | 0 | `missing_dependency_discovery` 9 |
| `testcode-java` | complete | 69 | 207 | none |
| `testcode-rs` | incomplete | 0 | 0 | `missing_dependency_discovery` 15, `unsupported_generated_surface` 9 |
| `testcode-ts` | incomplete | 390 | 1170 | `missing_dependency_discovery` 3 |
| `testcode-ruby` | incomplete | 0 | 0 | `missing_dependency_discovery` 12, `unsupported_semantics` 3 |
| `testcode-cs` | incomplete | 0 | 0 | `missing_dependency_discovery` 99, `unsupported_semantics` 15 |

Counts are totals across the three phases, which measure the same files three
times; per-pass error counts are given separately.

`Status: incomplete` is not a failure. It means at least one outcome carried a
typed suppression, which is the proof system working: a name the session cannot
prove absent produces a suppression rather than an error.

Emitted errors always equal the complete-absence proof count, which the
artifact validator enforces. No run published an error without a proof.

`testcode-ts` publishes 390 errors across 21 files and `testcode-java` publishes
69 across 26. Those counts are large because these fixtures are deliberately
full of unresolved references. They are the highest-value input to the
zero-confirmed-false-positive review in the runbook, not a latency concern.

## What this baseline does not establish

- It does not measure a workspace with real dependency packs. Every fixture
  activates an empty model set, so pack decode, hydration, and matcher
  construction are all near zero here. A pinned real-project campaign is
  required before enablement; the runbook describes it.
- It does not measure a release build.
- It does not set or propose a p95 threshold.
- It carries no variance estimate.
