# Persisted Query Read Models for Analyzer Performance

This ExecPlan is a living document. Maintain it under `.agents/PLANS.md` while the SQLite-backed analyzer store work is in progress.

## Purpose / Big Picture

The SQLite analyzer store must retain cold-start data across application updates without making normal MCP reads impractically slower than the former in-memory analyzer. After this work, `get_summaries` and other read-heavy tools will retrieve only the persisted facts they need instead of reconstructing a full `FileState` containing unrelated graph, import, and type data. The outcome is observable through the Google Gson benchmark: query latency remains close to the current master implementation while responses remain byte-for-byte equivalent.

## Progress

- [x] (2026-07-10 20:33Z) Replaced the hot candidate-query side-table count audit with an atomic `blob_meta.is_complete` transaction marker. Full count validation remains on hydration and explicit cache-presence checks.
- [x] (2026-07-10 20:35Z) Bulk-hydrated file states when building the usage-facts index, with a regression test covering more files than the transient cache capacity.
- [x] (2026-07-10 21:15Z) Measured fresh Google Gson master and candidate reports and profiled exact MCP calls.
- [x] (2026-07-10 21:30Z) Removed an unsuccessful primary-range search experiment after fresh measurements showed no improvement.
- [x] Defined persisted summary and symbol-candidate projections, including generic `IAnalyzer` fallbacks and projection-level tests.
- [x] Replaced broad repeated hydration with a bounded request-scoped read cache that clears at the outer query boundary.
- [x] Added a compact usage-facts projection and reused the immutable definition lookup index for Java usage resolution.
- [x] (2026-07-10 22:38Z) Took fresh back-to-back master/candidate Google Gson reports and posted the caveated evidence to PR #447.

## Surprises & Discoveries

- Observation: The initial `get_summaries` regression was mostly caused by the persistence access pattern, not SQLite execution alone.
  Evidence: The Google Gson median fell from about 298 ms to about 29 ms after the completion-marker change, with SQLite still enabled.
- Observation: The remaining summary cost is a full-state read-model mismatch.
  Evidence: An exact persisted `get_summaries` MCP request spends 43.3 ms in `searchtools::summarize_files`; the response is 3,786 bytes and exactly matches master. The benchmark medians are 29.3 ms on the candidate and 2.45 ms on master.
- Observation: Carrying primary ranges through all search candidates made `search_symbols` slower because symbol search still scans every declaration and separately evaluates test status.
  Evidence: Fresh candidate medians were about 621 ms with the experiment versus about 608 ms before it. The experiment was removed rather than extended.
- Observation: A bulk preload of complete file states did not improve the Java usage scan.
  Evidence: It added source reads and hashing before the walker, duplicating the source work the scanner already performs. The experiment was removed.
- Observation: The paired final report meets the 1.5x goal for `scan_usages` and reaches its boundary for call hierarchy, but not for type hierarchy.
  Evidence: `scan_usages` was 1282.5 ms versus 893.2 ms (1.44x); call hierarchy 2457.0 ms versus 1636.4 ms (1.50x); type hierarchy 792.2 ms versus 459.5 ms (1.72x).

## Decision Log

- Decision: Treat `blob_meta.is_complete` as the fast hot-path validity predicate and preserve full row-count validation at hydration and explicit cache checks.
  Rationale: Writes publish rows and the marker in one SQLite transaction. This avoids whole-database count scans on every candidate query without accepting incomplete writes as valid state.
  Date/Author: 2026-07-10 / Codex
- Decision: Use query-shaped persisted projections instead of adding another generic `FileState` cache.
  Rationale: A summary requires a small, stable subset of persisted tables. A cache would retain the cost of reading irrelevant tables and would only hide it for repeated access.
  Date/Author: 2026-07-10 / Codex
- Decision: Do not optimize `search_symbols` by changing query semantics until a safe candidate index can represent path-derived language qualifiers.
  Rationale: Go, Rust, and Python derive part of their qualified name from the live file path, so filtering rows solely by persisted `content_qualifier` could silently omit valid symbols.
  Date/Author: 2026-07-10 / Codex
- Decision: Use a request-scoped hash map for hydrated file states instead of enlarging the cross-request LRU.
  Rationale: A bounded LRU pays recency-maintenance cost on every node lookup and thrashes when a graph traversal exceeds its capacity. The request map is bounded to 1,024 states, has O(1) access, and is released after the outer query.
  Date/Author: 2026-07-10 / Codex
- Decision: Stop performance changes after the measured query projections and cache lifecycle work.
  Rationale: The remaining type-hierarchy gap needs a dedicated hierarchy read model. Further local cache or preload variants either did not improve the paired result or duplicated source reads.
  Date/Author: 2026-07-10 / Codex

## Outcomes & Retrospective

The completion marker removed the largest accidental persistence cost while preserving corruption quarantine. Summary, symbol, and usage-facts projections now avoid full-state hydration for their read paths, and query-scoped state reuse prevents broad graph traversals from thrashing the global cache. The final paired result does not justify claiming the broad 1.5x objective: type hierarchy remains 1.72x slower and requires a dedicated follow-up rather than another local cache adjustment.

## Context and Orientation

`src/analyzer/tree_sitter_analyzer.rs` owns the persisted `TreeSitterAnalyzer`. `fetch_file_state` currently resolves a live blob OID, reads the source file, and calls `AnalyzerStore::hydrate_file_state_with_source`. Hydration in `src/analyzer/store/mod.rs` reads all persisted side tables and verifies their stored counts before assembling the general `FileState` structure.

`src/searchtools.rs` implements MCP output. `summarize_files` currently calls `IAnalyzer::top_level_declarations`, `signatures`, `ranges`, and `direct_children`; those methods all obtain data from the general `FileState`. The former in-memory master keeps that state resident, while the SQLite branch has to reconstruct it for a cold file.

The schema lives in `src/cache_db.rs`. `blob_meta` records a transaction-published `is_complete` marker and counts for side-table integrity checks. `code_units`, `unit_ranges`, `unit_signatures`, and `unit_children` are the tables needed to describe a summary. A projection is a purpose-built value containing only those rows, not a partially filled `FileState` that other analyzer APIs might accidentally use.

## Plan of Work

Add a small analyzer-model value for summary declarations. Each value must carry a `CodeUnit`, its display signatures, its declaration ranges, and enough parent/child information to flatten a file's top-level summaries exactly as `summary_elements_for_code_unit_in_file` does today. Keep the value independent of searchtools output types so the analyzer does not depend on MCP rendering.

In `AnalyzerStore`, add a single-file projection reader that selects the complete blob's declaration rows, ranges, signatures, and child links. It must use the same `is_complete` predicate as other hot query reads. It must not replace `hydrate_file_state_with_source`: normal analyzer operations still require full-state integrity checks. The projection reader should validate that the required rows are structurally usable and return no projection on a malformed blob, allowing the analyzer to use its existing parse-and-store transient recovery path.

In `TreeSitterAnalyzer`, expose an `IAnalyzer` method for summary declarations. The default method must reproduce existing behavior from `top_level_declarations`, `signatures`, `ranges`, and `direct_children`. The persisted override must use the projection for clean files, retain dirty overlay behavior, and preserve current ordering and de-duplication.

In `searchtools`, change only the summary traversal to consume the new analyzer summary values. Keep output construction, element de-duplication, fallback handling, and preamble rendering unchanged. Add parity tests that construct a small inline Java project, compare the generic/default and persisted output shape, and verify a corrupted required projection row falls back to transient parsing rather than emitting incomplete summaries.

## Concrete Steps

From `/Users/dave/.codex/worktrees/42d7/bifrost`:

    cargo fmt
    cargo test --features nlp --lib searchtools::tests
    cargo test --features nlp --lib analyzer::store::tests
    cargo clippy --all-targets --all-features -- -D warnings

Build the benchmark binaries and run paired master/candidate reports against the same Google Gson checkout:

    BIFROST_SEMANTIC_INDEX=off ./target/debug/bifrost_benchmark run --manifest benchmark/targets.toml --repo google-gson --output /private/tmp/bifrost-perf-master
    BIFROST_SEMANTIC_INDEX=off BIFROST_BENCHMARK_BIFROST_BIN=$PWD/target/debug/bifrost ./target/debug/bifrost_benchmark run --manifest benchmark/targets.toml --repo google-gson --output /private/tmp/bifrost-perf-candidate

The expected evidence is unchanged structured `get_summaries` content and a lower candidate median. Do not interpret a single direct MCP call as a benchmark result; the harness uses two warmups and ten measured calls.

## Validation and Acceptance

The projection is correct when existing summary tests pass, new parity tests show the same paths, symbols, signatures, and ranges as the generic route, and a deliberately removed required projection row triggers transient parsing instead of partial output. It is performant when a fresh paired Google Gson report shows a materially lower `get_summaries` median without a regression in the other scenarios. The broader 1.5x goal is met only if the fresh report proves it for the relevant operations.

## Idempotence and Recovery

The store projection is read-only. Schema changes must use the analyzer schema version so old analyzer rows rebuild while semantic rows remain intact. If projection validation fails, return to the existing full parse-and-store transient path; never invent missing declarations from source text. Benchmark output directories are disposable and must use a new directory for each run.

## Artifacts and Notes

Fresh benchmark evidence recorded before the projection work:

    master get_summaries median: 2.45 ms
    candidate get_summaries median after completion marker: 29.29 ms
    candidate exact MCP summarize_files scope: 43.3 ms
    candidate and master response size: 3,786 bytes

## Interfaces and Dependencies

Define the summary projection in the analyzer model layer, not in `searchtools`. The final `IAnalyzer` API should have a default implementation so non-persisted analyzers preserve current behavior. The persisted override must return a complete projection or fall back to the existing analyzer parse path; it must never expose a partially hydrated `FileState`.

Revision note (2026-07-10): Created after profiling demonstrated that generic persisted hydration, rather than SQLite alone, is the remaining summary bottleneck.
Revision note (2026-07-10): Updated after final paired Gson evidence; the rejected preload experiment and remaining hierarchy gap are recorded above.
