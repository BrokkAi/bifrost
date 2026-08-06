# Prevent FileState hydration thrash with a byte-bounded adaptive cache

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current.

Maintain this document according to `.agents/PLANS.md` in the repository root.

## Purpose / Big Picture

Large Bifrost workspaces can repeatedly rebuild the same analyzer file state from SQLite. This happens when a probe visits more than 1,024 files. The fixed entry limit then evicts data that the probe soon needs again.

After this work, Bifrost will limit retained file states by estimated bytes. It will keep repeatedly used states ahead of one-time scan data. It will also avoid repeated full hydration when one bounded cache cannot hold the required working set.

The existing `AnalyzerConfig::memo_cache_budget_bytes` remains the memory ceiling. The change must not create an independent, unbounded cache setting. A deterministic regression test will show bounded retained bytes and bounded repeat hydrations. The Phalcon shard from issue #1707 will show steady probe progress without multi-hour stalls.

## Progress

- [x] (2026-08-06) Read issue #1707, its Chromium evidence, and linked issues #1689 and #1698.
- [x] (2026-08-06) Inspect the current cache, query lifetime, hydration path, persisted payload accounting, and memory benchmark.
- [x] (2026-08-06) Select a byte-bounded, scan-resistant cache with a bounded query reserve.
- [ ] Record the exact Phalcon miss sequence and establish deterministic baseline measurements.
- [x] (2026-08-06) Add retained-byte estimates and active-corpus byte estimates.
- [x] (2026-08-06) Replace fixed-entry LRU with a byte-bounded probation and protected cache.
- [x] (2026-08-06) Replace the query cache entry limit with a byte reserve under the same configured ceiling.
- [ ] Remove the repeated full-hydration loop that remains when the working set exceeds the ceiling.
- [ ] Run focused tests, the memory benchmark, the Phalcon probe, formatting, Clippy, and policy checks.

## Surprises & Discoveries

- Observation: The active-query cache also stops at 1,024 file states.
  Evidence: `QueryReadCache::file_states` inserts only while its length is below `QUERY_FILE_STATE_CACHE_CAPACITY`.

- Observation: The active-query cache does not evict after reaching its limit.
  Evidence: Later states remain dependent on `transient_file_states`, which uses LRU eviction.

- Observation: Bifrost already has a configured memo-cache budget.
  Evidence: `crates/bifrost-core/src/analyzer/config.rs` defaults `memo_cache_budget_bytes` to 256 MiB.

- Observation: The store already records persisted payload costs by blob and language.
  Evidence: `blob_payload_costs` and `PreparedParsedBlob::persisted_payload_bytes` exclude source text.

- Observation: A bounded cache cannot retain a uniformly reused working set larger than its byte ceiling.
  Evidence: Every finite eviction policy must miss on some part of a larger cyclic sequence.

- Observation: The Bifrost symbol search used during planning exceeded five seconds and returned a cancelled partial result.
  Evidence: One four-pattern `search_symbols` call took 6.3 seconds and returned no observed files.

## Decision Log

- Decision: Bound file-state retention by estimated bytes, not entry count.
  Rationale: A Phalcon amalgamation and a small source file have very different retained costs.
  Date/Author: 2026-08-06 / Codex

- Decision: Derive the cache ceiling from `AnalyzerConfig::memo_cache_budget_bytes`.
  Rationale: This keeps one memory control and preserves horizontal scaling.
  Date/Author: 2026-08-06 / Codex

- Decision: Make the working target a bounded percentage of active-corpus bytes.
  Rationale: Small workspaces can retain most useful states. Whale workspaces still stop at the fixed ceiling.
  Date/Author: 2026-08-06 / Codex

- Decision: Use a two-segment cache instead of a full TinyLFU implementation.
  Rationale: A probation segment filters scans. A protected segment retains entries that receive a second use.
  Date/Author: 2026-08-06 / Codex

- Decision: Use no new cache dependency.
  Rationale: The current stamped lazy-LRU supplies the required O(1) queue operations.
  Date/Author: 2026-08-06 / Codex

- Decision: Give active queries a bounded byte reserve, not unlimited pinning.
  Rationale: Unlimited pins multiply memory by the number of concurrent probes.
  Date/Author: 2026-08-06 / Codex

- Decision: Treat cache policy and hydration scope as separate corrections.
  Rationale: Adaptive eviction protects hot data, but it cannot fit an oversized cyclic working set.
  Date/Author: 2026-08-06 / Codex

- Decision: Estimate corpus bytes from complete persisted payload rows and multiply by four before applying the ten-percent target.
  Rationale: Persisted payloads exclude source text and allocator costs. The expansion is conservative until Phalcon measurements calibrate it.
  Date/Author: 2026-08-06 / Codex

## Outcomes & Retrospective

The first implementation milestone is complete. The cache now derives its byte target from complete active persisted payload rows, keeps a hard share of the existing memo budget, and protects second-use entries from cold scans. The exact Phalcon replay and the remaining oversized hydration path still need runtime evidence.

## Context and Orientation

All paths in this plan are relative to the repository root.

`FileState` is the complete in-memory analyzer record for one source file. It contains source text, declarations, ranges, imports, signatures, hierarchy facts, and other maps. Its heap cost varies with file size and declaration count.

`crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs` owns both relevant caches. `transient_file_states` is a shared `BoundedFileCache<FileState>`. It currently retains 1,024 entries. `QueryReadCache::file_states` retains up to 1,024 entries during an active query.

`TreeSitterAnalyzer::fetch_file_state_for_key_with_source` checks query-local and shared caches. A miss calls `AnalyzerStore::hydrate_file_state_with_source`. That store method reads SQLite rows and rebuilds a complete `FileState`.

`crates/bifrost-analysis/src/analyzer/store/mod.rs` persists analyzer rows. The `blob_payload_costs` table records serialized analyzer bytes. The value excludes source text. It is a useful corpus estimate, but it is not an exact heap measurement.

`crates/bifrost-core/src/analyzer/config.rs` defines `AnalyzerConfig::memo_cache_budget_bytes`. Its default is 256 MiB. Other memoized analyzer structures already derive their limits from this value.

Issue #1707 reports four Phalcon probes. They stop after approximately 50 records. The workers remain busy in SQLite hydration and cache eviction. Chromium shows the same signature. This makes the problem workspace-independent.

The exact Phalcon command is:

    target/release/bifrost_mcp_property_fuzzer --clones-root /tmp/local-clones \
      --language php --repo phalcon__cphalcon --repo-jobs 1 --jobs 4 \
      --shard 3/5 --max-service-symbols 200 --max-scan-probes 20 --cache-mode ephemeral \
      --out /tmp/t7-php-phalcon__cphalcon-shard3.jsonl \
      --dump-probes /tmp/t7-php-phalcon__cphalcon-shard3-dump.jsonl

The term “probation” means the cache has seen an entry once. The term “protected” means the cache has seen an admitted entry again. A large sequential scan fills probation first. It does not remove frequently reused protected entries.

## Plan of Work

### Milestone 1: Measure the miss sequence and create the regression

Add cache counters beside `full_hydration_count` in `TreeSitterAnalyzer`. Count hits, misses, admissions, promotions, evictions, rejected admissions, and estimated retained bytes. Also count a rehydration after prior eviction. Keep production overhead to relaxed atomic increments. Do not log one line per access.

Add test-only accessors through `IAnalyzer` only where an integration test needs them. Prefer a private statistics snapshot for unit tests. Include complete counters in one diagnostic value.

Run the Phalcon shard until the first stalled batch appears. Preserve its probe dump. Add a narrow fuzzer replay option only if the existing runner cannot execute selected dumped probes. The replay input must use the existing structured JSON fields. Do not parse source text or tool arguments with regular expressions.

Record these baseline values in this plan:

- The distinct file-state keys per stalled probe.
- The estimated bytes for those keys.
- Rehydrations by key.
- Eviction-to-next-use distance.
- SQLite hydration time.
- Cache-lock time.
- Peak and steady RSS.

Create a deterministic cache regression in the existing inline test module of `tree_sitter_analyzer.rs`. Use weighted dummy values. Warm a small hot set, scan more cold bytes than the cache holds, and access the hot set again. The current LRU must evict the hot set. The new policy must retain it.

Create an analyzer behavior regression in an applicable integration suite under `tests/<suite>/`. Build a small project with enough weighted file states to exceed a small test budget. Execute the smallest structured query sequence found in the Phalcon dump. Assert result equality, bounded retained bytes, and a strict hydration bound.

Milestone acceptance requires a repeatable failing test before the policy change. It also requires a saved baseline in `Surprises & Discoveries`.

### Milestone 2: Add byte estimates and calculate the target

Add a private retained-byte estimate for `FileState`. Count source capacity and heap-backed collection capacities. Count owned string capacities. Count nested vectors and maps. Use saturating arithmetic. Do not claim allocator-exact measurement.

Keep this estimator next to `FileState` in `tree_sitter_analyzer.rs`. More than one cache consumer will use it. Add focused tests where larger sources and collections produce larger estimates.

Add one bounded store query in `store/mod.rs` for active corpus payload bytes. Sum `blob_payload_costs.payload_bytes` only for current, complete blobs in the requested languages and generation. Add live source byte sizes from the immutable project snapshot. Do not hydrate file states to calculate the corpus estimate.

Calculate the working target as follows:

    corpus_target = round_up_to_mib(active_corpus_estimated_bytes / 10)
    file_state_ceiling = an explicitly documented share of memo_cache_budget_bytes
    target = min(max(corpus_target, minimum_useful_bytes), file_state_ceiling)

Determine the ceiling share during baseline calibration. Start with one half of `memo_cache_budget_bytes`. Reduce it if the existing full memory benchmark exceeds its bound. Record the final share and measured reason in `Decision Log`.

For very small configured budgets, use the configured ceiling directly. Never let rounding exceed the ceiling. An entry larger than the ceiling can serve its caller, but the cache must not retain it.

Milestone acceptance requires unit tests for rounding, minimum, maximum, overflow, zero corpus bytes, and one oversized entry.

### Milestone 3: Replace entry LRU with byte-bounded segmented LRU

Replace `BoundedFileCache<T>` with an internal weighted cache. Keep stamped lazy queues, O(1) touches, and bounded queue compaction.

Each entry must contain its weight, segment, and latest stamp. New entries enter probation. A probation hit promotes the entry to protected. Protected hits refresh protected recency.

Reserve most bytes for protected entries. Start with 80 percent protected and 20 percent probation. Calibration can change this split. Record a changed split in `Decision Log`.

When protected exceeds its share, demote its least-recent entry to probation. When total bytes exceed the target, evict probation first. Evict protected entries only when probation cannot restore the bound. Never retain one entry above the total target.

Do not use frequency divided by bytes as the only score. That rule can reject a large amalgamation even when it is the hottest file. Segmentation supplies scan resistance. Byte weights supply memory control.

Update the existing cache tests. Add tests for exact byte accounting, replacement weight changes, promotion, demotion, scan resistance, oversized rejection, and queue compaction. Preserve most-recent behavior within each segment.

Construct the transient cache with the target from Milestone 2. Remove `TRANSIENT_FILE_STATE_CACHE_CAPACITY`. Keep the summary projection cache unchanged unless measurements show the same failure there.

Milestone acceptance requires all cache tests and the analyzer regression to pass. Retained estimated bytes must never exceed the target.

### Milestone 4: Bound query retention under the same memory policy

Replace `QUERY_FILE_STATE_CACHE_CAPACITY` with a byte reserve. Size the reserve as part of the file-state ceiling, not in addition to it. Start with 25 percent for active-query retention and 75 percent for shared retention.

The query map can retain `Arc<FileState>` values after shared eviction. Therefore, account query-held values conservatively. Double charging a value is acceptable. Undercharging an independently retained value is not acceptable.

Do not pin every visited file. Admit repeated query-local use first. Admit a first use only while the query reserve has free bytes. An oversized state remains available to the current caller but is not retained.

Keep concurrent query accounting bounded. The total query reserve is shared across active contexts. Do not allocate one full reserve per worker. Release reserved bytes when the last active query context ends.

Add concurrent tests with four query contexts. Prove that their combined retained estimate stays below the shared reserve. Prove that one query cannot remove all shared hot entries.

Milestone acceptance requires bounded combined bytes and correct cleanup on normal return, error return, and context overlap.

### Milestone 5: Remove the oversized cyclic hydration path

Use the Milestone 1 evidence to locate the operation that revisits more bytes than the ceiling. Update this plan with the exact function before editing that operation.

First prefer a store projection that reads only required rows. `AnalyzerStore::summary_file_projection` is the existing model. Add another typed projection only when the probe needs a strict subset of `FileState`.

If the operation needs complete states, reorder its structured traversal by file. Hydrate one file, consume all required facts, and then release it. Use a batch store read when the operation already knows a bounded set of file keys.

If concurrent workers request the same missing key, add a per-key single-flight cell. One worker performs hydration. Other workers wait for that result. Remove the cell after success or failure. Do not hold the cache mutex during SQLite work.

Do not add a text-search fallback. Do not increase the byte ceiling to make the test pass. The fixed ceiling is an acceptance constraint.

Milestone acceptance requires the deterministic analyzer test to keep rehydrations proportional to distinct required states. The repeated probe run must make steady progress under the configured ceiling.

### Milestone 6: Validate memory, latency, and policy

Run focused tests after each milestone. Run the ignored memory benchmark after byte accounting and after query retention changes. Compare cold, warm, and peak RSS with the saved baseline.

Run the Phalcon command with the same repository, shard, jobs, symbols, scan count, and cache mode. Compare completed record rate, hydration count, rehydration count, CPU, and RSS. Also run one Chromium probe subset from issue #1707 when its dump is available.

The correction passes only when these conditions hold:

- Estimated retained bytes never exceed the configured file-state ceiling.
- Four concurrent probes do not receive four independent full reserves.
- The deterministic hot-set test has no hot-set rehydration after the cold scan.
- The exact Phalcon probe batch makes continuing progress.
- Peak RSS does not regress beyond the calibrated memory ceiling and normal measurement noise.
- Tool results remain byte-for-byte equivalent where ordering is contractual.

## Concrete Steps

Run all commands from the repository root.

Before implementation, capture the current state:

    git status --short --branch
    git rev-parse HEAD
    cargo test -p brokk-bifrost-analysis bounded_file_cache -- --nocapture

Run the focused tests introduced by this plan. Replace names below only when the final test modules use more precise names:

    cargo test -p brokk-bifrost-analysis adaptive_file_state_cache -- --nocapture
    cargo test --test suite_issues issue_1707_file_state_cache_thrash -- --nocapture

Run the memory benchmark without NLP:

    BIFROST_SEMANTIC_INDEX=off cargo test --test suite_semantic -- measure_analyzer_persisted_memory:: --ignored --nocapture

Build the release fuzzer and run the exact issue command:

    cargo build --release --bin bifrost_mcp_property_fuzzer
    target/release/bifrost_mcp_property_fuzzer --clones-root /tmp/local-clones \
      --language php --repo phalcon__cphalcon --repo-jobs 1 --jobs 4 \
      --shard 3/5 --max-service-symbols 200 --max-scan-probes 20 --cache-mode ephemeral \
      --out /tmp/t7-php-phalcon__cphalcon-shard3.jsonl \
      --dump-probes /tmp/t7-php-phalcon__cphalcon-shard3-dump.jsonl

Run the normal focused gate:

    cargo fmt --check
    cargo test -p brokk-bifrost-analysis
    cargo test --test suite_issues

Before a push, run the repository gate from the project instructions:

    scripts/pre-push-gate.sh

Do not enable NLP for routine development. The pre-push gate owns comprehensive feature validation.

Before completion, run one policy request against the active workspace. Include `bifrost.code-smells` and every executable repository policy root identified by the project. Treat `finding` as review work. Treat `unreliable` as a failed validation.

## Validation and Acceptance

The primary behavior test uses a cache smaller than its cold scan. It warms hot entries, scans cold entries, and then repeats the hot accesses. The old cache fails through hot rehydration. The new cache passes without exceeding its byte target.

The analyzer test executes the structured call pattern found in the Phalcon dump. It asserts identical results and a bounded hydration count. It must use `InlineTestProject` unless the fixture requires a large reusable corpus.

The memory benchmark must show that a larger workspace does not make retained cache bytes exceed the configured ceiling. RSS can include SQLite and allocator pages. Therefore, record both RSS and internal retained-byte counters.

The real Phalcon run must continue writing probe records. Four workers can remain CPU-bound, but the same four records must not remain active for hours.

## Idempotence and Recovery

All tests and measurements are safe to repeat. Use unique output paths or remove only exact prior fuzzer output files after inspection.

Do not create manual Cargo target directories under `/tmp`. Use `scripts/with-isolated-cargo-target.sh` when isolation is necessary.

If the Phalcon run stops before a dump appears, preserve available counters and profiles. Reduce the sampled probe set only through structured fuzzer options. Do not modify source fixtures to make the probe easier.

If retained-byte estimates differ greatly from RSS, keep the hard configured ceiling. Recalibrate the amplification factor and document the evidence. Do not remove the bound.

## Artifacts and Notes

Issue links:

- `https://github.com/BrokkAi/bifrost/issues/1707`
- `https://github.com/BrokkAi/bifrost/issues/1689`
- `https://github.com/BrokkAi/bifrost/issues/1698`

The implementation must add the Milestone 1 baseline and final comparison here. Include corpus revision, Bifrost revision, command, elapsed time, probe progress, hydration counters, cache counters, and RSS.

## Interfaces and Dependencies

Do not add a crate dependency.

In `crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs`, replace `BoundedFileCache<T>` with a private weighted segmented cache. Its insertion API must receive an explicit estimated byte weight. Its statistics API must return one complete snapshot.

Add a private `FileState::estimated_retained_bytes()` helper or an equivalent nearby free function. Use saturating arithmetic.

In `crates/bifrost-analysis/src/analyzer/store/mod.rs`, add one bounded active-corpus payload query. It must enforce current generation and complete blob state.

In `crates/bifrost-core/src/analyzer/config.rs`, add a derived `file_state_cache_ceiling_bytes()` method only if one shared calculation needs it. Do not add a second public configuration field.

Keep `TreeSitterAnalyzer::fetch_file_state_for_key_with_source` as the single cache admission point. Do not duplicate cache policy in language adapters.

Plan revision note: Created on 2026-08-06. This revision selects byte-bounded segmented LRU, bounded query retention, and hydration-scope correction for issue #1707.

Plan revision note: Updated on 2026-08-06. Implemented byte accounting, corpus sizing, segmented retention, and byte-bounded active-query retention. Left the live Phalcon replay and consumer-specific hydration correction open because no captured replay is available in this worktree.
