# Batch broad symbol-name scans across language indexes

This ExecPlan is a living document. Keep it in accordance with
`.agents/PLANS.md`.

## Purpose / Big Picture

`search_symbols` must return a small mixed JVM result before the interactive
deadline. It must not repeat the same active-blob SQL join once for each
language index. After this work, the issue #1668 request reads names for all
active languages in one query. It still resolves and reports the same symbols.

## Progress

- [x] (2026-08-07 12:02Z) Read issue #1668 and reproduced its exact request.
- [x] (2026-08-07 12:02Z) Measured one complete request in 4,493 ms. Three
  warm repeats took 639 ms, 556 ms, and 506 ms.
- [x] (2026-08-07 12:02Z) Found a second MCP session that reached the 4.5 s
  server deadline for the same request.
- [x] (2026-08-07 12:02Z) Found a complete cross-language batch design in
  commit `a9b33e656a0ff4f064efc31ccccea9899a45ce4a`.
- [x] (2026-08-07 12:02Z) Rejected a regex-literal prefilter experiment. It
  lost `usages.finder`, because a resolver creates part of that FQN later.
- [x] (2026-08-07 13:34Z) Batch the active symbol-name query across storage
  languages.
- [x] (2026-08-07 13:34Z) Add a mixed Java and Rust store regression test.
- [x] (2026-08-07 13:34Z) Run formatting, focused tests, and focused lint.
- [x] (2026-08-07 13:35Z) Run the current CLI for an exact-request smoke.
  Cache setup failed before tool execution because this linked worktree shares
  a read-only persisted cache location.
- [x] (2026-08-07 13:34Z) Run the required policy request. The MCP response
  was unreliable before policy execution. It is recorded as a failed gate.

## Surprises & Discoveries

- Observation: The exact request has three regex-like patterns.
  Evidence: `resolve.*Jvm`, `definition.*java`, and `hover.*java` occur in
  issue #1668.
- Observation: A regex-like pattern disables the existing SQL prefilter for
  the whole pattern batch.
  Evidence: `SearchSymbolPatternBatch::literal_ascii_substrings` returns
  `None` unless every pattern is an ASCII identifier.
- Observation: The same active-blob join runs for each language key.
  Evidence: `AnalyzerStore::search_candidate_name_rows_for_langs` loops over
  `langs` and calls its per-language helper.
- Observation: A mandatory regex literal is not always a stored name value.
  Evidence: Filtering `usages.finder` by `usages` removed a valid hit. The
  resolver creates the package name after the SQL name-row query.

## Decision Log

- Decision: Do not ship regex-literal SQL narrowing.
  Rationale: It changed the public result for package-qualified searches.
  Date/Author: 2026-08-07 / Codex.
- Decision: Batch existing name-row scans across all storage languages.
  Rationale: This keeps every candidate and removes repeated active-blob joins.
  Date/Author: 2026-08-07 / Codex.
- Decision: Keep the existing Rust matcher as the final authority.
  Rationale: The new SQL query changes query shape only. It must not change
  the resolver, regex, ranking, or render behavior.
  Date/Author: 2026-08-07 / Codex.

## Outcomes & Retrospective

The batched query keeps every candidate and preserves the original language
position by a SQL CASE projection. It removes repeated active-blob joins for
all-language symbol requests.

`cargo test -p brokk-bifrost-analysis
active_symbol_candidate_scan_batches_languages` passed. `cargo test --test
issue_1199_search_symbols_latency` passed all seven tests, including the
package-qualified name regression. `cargo fmt --check` passed. `cargo clippy
-p brokk-bifrost-analysis --all-targets -- -D warnings` passed.

The current CLI built successfully. Its exact one-shot smoke reached workspace
construction, then failed while it opened the shared linked-worktree cache:
`attempt to write a readonly database`. It did not execute `search_symbols`.
The focused tests establish the query result contract, but a same-revision MCP
latency measurement still needs a writable persisted cache or an ephemeral MCP
host.

The required MCP policy request selected `bifrost.code-smells` with date
`2026-08-07`. The repository names no executable policy root. The response was
`unreliable` with exit status 2 before policy execution, no diagnostics, and
no file-specific finding. It does not pass the policy gate.

## Context and Orientation

`TreeSitterAnalyzer::sql_search_symbol_candidates` in
`crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs` asks the store
for lightweight rows before it creates full code units. A row contains the
storage language position, blob identifier, unit key, short name, and content
qualifier.

`AnalyzerStore::search_candidate_name_rows_for_langs` in
`crates/bifrost-analysis/src/analyzer/store/mod.rs` first loads active blob
identifiers into a temporary table. It currently executes one statement for
each storage language. Every statement repeats the active table join.

The replacement will use `units.lang IN (...)` and a SQL `CASE` expression.
The CASE expression maps each selected language to the original position in
the `langs` slice. `QueryResolver` uses that position to select the matching
language adapter. The result must keep that position exactly.

## Plan of Work

Replace the per-language loop in
`AnalyzerStore::search_candidate_name_rows_for_langs` with one helper that
accepts the full language slice. Return an empty complete result for an empty
slice. Build one `IN` parameter list for the language strings. Add one CASE
projection that returns the original language position with every row.

Keep the literal-substring predicate. Offset its SQLite parameters after the
language parameters. Keep the active blob temporary table and cancellation
checks. Read the CASE result into `SearchCandidateNameRow::lang_index`.

Add a store test with Java and Rust blobs. Request both storage languages and
assert that the results contain rows for position zero and position one. The
test proves one batched query preserves resolver routing.

## Concrete Steps

Run these commands from the repository root:

    cargo test --test issue_1199_search_symbols_latency
    cargo test -p brokk-bifrost-analysis active_symbol_candidate_scan_batches_languages
    cargo fmt --check

Run the exact #1668 MCP request after the focused tests. Expect a complete,
untruncated response with the same result set. Run at least three warm calls.

Before task completion, run the required policy request against
`bifrost.code-smells` and each repository policy root. Treat a finding or an
unreliable result as a validation failure.

## Validation and Acceptance

The new store test must find both Java and Rust rows. Each row must retain its
correct language index. Existing `issue_1199_search_symbols_latency` tests
must keep their current results.

The exact MCP request must complete with `truncated=false` in a warm session.
Focused tests, formatting, and policy validation must pass.

## Idempotence and Recovery

The tests use temporary inline projects and temporary databases. They do not
change a repository or a persisted workspace cache. Repeat them after each
query change. If a language index routes to the wrong adapter, restore the
per-language query and compare the CASE parameter order.

## Artifacts and Notes

The first direct MCP call on 2026-08-07 completed in 4,493 ms with 18 files.
Three later calls completed in 639 ms, 556 ms, and 506 ms. Another MCP session
cancelled the same request at the 4.5 s server limit. The performance variance
needs less repeated SQL work, not a larger deadline.

Commit `a9b33e656a0ff4f064efc31ccccea9899a45ce4a` has the same safe design.
It is not an ancestor of this worktree. Adapt its algorithm without unrelated
documentation changes.

## Interfaces and Dependencies

Keep `AnalyzerStore::search_candidate_name_rows_for_langs` and
`SearchCandidateNameRow` unchanged. The private helper can change from one
language input to a language slice. Do not add a crate or change an MCP schema.

Plan created on 2026-08-07 after the exact #1668 query reached the MCP
deadline in a second session. It records the batched-query decision.

Plan updated on 2026-08-07 after an unsafe literal-filter prototype failed an
existing package-qualified behavior test. The prototype was removed.
