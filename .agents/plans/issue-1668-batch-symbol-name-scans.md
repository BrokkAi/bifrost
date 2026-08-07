# Batch broad symbol-name scans across language indexes

This ExecPlan is a living document. Keep it in accordance with
`.agents/PLANS.md`.

## Purpose / Big Picture

`search_symbols` must return a small mixed JVM result before the interactive
deadline. It must not repeat the same active-blob SQL join once for each
language index or re-query declaration ranges while it renders a matched
symbol. After this work, the issue #1668 request reads names for all active
languages in one query. It still resolves and reports the same symbols.

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
- [x] (2026-08-07 13:48Z) Profile an exact persistent RMCP request against
  the current binary.
- [x] (2026-08-07 14:50Z) Add render and candidate-projection timing scopes.
- [x] (2026-08-07 14:55Z) Reuse the stored primary declaration range during
  name-line rendering.
- [x] (2026-08-07 15:05Z) Re-run the required policy request. The broad pack
  completed with `unreliable` status because two rules exhausted discovery.
- [ ] Replay the exact request after a fully ready persistent workspace and
  reduce any remaining render cost.

## Surprises & Discoveries

- Observation: The exact request has three regex-like patterns.
  Evidence: `resolve.*Jvm`, `definition.*java`, and `hover.*java` occur in
  issue #1668.
- Observation: A regex-like pattern disables the existing SQL prefilter for
  the whole pattern batch.
  Evidence: `SearchSymbolPatternBatch::literal_ascii_substrings` returns
  `None` unless every pattern is an ASCII identifier.
- Observation: Before this repair, the same active-blob join ran for each
  language key.
  Evidence: The prior `AnalyzerStore::search_candidate_name_rows_for_langs`
  loop called a per-language helper.
- Observation: A mandatory regex literal is not always a stored name value.
  Evidence: Filtering `usages.finder` by `usages` removed a valid hit. The
  resolver creates the package name after the SQL name-row query.
- Observation: Result rendering uses most of the current exact-request time.
  Evidence: The current profile measured 3,666 ms in rendering, compared with
  485 ms in resolution and at most 129 ms in each name-row query.
- Observation: The renderer had each matched candidate's primary range, but
  asked the analyzer for all ranges again to locate its declaration name.
  Evidence: `RankedSearchCandidate::primary_range` comes from the hydrated
  `unit_ranges` row, while `search_symbol_display_range` called
  `DeclarationNameRangeContext::name_range`.
- Observation: A new RMCP process can consume the full request budget while
  the workspace initializes.
  Evidence: Two direct replays after 12 s and 25 s startup waits returned
  `workspace snapshot was not ready within the request-wide time budget` at
  4,507 ms and 4,550 ms.

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
- Decision: Keep the batched-query repair as a checkpoint, not issue closure.
  Rationale: It reduces name-row query time, but rendering now uses most of
  the interactive request budget.
  Date/Author: 2026-08-07 / Codex.
- Decision: Use the already selected primary declaration range for name-line
  rendering.
  Rationale: The range still lets the tree-sitter context find the identifier,
  including the name after a Java annotation, without another analyzer query.
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

The current CLI built successfully. The sandbox initially blocked its shared
linked-worktree cache. The same command with cache access returned 18 complete
files. A one-shot CLI request also includes workspace and history work, so it
does not measure the interactive MCP request by itself.

Fine-grained scopes now separate candidate name loading, name matching,
candidate hydration, row resolution, source context loading, signature lookup,
and declaration-name range lookup. The range lookup now uses the persisted
primary range in the current candidate. The focused Java annotation test still
reports the declaration name line, and the seven issue #1199 tests pass.

The required MCP policy request selected `bifrost.code-smells` with date
`2026-08-07`. The repository names no executable policy root. The response was
`unreliable` with exit status 2 before policy execution, no diagnostics, and
no file-specific finding. It does not pass the policy gate.

The final policy replay also returned `unreliable` with exit status 2. It ran
for about 80 seconds. `expensive-operation-in-nested-loop` and
`file-read-in-loop` exhausted their discovery budgets. The report has no
completed policy execution summary, so this remains a failed validation gate.

An exact persistent RMCP measurement against the current binary found that the
batch repair is necessary but not sufficient. The profiled complete request
took 4,288 ms, with 485 ms in resolution, at most 129 ms in each batched
name-row query, and 3,666 ms in result rendering. Earlier complete requests
took 4,906 ms and 17,611 ms. Another 4,552 ms response had no structured
result despite `isError=false`. Do not close #1668 from this change. The next
repair must profile and reduce rendering work while keeping the full result
contract.

## Context and Orientation

`TreeSitterAnalyzer::sql_search_symbol_candidates` in
`crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs` asks the store
for lightweight rows before it creates full code units. A row contains the
storage language position, blob identifier, unit key, short name, and content
qualifier.

`AnalyzerStore::search_candidate_name_rows_for_langs` in
`crates/bifrost-analysis/src/analyzer/store/mod.rs` loads active blob
identifiers into a temporary table. It executes one statement for all storage
languages and returns the input language position with a SQL CASE expression.

The statement uses `units.lang IN (...)` and a SQL `CASE` expression. The CASE
expression maps each selected language to its original position in `langs`.
`QueryResolver` uses that position to select the matching language adapter.

## Plan of Work

The completed batch milestone replaced the per-language loop in
`AnalyzerStore::search_candidate_name_rows_for_langs` with one helper that
accepts the full language slice. It returns an empty complete result for an
empty slice. It builds one `IN` parameter list and a CASE projection that
returns the original language position with every row.

Keep the literal-substring predicate. Offset its SQLite parameters after the
language parameters. Keep the active blob temporary table and cancellation
checks. Read the CASE result into `SearchCandidateNameRow::lang_index`.

Add a store test with Java and Rust blobs. Request both storage languages and
assert that the results contain rows for position zero and position one. The
test proves one batched query preserves resolver routing.

The next milestone must replay the request after workspace readiness. It must
use the new scopes to remove the remaining measured render operation without
changing result fields or lines.

## Concrete Steps

Run these commands from the repository root:

    cargo test --test issue_1199_search_symbols_latency
    cargo test -p brokk-bifrost-analysis active_symbol_candidate_scan_batches_languages
    cargo fmt --check

Run the exact #1668 MCP request after the focused tests. Expect a complete,
untruncated response with the same result set. Run at least three warm calls.

Do not confuse workspace readiness failures with a complete symbol-search
measurement. Wait for a successful warm request before the three exact calls.

The completed current-binary RMCP request returned 18 complete files in
4,288 ms. Its variation still exceeds the 4.5 s server budget, so it does not
meet #1668 acceptance.

Before task completion, run the required policy request against
`bifrost.code-smells` and each repository policy root. Treat a finding or an
unreliable result as a validation failure.

## Validation and Acceptance

The new store test must find both Java and Rust rows. Each row must retain its
correct language index. Existing `issue_1199_search_symbols_latency` tests
must keep their current results.

The batch milestone passes when the exact MCP request returns the same complete
result with correct language routing. The issue passes only when repeated warm
requests stay below the server budget and the policy request is reliable.

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

The current-binary persistent RMCP profile returned 18 complete files in
4,288 ms. Its rendering phase took 3,666 ms. Other complete calls took
4,906 ms and 17,611 ms. These results supersede a claim that the batch change
alone solves the issue.

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

Plan updated on 2026-08-07 after current-binary RMCP profiling found rendering
as the remaining dominant phase.

Plan updated on 2026-08-07 after render instrumentation and the stored-range
repair. Fresh-server startup still exhausted the request-wide readiness budget,
so a post-readiness replay remains required.
