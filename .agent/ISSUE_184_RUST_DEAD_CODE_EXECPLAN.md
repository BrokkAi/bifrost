# Issue 184 Rust Dead-Code Bulk Inbound Analysis

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md` in this repository. It is self-contained so a future contributor can resume the work from this file and the current working tree alone.

## Purpose / Big Picture

The `report_dead_code_and_unused_abstraction_smells` tool is used by SlopCop as a broad, heuristic report over a workspace. On large Rust repositories, the old implementation performed one usage query for each candidate symbol; each Rust query rebuilt scan-graph state, making the tool too slow for broad scans. After this change, Rust dead-code scoring will build the Rust whole-program caller-to-callee graph once, count inbound references for each candidate, and report zero-inbound or one-inbound symbols with wording that makes clear this is workspace evidence, not proof of dead code.

The visible result is that Rust dead-code reports still identify unused private helpers and one-call wrappers, but they do so through one inverted graph pass. Public Rust APIs with no workspace inbound references are reported conservatively as possibly untested or externally consumed public surface.

## Progress

- [x] (2026-06-17T08:00:19Z) Read `.agent/PLANS.md`, confirmed this ExecPlan format, and created this living plan before code edits.
- [x] (2026-06-17T08:00:19Z) Ran `git fetch` and `git rebase`; the current issue branch was already up to date.
- [x] (2026-06-17T08:04:17Z) Implemented Rust bulk inbound analysis in `src/code_quality/dead_code_smells.rs`.
- [x] (2026-06-17T08:04:17Z) Updated Rust dead-code tests for graph-derived counts, graph call-site truncation, and public API wording.
- [x] (2026-06-17T08:04:17Z) Ran `cargo test --test rust_dead_code_smells`; all 7 tests passed.
- [x] (2026-06-17T08:04:54Z) Ran `cargo test --test python_js_ts_dead_code_smells`; all 7 tests passed.
- [x] (2026-06-17T08:07:23Z) Ran `cargo fmt`; it completed without errors.
- [x] (2026-06-17T08:07:23Z) Ran `cargo clippy --all-targets --all-features -- -D warnings`; it completed without warnings.
- [x] (2026-06-17T08:07:23Z) Tried `./gradlew fix tidy`; this Rust worktree has no `./gradlew`, so Gradle fix/tidy/analyze are not runnable here.
- [x] (2026-06-17T08:49:55Z) Ran guided review over the uncommitted diff and fixed both findings: Rust cap handling and duplicated Rust analyzer resolution.
- [x] (2026-06-17T08:49:55Z) Re-ran `cargo test --test rust_dead_code_smells`; all 9 tests passed, including cap-regression tests.
- [x] (2026-06-17T08:49:55Z) Re-ran `cargo test --test python_js_ts_dead_code_smells`; all 7 tests passed.
- [x] (2026-06-17T08:49:55Z) Re-ran `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings`; both completed cleanly.
- [x] (2026-06-17T09:15:00Z) Started the deferred Python dead-code bulk graph scoring slice; JS/TS remains deferred because its candidate identity needs file-scoped handling.
- [x] (2026-06-17T09:22:00Z) Implemented Python bulk inbound scoring in `src/code_quality/dead_code_smells.rs` using one `build_python_usage_edges(...)` call per report.
- [x] (2026-06-17T09:22:00Z) Updated Python dead-code tests for graph-derived one-call evidence, graph call-site truncation, file-cap skipping, and usage-cap skipping.
- [x] (2026-06-17T09:22:00Z) Ran `cargo fmt` and `cargo test --test python_js_ts_dead_code_smells`; all 10 tests passed.
- [x] (2026-06-17T09:24:00Z) Re-ran `cargo test --test rust_dead_code_smells`; all 9 tests passed after the shared inbound-count refactor.
- [x] (2026-06-17T09:27:00Z) Re-ran `cargo clippy --all-targets --all-features -- -D warnings` and `git diff --check`; both completed cleanly.
- [x] (2026-06-17T10:16:00Z) Committed the Rust/Python bulk scoring slice as `88b56dc`.
- [x] (2026-06-17T10:25:00Z) Ran guided review against refreshed `origin/master`; reviewers found Rust member-call undercounting and a fixed graph callsite cap mismatch.
- [x] (2026-06-17T10:35:00Z) Fixed guided-review findings by routing Rust member candidates through the existing per-symbol Rust strategy and clamping the report usage cap to the inverted graph callsite cap.
- [x] (2026-06-17T10:42:00Z) Re-ran `cargo test --test rust_dead_code_smells`, `cargo test --test python_js_ts_dead_code_smells`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.
- [x] (2026-06-17T11:20:00Z) Implemented JS/TS file-scoped bulk dead-code scoring with reusable scoped usage node identity and scoped edge aggregation.
- [x] (2026-06-17T11:20:00Z) Added JS/TS tests for graph-derived evidence, duplicate export names, duplicate owner members, unseedable locals, and ambiguous star re-export aliases.
- [x] (2026-06-17T11:35:00Z) Ran `cargo fmt`, `cargo test --test python_js_ts_dead_code_smells`, `cargo test --test rust_dead_code_smells`, `cargo test --test usages_js_ts_graph_test`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.
- [x] (2026-06-17T12:05:00Z) Started the Java dead-code bulk graph scoring slice with conservative guards for constructors, overloads, and Java class references from Scala files.
- [x] (2026-06-17T12:20:00Z) Implemented Java bulk inbound scoring in `src/code_quality/dead_code_smells.rs` using one `build_java_usage_edges(...)` call for safe Java candidates.
- [x] (2026-06-17T12:20:00Z) Added `tests/java_dead_code_smells.rs` covering graph-derived Java findings, caps, constructor and overload precise-path guards, and Java class references from Scala files.
- [x] (2026-06-17T12:20:00Z) Ran `cargo test --test java_dead_code_smells`; all 8 tests passed.
- [x] (2026-06-17T12:30:00Z) Ran `cargo test --test usages_java_graph_test`, `cargo test --test rust_dead_code_smells`, `cargo test --test python_js_ts_dead_code_smells`, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.

## Surprises & Discoveries

- Observation: A direct integration test for `truncated_symbols` is feasible by generating 1001 Rust caller files that import and call one public helper.
  Evidence: `cargo test --test rust_dead_code_smells` passed with `rust_dead_code_smell_skips_truncated_usage_candidates`.

- Observation: This `bifrost` worktree does not contain a Gradle wrapper.
  Evidence: `./gradlew fix tidy` returned `zsh:1: no such file or directory: ./gradlew`, and `find .. -maxdepth 2 -name gradlew -type f` returned no matches.

- Observation: The first Rust bulk implementation bypassed two user-visible runtime caps.
  Evidence: Guided review found that `max_usage_candidate_files` and `max_usages_per_symbol` were accepted and printed but not applied by the Rust graph path.

- Observation: Python already exposes `build_python_usage_edges(...)`, so Python can move to the same one-pass inbound scoring shape without new resolver substrate work.
  Evidence: `src/analyzer/usages/python_graph.rs` resolves the Python analyzer, builds the Python workspace graph once, and returns `UsageEdges`.

- Observation: Rust's inverted graph intentionally does not resolve instance-method dispatch (`recv.method()`), while the existing Rust per-symbol strategy has member-target handling.
  Evidence: `src/analyzer/usages/rust_graph/inverted.rs` documents the recall gap, and `src/analyzer/usages/rust_graph/extractor.rs` contains `scan_files_for_member_target`.

- Observation: JS/TS `CodeUnit::fq_name()` values are often bare export names, so the whole-workspace graph must key by file plus fqn to avoid cross-counting duplicate exports.
  Evidence: tests can define `a.ts` and `b.ts` with separate `helper` exports whose `fq_name()` values are both `helper`.

- Observation: Java's whole-program inverted graph currently scans Java files only, while the precise Java usage strategy separately scans Scala files for Java type references.
  Evidence: `build_java_usage_edges(...)` collects `Language::Java` files, and `scan_scala_files_for_java_type(...)` is called only from `JavaUsageGraphStrategy::find_graph_usages`.

- Observation: The Java constructor guard routes constructor candidates to the precise path as intended; precise analysis can still report a one-call constructor with a concrete `new Target()` call site.
  Evidence: `java_constructor_candidate_stays_on_precise_path` asserts precise `only usage:` evidence rather than graph-derived zero-inbound evidence.

## Decision Log

- Decision: Keep this issue slice Rust-only for implementation, while tracking other language targets in this plan as follow-up slices.
  Rationale: Issue 184's current hot path is Rust dead-code reporting; Python and JS/TS tests should remain unchanged so this branch does not widen into a cross-language migration.
  Date/Author: 2026-06-17 / Codex

- Decision: Use whole-program inbound graph evidence directly for Rust instead of running recall-safe per-symbol confirmation queries.
  Rationale: The tool is intentionally a broad heuristic SlopCop report. The product goal is bounded runtime and clear wording, not definitive proof that public or dynamically used symbols are dead.
  Date/Author: 2026-06-17 / Codex

- Decision: If the Rust analyzed-file count exceeds `max_usage_candidate_files`, skip Rust bulk analysis for all Rust candidates as inconclusive instead of building a partial graph.
  Rationale: A partial whole-workspace graph can create false zero-inbound evidence. Skipping preserves the bounded-runtime contract and avoids misleading findings.
  Date/Author: 2026-06-17 / Codex

- Decision: Reuse `crate::analyzer::usages::rust_graph::resolve_rust_analyzer` from code-quality rather than keeping a local downcast/delegate helper.
  Rationale: There should be one Rust analyzer capability resolution path for Rust usage-graph consumers so MultiAnalyzer handling cannot drift.
  Date/Author: 2026-06-17 / Codex

- Decision: Implement Python as the next bulk scoring slice and leave JS/TS on the legacy per-symbol path for now.
  Rationale: Python's whole-workspace graph uses dotted FQN identity, while JS/TS needs a separate design for file-scoped identity before same-name exports can be scored safely.
  Date/Author: 2026-06-17 / Codex

- Decision: Keep Rust member candidates on the existing per-symbol Rust strategy until the inverted graph supports receiver/member inference.
  Rationale: Routing methods and fields through the bulk graph can undercount `recv.method()` calls and create false dead-code findings.
  Date/Author: 2026-06-17 / Codex

- Decision: Clamp `max_usages_per_symbol` to the inverted graph's fixed callsite cap and display the effective cap when clamped.
  Rationale: The shared inverted edge builder truncates at `MAX_CALLSITES`; reporting a higher accepted cap would be misleading unless the builder grows a configurable limit.
  Date/Author: 2026-06-17 / Codex

- Decision: Add a reusable `UsageNodeKey { file, fqn }` scoped identity seam parallel to existing string-keyed `UsageEdges`, and use it first for JS/TS only.
  Rationale: JS/TS needs file-scoped identity now, but migrating Rust/Python/other language graph builders would widen this slice unnecessarily.
  Date/Author: 2026-06-17 / Codex

- Decision: Skip JS/TS candidates with ambiguous export aliases instead of overcounting or falling back.
  Rationale: Dead-code reporting is heuristic; ambiguous alias evidence can create either false positives or false negatives, so the report should surface it as inconclusive.
  Date/Author: 2026-06-17 / Codex

- Decision: Add Java bulk dead-code scoring only for Java candidates whose FQN-only graph evidence is safe: non-constructor, non-overloaded candidates, and Java class candidates only when no Scala files are present.
  Rationale: Java FQNs are package-qualified, so scoped identity is unnecessary, but constructors/overloads need arity-aware precise analysis and Java classes can be referenced from Scala through the existing per-symbol strategy.
  Date/Author: 2026-06-17 / Codex

## Outcomes & Retrospective

2026-06-17: The Rust dead-code report now uses one inverted Rust usage graph build per report call and derives zero-inbound/one-inbound findings from graph edge weights. Rust bulk analysis now honors `max_usage_candidate_files` by skipping inconclusive oversized Rust workspaces and honors `max_usages_per_symbol` by skipping candidates whose inbound count exceeds the requested usage cap. Focused tests and Rust linting passed. Gradle checks were requested by the general project guidance but are not available in this Rust worktree because there is no `./gradlew`.

2026-06-17: The Python dead-code report now also uses one inverted Python usage graph build per report call and derives zero-inbound/one-inbound findings from graph edge weights. JavaScript and TypeScript intentionally remain on the legacy per-symbol path until file-scoped identity is designed. Python focused tests now cover graph-derived one-call evidence plus graph truncation, file-cap skipping, and usage-cap skipping.

2026-06-17: The JavaScript/TypeScript dead-code report now uses a file-scoped inverted graph path for exported candidates. The scoped identity seam is reusable for future languages, while existing string-keyed graph builders remain unchanged. Ambiguous JS/TS export aliases are skipped as inconclusive.

2026-06-17: The Java dead-code report now uses one inverted Java usage graph build per report call for safe Java candidates. Constructors, overloaded Java methods, and Java class candidates in mixed Java/Scala workspaces remain on the precise per-symbol path. Focused Java tests cover graph-derived findings and the guarded precise-path cases.

## Context and Orientation

The report entry point is `src/code_quality/dead_code_smells.rs`, function `report_dead_code_and_unused_abstraction_smells`. It resolves input files, selects candidate declarations, and currently calls `analyze_candidate` once per candidate. `analyze_candidate` uses per-symbol usage analysis and is still appropriate for the existing Python, JavaScript, and TypeScript behavior in this slice.

For Rust and Python, the scalable whole-program paths return `UsageEdges`, a crate-internal structure with an `edges` map keyed by `(caller_fqn, callee_fqn)` and a `truncated` map keyed by callee FQN for symbols whose call sites exceeded the enumeration guardrail. A caller is the enclosing function or class-like declaration containing a reference. A callee is the declaration being referenced. An inbound count for a candidate is the sum of edge weights where the edge callee equals the candidate's fully qualified name.

For JS/TS, bare FQN identity is insufficient because unrelated files can export the same local name. The scoped path uses `UsageNodeKey { file, fqn }` and `ScopedUsageEdges` so dead-code scoring can distinguish `a.ts::helper` from `b.ts::helper`. Ambiguous export aliases, star re-exports, and unseedable local symbols are skipped as inconclusive rather than forced into a potentially wrong key.

Rust visibility information already exists on `RustAnalyzer` as `is_rust_public_like_declaration`. Public-like means the declaration syntax has a Rust `pub...` visibility modifier. The dead-code report must reuse this analyzer helper rather than parsing visibility text again.

## Plan of Work

First, add the Rust bulk path to `src/code_quality/dead_code_smells.rs`. The report function should partition the selected candidates: Rust candidates go through one new helper, and unsupported bulk languages keep the existing `analyze_candidate` loop. The helper should resolve the concrete `RustAnalyzer`, build a Rust node set from all Rust function and class declarations plus all Rust smell candidates, call `build_rust_usage_edges` once with an all-files `keep_file` predicate, and compute inbound counts for each candidate from the resulting edges.

Second, build findings from inbound counts. Zero-inbound and one-inbound candidates produce findings; higher inbound counts produce no finding. Candidates present in `UsageEdges.truncated` are skipped with a clear inconclusive-evidence note and never flagged. Private Rust candidates can keep the existing strong dead-code and one-call-abstraction wording. Public Rust candidates must use lower score and confidence, and must say they are unreferenced or lightly referenced in the workspace and may be externally consumed or untested public surface.

Third, update `tests/rust_dead_code_smells.rs`. Existing private helper, one-call wrapper, recursion, explicit FQN targeting, and threshold behavior should still pass after expected wording changes. Add a public `pub fn` test that asserts conservative public-surface wording. Cover `truncated_symbols` behavior with an integration test that creates more than the Rust usage-graph call-site limit and asserts the candidate is skipped as inconclusive.

The Python follow-up slice now uses Python's inverted usage graph for the same one-pass inbound scoring shape. The JS/TS follow-up slice now uses file-scoped identity so same-name exports in different files do not cross-count. The Java follow-up slice uses Java's existing package-qualified FQN graph for safe candidates and keeps overlap-sensitive candidates precise. Deferred follow-up slices remain tracked here but are not implemented in this branch. Go, C#, C++, PHP, and Scala parity should only be pursued after the Rust, Python, JS/TS, and Java slices confirm product value and graph semantics. If broad graph cost still dominates after bulk dead-code scoring, later work can profile resolver/cache micro-optimizations.

## Concrete Steps

All commands are run from `/Users/dave/.codex/worktrees/89d9/bifrost`.

The branch sync step has already been run:

    git fetch
    git rebase

Expected result observed:

    Current branch 184-optimize-rust-dead-code-usage-graph-resolution-on-large-workspaces is up to date.

After implementation, run focused tests first:

    cargo test --test rust_dead_code_smells
    cargo test --test python_js_ts_dead_code_smells

Then run final checks:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    ./gradlew fix tidy
    ./gradlew analyze

## Validation and Acceptance

The new Rust tests should demonstrate the behavior change. A private unused helper should still appear in the report with zero total usages. A one-call wrapper should still appear with total usage count `1`. A public unused function should appear with conservative wording that includes "unreferenced in workspace" and mentions public surface risk rather than saying it is definitely dead. Python, JavaScript, and TypeScript dead-code tests should continue to pass unchanged.

The implementation is accepted when the focused tests pass, JS/TS graph strategy tests pass, formatting is clean, clippy reports no warnings, and Gradle tidy/fix/analyze complete successfully or any skipped final command is documented with the reason.

## Idempotence and Recovery

The implementation is additive and can be retried safely. If tests fail after the Rust fast path is added, inspect the report text emitted by the failing assertions and update the wording or expectations only when the behavior still matches the heuristic contract. Do not reset the worktree or discard unrelated user changes. If `./gradlew fix tidy` rewrites formatting, inspect the diff before continuing.

## Artifacts and Notes

Key implementation artifacts will be recorded here after code changes and test runs. The important proof will be focused test output for Rust dead-code and Python/JS/TS dead-code tests.

Rust focused test evidence:

    cargo test --test rust_dead_code_smells
    running 11 tests
    test rust_dead_code_smell_clamps_usage_cap_to_graph_callsite_limit ... ok
    test rust_dead_code_smell_does_not_undercount_instance_method_usage ... ok
    test rust_dead_code_smell_honors_usage_candidate_file_cap ... ok
    test rust_dead_code_smell_honors_usage_cap ... ok
    test rust_dead_code_smell_skips_truncated_usage_candidates ... ok
    test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Legacy Python/JS/TS focused test evidence:

    cargo test --test python_js_ts_dead_code_smells
    running 14 tests
    test ts_dead_code_smell_does_not_cross_count_duplicate_export_names ... ok
    test ts_dead_code_smell_does_not_cross_count_duplicate_owner_members ... ok
    test ts_dead_code_smell_skips_ambiguous_star_reexport_alias ... ok
    test python_dead_code_smell_clamps_usage_cap_to_graph_callsite_limit ... ok
    test python_dead_code_smell_honors_usage_candidate_file_cap ... ok
    test python_dead_code_smell_honors_usage_cap ... ok
    test python_dead_code_smell_skips_truncated_usage_candidates ... ok
    test ts_dead_code_smell_reexport_counts_as_usage ... ok
    test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

JS/TS usage graph regression evidence:

    cargo test --test usages_js_ts_graph_test
    running 35 tests
    test ts_duplicate_owner_names_do_not_cross_match_members ... ok
    test ts_local_barrel_reexport_is_followed ... ok
    test ts_static_member_on_namespace_import_resolves_member_usage ... ok
    test usage_finder_routes_jsts_targets_to_graph_strategy ... ok
    test result: ok. 33 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out

Java focused test evidence:

    cargo test --test java_dead_code_smells
    running 8 tests
    test java_dead_code_smell_reports_unused_private_helper ... ok
    test java_dead_code_smell_reports_one_call_wrapper ... ok
    test java_dead_code_smell_does_not_flag_symbol_with_multiple_inbound_edges ... ok
    test java_dead_code_smell_honors_usage_candidate_file_cap ... ok
    test java_dead_code_smell_honors_usage_cap ... ok
    test java_constructor_candidate_stays_on_precise_path ... ok
    test java_overloaded_methods_stay_on_precise_path ... ok
    test java_class_candidate_uses_precise_path_when_scala_files_are_present ... ok
    test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Java usage graph regression evidence:

    cargo test --test usages_java_graph_test
    running 32 tests
    test java_graph_finds_java_type_usages_from_scala_source ... ok
    test java_type_usage_lookup_merges_java_and_scala_source_hits ... ok
    test java_member_usage_lookup_does_not_claim_scala_source_hits ... ok
    test scala_target_usage_lookup_does_not_scan_java_source ... ok
    test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Rust formatting and lint evidence:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.62s

Whitespace evidence:

    git diff --check
    no output

Unavailable Gradle evidence:

    ./gradlew fix tidy
    zsh:1: no such file or directory: ./gradlew

## Interfaces and Dependencies

At the end of this work, `src/code_quality/dead_code_smells.rs` should contain a crate-internal Rust bulk helper with behavior equivalent to:

    fn analyze_rust_candidates_with_usage_graph(
        analyzer: &dyn IAnalyzer,
        candidates: &[CodeUnit],
        skipped: &mut Vec<String>,
    ) -> Vec<DeadCodeFinding>

The helper may use a different exact name if the surrounding code reads better, but it must resolve `RustAnalyzer`, call `build_rust_usage_edges` once, and produce `DeadCodeFinding` rows from inbound edge counts. It must not call `RustExportUsageGraphStrategy::find_usages` per non-member Rust candidate.

The Rust analyzer visibility helper `RustAnalyzer::is_rust_public_like_declaration` may be widened only as much as needed for crate-internal code-quality use.

The JS/TS scoped helper should build one scoped usage graph through `build_jsts_scoped_usage_edges`, score only candidates with resolved `UsageNodeKey` identity, and keep ambiguous or unseedable candidates in skipped/inconclusive evidence.
