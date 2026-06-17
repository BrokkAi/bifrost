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
- [x] (2026-06-17T13:10:00Z) Ran guided review on the Java slice and fixed findings: Java fields and static-import-sensitive methods now stay precise, Java overload/static-import metadata is lazy, Java public API findings use conservative wording, and Python/Java share the FQN bulk scorer.
- [x] (2026-06-17T13:10:00Z) Re-ran `cargo test --test java_dead_code_smells`; all 11 tests passed.
- [x] (2026-06-17T13:20:00Z) Re-ran `cargo test --test usages_java_graph_test`, `cargo test --test rust_dead_code_smells`, `cargo test --test python_js_ts_dead_code_smells`, `cargo fmt`, and `cargo clippy --all-targets --all-features -- -D warnings`; all passed.
- [x] (2026-06-17T14:00:00Z) Started the Scala dead-code bulk graph scoring slice with conservative guards for fields, constructors, overloads, import-sensitive members, and public/API-like declarations.
- [x] (2026-06-17T13:23:00Z) Added Scala bulk eligibility and report partitioning, then ran `cargo test --test usage_graph_scala_test --no-run`; compilation succeeded.
- [x] (2026-06-17T13:35:00Z) Added `tests/scala_dead_code_smells.rs` and ran `cargo test --test scala_dead_code_smells -- --nocapture`; all 13 tests passed.
- [x] (2026-06-17T13:45:00Z) Ran Scala slice regressions: `cargo test --test usage_graph_scala_test`, `cargo test --test rust_dead_code_smells`, `cargo test --test python_js_ts_dead_code_smells`, `cargo test --test java_dead_code_smells`, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed.
- [x] (2026-06-17T14:25:00Z) Ran guided review on the Scala slice and fixed findings: top-level Scala functions now stay precise, import sensitivity uses parsed `ImportInfo`, wildcard guards are candidate-aware, and Scala file-cap skipping avoids preflight source scans.
- [x] (2026-06-17T14:25:00Z) Re-ran `cargo test --test scala_dead_code_smells -- --nocapture`; all 16 tests passed, including top-level function and Scala 3 `.*`/`as` import regressions.
- [x] (2026-06-17T14:35:00Z) Re-ran `cargo test --test usage_graph_scala_test`, `cargo test --test rust_dead_code_smells`, `cargo test --test python_js_ts_dead_code_smells`, `cargo test --test java_dead_code_smells`, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all passed after Scala review fixes.
- [x] (2026-06-17T14:45:00Z) Ran a second guided review on the Scala review-fix diff and fixed the remaining performance finding by caching normalized Scala import exposure once per report.
- [x] (2026-06-17T14:45:00Z) Re-ran `cargo test --test scala_dead_code_smells -- --nocapture`; all 16 tests passed with the cached Scala bulk eligibility context.
- [x] (2026-06-17T15:05:00Z) Committed the Scala review-fix checkpoint as `0cce553` before starting the Go slice.
- [x] (2026-06-17T15:10:00Z) Started the Go dead-code bulk graph scoring slice; Go functions and types will use the shared FQN scorer, while Go fields stay on the precise path.
- [x] (2026-06-17T15:25:00Z) Implemented the initial Go report routing, Go public-surface wording, and `tests/go_dead_code_smells.rs`; first focused run passed 8 of 9 tests and exposed a test expectation mismatch for Go top-level external-usage ownership.
- [x] (2026-06-17T15:30:00Z) Re-ran `cargo test --test go_dead_code_smells -- --nocapture`; all 9 Go dead-code tests passed.
- [x] (2026-06-17T15:35:00Z) Ran `cargo test --test usages_go_graph_test`, `cargo test --test rust_dead_code_smells`, and `cargo test --test python_js_ts_dead_code_smells`; all passed.
- [x] (2026-06-17T15:40:00Z) Ran `cargo test --test java_dead_code_smells` and `cargo test --test scala_dead_code_smells`; all passed.
- [x] (2026-06-17T15:45:00Z) Ran `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all completed cleanly.
- [x] (2026-06-17T16:10:00Z) Ran guided review on the Go slice; reviewers found Go implicit entry points could be false positives, package-level initializer callers were not seeded as graph nodes, and low-severity duplication in public-surface finding/test helpers.
- [x] (2026-06-17T16:20:00Z) Started Go guided-review fixes: skip Go runtime/test entry points, seed module-level Go fields as caller nodes, centralize public-surface graph finding wording, and move shared Go test fixture setup into `tests/common`.
- [x] (2026-06-17T16:35:00Z) Implemented Go guided-review fixes and re-ran `cargo test --test go_dead_code_smells -- --nocapture`; all 11 tests passed, including new entry-point and package-initializer regressions.
- [x] (2026-06-17T16:40:00Z) Re-ran `cargo test --test usages_go_graph_test`; all 29 tests passed after adding explicit module-field caller attribution for top-level initializers.
- [x] (2026-06-17T16:50:00Z) Re-ran `cargo test --test rust_dead_code_smells`, `cargo test --test python_js_ts_dead_code_smells`, `cargo test --test java_dead_code_smells`, and `cargo test --test scala_dead_code_smells`; all passed after Go review fixes.
- [x] (2026-06-17T16:55:00Z) Re-ran `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all completed cleanly after removing one clippy `useless_conversion`.
- [x] (2026-06-17T17:05:00Z) Started the C# dead-code bulk graph scoring slice; C# classes and non-overloaded methods will use `build_csharp_usage_edges(...)`, while fields, constructors, overloads, static-using-sensitive methods, and runtime/test entry points stay precise or are skipped.
- [x] (2026-06-17T17:25:00Z) Implemented C# bulk routing, conservative C# API wording, entry-point exclusion, and `tests/csharp_dead_code_smells.rs`; `cargo test --test csharp_dead_code_smells -- --nocapture` passed with 12 tests.
- [x] (2026-06-17T17:30:00Z) Ran `cargo test --test usages_csharp_graph_test`; all 25 C# usage graph tests passed.
- [x] (2026-06-17T17:40:00Z) Re-ran `cargo test --test rust_dead_code_smells`, `cargo test --test python_js_ts_dead_code_smells`, `cargo test --test java_dead_code_smells`, `cargo test --test scala_dead_code_smells`, and `cargo test --test go_dead_code_smells`; all passed after the C# slice.
- [x] (2026-06-17T17:45:00Z) Re-ran `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all completed cleanly.
- [x] (2026-06-17T18:10:00Z) Ran guided review on the C# slice; reviewers found alias using directives, brittle static-using detection, over-broad `Main` exclusion, full-body public-surface classification, and duplicated/weak C# test-attribute detection.
- [x] (2026-06-17T18:20:00Z) Implemented C# guided-review fixes and re-ran `cargo test --test csharp_dead_code_smells`; all 16 tests passed, including new regressions for alias usings, whitespace static usings, qualified test attributes, non-static `Main`, and public classes with private members.
- [x] (2026-06-17T18:30:00Z) Re-ran `cargo test --test usages_csharp_graph_test`, all existing dead-code smell suites, `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`; all completed cleanly after C# review fixes.

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

- Observation: Java's inverted graph still misses bare identifier field reads and static-imported method calls that the precise Java strategy handles.
  Evidence: guided review identified false-positive scenarios for `return cached;` and `import static com.example.Target.run; run();`; regression tests now assert those candidates use precise `only usage:` evidence.

- Observation: Scala's precise usage scanner handles fields, constructors, direct member imports, wildcard ambiguity, and arity checks that the inverted Scala graph does not fully model.
  Evidence: `scala_graph::extractor` uses `TargetSpec`, `Visibility`, `direct_member_names`, `ambiguous_direct_member_names`, and `member_call_arity_matches`, while `scala_graph::inverted` records type references and method calls from receiver/enclosing-class inference only.

- Observation: Scala can reuse the shared string-keyed FQN bulk scorer without a new scoped identity seam in this slice, but only after routing unsafe member shapes to the precise scanner.
  Evidence: `cargo test --test usage_graph_scala_test --no-run` compiled after adding `scala_graph::dead_code_bulk_eligibility(...)` and the `Language::Scala` report partition.

- Observation: The Scala inverted usage graph counts unique caller-to-callee inbound edges, not repeated textual calls from the same caller.
  Evidence: the Scala cap and multi-inbound tests use two distinct callers; repeated calls inside one method produce one inbound edge.

- Observation: Scala field reads are not reliable enough for zero-usage dead-code reporting in this slice, even on the precise path.
  Evidence: the existing precise scanner can treat a same-owner `val` as locally shadowed; the report now skips empty Scala field evidence as inconclusive rather than emitting a zero-inbound finding.

- Observation: Scala 3 top-level functions and imported object members are unsafe for FQN-only bulk scoring unless the eligibility guard is candidate-aware.
  Evidence: guided review found that unqualified calls to top-level functions can be recorded by the inverted graph as enclosing-class member calls, and that Scala 3 `.*` / `as` imports are already normalized by `ImportInfo` but were missed by the raw import-line parser.

- Observation: Scala import sensitivity should use analyzer import metadata, not source-line parsing in the code-quality layer.
  Evidence: `scala_graph::dead_code_bulk_eligibility(...)` now uses `ScalaAnalyzer::import_info_of` plus `scala_import_path(...)` to route only imports that can expose the candidate owner/member to precise analysis.

- Observation: Candidate-aware Scala import sensitivity must be cached per report to avoid repeating the same workspace import walk for every candidate.
  Evidence: `ScalaDeadCodeBulkContext::from_analyzer(...)` now precomputes normalized wildcard-owner and direct-member import exposure sets once, and `report_dead_code_and_unused_abstraction_smells` reuses that context while still avoiding it when the Scala file cap skips bulk evidence.

- Observation: Go can reuse the shared FQN bulk scorer without a scoped identity seam or overload guard.
  Evidence: Go FQNs include the module/package path, and Go has no overloads; field evidence remains riskier because selectors and composite literals need a dedicated parity pass.

- Observation: Go top-level functions do not share a class-like owner, so a top-level caller of another top-level helper is counted as external usage by the shared report schema.
  Evidence: the first `cargo test --test go_dead_code_smells -- --nocapture` run showed `example.com/app.leaf` with total usages `1` and external usages `1` from `example.com/app.wrapper`.

- Observation: Go package-level `var` and `const` declarations are modeled as field declarations, but can still be callers in package initialization.
  Evidence: guided review pointed out that the shared inverted edge collector only emits caller-to-callee edges when the enclosing caller is in the seeded node set; a package-level `var x = helper()` needs the module field node seeded so the helper gets inbound evidence.

- Observation: Go has runtime and test entry points that are externally invoked without workspace inbound edges.
  Evidence: guided review identified `main`, `init`, and `_test.go` `TestXxx`/`BenchmarkXxx`/`ExampleXxx` functions as false-positive candidates if they flow through zero-inbound graph scoring.

- Observation: C# has a whole-workspace inverted edge builder that resolves type references, typed member calls, static member calls, and same-class bare member calls.
  Evidence: `src/analyzer/usages/csharp_graph.rs` exports `build_csharp_usage_edges(...)`, and `src/analyzer/usages/csharp_graph/inverted.rs` documents the C# caller-to-callee graph semantics.

- Observation: The C# inverted graph intentionally fails closed for static using and alias using member forms.
  Evidence: guided review pointed to `tests/usages_csharp_graph_test.rs` coverage for deferred using member forms, so C# bulk dead-code eligibility now keeps methods precise whenever a C# workspace contains alias or static using directives.

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

- Decision: Keep Java fields and Java methods in workspaces with static imports on the precise path until the inverted Java graph reaches parity for those reference forms.
  Rationale: The precise Java scanner handles bare identifier field reads and static imports; using bulk graph evidence for those shapes can create false zero-inbound dead-code findings.
  Date/Author: 2026-06-17 / Codex

- Decision: Add Scala bulk dead-code scoring only for Scala candidates whose current inverted graph evidence is safe: type declarations and non-overloaded methods without import-sensitive member exposure.
  Rationale: Scala's precise scanner covers richer member and import semantics than the inverted graph. The broad report should skip to precise analysis for fields, constructors, overloads, and direct-member-import/wildcard-ambiguity-sensitive cases.
  Date/Author: 2026-06-17 / Codex

- Decision: Add Go bulk dead-code scoring only for function and type/class candidates, leaving Go fields on the existing precise path.
  Rationale: Go's package-qualified FQNs and no-overload model make functions and types low-risk for one-pass inbound scoring, while field selector/composite-literal behavior should not be widened without a field-specific parity pass.
  Date/Author: 2026-06-17 / Codex

- Decision: Seed Go module-level fields in the bulk graph node set, but continue excluding Go field candidates from bulk findings.
  Rationale: Package initializers can be legitimate callers of functions and types; including those field nodes preserves inbound evidence without widening field dead-code reporting.
  Date/Author: 2026-06-17 / Codex

- Decision: Exclude Go `main`, `init`, and recognized `_test.go` test entry functions from dead-code candidates.
  Rationale: These functions are invoked by the Go toolchain/runtime, so zero workspace inbound edges are not meaningful dead-code evidence.
  Date/Author: 2026-06-17 / Codex

- Decision: Add C# bulk dead-code scoring only for class/type declarations and non-overloaded methods when no `using static` ambiguity guard applies.
  Rationale: C# FQNs are namespace/type-qualified and the graph handles type/member references, but constructors, overloads, fields, static-imported members, `Main`, and test entry methods need precise handling or exclusion to avoid false zero-inbound findings.
  Date/Author: 2026-06-17 / Codex

- Decision: Treat C# alias using directives as the same bulk-dead-code ambiguity class as static using directives, and detect both with whitespace-tolerant directive regexes.
  Rationale: Alias receivers and static-imported bare member calls are deferred by the C# usage graph; falling back to precise analysis avoids false graph-derived dead-code evidence.
  Date/Author: 2026-06-17 / Codex

## Outcomes & Retrospective

2026-06-17: The Rust dead-code report now uses one inverted Rust usage graph build per report call and derives zero-inbound/one-inbound findings from graph edge weights. Rust bulk analysis now honors `max_usage_candidate_files` by skipping inconclusive oversized Rust workspaces and honors `max_usages_per_symbol` by skipping candidates whose inbound count exceeds the requested usage cap. Focused tests and Rust linting passed. Gradle checks were requested by the general project guidance but are not available in this Rust worktree because there is no `./gradlew`.

2026-06-17: The Python dead-code report now also uses one inverted Python usage graph build per report call and derives zero-inbound/one-inbound findings from graph edge weights. JavaScript and TypeScript intentionally remain on the legacy per-symbol path until file-scoped identity is designed. Python focused tests now cover graph-derived one-call evidence plus graph truncation, file-cap skipping, and usage-cap skipping.

2026-06-17: The JavaScript/TypeScript dead-code report now uses a file-scoped inverted graph path for exported candidates. The scoped identity seam is reusable for future languages, while existing string-keyed graph builders remain unchanged. Ambiguous JS/TS export aliases are skipped as inconclusive.

2026-06-17: The Java dead-code report now uses one inverted Java usage graph build per report call for safe Java candidates. Constructors, overloaded Java methods, and Java class candidates in mixed Java/Scala workspaces remain on the precise per-symbol path. Focused Java tests cover graph-derived findings and the guarded precise-path cases.

2026-06-17: The Scala dead-code report now uses one inverted Scala usage graph build per report call for safe Scala candidates. Scala classes/objects and non-overloaded methods without import-sensitive exposure can be scored from inbound graph counts. Fields, constructors, overloaded methods, and direct/wildcard-import-sensitive methods stay conservative or precise; empty Scala field evidence is skipped as inconclusive instead of reported as dead code. Public-like Scala findings use lower score/confidence and workspace/public-surface wording.

2026-06-17: Guided review tightened the Scala slice. Top-level Scala functions now stay on the precise path, import sensitivity is computed with parsed Scala import metadata, wildcard imports only force precise analysis when they can expose the candidate owner, and oversized Scala workspaces skip bulk graph evidence before doing import-sensitive preflight work.

2026-06-17: A second guided review found the candidate-aware import guard was still too expensive when repeated for every method candidate. The Scala slice now builds one `ScalaDeadCodeBulkContext` per report and reuses it for all Scala candidate eligibility checks.

2026-06-17: The Go slice is now in progress. The intended implementation reuses the shared string-keyed FQN scorer for Go functions and types/classes through one `build_go_usage_edges(...)` pass per report, with exported Go symbols reported using conservative public-surface wording and Go fields kept precise.

2026-06-17: The Go dead-code report now bulk-scores Go functions and types/classes with one inverted Go usage graph pass per report. Go fields remain precise, exported Go findings use lower confidence and public-surface wording, and focused Go tests cover zero-inbound, one-inbound, cap handling, exported policy, and field fallback behavior.

2026-06-17: Guided review tightened the Go slice. Go runtime/test entry points are excluded from dead-code candidates, package-level initializer references can now be attributed to module field callers in the inverted graph, and public-surface finding construction/test fixture setup were deduplicated.

2026-06-17: The C# slice is now in progress. The intended implementation mirrors Java's conservative FQN bulk scorer shape: one `build_csharp_usage_edges(...)` pass for safe candidates, precise fallback for unsafe members, and conservative public/API-like wording for non-private declarations.

2026-06-17: The C# dead-code report now bulk-scores safe C# classes and non-overloaded methods with one inverted C# usage graph pass per report. Fields, constructors, overloaded methods, and static-using-sensitive methods stay on the precise path or are skipped as inconclusive, while `Main` and attributed test methods are excluded from candidate selection.

## Context and Orientation

The report entry point is `src/code_quality/dead_code_smells.rs`, function `report_dead_code_and_unused_abstraction_smells`. It resolves input files, selects candidate declarations, and currently calls `analyze_candidate` once per candidate. `analyze_candidate` uses per-symbol usage analysis and is still appropriate for the existing Python, JavaScript, and TypeScript behavior in this slice.

For Rust and Python, the scalable whole-program paths return `UsageEdges`, a crate-internal structure with an `edges` map keyed by `(caller_fqn, callee_fqn)` and a `truncated` map keyed by callee FQN for symbols whose call sites exceeded the enumeration guardrail. A caller is the enclosing function or class-like declaration containing a reference. A callee is the declaration being referenced. An inbound count for a candidate is the sum of edge weights where the edge callee equals the candidate's fully qualified name.

For JS/TS, bare FQN identity is insufficient because unrelated files can export the same local name. The scoped path uses `UsageNodeKey { file, fqn }` and `ScopedUsageEdges` so dead-code scoring can distinguish `a.ts::helper` from `b.ts::helper`. Ambiguous export aliases, star re-exports, and unseedable local symbols are skipped as inconclusive rather than forced into a potentially wrong key.

Rust visibility information already exists on `RustAnalyzer` as `is_rust_public_like_declaration`. Public-like means the declaration syntax has a Rust `pub...` visibility modifier. The dead-code report must reuse this analyzer helper rather than parsing visibility text again.

## Plan of Work

First, add the Rust bulk path to `src/code_quality/dead_code_smells.rs`. The report function should partition the selected candidates: Rust candidates go through one new helper, and unsupported bulk languages keep the existing `analyze_candidate` loop. The helper should resolve the concrete `RustAnalyzer`, build a Rust node set from all Rust function and class declarations plus all Rust smell candidates, call `build_rust_usage_edges` once with an all-files `keep_file` predicate, and compute inbound counts for each candidate from the resulting edges.

Second, build findings from inbound counts. Zero-inbound and one-inbound candidates produce findings; higher inbound counts produce no finding. Candidates present in `UsageEdges.truncated` are skipped with a clear inconclusive-evidence note and never flagged. Private Rust candidates can keep the existing strong dead-code and one-call-abstraction wording. Public Rust candidates must use lower score and confidence, and must say they are unreferenced or lightly referenced in the workspace and may be externally consumed or untested public surface.

Third, update `tests/rust_dead_code_smells.rs`. Existing private helper, one-call wrapper, recursion, explicit FQN targeting, and threshold behavior should still pass after expected wording changes. Add a public `pub fn` test that asserts conservative public-surface wording. Cover `truncated_symbols` behavior with an integration test that creates more than the Rust usage-graph call-site limit and asserts the candidate is skipped as inconclusive.

The Python follow-up slice now uses Python's inverted usage graph for the same one-pass inbound scoring shape. The JS/TS follow-up slice now uses file-scoped identity so same-name exports in different files do not cross-count. The Java follow-up slice uses Java's existing package-qualified FQN graph for safe candidates and keeps overlap-sensitive candidates precise. The Scala follow-up slice uses Scala's existing FQN graph only for safe candidates and keeps richer member/import semantics precise. The Go follow-up slice uses Go's existing package-qualified FQN graph for functions and types/classes while leaving fields precise. The current C# follow-up slice uses C#'s existing package-qualified FQN graph for safe classes and methods while leaving fields, constructors, overloads, static-using-sensitive methods, and externally invoked entry points conservative. Deferred follow-up slices remain tracked here but are not implemented in this branch. C++ and PHP parity should only be pursued after the Rust, Python, JS/TS, Java, Scala, Go, and C# slices confirm product value and graph semantics. If broad graph cost still dominates after bulk dead-code scoring, later work can profile resolver/cache micro-optimizations.

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

Key implementation artifacts will be recorded here after code changes and test runs. The important proof is focused dead-code test output plus the relevant usage-graph regression suite for each migrated language.

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
    running 11 tests
    test java_dead_code_smell_reports_unused_private_helper ... ok
    test java_dead_code_smell_reports_one_call_wrapper ... ok
    test java_dead_code_smell_does_not_flag_symbol_with_multiple_inbound_edges ... ok
    test java_dead_code_smell_honors_usage_candidate_file_cap ... ok
    test java_dead_code_smell_honors_usage_cap ... ok
    test java_constructor_candidate_stays_on_precise_path ... ok
    test java_overloaded_methods_stay_on_precise_path ... ok
    test java_class_candidate_uses_precise_path_when_scala_files_are_present ... ok
    test java_field_candidate_stays_on_precise_path_for_bare_identifier_reads ... ok
    test java_method_candidate_stays_on_precise_path_when_static_imports_are_present ... ok
    test java_public_api_uses_conservative_wording_and_score ... ok
    test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Java usage graph regression evidence:

    cargo test --test usages_java_graph_test
    running 32 tests
    test java_graph_finds_java_type_usages_from_scala_source ... ok
    test java_type_usage_lookup_merges_java_and_scala_source_hits ... ok
    test java_member_usage_lookup_does_not_claim_scala_source_hits ... ok
    test scala_target_usage_lookup_does_not_scan_java_source ... ok
    test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Scala focused test evidence:

    cargo test --test scala_dead_code_smells -- --nocapture
    running 16 tests
    test scala_dead_code_smell_reports_unused_private_method ... ok
    test scala_dead_code_smell_reports_one_call_method ... ok
    test scala_top_level_function_candidate_stays_on_precise_path ... ok
    test scala_type_usage_prevents_false_dead_code_finding ... ok
    test scala_dead_code_smell_does_not_flag_symbol_with_multiple_inbound_edges ... ok
    test scala_dead_code_smell_honors_usage_candidate_file_cap ... ok
    test scala_dead_code_smell_honors_usage_cap ... ok
    test scala_field_candidate_stays_on_precise_path_for_bare_identifier_reads ... ok
    test scala_constructor_candidate_stays_on_precise_path ... ok
    test scala_overloaded_methods_stay_on_precise_path ... ok
    test scala_direct_member_import_candidate_stays_on_precise_path ... ok
    test scala_wildcard_import_candidate_stays_on_precise_path ... ok
    test scala_star_import_candidate_stays_on_precise_path ... ok
    test scala_as_alias_import_candidate_stays_on_precise_path ... ok
    test scala_public_api_uses_conservative_wording_and_score ... ok
    test scala_private_method_keeps_strong_wording ... ok
    test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Scala usage graph regression evidence:

    cargo test --test usage_graph_scala_test
    running 6 tests
    test resolves_instance_object_and_unqualified_calls ... ok
    test type_references_edge_to_the_type_node ... ok
    test receiver_typing_is_type_based_not_name_based ... ok
    test self_recursion_produces_no_edge_and_unused_has_no_incoming ... ok
    test every_edge_endpoint_is_a_node ... ok
    test scala3_indented_this_and_block_scoping ... ok
    test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Go focused test evidence:

    cargo test --test go_dead_code_smells -- --nocapture
    running 11 tests
    test go_dead_code_smell_reports_unused_unexported_helper ... ok
    test go_dead_code_smell_reports_one_call_unexported_helper ... ok
    test go_type_usage_from_another_file_prevents_finding ... ok
    test go_symbol_with_two_distinct_inbound_callers_is_not_flagged ... ok
    test go_runtime_and_test_entry_points_are_not_dead_code_candidates ... ok
    test go_package_initializers_count_as_inbound_callers ... ok
    test go_dead_code_smell_honors_usage_candidate_file_cap ... ok
    test go_dead_code_smell_honors_usage_cap ... ok
    test go_exported_function_uses_conservative_wording_and_score ... ok
    test go_exported_type_uses_conservative_wording_and_score ... ok
    test go_field_candidate_stays_on_precise_path ... ok
    test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Go usage graph regression evidence:

    cargo test --test usages_go_graph_test
    running 29 tests
    test usage_finder_routes_go_targets_through_graph_strategy ... ok
    test go_graph_strategy_finds_same_package_references_without_imports ... ok
    test go_graph_strategy_resolves_qualified_and_aliased_import_selectors ... ok
    test go_graph_strategy_finds_methods_and_fields_through_local_receiver_inference ... ok
    test go_graph_strategy_enforces_max_usages_limit ... ok
    test result: ok. 29 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

C# focused test evidence:

    cargo test --test csharp_dead_code_smells
    running 16 tests
    test csharp_dead_code_smell_reports_unused_private_method ... ok
    test csharp_dead_code_smell_reports_one_call_method ... ok
    test csharp_type_usage_from_another_file_prevents_finding ... ok
    test csharp_symbol_with_two_distinct_inbound_callers_is_not_flagged ... ok
    test csharp_dead_code_smell_honors_usage_candidate_file_cap ... ok
    test csharp_dead_code_smell_honors_usage_cap ... ok
    test csharp_public_api_uses_conservative_wording_and_score ... ok
    test csharp_public_class_with_private_member_uses_conservative_wording ... ok
    test csharp_constructor_candidate_stays_on_precise_path ... ok
    test csharp_overloaded_methods_stay_on_precise_path ... ok
    test csharp_field_candidate_stays_on_precise_path ... ok
    test csharp_static_using_method_stays_on_precise_path ... ok
    test csharp_static_using_with_whitespace_stays_on_precise_path ... ok
    test csharp_alias_using_method_stays_on_precise_path ... ok
    test csharp_main_and_test_methods_are_not_dead_code_candidates ... ok
    test csharp_non_static_main_is_still_dead_code_candidate ... ok
    test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

C# usage graph regression evidence:

    cargo test --test usages_csharp_graph_test
    running 25 tests
    test usage_finder_routes_csharp_targets_through_graph_strategy ... ok
    test csharp_graph_covers_non_class_type_targets ... ok
    test csharp_graph_finds_static_and_instance_member_references ... ok
    test csharp_graph_keeps_constructor_and_method_overloads_narrow ... ok
    test csharp_graph_fails_closed_for_deferred_using_member_forms ... ok
    test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Rust formatting and lint evidence:

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.94s

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
