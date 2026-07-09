# Calibrate unproven inbound dead-code evidence for issue 529

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agents/PLANS.md` from the repository root. Keep this file in `.agents/plans/` and keep it self-contained whenever it is revised.

At the time this plan is created, it is only a plan. Do not start the implementation milestones until the user explicitly asks to execute this ExecPlan.


## Purpose / Big Picture

Bulk dead-code analysis reports symbols that appear to have no non-self usages. For C#, Java, Go, Rust, and C++, the inverted usage-edge pipeline can now distinguish "no usage exists" from "a structurally plausible call exists, but its receiver type could not be proven." That second state is called `unproven_inbound`; dead-code analysis skips such candidates as inconclusive instead of calling them dead.

Issue #529 extends that same safety to the remaining bulk dead-code paths: PHP, Scala, scoped JavaScript/TypeScript, Python, and Ruby. After this work, a method or class used only through an untypeable but structurally plausible receiver in those languages should be reported as "evidence is inconclusive", while genuinely unused symbols should still be reported as dead. The observable proof is focused dead-code tests per language plus benchmark-harness probes that exercise `report_dead_code_and_unused_abstraction_smells` on the pinned benchmark corpus.


## Progress

- [x] (2026-07-09T07:44:31Z) Created this ExecPlan from issue #529, `.agents/PLANS.md`, the existing issue #528 Stage 7 design record, and the current benchmark/dead-code code paths.
- [x] (2026-07-09T07:59:56Z) Milestone 0: added benchmark-harness support for a `dead_code_smells` scenario and pinned manifest probes.
- [ ] Milestone 1: calibrate PHP bulk dead-code unproven-inbound evidence.
- [ ] Milestone 2: calibrate Scala bulk dead-code unproven-inbound evidence.
- [ ] Milestone 3: calibrate scoped JavaScript/TypeScript bulk dead-code unproven-inbound evidence.
- [ ] Milestone 4: calibrate Python bulk dead-code unproven-inbound evidence.
- [ ] Milestone 5: calibrate Ruby bulk dead-code unproven-inbound evidence.
- [ ] Final validation and retrospective.


## Surprises & Discoveries

- Observation: The checked-in benchmark directory is `benchmark/`, not `benchmarks/`.
  Evidence: `benchmark/targets.toml`, `benchmark/README.md`, and the benchmark tests are present; `rg ... benchmarks` reports `No such file or directory`.

- Observation: The current benchmark harness has a closed scenario enum and no dead-code scenario.
  Evidence: `src/benchmark/manifest.rs` defines `BenchmarkScenario::ALL` with ten scenarios ending at `type_hierarchy`; `src/benchmark/runner.rs` maps scenarios to MCP tool calls and result assertions, with no `report_dead_code_and_unused_abstraction_smells` branch.

- Observation: The current pinned benchmark manifest covers Python, JavaScript, TypeScript, PHP, and Scala, but not Ruby.
  Evidence: `benchmark/targets.toml` includes `click-py`, `express-js`, `ky-ts`, `fastroute-php`, and `scala-xml`; `required_languages` does not list Ruby and no Ruby repo entry exists.

- Observation: The repository instructions conflict on initial rebasing for this worktree; the worktree was already on the issue branch, so only `git fetch` was run and rebase was skipped.
  Evidence: The top-level startup note says `git fetch && git rebase`, while the project Git instructions say "Do NOT create branches, switch branches, rebase, or open PRs unless I explicitly ask."

- Observation: The benchmark runner integration fixture should assert stable dead-code report plumbing, not incidental dead/findings wording for its tiny Java fixture.
  Evidence: The first Milestone 0 test run failed because the report did not contain `A.method1`; the second failed because it did not contain `no non-self usages found`. After changing the fixture assertion to `Candidate symbols analyzed: 1`, the focused benchmark tests passed.

- Observation: `cargo clippy-no-cuda` is currently blocked by local Rust metadata/toolchain state rather than milestone code.
  Evidence: A first run failed with many `E0514` "compiled by an incompatible version of rustc" errors. After `cargo clean` removed 9635 files and 3.9GiB of artifacts, a clean rerun failed with the same `E0514` errors for freshly built dependencies including `rayon`, `tree_sitter`, `serde_json`, and `chrono`.

- Observation: Guided review found that FQN-only dead-code probes were fragile in `--max-files` subset benchmark mode because subset preparation only pins path-based probe files.
  Evidence: `src/benchmark/subset_workspace.rs` gathered summary, seed, usage, definition, call-hierarchy, and type-hierarchy paths, but no dead-code paths.


## Decision Log

- Decision: Add benchmark support as Milestone 0 before language implementation.
  Rationale: The user asked to consider injecting dead code into current regression benchmarks, and chose a dedicated benchmark scenario milestone. The harness cannot express dead-code probes today, so the scenario must exist before per-language benchmark probes can be meaningful.
  Date/Author: 2026-07-09 / Codex.

- Decision: Keep scoped JavaScript and TypeScript in one milestone.
  Rationale: The dead-code path uses the shared scoped JS/TS edge builder and `UsageNodeKey` identity model, so splitting JS and TS would duplicate the same implementation and review checkpoint.
  Date/Author: 2026-07-09 / Codex.

- Decision: Do not use one global numeric confidence threshold.
  Rationale: Issue #529 is a per-language calibration problem. Dynamic languages have many untyped calls; a broad same-name threshold would mark too many candidates inconclusive and effectively disable dead-code detection. Each backend must count only structured sites where its own resolver got close enough to make "dead" unsafe.
  Date/Author: 2026-07-09 / Codex.

- Decision: After every implementation milestone, run Brokk guided review on uncommitted changes, fix accepted related findings, then commit only that milestone's files.
  Rationale: The user requested review between milestones and checkpoint commits. This keeps each language slice bisectable and prevents review findings from being deferred into later language work.
  Date/Author: 2026-07-09 / Codex.

- Decision: Milestone 0 benchmark probes assert dead-code report generation and absence of unsupported-definition errors, not final language-specific dead/inconclusive outcomes.
  Rationale: Milestone 0 is harness support. The semantic calibration fixtures for dead, proven inbound, and unproven-inbound inconclusive behavior belong to Milestones 1-5, where each language can use focused source fixtures and resolver-specific assertions.
  Date/Author: 2026-07-09 / Codex.

- Decision: Add `dead_code_file_paths` as an optional manifest field and use it to pin source files for subset benchmark runs.
  Rationale: Exact `fq_names` remain the dead-code report targets, but subset workspace preparation needs concrete paths to make those FQNs resolvable when benchmarks run against a reduced file set.
  Date/Author: 2026-07-09 / Codex.


## Outcomes & Retrospective

Milestone 0 added `dead_code_smells` as a normal benchmark scenario, manifest validation for dead-code probe fields, runner plumbing for `report_dead_code_and_unused_abstraction_smells`, report substring assertions, checked-in probes for Python, JavaScript, TypeScript, PHP, and Scala, subset-workspace pinning for dead-code source files, and README documentation. Ruby remains absent from benchmark coverage because the current pinned corpus has no Ruby repo entry.

Validation evidence after guided review fix:

    BIFROST_SEMANTIC_INDEX=off cargo test --test benchmark_manifest --test bifrost_benchmark_run --test bifrost_benchmark_cli
    result: passed at 2026-07-09T08:05:51Z; 4 benchmark_manifest tests, 3 bifrost_benchmark_cli tests, and 8 bifrost_benchmark_run tests passed

    BIFROST_SEMANTIC_INDEX=off cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml
    result: passed at 2026-07-09T08:05:51Z; validated 10 repos and covered scenarios now include dead_code_smells

    cargo fmt --check
    result: passed at 2026-07-09T08:05:51Z

    cargo clippy-no-cuda
    result: blocked by repeated E0514 incompatible-rustc dependency metadata errors, including after cargo clean and after the focused test rebuild

Guided review finding before commit:

    LOW / Infrastructure: dead-code FQN probes were not represented in subset workspace pinning, so future dead-code-only probes could fail under --max-files even when the full benchmark passed.
    Fix: added dead_code_file_paths to the manifest model, runner arguments, subset workspace pinned paths, current pinned repos, README, and checked-in manifest test.


## Context and Orientation

The public tool involved here is `report_dead_code_and_unused_abstraction_smells`. It is implemented in `src/code_quality/dead_code_smells.rs` and exposed through `src/searchtools_service.rs`. It accepts file paths and/or fully-qualified names, finds candidate symbols, counts inbound usage evidence, and reports likely dead code or one-call abstractions.

An "inverted edge builder" is a usage-graph pass that walks source files and records `(caller, callee)` edges without running a separate query for each target. Most language implementations live under `src/analyzer/usages/<language>_graph/inverted.rs`. The common edge result type is `UsageEdges` in `src/analyzer/usages/inverted_edges.rs`. It contains proven `edges`, truncated callsite counts, and `unproven_inbound`.

`unproven_inbound` means a structurally plausible call/member site matched a candidate's terminal name, but the analyzer could not prove the receiver or owner strongly enough to emit a real edge. Dead-code analysis already folds this signal in `incoming_usage_by_callee`: if a candidate has zero proven inbound usage and nonzero `unproven_inbound`, the report skips it with the message:

    N structurally matching usage site(s) could not be proven or disproven; evidence is inconclusive

Issue #528 Stage 7 added that signal for C#, Java, Go, Rust, and C++. It deliberately deferred Ruby, Python, Scala, PHP, and scoped JS/TS because those paths need language-specific calibration. The deferral record in `.agents/plans/issue-528-scan-usages-generalization.md` says Ruby's inverted path requires `ReceiverType` and `RubySemanticIndex`; Python shadows function-local names and records typed receiver attributes; Scala can fall back to visible extension methods when receiver typing fails; PHP skips untyped instance calls; and scoped JS/TS dead-code uses `UsageEdgeWeights<UsageNodeKey>` instead of plain `UsageEdges`.

The central rule for this plan is: do not replace structured resolver support with source text scanning. Do not use regexes, `split`, substring matching, or generic "same terminal name anywhere" logic to infer unproven evidence. Count unproven inbound only at points where a real AST call/member form has the candidate member name and the existing structured resolver or receiver-analysis code has enough context to say the site is plausible but not proven.

The main test files already exist:

- `tests/php_dead_code_smells.rs`
- `tests/scala_dead_code_smells.rs`
- `tests/python_js_ts_dead_code_smells.rs`
- `tests/ruby_dead_code_smells.rs`

Use `tests/common/inline_project.rs` and `InlineTestProject` for new small ad hoc projects. Do not create fixture directories unless a language-specific parser behavior cannot be expressed inline.


## Plan of Work

Milestone 0 adds benchmark-harness support. Extend `BenchmarkScenario` with `dead_code_smells`, add manifest fields for dead-code probes, wire the runner to call `report_dead_code_and_unused_abstraction_smells`, and add validation/assertions. Then add pinned manifest probes for Python, JS, TS, PHP, and Scala where stable fully-qualified names are known. Do not add a Ruby benchmark probe unless this milestone also adds a pinned Ruby repo entry; otherwise document that Ruby remains covered by focused tests only because the current benchmark corpus has no Ruby repo.

Milestone 1 implements PHP. Add tests in `tests/php_dead_code_smells.rs` before production edits. The calibration should start from `src/analyzer/usages/php_graph/inverted.rs`, where `member_call_expression` currently records `$obj->method()` only when `receiver_type_fqn` succeeds. Count unproven inbound for instance method calls only when the name node is a real `member_call_expression` method name, the method name matches at least one requested node through `EdgeCollector::record_unproven_name`, and the receiver is a structured variable/object expression that cannot be typed. Do not count dynamic method names or non-method property forms in this milestone.

Milestone 2 implements Scala. Add tests in `tests/scala_dead_code_smells.rs` first. Start from `src/analyzer/usages/scala_graph/inverted.rs`, especially the `call_expression` handling for `field_expression`. Count unproven inbound when the receiver is syntactically a member-call receiver, the field name is known, `receiver_type_fqn` fails, and the existing visible-extension fallback does not prove a target. Preserve current behavior for unqualified calls, type references, inherited method hits, and existing extension-method proofs. Avoid changing `ScalaDeadCodeBulkEligibility` except if a new test proves a candidate is currently routed to the precise path instead of the bulk path.

Milestone 3 implements scoped JS/TS. First extend `UsageEdgeWeights<K>` in `src/analyzer/usages/inverted_edges.rs` with `unproven_inbound: BTreeMap<K, usize>` and update all constructors/destructuring/callers. Then update `src/analyzer/usages/js_ts_graph/inverted.rs` so `ScopedTsScan` can record unproven scoped member inbound with `UsageNodeKey` identity. The scoped path should count unproven inbound only when a `member_expression` property name matches scoped candidate nodes and `JsTsReceiverFactProvider` returns `Unknown`, `Unsupported`, `ExceededBudget`, or an `Ambiguous` set that includes a matching owner candidate but cannot prove one target. Update `analyze_jsts_candidates_with_scoped_usage_graph` in `src/code_quality/dead_code_smells.rs` so zero-proven/nonzero-unproven scoped candidates skip as inconclusive. Add both TypeScript and JavaScript dead-code fixtures in `tests/python_js_ts_dead_code_smells.rs`.

Milestone 4 implements Python. Add tests in `tests/python_js_ts_dead_code_smells.rs` first. Start from `src/analyzer/usages/python_graph/inverted.rs`, where `handle_attribute` records `recv.method` only when imports or receiver-type facts prove the target. Count unproven inbound only for attribute nodes whose object is a receiver expression in function scope, whose attribute name matches a requested node, and whose local facts show the object is not a namespace import or a known shadowed non-receiver. Preserve the current "genuinely unused helper" and "one-call wrapper" findings. Be especially conservative: do not count every `x.method` where `x` is just any local variable unless existing scope facts show the resolver attempted receiver typing or the call shape is otherwise close to a target owner.

Milestone 5 implements Ruby. Add tests in `tests/ruby_dead_code_smells.rs` first. Start from `src/analyzer/usages/ruby_graph/inverted.rs`, where `record_method_reference` resolves receiver types and then calls `record_unique_method_candidate`. Count unproven inbound for Ruby method targets only when the query path would already have treated the site as an unproven method usage: explicit receiver calls with an untyped receiver, dynamic dispatch forms such as `send` or `public_send` when the dispatched symbol/string names the method, or candidate lookups that return multiple plausible methods rather than exactly one. Keep constants and fields out of scope for this milestone unless a test proves they already participate in the method-only unproven path.

Every milestone must update this ExecPlan before committing: mark progress, record surprises, record decisions, and paste concise validation evidence. Each milestone must end with a guided-review and commit checkpoint before the next milestone starts.


## Concrete Steps

Work from the repository root:

    cd /Users/dave/.codex/worktrees/e737/bifrost

Before starting Milestone 0, refresh the branch in the way allowed by the repository instructions and the current worktree state. Do not create or switch branches. If the branch has a normal upstream, run:

    git fetch
    git rebase

If the worktree is detached or the repository instructions in `AGENTS.md` forbid rebasing in the current context, run `git fetch`, record why rebase was skipped in `Surprises & Discoveries`, and continue on the current branch.

For Milestone 0, edit `src/benchmark/manifest.rs`:

- Add `BenchmarkScenario::DeadCodeSmells` serialized as `dead_code_smells`.
- Add it to `BenchmarkScenario::ALL`, `label`, and any match that must stay exhaustive.
- Add fields to `BenchmarkRepoTarget`:

        #[serde(default)]
        pub dead_code_file_paths: Vec<String>,
        #[serde(default)]
        pub dead_code_fq_names: Vec<String>,
        #[serde(default)]
        pub dead_code_expect_report_contains: Vec<String>,
        #[serde(default)]
        pub dead_code_expect_report_absent: Vec<String>,

- Validate that any repo enabling `dead_code_smells` has at least one `dead_code_fq_names` entry and at least one expected report assertion. Reject blank values in these fields, including `dead_code_file_paths` when present.

Then edit `src/benchmark/runner.rs`:

- In `tool_arguments`, map `BenchmarkScenario::DeadCodeSmells` to the MCP tool `report_dead_code_and_unused_abstraction_smells` with:

        {
          "fq_names": target.dead_code_fq_names,
          "file_paths": target.dead_code_file_paths,
          "max_usage_candidate_files": 2000,
          "max_usages_per_symbol": 1000
        }

  `fq_names` are the dead-code targets. `dead_code_file_paths` pins the files that contain those targets so subset benchmark runs can still resolve them.

- In `assert_scenario_result`, read `structuredContent.report` as a string. Every `dead_code_expect_report_contains` substring must be present. Every `dead_code_expect_report_absent` substring must be absent. A missing report string is a scenario failure.

Then update `benchmark/targets.toml`, `benchmark/README.md`, and benchmark tests such as `tests/benchmark_manifest.rs`, `tests/bifrost_benchmark_run.rs`, and `tests/bifrost_benchmark_cli.rs` to cover the new scenario and fields. Add `dead_code_smells` to `required_scenarios`.

For each language milestone, follow this exact loop:

1. Add the focused red tests first. Include one unproven-only false-positive fixture, one genuinely unused fixture, and one proven-inbound fixture. The unproven-only test should assert the inconclusive skip message and assert the target is not present in the findings table as dead.
2. Run the focused test before production edits and record the failing assertion in `Surprises & Discoveries`.
3. Implement the minimal structured unproven-inbound emission for that language.
4. Run focused tests for that language and neighboring usage-graph tests.
5. Run `cargo fmt --check`, `cargo clippy-no-cuda`, and benchmark validation.
6. Run Brokk guided review in "Uncommitted changes" mode. If the review process presents a menu, choose "Uncommitted changes".
7. Fix accepted findings that are related to the milestone. Do not fix unrelated findings in the same commit. Rerun focused validation after fixes.
8. Update this ExecPlan with progress, surprises, decisions, and validation evidence.
9. Stage only files changed for this milestone. Do not use `git add -A`.
10. Commit with a multiline message explaining why the calibration bar is correct for that language.

Use this commit message shape:

    git commit -m "Calibrate <language> dead-code unproven inbound" -m "<Why this milestone's structural bar is safe, which tests prove it, and what guided review found/fixed.>"


## Milestone Details and Acceptance

Milestone 0 is complete when the benchmark harness validates a manifest containing `dead_code_smells`, the benchmark runner can call the dead-code tool and assert report substrings, and the checked-in manifest includes stable probes for Python, JS, TS, PHP, and Scala. Run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test benchmark_manifest --test bifrost_benchmark_run --test bifrost_benchmark_cli
    BIFROST_SEMANTIC_INDEX=off cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml

Milestone 1 is complete when PHP bulk dead-code skips an untyped `$service->target()` style call as inconclusive, still reports a genuinely unused PHP function/class as dead, and still suppresses findings for proven inbound usage. Run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test php_dead_code_smells --test usage_graph_php_test

Milestone 2 is complete when Scala bulk dead-code skips an untyped receiver member call as inconclusive without breaking unqualified same-owner method calls, type usage, inherited method evidence, or extension-method behavior. Run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test scala_dead_code_smells --test usage_graph_scala_test --test usages_scala_graph_test

Milestone 3 is complete when scoped TypeScript and JavaScript dead-code skip unproven member receiver evidence as inconclusive while preserving duplicate-name scoped identity. Run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test python_js_ts_dead_code_smells --test usage_graph_ts_test --test usages_js_ts_graph_test --test usages_js_ts_path_alias_test

Milestone 4 is complete when Python bulk dead-code skips a calibrated untyped receiver attribute call as inconclusive, but existing helper and wrapper true-positive findings survive. Run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test python_js_ts_dead_code_smells --test usage_graph_test --test usages_python_graph_test

Milestone 5 is complete when Ruby bulk dead-code skips a calibrated unknown receiver or dynamic dispatch method call as inconclusive, but existing unused Ruby methods still report. Run:

    BIFROST_SEMANTIC_INDEX=off cargo test --test ruby_dead_code_smells --test usage_graph_ruby_test --test usages_ruby_test

After each milestone, also run:

    cargo fmt --check
    cargo clippy-no-cuda
    BIFROST_SEMANTIC_INDEX=off cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml

For final validation after Milestone 5, run all focused suites together:

    BIFROST_SEMANTIC_INDEX=off cargo test --test php_dead_code_smells --test scala_dead_code_smells --test python_js_ts_dead_code_smells --test ruby_dead_code_smells
    BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_php_test --test usage_graph_scala_test --test usage_graph_ts_test --test usage_graph_ruby_test --test usage_graph_test
    BIFROST_SEMANTIC_INDEX=off cargo test --test usages_scala_graph_test --test usages_js_ts_graph_test --test usages_js_ts_path_alias_test --test usages_python_graph_test --test usages_ruby_test
    cargo fmt --check
    cargo clippy-no-cuda
    BIFROST_SEMANTIC_INDEX=off cargo run --bin bifrost_benchmark -- validate --manifest benchmark/targets.toml


## Guided Review and Checkpoint Requirements

Brokk guided review is mandatory between milestones. Run it after the milestone implementation and focused validation, while the milestone changes are still uncommitted. Use "Uncommitted changes" mode. The review must evaluate only the current milestone diff.

If guided review reports findings, triage them one by one. Fix findings that are caused by this milestone's changes and are in scope for issue #529. If a finding is unrelated or would require a separate issue, record that in `Decision Log` and do not include it in the milestone commit. Rerun the focused validation after any accepted fix.

The milestone commit must include only files changed for that milestone. Never stage unrelated working-tree changes. Never use `git add -A`. If two milestones touch the same file, commit the first milestone before starting the second so history remains bisectable.


## Validation and Acceptance

The feature is accepted when all target languages have focused dead-code tests proving three behaviors:

1. A candidate with only structurally plausible but unproven inbound evidence is skipped as inconclusive.
2. A genuinely unused candidate still appears as a dead-code finding.
3. A candidate with proven inbound usage keeps its current score/reporting behavior and is not over-counted by unproven evidence.

The benchmark harness is accepted when `dead_code_smells` is a normal manifest scenario, `benchmark/targets.toml` validates, and pinned probes assert meaningful report text for Python, JS, TS, PHP, and Scala. Ruby benchmark coverage is accepted only if a Ruby pinned repo is added; otherwise Ruby remains covered by focused tests and this limitation must be recorded in `Outcomes & Retrospective`.

The final implementation must not change `scan_usages` query behavior except where shared helper changes are unavoidable and covered by existing usage tests. The issue says the query path already emits labeled unproven sites; this plan is about the bulk dead-code edge path.


## Idempotence and Recovery

All milestones are additive and can be retried. If a focused test fails before production edits, keep it and implement the planned fix. If a production edit broadens unproven evidence too far and existing true-positive dead-code tests disappear, revert only that milestone's local edits or tighten the structural bar; do not weaken the tests.

If benchmark probes are unstable because a pinned upstream repo does not contain a durable dead-code target, keep the benchmark scenario support and omit that repo's probe with an explicit note in `Surprises & Discoveries`. Do not inject unpinned or generated source into cached third-party checkouts as a hidden benchmark step. Any benchmark source changes must be represented explicitly by manifest support, a deterministic subset fixture, or a checked-in local benchmark test.

If guided review produces a finding that spans multiple language milestones, fix only the part introduced by the current milestone. Record the broader follow-up in `Outcomes & Retrospective` or open a separate issue if the user asks.


## Artifacts and Notes

Issue #529 states that `UsageEdges::unproven_inbound` is already emitted by C#, Java, Go, Rust, and C++, but not by Ruby, Python, Scala, PHP, or scoped JS/TS. The issue's acceptance shape is the basis for every language milestone: unproven-only caller flips from dead finding to inconclusive skip; genuinely unreferenced remains a finding; proven-inbound candidates stay unchanged; true-positive dead-code suites survive.

The relevant issue #528 Stage 7 design language is:

    A structurally valid call/selector site whose member name matches a node in the requested node set but which resolves to no proven edge marks every name-matching node in the node set as having unproven inbound evidence.

For this plan, "structurally valid" always means language-specific AST and resolver evidence, not text search.


## Interfaces and Dependencies

At the end of Milestone 0, the benchmark manifest interface must include these stable fields on each repo entry:

    dead_code_file_paths = ["path/to/source.ext"]
    dead_code_fq_names = ["fully.qualified.Symbol"]
    dead_code_expect_report_contains = ["substring expected in report"]
    dead_code_expect_report_absent = ["substring that must not appear"]

At the end of Milestone 3, `UsageEdgeWeights<K>` must have the same semantic information needed by scoped JS/TS dead-code that `UsageEdges<K>` already has for FQN-based languages:

    pub(crate) unproven_inbound: BTreeMap<K, usize>

This must be additive. Existing edge weights and truncation semantics must not change. Consumers that only care about proven edges should keep reading only `edges` and `truncated`.

All language milestones should use `EdgeCollector::record_unproven_name` or a scoped equivalent that preserves these properties: enclosing-caller attribution, self/definition-span exclusion, and per-offset deduplication. Do not introduce a parallel string-scanning unproven recorder.


Revision note (2026-07-09 / Codex): Initial ExecPlan created for issue #529. It records the requested milestone order, benchmark-harness milestone, guided-review and commit cadence, and per-language calibration constraints without starting implementation.
