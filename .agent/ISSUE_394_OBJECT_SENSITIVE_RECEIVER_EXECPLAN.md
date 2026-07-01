# Add Bounded Object-Sensitive Receiver Analysis

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

Issue #394 adds a bounded, demand-driven receiver/value analysis that usage graph resolution can query when local type facts are not enough. After this work, Bifrost can resolve simple factory and constructor receiver calls such as `const s = makeService(); s.run()` to the correct `Service.run`, refuse ambiguous same-name member calls instead of guessing, and report explicit budget exits when a query would become too expensive.

The change improves both recall and precision. Recall improves because calls through structurally proven factory results become graph edges. Precision improves because calls through ambiguous or unsupported receivers no longer succeed through same-name matching. The behavior is observable through focused `usage_graph`, `scan_usages`, and `get_definition` tests that fail before each milestone and pass after it.

## Progress

- [x] (2026-07-01T10:30Z) Created this ExecPlan at `.agent/ISSUE_394_OBJECT_SENSITIVE_RECEIVER_EXECPLAN.md`.
- [x] (2026-07-01T10:35Z) Add the shared receiver analysis API, budget model, no-op provider, cache key shape, and unit tests.
- [x] (2026-07-01T10:48Z) Implement and test the JS/TS milestone, including a second consumer through `get_definition` or type lookup.
- [x] (2026-07-01T10:54Z) Implement and test the Java milestone.
- [x] (2026-07-01T10:56Z) Implement and test the C# milestone.
- [x] (2026-07-01T10:58Z) Implement and test the C++ milestone.
- [x] (2026-07-01T11:00Z) Implement and test the Go milestone.
- [x] (2026-07-01T11:08Z) Implement and test the PHP milestone.
- [x] (2026-07-01T11:18Z) Implement and test the Python milestone.
- [ ] Implement and test the Ruby milestone.
- [ ] Implement and test the Rust milestone.
- [ ] Implement and test the Scala milestone.
- [ ] Add budget, ambiguity, and performance instrumentation tests.
- [ ] Run final focused validation, `cargo fmt`, `cargo clippy-no-cuda`, and `git diff --check`.

## Surprises & Discoveries

- Observation: The branch starts from issue branch `394-add-bounded-object-sensitive-receiver-analysis-for-usage-graph-resolution`.
  Evidence: `git status --short --branch` reported `## 394-add-bounded-object-sensitive-receiver-analysis-for-usage-graph-resolution...origin/394-add-bounded-object-sensitive-receiver-analysis-for-usage-graph-resolution`.

- Observation: The existing #393 plan created a vocabulary module but deliberately did not create a fact provider.
  Evidence: `src/analyzer/usages/receiver_facts.rs` says it defines names and states, not a full fact provider.

- Observation: Receiver inference already exists in scattered language-specific graph and get-definition modules.
  Evidence: repository search found constructor/factory receiver handling in `src/analyzer/usages/js_ts_graph`, `src/analyzer/usages/get_definition/js_ts.rs`, `src/analyzer/usages/ruby_graph.rs`, and graph tests for Go, Java, C#, C++, PHP, Rust, and Scala.

- Observation: The shared provider can compile and test independently before any language backend adopts it.
  Evidence: `cargo test --lib receiver_analysis` passed 9 unit tests covering `Precise`, `Ambiguous`, `Unknown`, `Unsupported`, `ExceededBudget`, cache key identity, exact-single receiver classification, and no-op provider behavior.

- Observation: The pre-existing JS/TS whole-workspace graph used the string-keyed inverted pass, while a file-scoped builder exists for narrower same-name handling.
  Evidence: `src/searchtools.rs` calls `build_jsts_usage_edges` in `usage_graph::resolve_jsts`; `build_jsts_scoped_usage_edges` is present but not used on that path.

- Observation: JS/TS get-definition already had a local `new Class()` receiver path, but factory-returned receivers were not behind a composable provider.
  Evidence: `src/analyzer/usages/get_definition/js_ts.rs` called `jsts_local_new_receiver_owner_candidates` directly before this milestone.

- Observation: Java whole-workspace graph already had declared-type receiver inference; the object-sensitive gap was untyped locals initialized from constructor/factory results.
  Evidence: `src/analyzer/usages/java_graph/inverted.rs` seeded locals from declaration types and skipped untyped/shadowed locals before this milestone.

- Observation: C# already inferred `var x = new Foo()` in the inverted graph, and the reusable return-type resolver existed in the forward graph.
  Evidence: `src/analyzer/usages/csharp_graph/inverted.rs` used `object_created_type` for `var`, while `src/analyzer/usages/csharp_graph/resolver.rs` exposed `method_return_type_fq_name`.

- Observation: C++ already inferred `auto` receivers from constructors and free-function return types; static factory method return types were the missing factory shape.
  Evidence: `src/analyzer/usages/cpp_graph/resolver.rs` had `infer_cpp_initializer_type` and `resolve_call_return_type` for free functions before this milestone.

- Observation: Go already had a constructor-return index used by the inverted graph.
  Evidence: `src/analyzer/usages/go_graph/resolver.rs` builds `constructor_return_types`, and `src/analyzer/usages/go_graph/inverted.rs` uses it when seeding short-var receiver bindings.

- Observation: PHP already seeded local receiver facts from `new Service()`, but not from factory calls.
  Evidence: `src/analyzer/usages/php_graph/inverted.rs` seeded `$x = new Foo()` and shadowed other assignments before the PHP milestone.

- Observation: Python's whole-workspace graph already reused forward scope facts for typed parameters and `x = Class()` locals.
  Evidence: `src/analyzer/usages/python_graph/inverted.rs` calls `collect_scope_facts`, and `src/analyzer/usages/python_graph/extractor.rs` seeded assignments from normalized call callee names before the Python milestone.

## Decision Log

- Decision: Implement #394 as a shared demand-driven provider plus language milestones, not as another set of independent language-specific heuristics.
  Rationale: The user wants composable systems before later data-flow or control-flow work. A shared provider boundary lets usage graph, get-definition, and future analyses query the same facts.
  Date/Author: 2026-07-01 / Codex planning

- Decision: Treat JavaScript and TypeScript as one milestone.
  Rationale: Their usage and get-definition infrastructure is shared in this repository, and splitting them would duplicate the same provider work.
  Date/Author: 2026-07-01 / Codex planning

- Decision: Include every current usage-graph backend as a target language.
  Rationale: The user selected all graph languages as the meaning of “each target language.” The milestones are Java, C#, C++, Go, JS/TS, PHP, Python, Ruby, Rust, and Scala.
  Date/Author: 2026-07-01 / Codex planning

- Decision: Do not start with pushdown automata, full pointer analysis, control-flow graphs, or path-sensitive data-flow.
  Rationale: The first useful behavior is bounded receiver/value facts with explicit conservative exits. A finite worklist with memoized summaries and hard budgets is simpler, cheaper, and easier to verify.
  Date/Author: 2026-07-01 / Codex planning

## Outcomes & Retrospective

Shared API milestone complete. Added `src/analyzer/usages/receiver_analysis.rs` and exposed it internally from `src/analyzer/usages/mod.rs`. The module defines bounded receiver outcomes, receiver values, the default budget, query/cache-key shapes, a budget tracker, the provider trait, and a no-op provider for unsupported rollout stages. Validation: `cargo test --lib receiver_analysis` passed 9 tests after the JS/TS milestone added exact-single receiver classification coverage.

JS/TS milestone complete. Added `src/analyzer/usages/js_ts_graph/receiver_analysis.rs` and wired it into JS/TS usage graph member resolution and JS/TS get-definition member lookup. The first provider slice resolves `new Service()`, local receivers assigned from factory calls, top-level factories returning constructed values, and class factory methods returning constructed values. Ambiguous factory returns stop without emitting a partial same-name edge. Validation so far: `cargo test --test usages_js_ts_graph_test`, `cargo test --test usage_graph_ts_test`, and `cargo test --test get_definition_test typescript_factory_receiver_member_resolves_to_definition` passed.

Java milestone complete. Extended `src/analyzer/usages/java_graph/inverted.rs` so untyped `var` locals can be seeded from constructor expressions, same-class factory method returns, and cross-file static factory declared return types. Multi-target factory returns are treated as ambiguous and do not seed a receiver binding, so no partial same-name member edge is emitted. Validation: `cargo test --test usage_graph_java_test` passed 11 tests.

C# milestone complete. Extended `src/analyzer/usages/csharp_graph/inverted.rs` so `var` locals can be seeded from constructor expressions and factory invocation declared return types, including static factories. Unsupported or ambiguous `object` factories remain unseeded and therefore do not emit partial same-name member edges. Validation: `cargo test --test usage_graph_csharp_test` passed 10 tests.

C++ milestone complete. Added regression coverage for `auto` receivers initialized from free factories and static factories, and extended C++ initializer inference to resolve `Service::create()` return types from visible static method declarations. Unsupported conditional receivers remain unseeded and do not emit partial same-name member edges. Validation: `cargo test --test usage_graph_cpp_test` passed 11 tests.

Go milestone complete. Added inline regression coverage proving `service := makeService(); service.Run()` resolves only to `Service.Run`, while an unsupported interface-return factory remains unseeded and emits no partial same-name edge. The existing constructor-return index already provided the implementation. Validation: `cargo test --test usage_graph_go_test` passed 10 tests.

PHP milestone complete. Extended `src/analyzer/usages/php_graph/inverted.rs` so `$x = makeService()` and `$x = Service::create()` seed receiver facts only when the called free function or static method has a single declared class return type. The implementation uses AST declaration lookup and a per-file return-type cache, not text fallback. Untyped ambiguous factories remain unseeded and do not emit partial same-name member edges. Validation: `cargo test --test usage_graph_php_test` passed 11 tests.

Python milestone complete. Extended `src/analyzer/usages/python_graph/extractor.rs` so the shared scope fact collector builds a same-file factory return index for `make_service()` and `Service.create()` calls. The index reads return annotations and single unambiguous `return Service()` bodies from the Python AST, then seeds receiver locals through the existing local inference engine. Multi-return incompatible factories remain unseeded and do not emit partial same-name member edges. Validation: `cargo test --test usage_graph_test` passed 9 tests.

At completion, summarize which languages gained object-sensitive receiver tests, which consumers query the provider, any budget behavior observed, and any language-specific receiver semantics deferred to follow-up issues.

## Context and Orientation

The usage graph code lives under `src/analyzer/usages/`. The forward `scan_usages` path asks a per-language `UsageQueryResolver` to find references to a target symbol. The whole-workspace `usage_graph` path asks a per-language `UsageEdgeResolver` to build caller-to-callee edges. These traits are defined in `src/analyzer/usages/traits.rs`.

The result type used by graph strategies is `GraphUsageOutcome` in `src/analyzer/usages/outcome.rs`. It distinguishes resolved results from fallback-safe failures. A fallback-safe failure tells callers that the graph strategy could not prove a result and that other strategies may try. For #394, ambiguous, unsupported, or budget-exceeded receiver facts must not silently become partial graph edges.

The #393 vocabulary lives in `src/analyzer/usages/receiver_facts.rs`. It defines concepts such as receiver origin and receiver resolution, but it is intentionally not a provider. #394 should add a new internal provider module next to it, not overload the vocabulary-only module.

The existing helper `src/analyzer/usages/local_inference.rs` already provides a small bounded local binding engine with `Precise`, `Ambiguous`, and `Unknown` outcomes. #394 should reuse the same style and semantics where practical, but should expose receiver/value-specific types because this issue needs object values, call summaries, budgets, and unsupported/budget states.

In this plan, “object-sensitive” means that a receiver can be identified by the abstract object or allocation site that produced it, not only by a variable name. For example, if `makeService()` returns `new Service()`, a later `s.run()` where `s = makeService()` can resolve to `Service.run`. “Bounded” means the analysis stops after configured limits and returns `ExceededBudget` rather than continuing indefinitely. “Demand-driven” means the provider runs when a resolver asks a receiver question; it is not a mandatory whole-workspace prepass.

## Plan of Work

First, add `src/analyzer/usages/receiver_analysis.rs`. Define `ReceiverAnalysisOutcome<T>`, `ReceiverValue`, `ReceiverAnalysisBudget`, `ReceiverAnalysisQuery`, `ReceiverSummaryQuery`, `ReceiverAnalysisCacheKey`, and `ReceiverFactProvider`. Provide `NoopReceiverFactProvider` for languages that have not yet implemented a milestone. Add small unit tests proving that bounded collection returns `Precise` under the target cap, `Ambiguous` when incompatible targets exceed the cap, and `ExceededBudget` when a budget counter is exhausted.

Second, re-export the new module internally from `src/analyzer/usages/mod.rs`. Do not make it public API outside the crate. The provider should use existing repository types such as `CodeUnit`, `ProjectFile`, and `Language`, but should not require concrete language analyzers in the shared trait.

Third, wire the provider into JS/TS. Start with the simplest structurally proven forms: `new Service()`, a factory function or method that returns `new Service()`, a local binding assigned from that factory, and a member call on that local. Use a small per-file or per-scope cache keyed by file, byte range or scope id, receiver text, member name, and budget class. In the usage graph path, a precise `Service` receiver should produce only `Service.run`. An ambiguous or budget-exceeded receiver must not produce an `Other.run` edge by same-name fallback. In the second consumer, use the same facts from `get_definition` or type lookup for a matching fixture.

Fourth, repeat the same pattern as a narrow milestone for every other usage-graph backend. Each language milestone should keep the first implementation small: constructor allocation, simple factory return summary, local binding from the factory, and same-name ambiguity refusal. Use each language’s existing usage graph test file unless there is no suitable file, in which case create a focused test next to the closest existing graph test.

Fifth, add explicit budget and performance tests. The test must be able to force `ExceededBudget` with a tiny budget without relying on wall-clock time. Add a fanout test proving more than four incompatible receiver targets becomes `Ambiguous` or `ExceededBudget`. Add `profiling::scope` labels around provider queries and summary building. If a diagnostic or counter surface already exists for graph failures, use it; otherwise, keep budget evidence in tests and profiling labels rather than adding user-visible response fields in this issue.

Finally, run all focused language tests, `cargo fmt`, `cargo clippy-no-cuda`, and `git diff --check`. Optionally run `usagebench` against the exact working tree to monitor recall and precision movement; record the report metadata and any notable improvements or regressions in this document.

## Concrete Steps

From `/Users/dave/.codex/worktrees/a8df/bifrost`:

1. Confirm the branch and sync before implementation:

       git status --short --branch
       git fetch
       git rebase

2. Create this ExecPlan and commit it alone:

       git add .agent/ISSUE_394_OBJECT_SENSITIVE_RECEIVER_EXECPLAN.md
       git commit -m "Add issue 394 object-sensitive receiver execplan"

3. Shared API milestone:

       cargo test --lib receiver_analysis

   If Cargo cannot filter the module by that exact name, run the nearest focused library test filter that includes the new module tests:

       cargo test --lib receiver

4. JS/TS milestone:

       cargo test --test usages_js_ts_graph_test
       cargo test --test usage_graph_ts_test
       cargo test --test get_definition_test <new_js_ts_filter>

5. Per-language milestones:

       cargo test --test usage_graph_java_test
       cargo test --test usage_graph_csharp_test
       cargo test --test usage_graph_cpp_test
       cargo test --test usage_graph_go_test
       cargo test --test usage_graph_php_test
       cargo test --test usage_graph_test <new_python_filter>
       cargo test --test usages_ruby_test <new_ruby_filter>
       cargo test --test usage_graph_rust_test
       cargo test --test usage_graph_scala_test

6. Budget and performance milestone:

       cargo test --lib receiver_analysis_budget
       cargo test --test <language_test_with_budget_fixture>

   Existing ignored memory tests may be run for measurement only:

       cargo test --test measure_jsts_usage_graph_memory -- --ignored --nocapture
       cargo test --test measure_python_usage_graph_memory -- --ignored --nocapture
       cargo test --test measure_go_usage_graph_memory -- --ignored --nocapture

7. Final validation:

       cargo fmt
       cargo clippy-no-cuda
       git diff --check

Commit after every completed milestone, staging only files changed for that milestone.

## Validation and Acceptance

Acceptance is behavioral. For each target language, a focused usage graph test must prove that a receiver produced by a simple constructor or factory summary creates an edge to the correct owner method and not to a same-name method on an unrelated class.

For each target language, a focused ambiguity or unsupported-receiver test must prove that the graph does not emit a partial name-only edge when the receiver has several incompatible possible object values or when the syntax is outside the milestone’s supported model.

For JS/TS, at least one `get_definition` or type-lookup test must use the same provider facts as the usage graph fixture. This proves the provider is composable and not only a graph-path helper.

Budget acceptance requires a deterministic tiny-budget test that returns `ExceededBudget` and emits no partial graph edge. Fanout acceptance requires a test where more than four incompatible possible receiver targets is reported as `Ambiguous` or budget-exceeded instead of choosing one.

Final validation passes when all focused tests listed in the concrete steps pass, `cargo fmt` makes no remaining changes, `cargo clippy-no-cuda` passes, and `git diff --check` reports no whitespace errors.

## Idempotence and Recovery

All implementation steps are additive and test-backed. If a language-specific milestone becomes too broad, keep the shared API and completed prior milestones, then mark that language outcome as `Unsupported` or `Unknown` behind the provider until a narrower follow-up can implement it. Do not add regex or source-text mini parsers to make a receiver case pass.

If a provider query risks returning a partial edge, prefer `Ambiguous`, `Unknown`, `Unsupported`, or `ExceededBudget`. A missing edge is acceptable for unsupported receiver shapes; a false edge to the wrong same-name member is not.

Do not create or switch branches. Do not rebase after implementation starts unless explicitly asked or unless reconciling with the current branch before the first code change. Stage and commit only milestone files.

## Interfaces and Dependencies

Add `src/analyzer/usages/receiver_analysis.rs` with these internal interfaces:

    pub(crate) const DEFAULT_RECEIVER_CONTEXT_DEPTH: usize = 1;
    pub(crate) const DEFAULT_RECEIVER_MAX_TARGETS: usize = 4;
    pub(crate) const DEFAULT_RECEIVER_MAX_SUMMARY_EXPANSIONS: usize = 64;
    pub(crate) const DEFAULT_RECEIVER_MAX_SCOPE_NODES: usize = 20_000;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum ReceiverAnalysisOutcome<T> {
        Precise(Vec<T>),
        Ambiguous(Vec<T>),
        Unknown,
        Unsupported { reason: &'static str },
        ExceededBudget { limit: &'static str },
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub(crate) enum ReceiverValue {
        InstanceType(CodeUnit),
        ClassOrStaticObject(CodeUnit),
        ModuleOrExportObject(CodeUnit),
        CurrentReceiver(CodeUnit),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct ReceiverAnalysisBudget {
        pub context_depth: usize,
        pub max_targets: usize,
        pub max_summary_expansions: usize,
        pub max_scope_nodes: usize,
    }

    pub(crate) trait ReceiverFactProvider {
        fn resolve_receiver(&self, query: ReceiverAnalysisQuery<'_>) -> ReceiverAnalysisOutcome<ReceiverValue>;
        fn summarize_call_result(&self, query: ReceiverSummaryQuery<'_>) -> ReceiverAnalysisOutcome<ReceiverValue>;
    }

The exact fields of `ReceiverAnalysisQuery`, `ReceiverSummaryQuery`, and `ReceiverAnalysisCacheKey` should include the current file, source text or parsed tree handle where needed, receiver expression text or byte range, optional member name, language, context depth, and budget. Keep them small enough to cache without cloning full source text or parse trees.

Language implementations may use existing helpers in their graph and get-definition modules, but shared outcome handling must stay in `receiver_analysis.rs`. The provider must not expose public crate API in this issue.

## Artifacts and Notes

Reference issues: #394 and #393. #394 depends on the receiver/fact vocabulary and usage-hit surface contracts from #393.

Revision note 2026-07-01 / Codex: initial ExecPlan created from the user-approved implementation plan. It locks the language scope to every current usage-graph backend and treats JS/TS as one shared milestone.
