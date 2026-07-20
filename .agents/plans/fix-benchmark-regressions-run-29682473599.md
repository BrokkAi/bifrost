# Restore fmt definition resolution and Python dead-code performance

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The scheduled benchmark at GitHub Actions run `29682473599` exposed two independent regressions. A C++ call inside fmt's `base.h` no longer resolves `detail::vformat_to`, and a one-symbol Python dead-code query on Click became several times slower. After this work, the pinned fmt query must again return the indexed `detail.vformat_to` definition, the Click dead-code query must return the same correctness result without whole-workspace repeated resolution work, and the focused correctness suites added by the originating C++ and Python parity commits must remain green.

## Progress

- [x] (2026-07-20 10:05 SAST) Reproduced both failures at current `master`, identified introducing commits `79a0f2c5` and `7cac14b6`, and measured the Python query before and after its introducing commit.
- [x] (2026-07-20 10:10 SAST) Chose root-cause boundaries and wrote this implementation plan.
- [x] (2026-07-20 11:05 SAST) Added a minimized fmt-shaped C++ definition regression and repaired structured declaration visibility without weakening source-order or include visibility.
- [x] (2026-07-20 11:05 SAST) Validated the C++ definition suite, the originating direct-temporary parity test, and the pinned fmt benchmark probe.
- [x] (2026-07-20 11:29 SAST) Added targeted Python dead-code graph coverage and removed repeated resolution of non-candidate callees without dropping constructor keyword, call-result receiver, typed receiver, namespace, inheritance, or unproven-reference edges.
- [x] (2026-07-20 11:29 SAST) Validated the complete Python usage-graph suite, Python dead-code tests, and pinned Click probe at 226.1 ms.
- [ ] Re-run both pinned benchmark probes and the repository-wide formatting, Clippy, and `nlp,python` test gates.
- [ ] Review the completed diff, update this plan's retrospective, and commit the reviewed final state.

## Surprises & Discoveries

- Observation: The C++ tool indexes the `FMT_FUNC` definition as `detail.vformat_to`, but tree-sitter recovery flattens the earlier `FMT_API` declaration to unqualified `vformat_to` after losing the macro-opened namespace scope.
  Evidence: exact AST ancestry puts the line 2395 declaration directly under the translation unit, with a macro token in the `type` field, the displaced `void` in an `ERROR` child, and the unmatched `}` for `namespace detail` later as a direct root error node.
- Observation: Exact signature metadata survives the flattened namespace parse.
  Evidence: both the unqualified declaration and qualified definition normalize to `(int &, int, int, int)` in the minimized fixture, so the recovery can retain kind, identifier, and signature equality rather than accepting a name-only match.
- Observation: The Python slowdown is deterministic and attributable to `7cac14b6`, not runner noise.
  Evidence: the pinned Click probe measured 183.3 ms at `7cac14b6^` and 5,286.5 ms at current `master` on the same machine; CI measured 2,076.7 ms versus 13,458.6 ms.
- Observation: Dead-code analysis needs every declaration as a possible caller, but it only consumes inbound edges for the bounded candidate list.
  Evidence: `EdgeCollector` rejects callers outside `nodes`, while `incoming_usage_by_callee` is queried only for `candidates`; using the complete node domain as the resolution target set forced expensive Python member resolution for unrelated callees whose edges were immediately discarded.
- Observation: Separating caller nodes from callee targets removed most of the slowdown, and moving the same terminal-name gate ahead of typed-receiver and namespace-canonicalization resolution removed the remainder.
  Evidence: the pinned Click probe improved first from 5,286.5 ms to 1,023.2 ms, then to 226.1 ms after all member-resolution paths checked the bounded target terminal set before resolving.
- Observation: The installed structured Bifrost CLI redirects linked-worktree cache storage to the primary checkout, which is read-only in this sandbox.
  Evidence: one-shot `search_symbols` failed opening `/Users/dave/Workspace/BrokkAi/bifrost/.brokk/bifrost_cache.db`; source inspection remains available directly.

## Decision Log

- Decision: Keep the C++ declaration-visibility filter introduced by `79a0f2c5` and repair the missing structured declaration/activation proof rather than bypassing visibility for fmt.
  Rationale: Removing the filter could reintroduce calls to declarations that are not yet visible or are hidden behind inactive includes. The repository requires root-cause structured fixes.
  Date/Author: 2026-07-20 / Codex
- Decision: Permit a qualified definition to use an unqualified activation declaration only when the declaration is translation-unit-level, has a macro-displaced return type, has identical kind/identifier/signature, and precedes a direct unmatched closing brace before the reference.
  Rationale: These AST facts describe the namespace-flattening recovery left by fmt without broadly equating global and namespaced symbols. A negative test keeps an ordinary global macro forward declaration from activating a later namespaced definition.
  Date/Author: 2026-07-20 / Codex
- Decision: Preserve constructor keyword-label and call-result receiver parity from `7cac14b6`; optimize the inverse builder with a bounded callee-target set and cheap terminal-name gating rather than deleting those semantics.
  Rationale: Those edges fixed real forward/inverse correctness gaps. Performance must not be recovered by losing them.
  Date/Author: 2026-07-20 / Codex
- Decision: Give the Python inverted builder separate complete `nodes` and bounded `targets` sets, while passing `nodes` for both in ordinary whole-workspace graph builds.
  Rationale: Dead-code analysis retains all declarations for caller attribution but only resolves candidate callees. Full graph APIs keep their exact behavior because their target set remains the complete graph domain.
  Date/Author: 2026-07-20 / Codex
- Decision: Prove the targeted path behaviorally with both constructor-keyword and call-result member edges plus irrelevant resolvable noise, and use the pinned benchmark for elapsed-time proof.
  Rationale: The test asserts the semantics that must survive the optimization without introducing production instrumentation or flaky wall-clock assertions; the exact Click manifest proves the real performance effect.
  Date/Author: 2026-07-20 / Codex

## Outcomes & Retrospective

Both implementation milestones are complete. The pinned fmt query resolves `detail.vformat_to` in 319.3 ms. The pinned Click dead-code query retains `Candidate symbols analyzed: 1` and improved from 5,286.5 ms to 226.1 ms locally, close to the 183.3 ms pre-regression measurement. All 67 C++ definition tests, the originating C++ direct-temporary parity test, all 92 active Python usage-graph tests, and all 10 Python dead-code tests pass. Repository-wide gates and final review remain.

## Context and Orientation

`benchmark/targets.toml` pins fmt commit `9afcd929...` and asks `get_definitions_by_location` to resolve `include/fmt/base.h:2798:11` to `detail.vformat_to`. The C++ dispatcher in `src/analyzer/usages/get_definition/cpp.rs` gathers qualified free-function candidates, filters them through `CppVisibilityIndex::declaration_visible_at`, then tries constructor and namespace-member fallbacks. `src/analyzer/usages/cpp_graph/resolver.rs` implements visibility by finding a physically visible declaration with the same kind, fully qualified name, and signature as the selected definition. Tree-sitter indexes fmt's earlier macro-decorated declaration as unqualified `vformat_to` after flattening `namespace detail`, so strict FQN equality discarded the otherwise exact activation proof and the later fallback reported an import boundary.

`benchmark/targets.toml` also pins Click commit `c480210...` and asks `report_dead_code_and_unused_abstraction_smells` about `click.core.Command.main`. `src/code_quality/dead_code_smells.rs` collects all Python declaration names as the caller graph domain and invokes the targeted Python edge builder with only bounded candidates as callees. `src/analyzer/usages/python_graph/inverted.rs` scans every Python AST, but expensive constructor, call-result, typed-receiver, hierarchy, and namespace-canonicalization resolution now runs only when the accessed terminal name belongs to a requested target. Ordinary full usage graphs pass the complete node set as both domains and retain their existing semantics.

Tests use `InlineTestProject` from `tests/common/inline_project.rs`. C++ location-resolution behavior belongs in `tests/get_definition_test.rs`; Python forward, targeted inverse, and whole-graph parity belongs in `tests/usages_python_graph_test.rs`. Any performance instrumentation added solely for tests must be bounded, resettable, and excluded from production overhead where practical.

## Plan of Work

First add a two-file inline C++ project that mirrors fmt: a header contains a macro-decorated forward declaration and a qualified call, while a second header contains the definition. Assert that the qualified call resolves to the definition. Also retain negative cases proving a later declaration, an unrelated namespace, and an unresolved external include do not resolve. Trace the declaration extractor and signature normalization used by `CppVisibilityIndex`; make macro-decorated function declarations enter the same logical redeclaration group as their definitions without inventing source-text fallbacks. If signatures differ only by declaration/definition decoration or default arguments, reconcile them through existing structured callable metadata.

After focused C++ tests pass, format, inspect the milestone diff, update this plan, and commit only the plan plus C++ files.

Next add Python coverage that contains irrelevant keyword arguments and call-result attributes alongside the exact constructor keyword and call-result receiver cases fixed by `7cac14b6`. Change `build_python_edges` so dead-code analysis retains the complete caller node domain but resolves only bounded candidate callees, and ensure expensive constructor, return-type, hierarchy, typed-receiver, and namespace-canonicalization work happens only when the member name can map to a requested target. The result must still produce exact targeted and whole-graph edges for subclass keyword fields, constructor-return receivers, imported aliases, and conditional bindings.

After focused Python tests pass, format, inspect the milestone diff, update this plan, and commit only the plan plus Python files. Finally build release benchmark binaries, run one-repository pinned fmt and Click probes, then execute Clippy and the full feature-enabled test suite.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/d013/bifrost`.

For C++ development, run:

    cargo test --test get_definition_test cpp_ -- --nocapture
    cargo test --test usages_cpp_graph_test -- --nocapture

For Python development, run:

    cargo test --test usages_python_graph_test -- --nocapture
    cargo test --test get_definition_test python_ -- --nocapture

For pinned end-to-end validation, build both release binaries and run narrow manifests derived from `benchmark/targets.toml` against the pinned fmt and Click repositories. The fmt result must be `resolved`; the Click report must contain `Candidate symbols analyzed: 1` and show a large reduction from the reproduced 5.3-second local current-head query.

For final repository gates, run:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    git diff --check

## Validation and Acceptance

The C++ milestone is accepted when the new fmt-shaped inline test fails on `b20da06f`, passes after the structured fix, and the existing C++ definition and usage-graph suites pass without weakening import/source-order negatives.

The Python milestone is accepted when all parity cases from `tests/usages_python_graph_test.rs` continue to pass, the targeted dead-code test proves constructor-keyword and call-result receiver edges survive alongside irrelevant resolvable syntax, and the pinned Click query retains its report while materially improving from the 5,286.5 ms reproduced current-head measurement.

The entire plan is accepted when both pinned probes pass, formatting and Clippy are clean, the complete `cargo test --features nlp,python` gate passes, and `git status` contains only intentional committed work.

## Idempotence and Recovery

All tests use temporary inline projects and may be repeated safely. Pinned benchmark clones are read-only inputs; reuse their caches rather than deleting them. Release builds write only normal ignored `target/` artifacts. If an isolated Cargo target command fails, the helper removes its managed directory automatically. Do not delete the shared primary-checkout `.brokk/bifrost_cache.db` to work around the linked-worktree cache issue.

## Artifacts and Notes

The failing workflow is `https://github.com/BrokkAi/bifrost/actions/runs/29682473599`, head `f40289de`. Its compare report recorded:

    click-py dead_code_smells: 2,076.7 ms -> 13,458.6 ms
    fmt-cpp get_definition: resolved -> unresolvable_import_boundary

Current `master` at `b20da06f` reproduces both. The narrow local Python comparison was:

    7cac14b6^: 183.3 ms
    b20da06f: 5,286.5 ms

## Interfaces and Dependencies

Do not add dependencies. Preserve `CppVisibilityIndex::declaration_visible_at` as the source-order/include activation boundary. Preserve the `UsageEdgeBuildOutput` abstraction and the public Python usage APIs. Any new cache should be local to one `build_python_edges` invocation or one parsed-file scan and keyed by structured AST-derived identities, not source substrings.

Revision note (2026-07-20): Created the plan after reproducing run `29682473599`, attributing each regression to an introducing commit, and choosing structured root-cause fixes that retain the correctness intent of those commits.
