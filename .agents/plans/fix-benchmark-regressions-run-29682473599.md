# Restore fmt definition resolution and Python dead-code performance

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain this document in accordance with `.agents/PLANS.md`.

## Purpose / Big Picture

The scheduled benchmark at GitHub Actions run `29682473599` exposed two independent regressions. A C++ call inside fmt's `base.h` no longer resolves `detail::vformat_to`, and a one-symbol Python dead-code query on Click became several times slower. After this work, the pinned fmt query must again return the indexed `detail.vformat_to` definition, the Click dead-code query must return the same correctness result without whole-workspace repeated resolution work, and the focused correctness suites added by the originating C++ and Python parity commits must remain green.

## Progress

- [x] (2026-07-20 10:05 SAST) Reproduced both failures at current `master`, identified introducing commits `79a0f2c5` and `7cac14b6`, and measured the Python query before and after its introducing commit.
- [x] (2026-07-20 10:10 SAST) Chose root-cause boundaries and wrote this implementation plan.
- [x] (2026-07-20 11:05 SAST) Added a minimized fmt-shaped C++ definition regression and repaired structured declaration visibility without weakening source-order or include visibility.
- [x] (2026-07-20 11:05 SAST) Validated the C++ definition suite, the originating direct-temporary parity test, and the pinned fmt benchmark probe.
- [ ] Add deterministic Python work/correctness coverage and remove repeated whole-graph resolution work without dropping constructor keyword or call-result receiver edges.
- [ ] Validate and checkpoint the Python milestone.
- [ ] Re-run both pinned benchmark probes and the repository-wide formatting, Clippy, and `nlp,python` test gates.
- [ ] Review the completed diff, update this plan's retrospective, and commit the reviewed final state.

## Surprises & Discoveries

- Observation: The C++ tool indexes the `FMT_FUNC` definition as `detail.vformat_to`, but tree-sitter recovery flattens the earlier `FMT_API` declaration to unqualified `vformat_to` after losing the macro-opened namespace scope.
  Evidence: exact AST ancestry puts the line 2395 declaration directly under the translation unit, with a macro token in the `type` field, the displaced `void` in an `ERROR` child, and the unmatched `}` for `namespace detail` later as a direct root error node.
- Observation: Exact signature metadata survives the flattened namespace parse.
  Evidence: both the unqualified declaration and qualified definition normalize to `(int &, int, int, int)` in the minimized fixture, so the recovery can retain kind, identifier, and signature equality rather than accepting a name-only match.
- Observation: The Python slowdown is deterministic and attributable to `7cac14b6`, not runner noise.
  Evidence: the pinned Click probe measured 183.3 ms at `7cac14b6^` and 5,286.5 ms at current `master` on the same machine; CI measured 2,076.7 ms versus 13,458.6 ms.
- Observation: The installed structured Bifrost CLI redirects linked-worktree cache storage to the primary checkout, which is read-only in this sandbox.
  Evidence: one-shot `search_symbols` failed opening `/Users/dave/Workspace/BrokkAi/bifrost/.brokk/bifrost_cache.db`; source inspection remains available directly.

## Decision Log

- Decision: Keep the C++ declaration-visibility filter introduced by `79a0f2c5` and repair the missing structured declaration/activation proof rather than bypassing visibility for fmt.
  Rationale: Removing the filter could reintroduce calls to declarations that are not yet visible or are hidden behind inactive includes. The repository requires root-cause structured fixes.
  Date/Author: 2026-07-20 / Codex
- Decision: Permit a qualified definition to use an unqualified activation declaration only when the declaration is translation-unit-level, has a macro-displaced return type, has identical kind/identifier/signature, and precedes a direct unmatched closing brace before the reference.
  Rationale: These AST facts describe the namespace-flattening recovery left by fmt without broadly equating global and namespaced symbols. A negative test keeps an ordinary global macro forward declaration from activating a later namespaced definition.
  Date/Author: 2026-07-20 / Codex
- Decision: Preserve constructor keyword-label and call-result receiver parity from `7cac14b6`; optimize the inverse builder with cheap target gating and shared per-file resolution state rather than deleting those semantics.
  Rationale: Those edges fixed real forward/inverse correctness gaps. Performance must not be recovered by losing them.
  Date/Author: 2026-07-20 / Codex
- Decision: Use deterministic work-count or cache-identity assertions for the Python regression and retain the external pinned benchmark as the end-to-end latency proof.
  Rationale: Wall-clock unit tests are flaky across CI hosts; bounded structured work is stable while the benchmark supplies real elapsed time.
  Date/Author: 2026-07-20 / Codex

## Outcomes & Retrospective

The C++ milestone is complete. The pinned fmt query now resolves `detail.vformat_to` in 319.3 ms, all 67 C++ definition tests pass, and the originating direct-temporary inverse/forward parity test remains green. Python performance work remains in progress.

## Context and Orientation

`benchmark/targets.toml` pins fmt commit `9afcd929...` and asks `get_definitions_by_location` to resolve `include/fmt/base.h:2798:11` to `detail.vformat_to`. The C++ dispatcher in `src/analyzer/usages/get_definition/cpp.rs` gathers qualified free-function candidates, filters them through `CppVisibilityIndex::declaration_visible_at`, then tries constructor and namespace-member fallbacks. `src/analyzer/usages/cpp_graph/resolver.rs` implements visibility by finding a physically visible declaration with the same kind, fully qualified name, and signature as the selected definition. Tree-sitter indexes fmt's earlier macro-decorated declaration as unqualified `vformat_to` after flattening `namespace detail`, so strict FQN equality discarded the otherwise exact activation proof and the later fallback reported an import boundary.

`benchmark/targets.toml` also pins Click commit `c480210...` and asks `report_dead_code_and_unused_abstraction_smells` about `click.core.Command.main`. `src/code_quality/dead_code_smells.rs` collects all Python declaration names and invokes `build_python_usage_edges`. `src/analyzer/usages/python_graph/inverted.rs` then scans every Python AST. Commit `7cac14b6` added structured constructor keyword and call-result receiver resolution inside that scan. Those operations currently run before a cheap proof that the accessed member name could match a requested graph node, causing repeated global definition and hierarchy queries for irrelevant syntax.

Tests use `InlineTestProject` from `tests/common/inline_project.rs`. C++ location-resolution behavior belongs in `tests/get_definition_test.rs`; Python forward, targeted inverse, and whole-graph parity belongs in `tests/usages_python_graph_test.rs`. Any performance instrumentation added solely for tests must be bounded, resettable, and excluded from production overhead where practical.

## Plan of Work

First add a two-file inline C++ project that mirrors fmt: a header contains a macro-decorated forward declaration and a qualified call, while a second header contains the definition. Assert that the qualified call resolves to the definition. Also retain negative cases proving a later declaration, an unrelated namespace, and an unresolved external include do not resolve. Trace the declaration extractor and signature normalization used by `CppVisibilityIndex`; make macro-decorated function declarations enter the same logical redeclaration group as their definitions without inventing source-text fallbacks. If signatures differ only by declaration/definition decoration or default arguments, reconcile them through existing structured callable metadata.

After focused C++ tests pass, format, inspect the milestone diff, update this plan, and commit only the plan plus C++ files.

Next add Python coverage that contains many irrelevant keyword arguments and call-result attributes alongside the exact constructor keyword and call-result receiver cases fixed by `7cac14b6`. Expose or reuse a deterministic test work counter if needed. Change `build_python_edges` so expensive constructor, return-type, and hierarchy resolution happens only when the member name can map to at least one requested node, and memoize repeated resolution within one file scan. The result must still produce exact targeted and whole-graph edges for subclass keyword fields, constructor-return receivers, imported aliases, and conditional bindings.

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

The Python milestone is accepted when all parity cases from `tests/usages_python_graph_test.rs` continue to pass, the new deterministic bounded-work test proves irrelevant syntax does not trigger expensive resolution, and the pinned Click query retains its report while materially improving from the 5,286.5 ms reproduced current-head measurement.

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
