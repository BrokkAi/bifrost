# Reach Python Usage Graph Parity With Brokk

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

After this work, `bifrost` will be able to answer Python usage queries with the same broad behavior that Brokk already proves in its Java test suite: graph-first routing for eligible Python targets, correct import and re-export traversal, member-usage inference from receiver types, and stable behavior around shadowing, ambiguity, inheritance, and cache invalidation. A user should be able to run focused Rust usage tests and see Python scenarios that are currently only covered in Brokk pass in `bifrost` as well.

The immediate outcome is not one code patch. It is a durable implementation program that starts with finishing issue `#74` and then tracks the remaining stages needed to reach practical parity in functionality and unit-test coverage.

## Progress

- [x] (2026-05-18T11:30Z) Read `.agent/PLANS.md`, `src/usages/graph_core.rs`, `src/usages/python_graph.rs`, `src/usages/finder.rs`, `tests/usages_python_test.rs`, `tests/common/inline_project.rs`, and Brokk’s Python usage-graph strategy/reference-graph tests.
- [x] (2026-05-18T11:30Z) Chose a new repo-root plan name, `PYTHON_USAGE_GRAPH_PARITY_EXECPLAN.md`, because this document is intentionally broader than issue `#74`.
- [x] (2026-05-18T11:30Z) Captured the current `bifrost` baseline: Python is already routed through `PythonExportUsageGraphStrategy`, but Rust-side coverage is still shallow compared with Brokk’s strategy and reference-graph suites.
- [x] (2026-05-18T12:05Z) Completed Milestone 1 by expanding the focused Python graph suite for `UsageFinder` routing, `MultiAnalyzer` routing, `TooManyCallsites`, and same-file regex fallback, then fixing `PythonExportUsageGraphStrategy` so it can resolve a `PythonAnalyzer` out of `MultiAnalyzer` instead of silently dropping to regex.
- [x] (2026-05-18T12:35Z) Completed Milestone 2 by porting nested `__init__.py` barrels, dotted namespace imports, dotted namespace aliases, package-imported submodule qualifiers, relative submodule qualifiers, and wildcard-barrel cases into `tests/usages_python_graph_test.rs`, then fixing Python import binding and re-export seeding so those cases route through the graph successfully.
- [ ] Implement Milestone 3 by porting Python receiver/member inference cases from Brokk into focused Rust tests and then fixing any uncovered inference gaps.
- [ ] Implement Milestone 4 by porting Python negative and ambiguity cases from Brokk into focused Rust tests and then fixing any uncovered false-positive or fallback gaps.
- [ ] Implement Milestone 5 by porting Python inheritance and cache/update cases from Brokk into focused Rust tests and then fixing any uncovered hierarchy or invalidation gaps.
- [ ] Complete Milestone 6 by reviewing residual Brokk Python usage tests, marking each as `done`, `missing`, `different by design`, or `deferred`, and recording the reason.

## Surprises & Discoveries

- Observation: issue `#74` is no longer a greenfield feature request in this worktree; the shared usage-graph core from issue `#73`, `src/usages/python_graph.rs`, and Python routing in `src/usages/finder.rs` already exist.
  Evidence: `src/usages/mod.rs` exports `PythonExportUsageGraphStrategy`, and `src/usages/finder.rs` already installs it for `Language::Python`.

- Observation: `bifrost` currently proves only a narrow slice of Python usage-graph behavior.
  Evidence: `tests/usages_python_test.rs` currently contains a small set of coverage around regex usage, default routing, one positive graph case, one missing-seed case, and generic search-pattern checks.

- Observation: Brokk’s parity target is much broader than the current Rust suite and is split into two meaningful layers.
  Evidence: `/Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/test/java/ai/brokk/analyzer/usages/PythonExportUsageGraphStrategyTest.java` covers selector/routing behavior, while `PythonExportUsageReferenceGraphTest.java` covers many import, receiver, inheritance, and cache scenarios.

- Observation: the shared inline harness in `tests/common/inline_project.rs` is already the right default for this plan.
  Evidence: it builds ad hoc temporary test projects with inferred or explicit language selection and removes the need for hand-managed tempdirs in most small Python graph cases.

- Observation: `PythonExportUsageGraphStrategy` originally only worked when the caller passed a concrete `PythonAnalyzer`.
  Evidence: a new focused `MultiAnalyzer` routing test initially returned two regex hits instead of one graph-proven hit, because `src/usages/python_graph.rs` downcast directly to `PythonAnalyzer` and therefore forced `UsageFinder` to fall back on `Failure`.

- Observation: several Python import topologies were already parseable by the analyzer but were not being expressed in the usage graph with the right shape.
  Evidence: Milestone 2 tests for `from pkg import timestamps`, `from . import service`, `from .. import service`, and `from .service import *` initially failed because `import_binder_of` treated submodule imports as named symbol imports and `export_index_of` ignored wildcard re-export edges.

## Decision Log

- Decision: make this a broader parity program document instead of `ISSUE_74_EXECPLAN.md`.
  Rationale: the user asked for one place to track the full staged path to Brokk-level Python parity, and later milestones intentionally extend beyond issue `#74`.
  Date/Author: 2026-05-18 / Codex

- Decision: define parity by observable `bifrost` behavior and focused Rust tests, not by mechanically mirroring Brokk’s Java class structure.
  Rationale: `bifrost` and Brokk share concepts but not implementation language or exact file layout; the stable contract is testable behavior.
  Date/Author: 2026-05-18 / Codex

- Decision: prefer `tests/common/inline_project.rs` for new Python usage-graph tests unless a case truly needs a reusable fixture tree or unusual filesystem behavior.
  Rationale: the inline harness keeps tests small, local, and easy to read while matching the repo guidance in `AGENTS.md`.
  Date/Author: 2026-05-18 / Codex

- Decision: treat typed-parameter receiver inference as Milestone 3 work even though it was uncovered while expanding Milestone 1 coverage.
  Rationale: the failure required receiver-type reasoning rather than strategy-selection logic, so keeping it in the later milestone preserves the milestone boundaries and keeps the first checkpoint narrowly about routing and fallback behavior.
  Date/Author: 2026-05-18 / Codex

- Decision: model `from ... import submodule` bindings as namespace imports when the imported name resolves to a Python module code unit.
  Rationale: later attribute access such as `timestamps.MonotonicTimestampGenerator()` or `service.Service()` is namespace-style usage of a module object, and the graph scanner already knows how to prove namespace attribute hits.
  Date/Author: 2026-05-18 / Codex

- Decision: record Python wildcard re-exports in `ExportIndex.reexport_stars` instead of silently discarding them.
  Rationale: `from .service import *` is an actual graph edge used by Brokk’s package-barrel tests, so skipping it prevents valid re-export seeds from ever being discovered.
  Date/Author: 2026-05-18 / Codex

## Outcomes & Retrospective

At the moment this plan is created, `bifrost` has already crossed the architecture threshold for Python usage graphs: the shared graph core from issue `#73` exists, Python routing is enabled, and a Python graph strategy is present. Milestone 1 converted that architecture into stronger proof by covering graph routing, fallback behavior, bounded-candidate behavior, and `MultiAnalyzer` routing with focused Rust tests. Milestone 2 then closed the first substantial functionality gaps by teaching the graph about namespace-style submodule imports and wildcard re-export stars, which in turn unlocked Brokk-style barrel and submodule-qualifier cases. What is still missing is the larger parity tail around receiver inference, negative ambiguity control, inheritance, and cache invalidation.

This plan turns that gap into a staged implementation program. Success is not “Python has a graph class.” Success is that a contributor can work milestone by milestone, port the representative scenarios, fix the underlying behavior where needed, and finish with a parity matrix that says exactly what has been matched and what remains intentionally different.

## Context and Orientation

`bifrost`’s usage-finding subsystem lives under `src/usages/`. A “usage graph” in this repository means a graph-based path that starts from a target export, follows imports and re-exports across files, and scans only the narrowed file set for proven usages. The shared language-neutral graph bookkeeping extracted in issue `#73` now lives in `src/usages/graph_core.rs`.

Python-specific graph behavior lives in `src/usages/python_graph.rs`. That file builds the Python project graph, infers export seeds for top-level and member targets, resolves Python modules, and scans syntax trees for matching identifier and attribute usages. Public routing happens in `src/usages/finder.rs`, where `UsageFinder` chooses `PythonExportUsageGraphStrategy` for Python targets before falling back to `RegexUsageAnalyzer` when the graph cannot seed a query.

The current Rust-side proof is shallow. `tests/usages_python_test.rs` confirms that regex still works, that default `UsageFinder` routing returns results, that one positive graph case succeeds, and that one unresolved seed case returns failure at the strategy layer. It does not yet provide Brokk-level confidence around import chains, member inference, negative cases, inheritance, or update invalidation.

Brokk is the reference implementation for target behavior. The most relevant files are:

    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/PythonExportUsageGraphStrategy.java
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/test/java/ai/brokk/analyzer/usages/PythonExportUsageGraphStrategyTest.java
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/test/java/ai/brokk/analyzer/usages/PythonExportUsageReferenceGraphTest.java

The first Java test file is the narrow strategy/routing suite. The second is the broad reference-graph suite that defines most of the remaining parity backlog.

## Plan of Work

Start by finishing issue `#74` as a behavior-complete milestone instead of treating the current merged code as done. Expand `tests/usages_python_test.rs` or split out a new focused Rust test file if that keeps the suite clearer. The tests added in this milestone must prove the graph is selected for seeded exports, that member targets can seed from owner exports, that graph-first behavior still returns hits for Python imports, and that fallback boundaries are correct when a same-file function or another unseeded target cannot be proven from export seeds alone.

Next, port Brokk’s Python import and re-export coverage into Rust. The required scenarios are absolute imports, relative imports, package barrels through `__init__.py`, nested barrel chains, dotted namespace imports, dotted alias imports, imported submodule qualifiers, and import cycles that terminate without inventing hits. Keep these tests small and inline unless a nested package tree becomes too noisy to express without a dedicated fixture.

Then, port receiver/member inference coverage. This means adding tests for typed local variables, typed parameters, typed instance attributes, constructor-based receiver inference, simple aliases, and namespace-qualified annotation forms. The goal is to prove that member queries such as `Foo.bar` find only receivers that can actually be tied back to the target export, not every same-named attribute in the candidate files.

After that, port negative and ambiguity cases. Add tests proving that local shadowing blocks imported-name matches, that unknown constructors and unrelated same-name classes do not count as receiver evidence, that ambiguity caps do not create false positives, and that a graph path that successfully proves “zero hits” does not accidentally fall back to regex and fabricate text matches. This milestone is where false-positive control becomes explicit rather than incidental.

Then, port inheritance and cache/update cases. Add tests for inherited-member matches across local and cross-file hierarchies, override behavior between base and subclass queries, changed-file invalidation, and export-resolution cache invalidation after re-export changes. These tests should drive any changes needed in Python graph caching or hierarchy handling.

Finish by reviewing the remaining Brokk Python usage-graph tests line by line and recording them in the parity matrix below. No scenario should disappear silently. Every Brokk category must end up marked as already done in `bifrost`, missing and still to be implemented, intentionally different by design, or deferred with a concrete reason.

## Milestones

### Milestone 1: Finish issue `#74` core parity

At the end of this milestone, `bifrost` should prove the same core strategy behaviors that Brokk’s `PythonExportUsageGraphStrategyTest.java` already covers. A contributor should be able to run focused Rust tests and see graph-first routing, seeded export handling, member-owner fallback, and controlled regex fallback boundaries behaving as expected.

Implement this by expanding the strategy/routing coverage around `UsageFinder` and `PythonExportUsageGraphStrategy`. Preserve the public contract that `UsageFinder` routes Python through `PythonExportUsageGraphStrategy` before regex fallback. Add or refine tests so a novice can see which cases are graph-seeded, which cases are intentionally unseeded, and which cases should still succeed because the fallback path is allowed to rescue them.

Acceptance for this milestone is that focused Python usage tests fail before the changes and pass after, while still proving the graph path is used for seeded queries instead of only proving that some result came back somehow.

### Milestone 2: Port import and re-export reference-graph coverage

At the end of this milestone, `bifrost` should be able to prove Python usage hits through common import and re-export topologies rather than only direct one-hop imports. That includes `from module import Name`, relative package imports, `__init__.py` barrel exports, nested barrel chains, dotted namespace imports, and cycle-safe traversal.

Implement this by porting the representative cases from Brokk’s reference-graph suite into Rust, favoring the inline harness. If a scenario exposes a real graph-resolution gap in `src/usages/python_graph.rs`, fix the code only after a focused failing test exists.

Acceptance is that each added scenario has a focused test that demonstrates the path from the defining module to the consuming usage and that cyclic import setups terminate without infinite traversal or invented hits.

### Milestone 3: Port receiver/member inference coverage

At the end of this milestone, member queries should work for the main receiver facts Brokk already proves: typed locals, typed parameters, instance attributes, constructor-seeded locals, aliases, and qualified annotations. The user-visible effect is that Python member usage lookups return the right call sites for the right class, not just text matches on the member name.

Implement this by porting the representative member cases from Brokk and tightening `src/usages/python_graph.rs` wherever receiver inference is too weak or too permissive.

Acceptance is that focused member tests demonstrate both positive inference and scope control, so the same member name on an unrelated receiver is not enough to count as a usage.

### Milestone 4: Port negative and ambiguity behavior

At the end of this milestone, `bifrost` should reject the main false-positive scenarios Brokk already guards against. This includes shadowing, unrelated same-name types, unknown constructors, and ambiguous type facts that should stop the graph from claiming a usage. It also includes the subtle rule that a successful graph evaluation with zero hits must remain zero hits rather than triggering regex fallback.

Implement this by adding focused negative tests first, then adjusting fallback and binding logic until those tests pass.

Acceptance is that the negative tests stay stable and specifically prove that `bifrost` is not merely finding strings in files.

### Milestone 5: Port inheritance and cache/update coverage

At the end of this milestone, Python member usage should survive common inheritance patterns and updates without stale graph state. That means inherited-member matches, override behavior, cross-file hierarchy cases, changed-file invalidation, and re-export cache invalidation all have focused Rust proof.

Implement this by porting the representative Brokk hierarchy and cache tests and then fixing any invalidation or hierarchy gaps in `bifrost`.

Acceptance is that repeated analyzer or usage runs on changed inline projects reflect the new source state, and hierarchy-aware member queries behave consistently across base and subclass relationships.

### Milestone 6: Close the residual parity matrix

At the end of this milestone, the document should be able to tell a future contributor exactly what parity work is complete and what remains. Every meaningful category from Brokk’s Python usage-graph tests must be accounted for explicitly.

Implement this by updating the parity matrix below and, if needed, appending short notes that explain why a scenario is deferred or does not apply cleanly to `bifrost`.

Acceptance is that no future contributor needs to re-scan the Brokk suite just to understand the remaining backlog.

## Concrete Steps

From `/Users/dave/.codex/worktrees/f4dc/bifrost`:

1. Keep this document updated before and after each milestone so the `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` sections reflect the true state.
2. Add or expand focused Rust tests for the current milestone. Prefer `tests/usages_python_test.rs` for small additions and a new focused test file only when the milestone becomes easier to read in its own suite.
3. Use `tests/common/inline_project.rs` for new ad hoc Python project layouts unless the scenario truly needs a reusable fixture tree.
4. After the tests for a milestone are in place, make the smallest code changes needed in `src/usages/python_graph.rs`, `src/usages/finder.rs`, or closely related modules to satisfy the new proofs.
5. Run:

       cargo fmt

6. Run the focused Python usage tests for the milestone, including:

       cargo test --test usages_python_test

   and any additional focused Python usage-graph test files added by the implementation.

7. Once the milestone’s focused tests pass, run:

       cargo fmt --check
       cargo clippy --all-targets --all-features -- -D warnings

8. Record the outcome, any surprising behavior, and the updated parity-matrix status in this document.

## Validation and Acceptance

Validation must stay behavior-focused.

For every milestone, run `cargo test --test usages_python_test` and any new focused Python usage-graph test file added for that milestone. The proof must show a specific Python usage scenario that was previously uncovered or incorrect and is now correct.

Run `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` after the milestone’s focused tests are green. These commands prove the Rust code still meets the repo’s formatting and lint expectations.

Success for this ExecPlan is not “the code compiles.” Success is that `bifrost` can demonstrate, with focused Rust tests, that it now matches Brokk’s Python usage-graph behavior across routing, imports, receiver inference, negative cases, inheritance, and update invalidation, or that the remaining differences are recorded explicitly as intentional or deferred.

## Idempotence and Recovery

This plan is safe to execute incrementally. Re-running `cargo fmt`, the focused `cargo test` commands, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings` is safe.

If a milestone stalls midway, do not skip ahead. Update `Progress` to describe exactly what is done and what remains, keep the failing focused tests in place if they represent a real uncovered behavior, and continue from the smallest remaining gap. If a test scenario turns out not to apply to `bifrost`, mark that explicitly in the parity matrix instead of deleting the record.

## Artifacts and Notes

Important local references for this plan are:

    .agent/PLANS.md
    src/usages/graph_core.rs
    src/usages/python_graph.rs
    src/usages/finder.rs
    tests/usages_python_test.rs
    tests/common/inline_project.rs
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/main/java/ai/brokk/analyzer/usages/PythonExportUsageGraphStrategy.java
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/test/java/ai/brokk/analyzer/usages/PythonExportUsageGraphStrategyTest.java
    /Users/dave/Workspace/BrokkAi/brokk/brokk-shared/src/test/java/ai/brokk/analyzer/usages/PythonExportUsageReferenceGraphTest.java

The most important current evidence snapshot is:

    `bifrost` already has Python graph routing and a Python graph strategy, but `tests/usages_python_test.rs` is still much smaller than Brokk’s combined strategy/reference-graph Python suite.

## Interfaces and Dependencies

The public behavior expected at the end of this plan is:

    `UsageFinder` continues routing Python targets through `PythonExportUsageGraphStrategy` before regex fallback;

    `PythonExportUsageGraphStrategy` remains the Python graph façade rather than exposing a new public usage-finder API;

    new Python parity tests default to `tests/common/inline_project.rs` unless a bespoke fixture tree is justified by the scenario.

The implementation dependencies for parity work are the shared usage-graph IR in `src/usages/graph_core.rs`, the Python graph adapter/scanner logic in `src/usages/python_graph.rs`, and the existing analyzer/export-index/import-binder surfaces that the Python graph already uses.

## Parity Matrix

This matrix must be kept current as milestones land.

- Strategy and routing parity: `done`
  Brokk reference: `PythonExportUsageGraphStrategyTest.java`.
  Current `bifrost` proof: focused Rust tests now cover seeded export routing, multi-analyzer compatibility, `TooManyCallsites`, and same-file regex fallback boundaries through `tests/usages_python_graph_test.rs` and `tests/usages_python_test.rs`.

- Import and re-export resolution parity: `missing`
- Import and re-export resolution parity: `done`
  Brokk reference: absolute imports, relative imports, `__init__.py` barrels, nested barrel chains, dotted namespace imports, dotted aliases, submodule qualifiers, and cycle-safe traversal in `PythonExportUsageReferenceGraphTest.java`.
  Current `bifrost` proof: focused Rust tests now cover absolute imports, relative imports, package barrels, nested `__init__.py` chains, dotted namespace imports and aliases, package-imported submodule qualifiers, relative submodule qualifiers, wildcard barrels, and cycle-safe traversal.

- Receiver/member inference parity: `missing`
  Brokk reference: typed locals, typed parameters, typed instance attributes, constructed locals, aliases, and qualified annotations in `PythonExportUsageReferenceGraphTest.java`.

- Negative and ambiguity parity: `missing`
  Brokk reference: shadowing, unknown constructors, unrelated same-name receivers, ambiguity caps, and “graph success with no hits does not fallback to regex” in `PythonExportUsageReferenceGraphTest.java`.

- Inheritance and cache/update parity: `missing`
  Brokk reference: inherited members, overrides, cross-file hierarchy cases, changed-file invalidation, and export-resolution cache invalidation in `PythonExportUsageReferenceGraphTest.java`.

- Container-flow and out-of-scope residuals: `deferred`
  Brokk reference: the container element/value flow cases in `PythonExportUsageReferenceGraphTest.java` that Brokk itself marks as intentionally out of scope for the current Python graph. `bifrost` should record these explicitly rather than silently omitting them.

Revision note: created this broader parity ExecPlan after issue `#73` had already landed and issue `#74` had partially landed, so the document starts from the real current Python graph baseline instead of pretending the work is still unstarted.

Revision note: updated after Milestone 1 to record the added routing/fallback tests and the `MultiAnalyzer` fix in `src/usages/python_graph.rs`.

Revision note: updated after Milestone 2 to record the new import/re-export parity tests plus the analyzer changes that treat imported submodules as namespace bindings and wildcard re-exports as graph edges.
