# Preserve nested semantic access paths

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Java and TypeScript already lower a nested expression such as `box.next.next.value` into structured semantic memory loads, but the workspace value-flow oracle currently projects only the final load or store row. Public and direct value-flow clients therefore see a temporary value as the access-path root and only the final field as a selector. They cannot apply the configured access-path length bound to the full chain or distinguish exact sibling paths reliably.

After this change, the oracle will reconstruct the full structured receiver chain from the existing semantic IR without reparsing source. With the default access-path limit of eight selectors, a nine-selector field path will retain root `box`, the first eight selectors, and a summary tail. The direct and public Java and TypeScript conformance tests will demonstrate the behavior, including the stable public carrier's `exact: false` marker.

## Progress

- [x] (2026-08-01 07:45Z) Verified issue #1407, the clean attached issue branch, and current `origin/master` baseline.
- [x] (2026-08-01 07:45Z) Diagnosed the shared oracle projection as the information-loss boundary and approved the implementation plan.
- [ ] Implement a procedure-local load-result index and iterative access-path composition in the workspace value-flow oracle.
- [ ] Add conservative ambiguity and cycle behavior plus semantic-work and cancellation accounting.
- [ ] Activate the four existing Java and TypeScript readiness probes and add focused near-miss coverage where the shared scenarios do not already prove it.
- [ ] Run focused and broad Rust validation, the required policy selection, and specialist review.

## Surprises & Discoveries

- Observation: The Java and TypeScript adapters already preserve every receiver step as a structured `MemoryLoad`; the loss occurs later when `abstract_location` projects one `MemoryLocationKind` row in isolation.
  Evidence: `crates/bifrost-analysis/src/analyzer/java/semantic/control.rs` and `crates/bifrost-analysis/src/analyzer/js_ts/semantic/control.rs` emit successive field/index loads, while `crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/value_flow.rs::abstract_location` always creates a value root plus at most one selector.

- Observation: The existing readiness fixtures already encode the exact desired root, eight retained `next` selectors, and a non-exact public carrier.
  Evidence: `tests/common/value_flow_scenarios.rs::with_over_bound_field_access_flow` supplies those milestones to ignored tests in `tests/suite_semantic/value_flow_language_conformance.rs` and `tests/suite_cross_language/code_query_value_flow.rs`.

- Observation: Parallel and usage-scan Bifrost MCP calls exceeded their request budgets during diagnosis, independently of #1407.
  Evidence: Open issue #1419 owns the parallel-call family; focused rmcp `scan_usages_by_location` evidence was filed separately as #1434. Exact sequential symbol reads remained responsive and the implementation diagnosis did not rely on the failed calls.

## Decision Log

- Decision: Compose access paths at the neutral workspace-oracle boundary rather than changing Java and TypeScript syntax lowering or extending semantic IR.
  Rationale: The validated IR already contains the structured load-result chain. Reusing it fixes every producer with the same representation and avoids duplicating parser-specific path logic.
  Date/Author: 2026-08-01 / Codex

- Decision: Follow only a unique load origin for a base value, use an iterative visited set, and mark unresolved ambiguity or cycles as a summary tail.
  Rationale: Exactness must never be invented when a value has conflicting origins, and semantic traversals must remain stack-safe and terminating.
  Date/Author: 2026-08-01 / Codex

- Decision: Keep selector retention bounded while continuing inward until the original root is known.
  Rationale: For an over-bound chain, stopping when the selector budget is reached would leave an intermediate temporary as the root. Traversal must find `box` while retaining only the root-nearest selectors required by `OracleLimits::access_path_length`.
  Date/Author: 2026-08-01 / Codex

## Outcomes & Retrospective

Implementation has not started. The intended outcome is a shared structured fix with no source-text parsing, no Java/TypeScript-specific path walker, and direct/public conformance proving the exact bounded carrier shape.

## Context and Orientation

The language adapters under `crates/bifrost-analysis/src/analyzer/java/semantic/` and `crates/bifrost-analysis/src/analyzer/js_ts/semantic/` lower parsed syntax into a language-neutral semantic intermediate representation (IR). A `MemoryLocationKind::Field` stores a base `ValueId` and a structured field locator; an index location stores a base and an optional structured index value. A `SemanticEffect::MemoryLoad` associates a memory location with its result value, so nested receiver expressions form a def-use chain: the result of one load is the base of the next location.

`crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/value_flow.rs` converts validated IR events into neutral `ValueFlowRelation` records. Its `abstract_location` function currently handles one memory-location row, producing an `AccessPathRoot::Value(base)` and one selector. `AccessPath::bounded` in `crates/bifrost-analysis/src/analyzer/semantic/oracle/model.rs` already performs correct truncation and changes an over-bound path's `AccessPathTail` from `Exact` to `Summary`. `ValueFlowCarrier::stable_key` in `crates/bifrost-analysis/src/analyzer/value_flow/model.rs` already preserves the resulting root, selector sequence, and exactness.

The shared scenario builder in `tests/common/value_flow_scenarios.rs` runs equivalent Java and TypeScript fixtures through direct semantic value-flow and public CodeQuery/RQL adapters. The two direct tests and two public tests for #1407 are currently ignored readiness probes. Their expected carrier is root `box`, eight `next` field selectors, and `exact: false` for the nine-selector path ending in `value`.

## Plan of Work

First, modify `crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/value_flow.rs`. Build a procedure-local index from every `SemanticEffect::MemoryLoad` result to its memory location. Repeated events naming the same result and same location remain a unique origin; conflicting locations make the result ambiguous. Check cancellation while walking procedure points and events.

Replace the one-row field/index projection in `abstract_location` with an iterative resolver that accepts this index. Starting from the requested location, collect its structured selector and inspect its base value. If that value has one load origin, continue through that location. Stop at a value without a load origin or at a static, lexical-cell, or capture root. Track visited values or locations so malformed cyclic input terminates. A conflicting origin or cycle must preserve the best available root and set `AccessPathTail::Summary` rather than claiming an exact path.

Selectors are discovered from the outermost access toward the root. Retain only the root-nearest `access_path_length` selectors while continuing the bounded, cancellation-aware walk until the root is known, then reverse them into source order. Mark the tail `Summary` when any outer selectors were discarded, when an `Any` index is present, or when ambiguity/cycles prevent an exact chain. Construct the final path through `AccessPath::bounded` so the existing contract remains authoritative.

Update the relation work calculation so every extra chased base value and memory location is charged through `SemanticWork`. Do not hide budget exhaustion: if the resolver cannot finish within the request budget, return the normal typed partial or exceeded-budget outcome rather than silently producing an exact shortened path. Keep the implementation iterative and avoid persistent per-procedure indexes that would increase every artifact's retained memory for a query-local need.

Second, update the shared tests. Remove the four `#[ignore]` attributes owned by #1407. Add focused oracle-level coverage only for behavior not already demonstrated by the scenarios: conflicting load origins and an artificial cycle must be non-exact and terminating. Reuse the existing Java/TypeScript field and exact-index scenarios for sibling field/index distinctness when their assertions already cover the contract; add one minimal nested mixed field/index near miss only if inspection shows the current fixtures cannot detect selector-order or identity regressions.

Finally, format and validate the focused tests, then the complete semantic and cross-language integration binaries. Run featureless all-target Clippy because this work does not touch NLP or Python. Use the installed Bifrost policy skill to run `bifrost.code-smells` together with every executable repository policy root in one request. Review the full diff with the guided issue specialists, address substantive findings, and update this plan's living sections after each milestone.

## Concrete Steps

Run all commands from `/Users/dave/.codex/worktrees/ccbb/bifrost`.

After implementing the first production slice, run:

    cargo fmt --all -- --check
    cargo test --test suite_semantic java_over_bound_access_path_is_an_explicit_summary -- --ignored --nocapture
    cargo test --test suite_semantic typescript_over_bound_access_path_is_an_explicit_summary -- --ignored --nocapture

After activating the tests, omit `--ignored` and run both public probes:

    cargo test --test suite_semantic over_bound_access_path -- --nocapture
    cargo test --test suite_cross_language over_bound_access_path -- --nocapture

Then run the complete affected binaries and lint gate:

    cargo test --test suite_semantic --test suite_cross_language
    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings

The focused tests must report the Java and TypeScript over-bound cases as passed, not ignored. The complete binaries must pass without changing unrelated expected incompleteness classifications. Clippy must produce no warnings.

## Validation and Acceptance

The direct Java and TypeScript relations must expose a `MemoryStore.target` and `MemoryLoad.source` whose stable location root is the source-backed `box` value. The selectors must be the first eight `next` fields in source order and the path tail must be `Summary`. The public CodeQuery/RQL carrier must serialize the same structure with `exact: false`.

Under-bound field and exact-index scenarios must remain exact. Different sibling fields and indices must not collapse to the same exact stable key. A chain with conflicting load origins or a cycle must terminate and must not claim `exact: true`. Cancellation and semantic-work limits must remain observable through the existing `SemanticOutcome` variants.

The final acceptance gate is: all focused probes pass enabled; the full `suite_semantic` and `suite_cross_language` binaries pass; formatting and featureless all-target Clippy pass; the required policy selection is clean; and specialist review has no unresolved critical or high finding.

## Idempotence and Recovery

All edits are ordinary Rust and test changes and can be reapplied safely. Tests use inline temporary projects and do not persist analyzer caches. If a validation command is interrupted, rerun the same command. Do not create manually named temporary Cargo target directories; use the repository helper if an isolated target becomes necessary. Do not change branches, rebase, push, or open a pull request without a separate explicit request.

If the access-path resolver reveals that validated IR permits a case the procedure-local index cannot represent safely, keep that case non-exact, record the evidence in `Surprises & Discoveries`, and add a focused test before broadening the design.

## Artifacts and Notes

Issue #1407 is the behavior owner. Issue #1419 owns parallel MCP request-budget failures, and #1434 owns the rmcp usage-scan budget overrun observed during diagnosis. Those tooling issues must remain separate from the semantic correctness change.

## Interfaces and Dependencies

No external dependency or public wire type should change. The implementation should add private, file-local resolver/index types next to `abstract_location` in `crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/value_flow.rs`. It must continue to construct public paths with `AccessPath::bounded` and existing `AccessPathRoot`, `AccessSelector`, `IndexSelector`, and `AccessPathTail` types.

Revision note (2026-08-01): Created the initial self-contained implementation plan after issue diagnosis and user approval.
