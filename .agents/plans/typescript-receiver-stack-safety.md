# Make TypeScript receiver resolution stack safe

This ExecPlan is a living document and must be maintained according to `.agents/PLANS.md`.

## Purpose / Big Picture

Large real-world TypeScript workspaces can currently abort while resolving a public symbol reference because receiver inference recursively walks syntax trees and can revisit the same semantic receiver state through contextual callbacks. After this change, definition and usage tools must terminate on cyclic receiver inference and on deeply nested but valid TypeScript while retaining precise owner selection.

## Progress

- [x] (2026-07-12 20:00Z) Reproduced the default-stack abort on `elastic__kibana` with the production differential command and persisted cache.
- [x] (2026-07-12 20:05Z) Captured a debugger trace identifying the receiver binding, expression, call, and contextual callback cycle.
- [x] (2026-07-12 20:28Z) Replaced recursive syntax-tree scans and added semantic visited-state tracking.
- [x] (2026-07-12 21:05Z) Added public regressions for local and contextual callback cycles, deep acyclic syntax and semantic chains, and unrelated owners.
- [x] (2026-07-12 21:18Z) Passed focused tests, formatting, all-feature clippy, release build, and the exact default-stack Kibana differential command.

## Surprises & Discoveries

- Observation: Raising the main-thread stack from the default to 64 MiB did not complete the run.
  Evidence: Both runs aborted with `thread 'main' has overflowed its stack`; GDB showed repeating `ts_collect_receiver_owners_from_bindings`, `ts_expression_property_owners`, `ts_call_expression_callees`, `ts_expression_receiver_owners`, and `ts_receiver_owner_candidates_at_byte` frames.
- Observation: The contextual callback path resets the numeric depth budget to zero, so the existing depth cap cannot stop a semantic cycle.
  Evidence: `ts_receiver_owners_from_contextual_callback` calls `ts_call_expression_callees(..., 0)`.
- Observation: Once cyclic receiver inference was stopped, member-call resolution still fell through to a bare property-name lookup and selected an unrelated same-named owner.
  Evidence: The compact fixture initially resolved `service.run()` to `Unrelated.run`; returning no callee after failed structured member receiver resolution changed it to `no_definition`.
- Observation: A visited set does not bound an acyclic chain of unique receiver states.
  Evidence: Review identified that each receiver entry reset the old numeric depth; a generated 4,000-step alias/call chain now terminates through a non-resetting per-query depth budget.

## Decision Log

- Decision: Preserve bounded best-effort inference but supplement it with an active semantic-state set keyed by receiver scope, name, and reference byte.
  Rationale: A numeric depth cap bounds acyclic inference but cannot recognize a revisited state, especially where existing public entry points reset depth.
  Date/Author: 2026-07-12 / Codex
- Decision: Use iterative tree-sitter node traversal for binding and return scans.
  Rationale: Syntax-tree depth is input-controlled and repository guidance requires stack-safe analyzer traversal.
  Date/Author: 2026-07-12 / Codex
- Decision: Do not reinterpret a failed member-expression receiver as an unqualified function call.
  Rationale: The AST says the property is receiver-qualified, and the old fallthrough created an unrelated-owner false positive after cycle detection correctly returned no receiver.
  Date/Author: 2026-07-12 / Codex
- Decision: Limit active semantic receiver resolution to 64 states and release both depth and visited keys with an RAII guard.
  Rationale: This bounds unique-state recursion without resetting across contextual callbacks, while cleanup on every return preserves independent branches and panic safety.
  Date/Author: 2026-07-12 / Codex

## Outcomes & Retrospective

The resolver now terminates on cyclic and deep acyclic TypeScript receiver inference without a larger process stack. The exact 1,000-file Kibana run completed on the default stack in 83.9 seconds with 10,000 sampled sites and no file errors. Its remaining 31 missing inverse findings are differential follow-up work, not initialization failures.

## Context and Orientation

`src/analyzer/usages/get_definition/js_ts.rs` implements TypeScript forward definition lookup and receiver-owner inference. A receiver owner is the class or interface whose member a property access can reference. `tests/usage_graph_ts_test.rs` exercises that logic through the public `usage_graph` search tool using inline projects. `tests/get_definition_by_reference_test.rs` covers the public definition lookup boundary. The corpus runner in `src/bin/bifrost_reference_differential.rs` samples public reference sites and compares forward lookup with inverse usage lookup.

## Plan of Work

Introduce a small per-query receiver-resolution context in `js_ts.rs`. Thread it through paths that can return from expression and call inference to receiver inference, retaining the existing depth budget while preventing an active receiver state from being entered twice. Rewrite binding and return syntax-tree collection with explicit `Vec<Node>` stacks, preserving source order where latest assignments matter by pushing children in reverse order. Add inline public tests that demonstrate termination and owner precision.

## Concrete Steps

From `/home/jonathan/Projects/bifrost`, edit `src/analyzer/usages/get_definition/js_ts.rs` and focused TypeScript tests. Then run:

    cargo test --test usage_graph_ts_test
    cargo test --test get_definition_by_reference_test
    cargo test --test usages_finder_fallback_test
    cargo fmt --check
    cargo clippy --all-targets --all-features -- -D warnings
    cargo build --release --bin bifrost_reference_differential --bin bifrost

Finally rerun the exact Kibana command with the default stack and expect `/tmp/n1-ts.jsonl` to contain one completed report rather than an abort.

## Validation and Acceptance

Acceptance requires all focused JS/TS definition, usage, and service tests to pass; the new cyclic and deep inputs must terminate without a larger stack; the unrelated same-named member must not be selected; clippy must be warning-free; and the exact 1000-file Kibana differential must write a completed JSONL record on the default stack.

## Idempotence and Recovery

Tests and corpus runs are repeatable. The corpus command uses `--force`, so remove only `/tmp/n1-ts.jsonl` when a clean single-record diagnostic output is required; the persisted workspace cache is intentionally retained.

## Artifacts and Notes

The production backtrace repeats the semantic cycle described above and reaches the liveness store only while checking candidate types; workspace persistence itself is not the recursive boundary.

## Interfaces and Dependencies

Use the existing tree-sitter `Node` identifiers and repository `HashSet` alias. Do not add a parser, text-search fallback, dependency, or larger-stack runtime configuration.

Revision note (2026-07-12): Completed after review added a non-resetting semantic budget, RAII cleanup, iterative pattern walks, expanded regressions, and a second successful default-stack Kibana run.
