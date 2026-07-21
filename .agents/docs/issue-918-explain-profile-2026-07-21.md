# Issue #918 Milestone 5: public explain and profile

Milestone 5 publishes the planning and measurement work from M1-M4 without
making the internal benchmark profiler a compatibility surface.

## Contract

- JSON uses one root `execution_mode`: `results` (default), `explain`, or
  `profile`. RQL uses `(explain QUERY)` and `(profile QUERY)` wrappers.
- The control is schema-authoritative, root-only, absent from semantic plan
  identity, and rejected in static-analysis policy selectors.
- `results` serializes as the existing unwrapped `CodeQueryResult` and does not
  allocate public explain/profile observations.
- `bifrost_code_query_explain/v1` exposes the query schema version, canonical
  parsed query, dependency-first logical plan, selected physical plan, and
  production scheduling choice. Planning does not access analyzer data during
  lowering or selection, though a host may initialize/index first.
- `bifrost_code_query_profile/v1` nests the exact ordinary result from the same
  execution, then exposes execution-core timings, budget-accounted work,
  deterministic typed cache layers, bounded-scheduler observations, and
  operator identity, cardinality, timing, disposition, termination, work,
  cache, cancellation, and lower-bound temporary-capacity fields.
- Internal v4 evidence, fingerprints, storage generations, representation
  details, authored-suffix flags, and overlapping worker-task elapsed fields
  are deliberately not public.

`timings_ns.total` starts after analyzer query-scope setup and ends before that
scope is cleaned up. It also excludes public profile projection,
serialization, transport, host workspace initialization, and client rendering,
so it is not end-to-end latency.

## Supported surfaces

The root contract is exercised through the MCP schema/runtime, one-shot CLI and
saved query files, REPL, top-level Rust API, Python client models, LSP, and VS
Code. Python dispatches the two versioned report formats into typed models and
preserves unknown nested metric fields for forward compatibility. VS Code
keeps profiled ordinary rows navigable and writes the complete versioned report
to the Bifrost output channel. The REPL renders the same full report after its
ordinary rows.

The top-level Rust `execute_request_with_cancellation` API returns a profiled
cancellation-safe partial result and operator cancellation observations. LSP
keeps standard protocol semantics: a cancelled request returns
`RequestCancelled` and does not deliver the partial profile.

## Scheduling and adjacent alternatives

Production `Auto` remains sequential. The M4 bounded two-worker
`ParallelUnion`, parity suite, and release harness remain evidence-bearing
infrastructure, but no force-parallel request flag is public. At 257, 513, and
1,001 TypeScript files, the final reversed-order cold/warm rounds changed sign
by scale, cache state, or round; absolute timings varied by several multiples
without a result, work, cache, or source-fingerprint change. There is no stable
observable pre-execution selector in that evidence.

Adjacent choices stopped at different gates:

- bitmap-backed sets were ineligible because no stable dense identity domain
  existed;
- the normalized SQL edge-table negative control was discarded because its
  consumer result was non-equivalent and it lacked exact snapshot identity;
- arbitrary recursive graph splitting remained a safety/ownership non-goal for
  the current shared caches, resolver state, budgets, and derived dependencies.

The exact M4 absolute table and experiment limits are published on
`docs/src/content/docs/code-query-explain-profile.md`.

## Validation

Focused Rust schema, plan/profile, ordinary-wire, cancellation, MCP, CLI, REPL,
service, LSP, and executable-doc tests pass. The native Python suite passes 51
tests. The VS Code formatting, typecheck, lint, compile, license, grammar, and
unit gates pass 60 tests. The Astro build renders 56 pages and checks 5,210
internal links; the Explain and Profile page was also inspected in the browser
with no horizontal overflow or console warnings. Formatting, `git diff --check`,
and strict pinned-toolchain all-target/all-feature Clippy pass. The full
`nlp,python` Rust suite passes on the final tree: the library reports 1,519
passed and 5 ignored, the `bifrost` binary reports 22 passed, and every
integration binary and doc-test target passes. Final adversarial re-review has
no remaining P0-P3 findings.
