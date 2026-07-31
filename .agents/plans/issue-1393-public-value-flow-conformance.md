# Prove public value-flow queries with shared cross-language scenarios

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost already has two valuable but disconnected pieces. The direct value-flow conformance harness proves exact Java, TypeScript, and other adapter behavior by invoking `ValueFlowPlan` and the summary solver directly. The public CodeQuery/RQL adapter exposes diagnostic-neutral flow endpoints and witnesses, but its current tests use a small synthetic Java plan and only prove that a witness is non-empty. A user therefore cannot tell whether the public result preserves the exact source-backed symbols, matched call/return behavior, absent meetings, uncertainty, or truncation that the direct solver produced.

After this work, one language-neutral scenario description can be run through both paths. The public `flow_witness` result will include stable structured input and output fact symbols for every retained step. Java and TypeScript will exercise equivalent branches, loops, abrupt completion, matched returns, exceptional cleanup, receiver and capture propagation, fields and bounded access paths, ambiguity, unresolved calls, cancellation, truncation, and every applicable budget. The same descriptions will then be reused for the remaining adapters, with explicit typed incompleteness or strict readiness probes where production semantics are not ready.

The observable proof is the consolidated Rust integration suite: it compares the complete canonical direct and public endpoint sets, asserts every ordered source-backed witness symbol, and fails on any unexpected or missing meeting. Python and VS Code tests prove the same wire shape survives the supported transports.

## Progress

- [x] (2026-07-31 09:30Z) Verified issue #1393, the matching attached branch, clean worktree, and current `origin/master` baseline.
- [x] (2026-07-31 09:30Z) Diagnosed the public projection gap and approved the milestone plan.
- [x] (2026-07-31 10:25Z) Added stable public zero, carrier, and meeting fact symbols to flow witness steps.
- [x] (2026-07-31 10:25Z) Carried the symbols through Python and VS Code models while leaving taint fact fields absent.
- [x] (2026-07-31 12:05Z) Consolidated `tests/code_query_value_flow.rs` into `suite_cross_language` and exposed a reusable resolved conformance scenario.
- [x] (2026-07-31 12:05Z) Ran the shared Java and TypeScript helper scenario through direct and public executors with exact endpoint and ordered witness-symbol parity.
- [x] (2026-07-31 13:10Z) Added shared Java and TypeScript branch/merge, loop/exit, early-return/unreachable, and two-call matched-return scenarios with exact direct/public parity.
- [x] (2026-07-31 12:30Z) Ran every shared scenario through equivalent JSON and RQL queries and asserted identical complete responses.
- [x] (2026-07-31 12:30Z) Added receiver, exceptional, cleanup, capture, field-store/load, bounded-access-path, and alias scenarios with exact positive or typed-inconclusive expectations.
- [x] (2026-07-31 14:15Z) Added unresolved-call and same-name ambiguous-dispatch scenarios with exact reached/inconclusive endpoint sets and public ambiguity assertions.
- [x] (2026-07-31 14:15Z) Classified all fact-only and IDE-only solver dimensions and proved every applicable public solver boundary, including the minimum witness-relation limit.
- [x] (2026-07-31 16:05Z) Added exact and one-beyond coverage for all outer, semantic, retention, endpoint, witness, aggregate, query-local, and applicable solver budgets plus phase-targeted cancellation.
- [x] (2026-07-31 16:05Z) Added exact index selectors and strict over-bound access-path readiness probes; filed structured adapter owner #1407.
- [x] (2026-07-31 16:05Z) Reused the exact-helper scenario across JavaScript, Go, PHP, Ruby, and the remaining single-file direct adapters; JavaScript, Go, and PHP pass the public runner and Ruby remains a strict #1408 readiness probe.
- [x] (2026-07-31 16:41Z) Completed focused and broad validation, the required policy selection, and final self-review; fixed all in-scope Clippy findings and recorded the repository-wide unreliable policy result.

## Surprises & Discoveries

- Observation: `SummaryWitnessStep` already retains both `input_fact` and `output_fact`; the information loss is entirely in the public projection.
  Evidence: `crates/bifrost-analysis/src/analyzer/dataflow/witness.rs` stores both fields, while `public_witness_step` in `crates/bifrost-analysis/src/analyzer/structural/search/value_flow.rs` serializes neither.

- Observation: the direct #1205 harness already contains the stable fact-to-carrier mapping needed by production.
  Evidence: `tests/common/value_flow_conformance.rs::fact_carrier` resolves `FactId -> ValueFlowFact -> ValueFlowCarrierId -> ValueFlowCarrierKey` without exposing run-local IDs.

- Observation: public taint witnesses deliberately reuse `CodeQueryFlowWitnessStep`.
  Evidence: `crates/bifrost-analysis/src/analyzer/structural/search/witness_projection.rs` calls the flow step projector for retained taint witnesses, so flow-specific fact symbols must be optional on the shared step or use a separate flow-only envelope.

- Observation: one `get_symbol_sources` request exceeded its request-wide budget after roughly 26 seconds, while narrower Bifrost calls completed promptly.
  Evidence: the batched request for `SemanticLocator`, `StableLocator`, `StableCarrier`, and `render_carrier` returned `get_symbol_sources was cancelled or exceeded its request-wide time budget`; no open issue matched that exact tool path, so follow-up #1411 records the exact request and timing.

- Observation: structured input/output facts materially increase retained witness bytes, as intended.
  Evidence: the seven-step Java public fixture now retains 2,929 serialized step bytes while remaining below its 16,384-byte query cap; the existing byte-clamp regression still truncates cleanly at a one-byte limit.

- Observation: a fact's carrier alone cannot recover the configured source or sink carrier, and simple path/range step sites cannot prove declaration identity or matched call origins.
  Evidence: the first shared Java run exposed a temporary carrier as the first non-zero witness fact even though the configured source is the `run` parameter. Exact direct/public parity required source/sink events to carry their configured carrier and full site, plus full source/target/origin symbols on each flow step.

- Observation: public endpoints intentionally deduplicate semantically identical solver meetings while merging provenance.
  Evidence: the TypeScript helper produces six raw solver meetings but four distinct public endpoints; two public rows retain two provenance paths. The shared scenario records both the raw meeting count and the exact projected endpoint count.

- Observation: negative public endpoints must be matched by their full sink event rather than argument ordinal.
  Evidence: the early-return scenario has two `sink` calls whose first arguments both use ordinal zero. Matching path, full source anchor, occurrence, and event ordinal distinguishes the reachable and unreachable sinks and asserts zero false meetings at the latter.

- Observation: TypeScript's multiple structured provenance paths recur across intraprocedural control flow.
  Evidence: branch, loop, and early-return scenarios each retain three raw meetings and three distinct public endpoints for the reached sink, while Java retains one. Exact canonical witness-set parity confirms these are real paths rather than duplicated envelopes.

- Observation: the current Java and TypeScript adapters lower field stores and loads to exact structured memory relations but do not propagate a meeting through the location.
  Evidence: both field scenarios contain exactly one `MemoryStore` into and one `MemoryLoad` from the same stable `box.value` location, while the direct and public sink outcomes remain explicitly inconclusive. Receiver-alias variants are likewise inconclusive.

- Observation: callable capture relations are materialized, but invocation resolution does not connect the selected callback call to the lambda body in either initial adapter.
  Evidence: the Java and TypeScript capture scenarios preserve typed incomplete discovery and emit no meeting or public witness rather than manufacturing a cross-closure flow.

- Observation: TypeScript public endpoints retain a deterministic mixed evidence multiset.
  Evidence: intraprocedural scenarios project one exact/complete endpoint plus may/partial alternatives; interprocedural helper, receiver, and matched-call scenarios additionally retain one may/complete endpoint. The shared expectation asserts each variant count rather than accepting any matching row.

- Observation: Java same-name static imports preserve ambiguous result coverage even when plan discovery is unknown, while TypeScript drops both same-name imported candidates before dispatch projection.
  Evidence: the shared Java case exposes `ambiguous: true` and an inconclusive negative; the TypeScript case remains unknown and inconclusive but cannot expose ambiguity. Follow-up #1406 owns the TypeScript resolver gap.

- Observation: the fact-only value-flow client charges eleven solver dimensions and leaves all six IDE-only dimensions at zero.
  Evidence: exact helper and unresolved-call direct solves jointly charge interned facts, reached states, flow evaluations, callback rows, propagated outputs, end summaries, incoming calls, provider materializations, summary applications, coverage rows, and witness relations. IDE relations, edge functions and operations, IDE values, value operations, and IDE propagations remain zero.

- Observation: public endpoint solving intentionally retains at most one witness relation per meeting.
  Evidence: `ValueFlowQueryState` constructs `WitnessRetentionLimits::best_effort(1, ...)`, so the exact public witness-relation solver limit is the minimum valid value `1`; `0` is rejected as an invalid plan before execution.

- Observation: witness reconstruction and solver-retention truncation set the public witness's partial quality but previously did not set the profile truncation flag or emit the typed witness diagnostic.
  Evidence: `ValueFlowQueryState::witnesses` only recorded truncation when byte-prefix projection removed steps. It now records every truncated witness consistently, and all six per/aggregate step, expansion, and byte boundaries prove the behavior.

- Observation: Java and TypeScript preserve exact array indices but flatten nested field receiver chains before the semantic access-path bound is applied.
  Evidence: index `0` and index `1` remain distinct exact `ExactIndex` selectors in store/load relations. A nine-field path becomes an exact temporary root containing the whole receiver expression plus only the final field, rather than root `box`, eight selectors, and a summary tail. Follow-up #1407 owns the adapter fix and the full expected paths remain ignored readiness probes.

- Observation: Ruby direct value-flow conformance is ready, but public structural seeds do not bridge to its semantic method procedures.
  Evidence: the shared Ruby helper produces six direct meetings while both method and function public seeds produce zero rows and no typed unsupported result. Follow-up #1408 owns the bridge; the public scenario remains an ignored readiness probe.

## Decision Log

- Decision: add optional `input` and `output` fields to `CodeQueryFlowWitnessStep`, populated for public value-flow witnesses and omitted for the currently shared taint projection.
  Rationale: the wire step is intentionally shared with taint. Separate value-flow and taint projection functions avoid a mode flag while preserving the existing taint payload.
  Date/Author: 2026-07-31 / Codex

- Decision: model facts as a tagged public zero/carrier/meeting enum and carriers as tagged structured value/port/allocation/call-result/scoped-root/location symbols.
  Rationale: readable strings alone cannot prove selector ordinals, exactness, ports, or nested access paths. The tagged representation remains stable and testable without leaking `FactId`, dense IDs, or mount identities.
  Date/Author: 2026-07-31 / Codex

- Decision: do not bump the RQL query schema solely for the added result evidence.
  Rationale: no query term, operation, field selector, accepted spelling, or validation behavior changes. Existing schema-v6/v7 queries receive additional structured evidence in the result, while query parsing and lowering remain unchanged.
  Date/Author: 2026-07-31 / Codex

- Decision: move the existing root `code_query_value_flow` test into `suite_cross_language`.
  Rationale: it has no process-global isolation requirement and is not listed in the keep-separate manifest. The project requires new ordinary integration coverage to use a consolidated suite.
  Date/Author: 2026-07-31 / Codex

- Decision: preserve #1205 as the direct execution baseline and add a second executor over the same scenario data.
  Rationale: replacing the direct runner would remove the independent oracle that detects public projection errors. Copying scenarios would allow the two paths to drift.
  Date/Author: 2026-07-31 / Codex

## Outcomes & Retrospective

The first two implementation milestones are complete. Public value-flow witness steps now preserve zero, carrier, and meeting facts; carriers contain stable source-backed value, port, allocation, call-result, scoped-root, and bounded location structures; source/sink events retain their configured carrier and full site; and every flow step retains full source/target/origin symbols. Run-local IDs and workspace mounts remain absent. Python parses the tagged shape strictly, VS Code preserves and renders concise fact transitions, and shared taint steps continue to omit flow-only facts.

The former root public-query test is now part of `suite_cross_language`. One shared Java/TypeScript helper description drives the direct solver and public CodeQuery paths. The harness compares exact detected and absent sink projections, raw versus deduplicated meeting counts, and the complete ordered witness-symbol sequences after removing only generated IDs and redundant display ranges. Focused validation passed all 14 public-query module tests and the two direct Java/TypeScript baseline tests.

The first control-flow matrix is also complete. Shared Java and TypeScript descriptions now prove branch joins, loop exits, early returns, an unreachable post-return call, and two call sites whose normal returns preserve their respective call origins. Public negative assertions identify sinks by full stable event identity, so same-ordinal arguments at different calls cannot alias in the test. Focused direct and public validation passes all eight new control-flow cases. Exceptional flow, heap/alias behavior, uncertainty, budgets, and remaining adapters remain in progress.

The next boundary slice is source-backed and exact. Receiver propagation reaches the callee receiver port in both adapters. TypeScript exceptional continuation reaches its catch sink; Java exceptional flow and both cleanup variants remain typed incomplete negatives. Capture invocation, field propagation, and receiver aliases are also explicit incomplete negatives, while the field scenarios separately prove exact structured `MemoryStore` and `MemoryLoad` relations over the same bounded access path. Every shared case now executes equivalent JSON and RQL and compares the complete serialized response. Over-bound access paths, full budgets, and adapter expansion remain in progress.

Ambiguous and unresolved dispatch are now explicit shared scenarios. An unresolved external result remains inconclusive while a source observed before the call still reaches its sink. Java preserves same-name dispatch ambiguity without inventing a target; TypeScript preserves the inconclusive negative but exposes a production resolver gap tracked by #1406. The solver-budget matrix classifies all seventeen dimensions and proves exact public boundaries for the eleven applicable fact-only dimensions, with the minimum-valid witness-relation boundary handled separately.

The complete public limit inventory is now table-driven. It finds the minimum passing boundary and executes one unit below for scanned files/source bytes/facts/pipeline rows, all five semantic controls, retained relations/bytes, endpoint and witness counts, all six per/aggregate witness dimensions, and both query-local clamps. Every partial witness is checked against the exact witness as a deterministic contiguous prefix. Cancellation is deterministically observed before execution, during semantic materialization, during solving, and between solving and witness reconstruction. The remaining adapter slice reuses the common exact-helper description: JavaScript, Go, and PHP pass direct plus JSON/RQL public execution; Ruby is direct-ready but public-blocked by #1408; the other single-file adapters now consume the same common builder in the direct matrix.

Final validation is complete. `cargo fmt --all -- --check`, the 585-test semantic binary (566 passed, 19 intentionally ignored), the 307-test cross-language binary (304 passed, three readiness probes ignored), all 62 Python tests with an isolated analyzer cache, all 80 VS Code tests, and strict all-target Python-feature Clippy pass. The final Clippy review boxed the large structured fact payloads inside `CodeQueryFlowFactSymbol` without changing their JSON shape and removed three needless test-harness borrows. The required `bifrost.code-smells` run completed but returned `unreliable`: five whole-workspace policies exhausted their execution budgets and the pack reported existing repository findings. The only new-file policy prompt is deliberate canonical JSON serialization in the test harness; the two `sort-in-loop` prompts on a changed production file predate this branch. No clean policy result is claimed. Follow-ups #1406, #1407, #1408, and latency owner #1411 retain the remaining adapter and tooling gaps.

## Context and Orientation

`crates/bifrost-analysis/src/analyzer/value_flow/` contains the production diagnostic-neutral value-flow client. A `ValueFlowPlan` owns stable `ValueFlowCarrierKey` values, structured source and sink event specifications, interprocedural bindings, and semantic completeness. `solve_value_flow_with_witnesses` runs the fact-only summary data-flow solver and returns `ValueFlowSummaryResult`. Each solver witness step stores source-backed program points, its interprocedural edge kind, proof/completeness, and run-local input/output fact IDs.

`crates/bifrost-analysis/src/analyzer/structural/search/value_flow.rs` is the public adapter. A host registers an immutable plan under a bounded `plan_ref`; CodeQuery/RQL executes `procedure -> value_flow -> flow_endpoint -> witness`. `ValueFlowQueryState::witnesses` reconstructs retained solver evidence and calls `public_witness_step`. Today that function projects sites and edge metadata but discards the facts.

`crates/bifrost-analysis/src/analyzer/structural/search/results.rs` owns the serialized Rust result types. `bifrost_searchtools/models.py` parses those results for Python clients. `editors/vscode/src/rql_query.ts` defines the corresponding VS Code result types and rendering helpers. Public taint projection in `crates/bifrost-analysis/src/analyzer/structural/search/witness_projection.rs` reuses `CodeQueryFlowWitnessStep`, so a flow-only symbol addition must not fabricate taint facts.

`tests/common/value_flow_conformance.rs` is the direct #1205 harness. It materializes inline projects, selects procedures and calls structurally, constructs production plans, compares exact meetings and sink outcomes, reconstructs witnesses, and projects facts into stable carriers. `tests/suite_semantic/value_flow_language_conformance.rs` defines the current cross-language helper scenarios. `tests/code_query_value_flow.rs` is the focused public adapter test added after the integration-suite consolidation; it will move to `tests/suite_cross_language/code_query_value_flow.rs`. New public parity scenarios will live beside it in the same suite and share the common harness.

A meeting is a source/sink encounter retained by the solver. An absent meeting means a configured sink is definitively not reached only when discovery and solving are complete; otherwise the public outcome must be inconclusive. A witness is a bounded contiguous sequence of solver steps. A carrier is the language-neutral semantic entity that currently holds the flowing value, such as a parameter port, local value, call result, receiver, capture slot, or bounded memory location.

## Plan of Work

First, define the public evidence contract in `results.rs`. Add a tagged `CodeQueryFlowFactSymbol` with zero, carrier, and meeting variants. Add tagged carrier, port, scoped-root, and selector representations that carry stable IDs, public source sites, roles, ordinals, exactness, and nested bounded structure. Extend `CodeQueryFlowWitnessStep` with optional input and output symbols. Re-export the new public types through the existing structural module surfaces.

Next, change the value-flow projection. Keep a source-site-only step projector for taint and introduce a value-flow projector that receives the registered plan, solve result, plan reference, workspace, and witness step. Resolve each `FactId` through `ValueFlowSummaryResult::result`, map source and sink IDs back to their event specs, map carrier IDs through `ValueFlowPlan::carrier_key`, and construct the public symbols. Assert plan/result ownership invariants at this boundary rather than returning partial optional symbols for impossible stale IDs. Reuse `hash_public_carrier_key`, `hash_public_locator`, `public_event`, and `locator_range`; never include `SemanticLocator::mount` or run-local IDs. The nested carrier shapes are bounded by the semantic model: exact-index selectors resolve to value keys and a location has a single structured root, so recursive public construction has a small semantic bound.

Then update transport models and tests. Python and TypeScript should parse every tagged variant strictly. VS Code witness rendering should show a concise input-to-output symbol transition without replacing the structured model. Existing taint fixtures must continue parsing steps without input/output fields. Re-run byte-truncation tests because the larger payload deliberately consumes more of the public witness byte budget.

After the production contract is green, consolidate the public test binary and refactor the shared harness. Introduce a public resolved-scenario wrapper that retains the inline project, workspace analyzer, root procedure, plan, and stable expected projection while keeping internal maps private. The existing direct assertion will call this wrapper. A public executor in `suite_cross_language` will register the same plan, run equivalent JSON and RQL, canonicalize volatile envelope details, and compare the complete endpoint and witness-symbol set with the direct projection. The first case is the existing Java/TypeScript helper flow, including its explicitly absent clean sink and matched call/normal-return milestones.

Expand the scenario descriptors only as each behavior requires. Branches, loops, and early returns can retain the existing parameter-source and call-argument-sink selection while adding expected local and control milestones. The two-call-site scenario will use distinct call aliases and require each normal return to carry the entering call's origin. Exceptional completion will add exceptional-return milestones. Receiver, capture, field, alias, and access-path scenarios will extend `CarrierMilestone` with the already-existing carrier variants rather than selecting syntax by source text. Unresolved-call cases will use a distinct structured call selector rather than a nullable callee or mode flag.

Build the budget matrix after the representative scenarios exist. Partition all `SolverBudgetDimension::ALL` entries into fact-only dimensions exercised by value flow and IDE-only dimensions that are explicitly inapplicable. Drive the outer query, semantic, solver, retention, endpoint, witness, step, expansion, and byte limits at exact boundaries and one below. Use deterministic cancellation hooks to cover cancellation before execution and, where the existing check-count token can target them reliably, during semantic materialization, solving, and witness reconstruction. Every case must assert diagnostic code, completion, semantic status, solver termination, truncation flags, omission bounds, and the absence of a false complete negative.

Finally, instantiate the shared scenarios for the remaining adapters. Existing direct-ready adapters should execute normally. A missing semantic capability remains a strict ignored readiness probe with the same expected path and a focused issue reference; no per-language expected path may silently omit a required milestone. Run the complete validation and specialist review. Fix every in-scope finding and rerun the same policy selection. Stop with validated local milestone commits; do not push or open a pull request without explicit user authorization.

## Concrete Steps

All commands run from `/Users/dave/.codex/worktrees/4286/bifrost`.

For the public symbol milestone:

    cargo fmt --all -- --check
    cargo test --test suite_cross_language -- code_query_value_flow::
    bash scripts/test_python.sh
    cd editors/vscode && npm test

Expected result: all focused Rust tests pass; Python parses flow symbols and taint steps; VS Code formatting, typechecking, lint, build, and unit tests pass.

For each scenario milestone:

    cargo test --test suite_semantic -- value_flow_language_conformance::
    cargo test --test suite_cross_language -- public_value_flow_conformance::

Expected result: every enabled Java/TypeScript scenario reports the exact expected meeting set and ordered witness symbols. Strict readiness probes remain ignored with issue references rather than passing weakened expectations.

For the final NLP-free Rust gate, because the Python surface changes:

    cargo fmt --all -- --check
    uv run --python 3.12 -- cargo clippy --all-targets --features python -- -D warnings
    cargo test --test suite_semantic
    cargo test --test suite_cross_language
    bash scripts/test_python.sh
    cd editors/vscode && npm test

The policy gate will use one Bifrost `run_policy` request containing `bifrost.code-smells` and every executable repository policy root named by the project. The exact policy roots will be discovered from repository instructions and the installed policy manifest before the run. A `finding` must be reviewed or fixed; `unreliable` is a failed validation result, not a clean run.

## Validation and Acceptance

The production symbol contract is accepted when a public Java helper witness contains structured input and output facts for every retained step; those facts include parameter, argument, formal, local, return, call-result, and sink carriers; and the serialized result contains neither mount identifiers nor dense IDs. Rebuilding the equivalent inline project under another temporary root must produce equal carrier and fact IDs.

The shared harness is accepted when the same Java and TypeScript scenario object is passed to both executors and JSON/RQL return the same canonical set as the direct helper. The test must fail if a public meeting is added or omitted, if an absent clean sink becomes reached, if the witness loses a carrier, or if one return is paired with the other call site's origin.

The Java/TypeScript matrix is accepted when all issue scenarios have enabled exact tests or an explicit typed-incomplete expectation justified by current production semantics. Branch, loop, abrupt, exceptional, cleanup, receiver, capture, field, access-path, alias, ambiguous, and unresolved boundaries must appear in assertions rather than only in fixture source.

Budget behavior is accepted when every applicable public limit has a boundary test and every solver dimension is classified. Cancellation or exhaustion must never produce a complete negative. Witness truncation must retain a contiguous prefix and report accurate omission lower bounds and profile flags.

Cross-adapter reuse is accepted when remaining language fixtures consume the same scenario descriptions and expected language-neutral milestones. Any ignored probe retains the full expected path and a focused owner issue.

## Idempotence and Recovery

All edits are ordinary source and test changes. Formatting and test commands are safe to rerun. Inline projects use managed temporary roots and clean themselves up. Rust builds use the worktree target unless an isolated comprehensive command is required; do not create manually named temporary Cargo target directories.

Milestones are committed only after their focused tests pass, and each commit stages only the files changed for that milestone. If a later scenario exposes an adapter bug, keep the failing expectation in the plan, fix the structured adapter or add a strict readiness probe, and rerun the direct baseline before returning to public parity. Never mask the gap with regex or source-text propagation.

If transport changes fail midway, Rust remains the source of truth. Re-run generated/static model checks only after the Rust wire shape is final, then update Python and TypeScript parsers from the canonical serialized fixture. Taint steps without flow facts remain valid because input/output fields are optional.

## Artifacts and Notes

Initial production gap:

    SummaryWitnessStep { ..., input_fact, output_fact }
        -> public_witness_step(workspace, step)
        -> CodeQueryFlowWitnessStep { kind, source, target, origin, boundary, evidence }

Target public shape, expressed schematically:

    CodeQueryFlowWitnessStep {
        kind,
        source,
        target,
        origin,
        boundary,
        input: Some(Zero | Carrier | Meeting),
        output: Some(Zero | Carrier | Meeting),
        evidence,
    }

The existing direct mapping to reuse is `tests/common/value_flow_conformance.rs::fact_carrier`. The existing stable hash traversal to reuse is `crates/bifrost-analysis/src/analyzer/structural/search/value_flow.rs::hash_public_carrier_key`.

## Interfaces and Dependencies

`crates/bifrost-analysis/src/analyzer/structural/search/results.rs` must expose public serializable fact and carrier symbol types used by `CodeQueryFlowWitnessStep`. Names may be adjusted during implementation for consistency, but the interface must distinguish zero, carrier, and meeting facts and every `ValueFlowCarrierKey`/`ValueFlowSelectorKey` variant.

`crates/bifrost-analysis/src/analyzer/structural/search/value_flow.rs` must contain separate functions for source-site-only shared projection and value-flow symbol projection. The flow function must accept enough immutable context to resolve facts through the exact plan/result that produced the witness. It must reuse the existing public locator and carrier hashes.

`tests/common/value_flow_conformance.rs` must expose a resolved scenario abstraction that can be consumed by both test suites without exposing internal run-local IDs. The abstraction must provide the workspace analyzer, root, immutable plan registration material, and canonical expected meetings/witness symbols.

No new third-party dependency is needed. Serde supplies the Rust tagged representation; the existing Python dataclasses and TypeScript discriminated unions mirror it.

Revision note (2026-07-31): Initial ExecPlan created after the user approved the diagnosis and milestone plan for issue #1393.

Revision note (2026-07-31): Recorded the completed public symbol and transport milestone, including the expected serialized-byte increase and validation evidence.

Revision note (2026-07-31): Recorded public event/step symbol completion, root-test consolidation, shared Java/TypeScript scenario execution, and exact direct/public canonical parity.

Revision note (2026-07-31): Recorded the Java/TypeScript branch, loop, early-return/unreachable, and matched-return milestone plus full sink-event negative matching.

Revision note (2026-07-31): Recorded JSON/RQL response parity and the receiver, exceptional, cleanup, capture, field/access-path, and alias readiness outcomes.

Revision note (2026-07-31): Recorded ambiguous/unresolved dispatch, TypeScript follow-up #1406, and the complete solver-dimension classification and boundary coverage.

Revision note (2026-07-31): Recorded the complete public budget/cancellation matrix, exact index coverage, over-bound follow-up #1407, and cross-adapter reuse with Ruby follow-up #1408.

Revision note (2026-07-31): Recorded final broad validation, strict Clippy closure, the reviewed unreliable policy-pack result, and `get_symbol_sources` latency follow-up #1411.
