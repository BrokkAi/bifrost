# Add the Java and TypeScript exact value-flow conformance baseline

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Bifrost already constructs language-neutral control-flow graphs, publishes structured value-flow relations and call bindings, and runs a context-respecting shared data-flow solver. Its current tests prove those pieces separately, but they do not show that a source selected from real Java or TypeScript reaches exactly the intended sink through the expected argument, formal-parameter, local-assignment, return, and caller-result transitions.

After this change, a contributor can run one integration test and see equivalent Java and TypeScript inline projects pass through the production `ValueFlowPlan` and shared solver. The test will compare the complete source-to-sink meeting set, reconstruct a source-backed witness, and assert stable semantic milestones without depending on dense fact IDs, temporary directories, or worklist order. This baseline is the prerequisite test harness for issue #825; it deliberately does not implement the resource typestate protocol, policy rendering, benchmarks, or remaining-language rollout.

## Progress

- [x] (2026-07-27 10:31Z) Fetched `origin`, confirmed the unrelated untracked `.brokk/` directory, and created `dave/issue-1205-value-flow-conformance` from current `origin/master` at `9d7591ad`.
- [x] (2026-07-27 10:31Z) Diagnosed the missing seam between language adapter facts, the production value-flow client, and bounded witness reconstruction; confirmed that the first Java/TypeScript slice can use public APIs from test code.
- [x] (2026-07-27 11:32Z) Added the reusable structured selector, plan builder, exact meeting comparison, stable carrier projection, compact source-backed witness rendering, and context-respecting call/return assertions under `tests/common/`.
- [x] (2026-07-27 11:32Z) Replaced the reachability-only Java helper test with an exact source-to-two-sink-arguments conformance case; the focused Java test passes.
- [x] (2026-07-27 11:40Z) Added the equivalent TypeScript case; it passes the same language-neutral carrier and call/return milestone contract with explicit incomplete aggregate discovery.
- [ ] Run focused tests, formatting, strict all-feature Clippy, and the complete `nlp,python` test gate.
- [ ] Run security, duplication, intent, operations, and architecture reviews; resolve accepted findings and record the outcome.

## Surprises & Discoveries

- Observation: The existing `tests/value_flow_client.rs` helper-flow test proves only that one Java sink is reached.
  Evidence: `exact_argument_and_return_bindings_flow_through_a_helper` calls `solve_value_flow_with_summaries`, which disables witness retention, and its only result assertion matches `ValueFlowSinkOutcome::Reached(_)`.

- Observation: The public value-flow and summary-result APIs already expose the pieces needed for a test-only stable projection.
  Evidence: a witness step exposes input and output `FactId` values; `ValueFlowSummaryResult::result().fact(...)` resolves those to `ValueFlowFact`; `ValueFlowFact::carrier()` yields the run-local carrier; and `ValueFlowPlan::carrier_key(...)` yields the stable semantic carrier identity.

- Observation: The summary witness API reconstructs one deterministic witness for a meeting and path quality but does not enumerate every retained alternative of the same quality.
  Evidence: `ValueFlowSummaryResult::witness_for_meeting` delegates to the singular `witness_for_reached_index` API. This does not block the single-path Java/TypeScript baseline; alternative enumeration remains later #1205 work if the broader matrix proves it necessary.

- Observation: A reusable inline analyzer harness must retain `BuiltInlineTestProject` through the solve, not only the `WorkspaceAnalyzer` and semantic handles.
  Evidence: the first Java solve failed to recapture `src/ExactFlowFixture.java` after `build_case` dropped the temporary project. Keeping the built project in `ResolvedCase` made source recapture and ICFG construction succeed.

- Observation: Binding a call-argument sink at the invoke point makes an unchanged meeting fact enter the callee as a new summary entry; the singular witness API can then select a seed-only witness for that meeting.
  Evidence: the first successful Java solve reconstructed only a `Seed` in `sink`. Selecting the same structured argument carrier at its producing value-flow relation after effects reconstructed the complete root-to-helper-to-root path. The stable sink key remains the call site plus argument ordinal.

- Observation: Java's positive helper path is proven complete even though aggregate discovery remains incomplete.
  Evidence: the Java meeting frontier is exactly `PROVEN_COMPLETE`, its may status is `Proven`, and it is not uncertain; `ValueFlowSummaryResult::is_complete()` is false, so the unrelated argument is correctly `Inconclusive`, not `NotReached`.

- Observation: TypeScript needs no language-specific witness normalization for the baseline helper flow.
  Evidence: `typescript_exact_helper_flow` passes the exact same expected carrier milestones and interprocedural edge milestones as Java, including a proven-complete positive path and an inconclusive unrelated sink argument.

## Decision Log

- Decision: Keep the first slice test-only unless implementation proves that a required semantic fact is inaccessible.
  Rationale: The production solver already retains structured program points, call origins, edge kinds, facts, proof, and completeness. Adding a second propagation engine or a public reporting abstraction would duplicate existing behavior and widen the prerequisite before #825.
  Date/Author: 2026-07-27 / Codex

- Decision: Select sources and sinks from semantic roles, procedure identities, call targets, and argument ordinals; attach source snippets only after selection.
  Rationale: Source text is useful in assertion failures but cannot be the authority for propagation. This keeps the harness aligned with the repository rule against regex or text-search fallbacks for structured analyzer semantics.
  Date/Author: 2026-07-27 / Codex

- Decision: Use one source and two sink arguments in both reference fixtures.
  Rationale: `sink(copy, clean)` gives one expected exact flow to argument zero and one explicitly absent meeting at argument one. Comparing both sink outcomes proves the complete meeting set instead of checking a single positive.
  Date/Author: 2026-07-27 / Codex

- Decision: Assert positive-path proof separately from aggregate discovery completeness.
  Rationale: TypeScript can retain a precise resolved candidate and context-respecting witness while the language's dispatch model remains open. The harness must preserve that distinction rather than weakening the positive assertion or claiming a complete negative.
  Date/Author: 2026-07-27 / Codex

- Decision: Normalize expression temporaries structurally while retaining explicit parameter ports, call-argument ordinals, locals, normal returns, caller results, and sink-argument ordinals.
  Rationale: Java emits source-backed expression temporaries around parameter uses and call arguments. The portable contract is the semantic role/port/call binding, so temporary values are omitted only by their structured `temporary` role; call and return milestones are recovered from exact ICFG edge kinds and call origins, never source-string matching.
  Date/Author: 2026-07-27 / Codex

## Outcomes & Retrospective

The Java and TypeScript milestones now exercise both production adapters, value-flow oracle, exact dispatch bindings, immutable plan, summary solver, and bounded witness reconstruction. Each asserts the complete meeting set, preserves incomplete aggregate discovery as an inconclusive negative, and projects the proven positive path into the same language-neutral carrier milestones with compact source snippets. Full validation and specialist review remain.

## Context and Orientation

`tests/common/inline_project.rs` builds temporary multi-file projects and infers analyzer languages from file extensions or an explicit `Language`. `tests/common/semantic_graph.rs` materializes normalized semantic artifacts and contains source-span helpers. The new harness will reuse both; it must not hand-write temporary filesystem setup.

`src/analyzer/semantic/workspace_oracle/value_flow.rs` derives a `ValueFlowSnapshot` for each procedure from normalized semantic events and derives candidate-specific `CallBindings` for actual arguments, receiver values, normal returns, and exceptional returns. A snapshot or binding arrives inside a `SemanticOutcome`; converting that outcome to `SemanticInputStatus` preserves whether discovery was complete, ambiguous, unproven, unsupported, budget-exhausted, or cancelled.

`src/analyzer/value_flow/plan.rs` combines snapshots, bindings, structured sources, and structured sinks into an immutable `ValueFlowPlan`. A carrier is the semantic entity whose value flows: a value, a procedure port such as parameter zero or normal return, or a structured abstract location. The plan interns carriers into dense run-local IDs but also exposes `ValueFlowCarrierKey`, whose locators, roles, ordinals, and access-path structure are stable across runs after the workspace mount is omitted.

`src/analyzer/value_flow/client.rs` runs that plan through the shared summary solver. `solve_value_flow_with_witnesses` opts into bounded predecessor retention. A meeting is a diagnostic-neutral result saying one source-derived carrier reached one configured sink. `src/analyzer/value_flow/result.rs` exposes the meeting's source and sink IDs, may status, deliberately unestablished must status, uncertainty, path-quality frontier, overall completeness, and bounded witness reconstruction.

`src/analyzer/dataflow/witness.rs` represents each reconstructed step with a source program point, optional target point, optional originating call, ICFG edge kind, proof, completeness, and input/output fact IDs. ICFG means the interprocedural control-flow graph: it joins procedure-local control-flow graphs with call and matched return edges. A context-respecting witness must return from a helper to the continuation of the same call that entered it.

The existing test `exact_argument_and_return_bindings_flow_through_a_helper` in `tests/value_flow_client.rs` manually selects the first Java parameter and assignment relations and asserts only reachability. The new integration suite replaces that end-to-end responsibility while leaving lower-level client tests in place.

## Plan of Work

First create `tests/common/value_flow_conformance.rs` and export it from `tests/common/mod.rs`. Define small table-driven descriptors for inline files, the root procedure, procedures whose value-flow snapshots are required, calls whose candidate-specific bindings are required, a parameter source, and call-argument sinks. Procedure selection must resolve a declaration from `ProcedureKind` plus its final declaration segment. Call selection must inspect structured call rows, resolve dispatch through `DispatchOracle`, and select the candidate whose target is the configured procedure. Argument selection must use the semantic call row's zero-based argument ordinal.

The harness will materialize every referenced file with `SemanticGraph`, obtain live `ProcedureHandle` values, query `ValueFlowOracle::procedure_relations` for each configured procedure, and query `DispatchOracle::resolve_call` plus `ValueFlowOracle::call_bindings` for each configured call/callee pair. It will preserve every outcome as `ValueFlowInput` with `SemanticInputStatus::from_outcome`, construct `ValueFlowSourceSpec` and `ValueFlowSinkSpec` values at the structured program points and observation phases, then build `ValueFlowPlan::try_new`.

The source selector for the baseline will bind the target carrier of the root procedure's `ValueFlowRelationKind::Parameter` relation at ordinal zero after that relation's effects. A sink selector will bind the semantic value used by one configured call argument at the call's program point before effects. Event keys must use the source-backed point locator plus a descriptor-provided ordinal so multiple sinks at the same call remain distinct.

Run the plan through `solve_value_flow_with_witnesses` using bounded positive witness-retention and reconstruction limits. Canonicalize each meeting to its stable source and sink event keys by resolving the meeting IDs through the plan. Compare the entire canonical meeting set against the expected set. Separately compare each configured sink outcome, including the difference between a complete `NotReached` result and an `Inconclusive` result caused by incomplete discovery.

Add a projector that starts from the configured source milestone, walks the reconstructed witness, resolves input/output fact IDs through the summary result, and resolves carrier IDs through the plan. A projected locator must retain workspace-relative path, language, declaration path, semantic role, source span, and occurrence while omitting `WorkspaceMountId`. A projected step must retain its stable carrier, procedure locator, source range and normalized one-line snippet, edge kind, originating call locator where present, proof, and completeness. Call edges must contextualize their input carrier as the matching actual argument ordinal and their output carrier as the corresponding callee formal. Return edges must retain the matching call origin and expose the callee return-to-caller-result transition. Intraprocedural carrier changes must retain parameter, local, and return roles. The final sink milestone comes from the structured sink binding even though the terminal meeting fact is not itself a carrier fact.

Before fixing the expected Java projection, render the first raw projected witness in an assertion failure or temporary diagnostic and inspect it. Define a structural normalization only for duplicated plumbing that means the same semantic milestone in both languages. Any normalization must use carrier variants, semantic roles, call origins, and edge kinds; never match source strings. Record the observed raw sequence and normalization decision in `Surprises & Discoveries` and `Decision Log`, then remove temporary diagnostics.

Create `tests/value_flow_language_conformance.rs`. Define equivalent Java and TypeScript inline fixtures containing `run`, `relay`, and `sink`: `run` passes its input through `relay`, assigns the result to `copy`, creates an independent `clean` value, and calls `sink(copy, clean)`. `relay` assigns its formal to a local and returns it. The shared expected milestone shape must include the root parameter, relay argument zero, relay formal zero, relay local, relay normal return, the exact caller result, caller local, and sink argument zero. The second sink must have no meeting. Each case may specify its aggregate semantic/discovery status, but both must require a proven exact positive meeting and a witness whose call and normal-return steps carry the same originating relay call.

Remove `exact_argument_and_return_bindings_flow_through_a_helper` from `tests/value_flow_client.rs` only after the Java conformance case passes and provides stronger coverage. Keep the existing helper source if another low-level test still uses it, and avoid unrelated test refactoring.

After the Java checkpoint and the TypeScript parity checkpoint, run the focused suites. Update this ExecPlan and commit only the files changed in that milestone. Then run formatting, strict all-target/all-feature Clippy, and the full `nlp,python` test suite in managed isolated Cargo targets. Finally review the diff for security, duplication, intent, operational, and architecture concerns, address accepted findings, update this plan, and create a post-review checkpoint commit. Do not push or open a pull request without a separate user request.

## Concrete Steps

Run commands from `/Users/dave/.codex/worktrees/74ad/bifrost`.

Create and exercise the Java harness first:

    cargo fmt --all
    scripts/with-isolated-cargo-target.sh cargo test --test value_flow_language_conformance java_exact_helper_flow -- --exact --nocapture

The new Java test must report one passing test. Its assertion output on failure must render stable milestones and source snippets, not opaque `FactId` or node numbers.

Exercise the complete new table and existing adjacent contracts:

    scripts/with-isolated-cargo-target.sh cargo test --test value_flow_language_conformance --test value_flow_client --test semantic_value_language_contract

Expect both new language cases and all existing client/oracle contract tests to pass. If the test binary uses different generated test names, list them with `cargo test --test value_flow_language_conformance -- --list` and update this section with the exact names.

Run the Rust CI checks:

    cargo fmt --all -- --check
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh env BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python

The formatting command must produce no diff. Clippy must exit zero with warnings denied. The full test command must exit zero; featureless `cargo test` is not an acceptable substitute because it skips NLP integration suites. If macOS rustdoc reports the known LLVM `E0514` mismatch, rerun the managed command with the matching rustup `RUSTDOC` path and record the exact command and result here.

## Validation and Acceptance

The first slice is accepted when the new integration test executes the production Java and TypeScript semantic adapters, `ValueFlowPlan`, ICFG provider, summary solver, and witness store without mocks or a replacement worklist.

For each language, the complete meeting set must contain only the root-input source meeting sink argument zero. Sink argument one must have no meeting. When discovery is complete, the second sink must be `NotReached`; when a language retains an open boundary, it must be `Inconclusive` rather than a false complete negative. The positive meeting must report its expected may status, `ValueFlowMustStatus::NotEstablished`, uncertainty, and path-quality frontier.

The reconstructed witness must contain a call edge from the root relay call into `relay`, a matched normal-return edge carrying the same call origin back to the root continuation, and the expected structured carrier milestones. Every milestone must retain a workspace-relative source range whose snippet matches the intended fixture construct. Re-running the test must produce identical projected milestones despite a different temporary project root.

No assertion may mention a run-local fact ID, dense carrier ID, ICFG node index, temporary absolute path, or worklist order. No production solver, policy syntax, public renderer, persistence layer, benchmark, resource protocol, or additional language adapter may enter this slice.

## Idempotence and Recovery

All fixture construction uses `InlineTestProject`, so each test run creates and removes its own temporary project. Managed Cargo targets are created by `scripts/with-isolated-cargo-target.sh` and removed on success, failure, or interruption. The commands are safe to repeat.

Do not delete or stage the pre-existing untracked `.brokk/` directory. Stage files explicitly by name at each checkpoint. If the projector reveals a missing public fact, stop before adding a production API, record the exact inaccessible evidence in this plan, and obtain approval for the scope change. If a test exposes a real Java or TypeScript adapter bug, first minimize it in the conformance case and fix the structured oracle or adapter root cause rather than weakening the expected trace.

## Artifacts and Notes

The implementation branch started from:

    9d7591ad (origin/master) Merge remote-tracking branch 'origin/master' into bifrost-fird

The intended language-neutral readable trace is:

    run:param(input) -> run:relay(input):arg0 -> relay:param(value)
    -> relay:local(relayed) -> relay:return(relayed)
    -> run:relay(input):result -> run:local(copy) -> run:sink(copy, clean):arg0

This is an explanatory rendering. Assertions remain structural and source-backed.

## Interfaces and Dependencies

In `tests/common/value_flow_conformance.rs`, define test-only equivalents of these responsibilities, refining names while preserving the boundaries:

    pub struct ValueFlowConformanceCase { ... }
    pub struct ProcedureSelector { ... }
    pub struct CallSelector { ... }
    pub enum EndpointSelector { Parameter { ... }, CallArgument { ... } }
    pub struct ExpectedMeeting { ... }
    pub struct ExpectedWitness { ... }
    pub struct ProjectedWitness { ... }
    pub struct ProjectedWitnessStep { ... }
    pub fn assert_value_flow_conformance(case: &ValueFlowConformanceCase<'_>);

The harness must reuse `InlineTestProject`, `SemanticGraph`, `WorkspaceAnalyzer::semantic_oracle_provider`, `WorkspaceAnalyzer::icfg_provider`, `SemanticInputStatus`, `ValueFlowInput`, `ValueFlowPlan`, `solve_value_flow_with_witnesses`, `ValueFlowSummaryResult`, `SummaryWitness`, and `ValueFlowCarrierKey`. No new crate dependency is needed.

Plan revision note (2026-07-27): Created after live issue diagnosis, refresh to current `origin/master`, explicit approval of the Java/TypeScript-first scope, and explicit approval to create the implementation branch.
