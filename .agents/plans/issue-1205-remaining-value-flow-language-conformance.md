# Extend exact value-flow conformance to the remaining language adapters

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It follows `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Issue #1205 has a production, source-backed Java and TypeScript helper-flow baseline. This continuation proves the same meaningful end-to-end path for every other currently analyzable Bifrost language adapter: C#, C/C++, Go, JavaScript, PHP, Python, Ruby, Rust, and Scala. Kotlin is deliberately excluded because its adapter is new and is not yet part of this readiness claim.

After this work, a contributor can run one integration target and see each enabled adapter carry a selected root parameter through an actual argument, callee formal, callee local, normal return, caller result, caller local, and sink argument. The shared harness runs the production `ValueFlowPlan`, shared solver, and witness reconstruction. It compares exact meetings and source-backed semantic milestones; source text is diagnostics only, never the propagation mechanism. An adapter that cannot satisfy this exact contract remains as an ignored strict test, not as a passing partial-conformance row.

## Progress

- [x] (2026-07-29 08:00Z) Fetched `origin`, verified the current worktree is clean and equal to both `origin/master` and its #1205 tracking branch at `49a7d86f`.
- [x] (2026-07-29 08:00Z) Confirmed the existing Java and TypeScript exact-flow cases pass from this worktree: `cargo test --test value_flow_language_conformance` passed 6 tests.
- [x] (2026-07-29 08:00Z) Selected the remaining roster from `Language::ANALYZABLE`, excluding Java and TypeScript because they are already covered and Kotlin by explicit request: C#, C/C++, Go, JavaScript, PHP, Python, Ruby, Rust, and Scala.
- [x] (2026-07-29 07:32Z) Add the smallest source-backed helper-flow fixture for every remaining adapter, with the Java/TypeScript `PROVEN_COMPLETE` witness contract required uniformly for every case. The initial strict run passed Java, TypeScript, JavaScript, Go, PHP, and Ruby and failed C#, C, C++, Python, Rust, and Scala.
- [x] (2026-07-29 07:32Z) Mark only the six failed strict cases `#[ignore = "..."]`, preserving their exact expected meetings, complete evidence requirement, canonical carriers, and call/return milestones as runnable readiness probes.
- [x] Fix the Go semantic-lowering defect exposed by the minimized fixture and retain its regression in the cross-language conformance target.
- [x] (2026-07-29 07:32Z) Run `cargo fmt --all -- --check`, the enabled 10-pass/6-ignored language-conformance target, and the 174 adjacent value-flow/semantic-language tests after tightening the witness contract.
- [ ] Reconfirm strict all-feature Clippy after tightening the witness contract. The isolated run compiled the all-feature crate and cleaned its managed target, but the terminal bridge detached before returning an exit status; this is not recorded as a passing lint result.
- [ ] Complete the monolithic `nlp,python` gate and a reliable complete code-smells policy evaluation. The first is blocked by host disk exhaustion during linking; the latter exhausts the repository-wide policy execution budget and is explicitly unreliable.

## Surprises & Discoveries

- Observation: The baseline conformance harness is language-neutral and already owns inline-project creation, structured procedure and call selection, exact meeting comparison, and witness projection.
  Evidence: `tests/common/value_flow_conformance.rs` accepts `ValueFlowConformanceCase` descriptors; `tests/value_flow_language_conformance.rs` contains only Java and TypeScript fixture data.

- Observation: A direct production ICFG call already exists for each target adapter, but a direct ICFG edge alone does not prove source-to-sink value flow.
  Evidence: `tests/semantic_language_conformance.rs` covers direct calls for C#, C/C++, Go, JavaScript, PHP, Python, Ruby, Rust, and Scala, while issue #1205 requires the production `ValueFlowPlan` and a source-backed witness.

- Observation: C# resolves the closed static calls but produces no source-to-sink meeting for the selected parameter and sink argument.
  Evidence: `csharp_exact_helper_flow` failed its strict exact-meeting-set assertion with an empty actual set. It is ignored with the reason `requires a proven complete source-to-sink meeting through C# static calls` and still expects one complete meeting when run with `--ignored`.

- Observation: Go lowered a single `return relayed` through both the `expression_list` wrapper and its identifier, creating distinct temporary values with the same stable source identity.
  Evidence: The Go helper initially failed `ValueFlowPlan::try_new` with `StableCarrierCollision`. Diagnostic lowering data showed two temporary values at the exact `relayed` return span. Flattening the return statement's expression list before lowering leaves one carrier and makes the complete source-backed Go witness pass.

- Observation: Rust, Python, C, and C++ reach an authoritative call-argument meeting but cannot reconstruct a `PROVEN_COMPLETE` producer-bound witness.
  Evidence: The strict test for each fails while locating a positive witness meeting, because the witness solver only supplies an unproven/partial route. Each test is ignored with a language-specific reason while retaining the Java/TypeScript witness expectation unchanged.

- Observation: PHP variables retain their `$` in stable source-backed carrier snippets.
  Evidence: The first PHP witness comparison differed only between `relayed`/`copy` and `$relayed`/`$copy`. The fixture helper now accepts explicit local snippets so the assertion remains source-backed without language-specific parsing.

- Observation: Scala resolves the two static calls but supplies no value-flow meeting for the selected source and sink.
  Evidence: `scala_exact_helper_flow` compares an empty actual meeting set with the selected event pair. It is ignored with the reason `requires a proven complete source-to-sink meeting through Scala calls`.

- Observation: Strict all-feature Clippy is sensitive to the host's mixed Rust toolchain paths.
  Evidence: An initial isolated run failed `E0514` because Homebrew's Clippy driver consumed Rustup-built metadata. With the Rustup 1.96.0 `bin` directory first in `PATH` and matching `RUSTC`/`RUSTDOC`, `scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings` passed and removed its target.

- Observation: The monolithic optional-feature test gate cannot complete on this host's available disk space.
  Evidence: The fresh isolated `nlp,python` build reached the Scala definition-scope integration binary, then the macOS linker failed with `errno=28` while 35 GiB remained available. The helper removed the failed target; three independently stale helper-managed targets were removed through the repository cleanup script, but the remaining space is still insufficient for another full fresh build.

- Observation: The required code-smells policy pack reports no findings in the changed files but cannot complete repository-wide evaluation within its configured execution budget.
  Evidence: The rerun reported 133 repository findings and no findings for the Go/language-conformance changes. Five rules were inconclusive after 535--1,090 files and up to 28.3 MiB of source, so the pack status is `unreliable` rather than clean.

## Decision Log

- Decision: Keep this continuation fixture-only until a failing exact case identifies a structured semantic defect.
  Rationale: The harness and solver are already proven by Java and TypeScript. Adding a second propagation engine, mock graph, text fallback, or parallel test framework would weaken the issue's purpose and violate the structured-analysis boundary.
  Date/Author: 2026-07-29 / Codex

- Decision: Treat C and C++ as two fixture dialects under the one `Language::Cpp` adapter.
  Rationale: They use the same Bifrost adapter but distinct parsers, file extensions, and header declaration paths. Both must retain a direct normal-call and return path to make the adapter claim meaningful.
  Date/Author: 2026-07-29 / Codex

- Decision: Never treat an incomplete result as passing value-flow conformance.
  Rationale: Issue #1205 is an exact-path readiness gate. A failing adapter keeps the same strict test behind `#[ignore = "specific reason"]`, which exposes the gap without weakening the enabled conformance suite.
  Date/Author: 2026-07-29 / Codex

- Decision: Use two type-qualified static C# calls and `object` values for the retained C# fixture.
  Rationale: This is the smallest source shape with a resolved direct candidate for both relay and sink in the current adapter. It separates the observed absent interprocedural proof from instance-receiver inference, which is a different boundary.
  Date/Author: 2026-07-29 / Codex

- Decision: Retain C# as an ignored exact helper-flow case.
  Rationale: The source shape is real and structurally resolved, but the production plan has no selected source/sink meeting. The strict expected meeting must remain visible and runnable until the adapter can join the enabled exact-flow set.
  Date/Author: 2026-07-29 / Codex

- Decision: Fix Go return lowering rather than weakening value-flow stable identity or adding an identity tie-breaker.
  Rationale: The duplicate values were an adapter artifact of a structural wrapper, not two semantically distinct carriers. Flattening `expression_list` at the return-statement boundary also correctly exposes multi-return shape as unsupported and preserves stable-key invariants for every client.
  Date/Author: 2026-07-29 / Codex

- Decision: Remove the partial-witness override from the shared conformance harness.
  Rationale: The harness must have one acceptance bar: every projected witness step is `Proven` and `Complete`. Rust, Python, C, and C++ retain their strict expected path under `#[ignore]` until that condition is true.
  Date/Author: 2026-07-29 / Codex

- Decision: Retain Scala as an ignored exact helper-flow case rather than treating resolved call edges as proof of value flow.
  Rationale: The production solver reports no selected source/sink meeting. The ignored test records the required behavior without turning that absence into passing conformance.
  Date/Author: 2026-07-29 / Codex

## Outcomes & Retrospective

The implementation covers every currently analyzable adapter except Kotlin, as requested. Complete source-backed witnesses pass for Java, TypeScript, JavaScript, Go, PHP, and Ruby. C#, C, C++, Python, Rust, and Scala remain explicitly ignored strict readiness tests because they fail the same exact witness contract; they are not counted as conformance support. The Go return-expression-list lowering defect was fixed at its structured source and its adapter epoch was bumped.

After the strict-contract correction, formatting passed, the language-conformance target reported 10 passed and 6 ignored, and 174 adjacent language/value-flow tests passed. The full all-feature Clippy process compiled and cleaned its isolated target, but the terminal bridge did not return its exit status; it remains unconfirmed rather than passing. The monolithic `nlp,python` gate is blocked by host linker disk exhaustion, and the mandatory full code-smells run is unreliable because multiple repository-wide rules exhaust their execution budget. None of those three is reported as a passing validation result.

## Context and Orientation

`tests/value_flow_language_conformance.rs` is the owning integration-test target. It imports `tests/common/value_flow_conformance.rs` with a path-scoped module so the specialized harness does not increase compilation work for unrelated integration targets. Its Java and TypeScript cases use one inline source file with three procedures named `run`, `relay`, and `sink`.

The shared harness builds an `InlineTestProject`, finds procedures and resolved call candidates structurally, constructs `ValueFlowSourceSpec` and `ValueFlowSinkSpec` values, then invokes `solve_value_flow_with_witnesses`. It asserts authoritative call-argument meetings separately from a companion producer-bound witness. This separation is necessary because a witness bound at a call argument can otherwise stop at the newly entered callee summary fact. A `CarrierMilestone` is the stable, source-backed identity of a parameter, local value, call argument, return, call result, or sink argument; it intentionally omits run-local fact and graph IDs.

`src/analyzer/model.rs::Language::ANALYZABLE` is the source of truth for the language roster. The existing `tests/semantic_language_conformance.rs` direct-call cases provide syntax and import/header patterns that the new fixtures should reuse where needed. Kotlin is intentionally not included in this plan.

## Plan of Work

Add descriptor-driven fixtures to `tests/value_flow_language_conformance.rs`, keeping each source small enough that a failure identifies one adapter and one call/return route. Use the current helper shape whenever the language syntax permits it: `run(input)` calls `relay(input)`, assigns the returned value to `copy`, assigns an unrelated `clean` value, and calls `sink(copy, clean)`; `relay(value)` assigns `value` to `relayed` and returns it. Use matching `ProcedureKind` values and the smallest real module, package, namespace, class, import, or header needed for a resolved direct call.

For each language case, state the full expected meeting set and both sink outcomes. The positive meeting must be `Proven` with `PROVEN_COMPLETE` path quality, and every reconstructed step must be `Proven` and `Complete`. The negative sink is `NotReached` only when its relevant discovery is complete; otherwise it is `Inconclusive`. Match the actual stable count of contexts only after inspecting the structural result. Do not reduce assertions to non-empty witness checks.

Add C and C++ cases with their normal header declarations and definitions so call binding crosses a real declaration/definition boundary. Keep JavaScript, Python, Ruby, PHP, Go, Rust, Scala, and C# fixtures idiomatic enough to select a resolved direct call, avoiding dynamic dispatch or language-specific deferred execution in this baseline. If a strict case fails, first minimize the evidence. Preserve the strict expectation and add a narrowly worded `#[ignore = "reason"]` only after observing the failure; never add source matching, a partial-evidence override, or a passing inconclusive alternative. Fix the adapter, semantic oracle, or shared value-flow lowering at its structured root cause before removing the ignore. Update this plan after every materially different result.

## Concrete Steps

Run the following from `/Users/dave/.codex/worktrees/8e80/bifrost`.

1. Add one minimized case and use its exact test name while discovering its contract:

       cargo test --test value_flow_language_conformance <case-name> -- --exact --nocapture

   A passing result must include one exact positive meeting and a source-backed call/return witness. A failure must be interpreted from the harness's structured comparison; do not infer semantics from fixture source text.

2. Run the focused suite:

       cargo test --test value_flow_language_conformance --test value_flow_client --test semantic_value_language_contract --test semantic_language_conformance

3. Run the Rust gates:

       cargo fmt --all -- --check
       scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
       scripts/with-isolated-cargo-target.sh env BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python

   The last command is required because a featureless test run omits `nlp`-gated suites. If host toolchain metadata is incompatible, use matching rustup `RUSTC` and `RUSTDOC` paths as documented in the preceding #1205 plan, preserving the isolated-target helper.

## Validation and Acceptance

Acceptance requires one focused source-backed case for C#, C, C++, Go, JavaScript, PHP, Python, Ruby, Rust, and Scala, in addition to the existing Java and TypeScript cases. Every case must execute the production semantic adapter, value-flow oracle, call bindings, immutable plan, ICFG provider, shared solver, and witness store. A passing case must retain the ordered parameter, actual argument, corresponding formal, relay local, normal return, caller result, caller local, and sink argument, plus matched call and normal-return edges, with complete proven evidence at every step. Every assertion must retain workspace-relative source backing and must avoid temporary roots, dense IDs, fact IDs, and worklist order.

The enabled target must report the strict passing rows and ignored blocked rows separately. At this checkpoint, `cargo test --test value_flow_language_conformance` reports `10 passed; 0 failed; 6 ignored`. Running `cargo test --test value_flow_language_conformance -- --ignored` currently fails for the six ignored adapters; that failure is intentional evidence that they have not met the readiness bar. An ignored case can be enabled only after that command passes for it without changing the exact expected path.

Kotlin is outside acceptance for this continuation. Dynamic dispatch, exception, heap, capture, cancellation, and budget matrix rows remain separately scheduled #1205 expansion work unless a minimal helper fixture exposes one of them as necessary to establish the requested adapter baseline.

## Idempotence and Recovery

`InlineTestProject` cleans up each fixture project automatically. The isolated-target helper cleans its temporary Cargo target on success, failure, or interruption. Re-running a single test is safe. Do not delete build output manually or stage unrelated files. If a fixture exposes a broader semantic defect, retain its strict minimized test as an ignored regression, add the observed failure reason, and update this plan before continuing.

## Artifacts and Notes

The starting revision is `49a7d86f` (`Refactor shared code-intelligence runtime (#1268)`). The prior Java/TypeScript checkpoint is documented in `.agents/plans/issue-1205-value-flow-conformance-baseline.md` and was merged as PR #1212. The required readable carrier shape is:

    run:param(input) -> run:relay(input):arg0 -> relay:param(value)
    -> relay:local(relayed) -> relay:return(relayed)
    -> run:relay(input):result -> run:local(copy) -> run:sink(copy, clean):arg0

This string is explanatory only. The implementation must keep the shared harness's structured carrier comparisons authoritative.

## Interfaces and Dependencies

No production interface is planned initially. Fixtures must use the existing test-only interfaces from `tests/common/value_flow_conformance.rs`:

    pub struct InlineSourceFile<'case> { pub path: &'case str, pub source: &'case str }
    pub struct ProcedureSelector<'case> { pub alias: &'case str, pub path: &'case str, pub name: &'case str, pub kind: ProcedureKind }
    pub struct CallSelector<'case> { pub alias: &'case str, pub caller: &'case str, pub callee: &'case str, pub occurrence: usize }
    pub struct ValueFlowConformanceCase<'case> { ... }
    pub fn assert_value_flow_conformance(case: &ValueFlowConformanceCase<'_>);

The implementation may add small test-data helpers to the owning integration target when they reduce repeated fixture descriptors without obscuring a language's source. Production code changes must name the exact semantic relation or lowering they correct and come with the smallest focused regression.

Plan revision note (2026-07-29): Created to continue issue #1205 beyond the intentionally complete Java/TypeScript baseline, after live branch/issue verification and explicit exclusion of Kotlin.

Plan revision note (2026-07-29 07:32Z): Replaced passing partial/inconclusive rows with ignored strict readiness tests after the user clarified that #1205 must assert complete exact paths for every target language.

Plan revision note (2026-07-29 07:47Z): Recorded the post-tightening validation outcome precisely: focused tests passed, while the isolated full-Clippy terminal session did not return an exit status after its managed target was cleaned.
