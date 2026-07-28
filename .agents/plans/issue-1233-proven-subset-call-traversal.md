# Make proven-only call traversal explicitly non-exhaustive

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. Maintain it according to `.agents/PLANS.md` from the repository root.

## Purpose / Big Picture

Policy authors need to detect callers that Bifrost can prove without pretending that every possible caller was discovered. After this change, a match policy can opt into a bounded `proven_subset` call traversal. It will report the callers reached through resolved proven edges, visibly say that the result is a proven subset, preserve the omitted-candidate diagnostic, and still allow the policy batch to return findings rather than exit as unreliable. Ordinary `callers` and `callees` traversals remain exhaustive: an omitted candidate still makes their result inconclusive.

The behavior is observable with the Java `System.exit` chain from GitHub issue #1233. The explicit subset policy returns `directTerminate` and `secondOrderTerminate`, reports a `proven_subset` completion and declared-non-exhaustive diagnostic, and exits 1 because it has findings. The identical exhaustive query exits 2 with `partial_discovery`.

## Progress

- [x] (2026-07-28 14:19Z) Inspected the issue, fetched `origin`, and traced its diagnostic from traversal through policy completion and batch exit status.
- [x] (2026-07-28 14:19Z) Chose an opt-in typed contract instead of weakening `proof: proven` or suppressing diagnostics.
- [x] (2026-07-28 15:12Z) Added the query-level traversal contract, canonical serialization, JSON validation, and RQL lowering.
- [x] (2026-07-28 15:12Z) Preserved declared omission metadata through detailed query execution and projected it to a reliable-but-non-exhaustive policy completion.
- [x] (2026-07-28 15:12Z) Rendered and parsed the new contract in JSON, human output, SARIF, documentation, and the VS Code policy UI.
- [ ] Add Java, Python, JavaScript, and TypeScript policy fixtures plus exhaustive, recursive, ambiguous, and no-caller controls.
- [x] (2026-07-28 15:12Z) Formatted, linted, and ran focused Rust and VS Code tests; reviewed the diff for whitespace errors.

## Surprises & Discoveries

- Observation: the omitted candidate is counted after proof filtering, so `proof: proven` does not by itself make the traversal safe to treat as exhaustive.
  Evidence: `src/analyzer/structural/search/expansions.rs` filters relation sites by proof before incrementing `omitted` when the next declaration has no exact indexed range.

- Observation: a policy run cannot be `Complete` while carrying the current `RunIncomplete` diagnostic.
  Evidence: `PolicyRun::validate_against_budget` checks diagnostic impact against `PolicyRunCompletion`, and `report_exit_status` assigns exit status 2 whenever completion is not complete.

- Observation: relation-layer omissions can be appended before the expansion result is finalized.
  Evidence: the first Java regression still produced `CallRelationCandidatesOmitted` after the expansion-only reclassification; `cached_call_relation` appends relation diagnostics directly, so eligible diagnostics must also be reclassified immediately after that call.

## Decision Log

- Decision: represent the author choice as `CallTraversalCompleteness::{Exhaustive, ProvenSubset}` on `CallTraversalFilter`, serialized as `completeness: "proven_subset"` in JSON and `:completeness proven-subset` in RQL.
  Rationale: it is explicit in the query’s canonical form, works consistently for saved JSON and RQL policies, and leaves `proof: proven` backward compatible.
  Date/Author: 2026-07-28 / Codex

- Decision: accept `proven_subset` only when `proof: proven`; reject it for `callees` until there is a separate use case.
  Rationale: the issue is specifically an incoming caller contract. Restricting it prevents a superficially similar but semantically unreviewed outgoing-graph promise, while the filter type may remain shared for future extension.
  Date/Author: 2026-07-28 / Codex

- Decision: add `PolicyRunCompletion::ProvenSubset` and `PolicyDiagnosticImpact::DeclaredNonExhaustive` rather than returning `Complete` or turning the diagnostic into an advisory.
  Rationale: a successful subset must be reliable enough for batch exit status 1, but it must never look exhaustive in JSON, terminal, SARIF, or editor output. A distinct completion and diagnostic preserve that distinction and keep report validation honest.
  Date/Author: 2026-07-28 / Codex

## Outcomes & Retrospective

The first implementation milestone is complete. A typed `proven_subset` contract is available only for `callers` with `proof: proven`; the default remains exhaustive. The issue's Java `System.exit` chain is covered end-to-end: the exhaustive policy returns exit status 2 with `inconclusive/partial_discovery`, while the explicit subset returns the same two findings, exit status 1, `proven_subset`, a retained omitted-candidates diagnostic, warning-style human/SARIF output, and partial finding evidence that says the result is non-exhaustive.

Focused validation passed:

    cargo fmt
    cargo check --lib --no-default-features
    cargo test --lib analyzer::structural::query --no-default-features
    cargo test --test policy_match_evaluation --no-default-features
    cargo test --test bifrost_policy_cli --no-default-features proven_subset_callers_are_visible_and_reliable_without_claiming_exhaustiveness
    npm --prefix editors/vscode run format
    npm --prefix editors/vscode run test:unit
    npm --prefix editors/vscode run format:check
    npm --prefix editors/vscode run typecheck
    npm --prefix editors/vscode run lint

The planned adapter matrix (Python, JavaScript, and TypeScript; recursion, ambiguity, and no-caller controls) remains intentionally incomplete. It is the next milestone, not evidence claimed by this implementation checkpoint.

## Context and Orientation

`src/analyzer/structural/query/ir.rs` owns the typed query plan. A call traversal currently contains a positive `depth` and an optional proof tier. `src/analyzer/structural/query/decode.rs`, `json.rs`, and `sexp.rs` turn JSON and RQL text into that plan and back into its canonical JSON form. `schema.rs` is the declarative registry that documents legal RQL operations and must remain the source of vocabulary.

`src/analyzer/structural/search/expansions.rs` walks caller and callee relations. A relation may be resolved well enough to prove a call but still lack an exact indexed declaration range that can be returned. Today that situation emits `call_relation_candidates_omitted` with incomplete impact. `src/analyzer/policy/evaluator.rs` adapts detailed query results into policy findings and turns incomplete query diagnostics into `partial_discovery`. `src/analyzer/policy/finding.rs` defines the canonical policy run, finding, completion, and diagnostic types. `src/analyzer/policy/coordinator.rs` chooses the CLI status: 0 for clean, 1 for findings, and 2 for an unreliable run.

Here, “exhaustive” means the analyzer can safely use an empty result to claim that no matching caller exists within the requested depth. A “proven subset” means every reported relationship is proved, but an omitted relationship may exist; therefore the result supports positive findings only and must not be read as all callers.

## Plan of Work

First extend `CallTraversalFilter` with a small enum whose default is exhaustive. Add schema-backed accepted labels, JSON decode validation, RQL lowering, canonical JSON output, and parser tests. The decoder will reject `proven_subset` without `proof: proven`, and will reject it on `callees`. The query schema and user documentation will state the negative-result limitation.

Next, carry the declared contract through call expansion. The engine must continue emitting the current omitted-candidate diagnostic and must not hide budget, parse, cancellation, or analyzer failures. It will additionally record a typed declared-subset outcome for only `CallRelationCandidatesOmitted` caused by a `callers` step whose filter is `proof: proven, completeness: proven_subset`. Detailed query output will serialize that outcome alongside its diagnostics, making direct query callers see the limitation.

Then update policy projection. The evaluator will recognize the declared subset outcome, keep the `call_relation_candidates_omitted` diagnostic with a new declared-non-exhaustive impact, and construct `PolicyRunCompletion::ProvenSubset` when no ordinary failure or incompleteness is present. This completion is batch-reliable but non-exhaustive. Existing exhaustive queries will retain `Inconclusive { partial_discovery }`. Policy finding evidence will include the traversal contract and omitted relation count or diagnostic references so a finding carries its bound.

Finally update all public consumers. JSON derives will expose the new tagged completion and diagnostic impact. Human rendering will say `proven subset (not exhaustive)` rather than `complete`; SARIF will emit a dedicated warning notification with the completion object; VS Code’s TypeScript union, status label/detail, completion icon, and report validation will recognize it. Tests will cover both the positive Java chain and the unchanged exhaustive control, then repeat the dynamic-language chain cases and recursive, ambiguous, and no-caller boundaries.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/c7b7/bifrost`.

1. Add `CallTraversalCompleteness` and wire the `completeness` option through `src/analyzer/structural/query/{ir.rs,schema.rs,decode.rs,json.rs,sexp.rs}`. Run:

       cargo test --lib analyzer::structural::query

   Expect parsing and canonical round-trip tests to distinguish the default exhaustive contract from the explicit proven subset contract.

2. Extend detailed structural-search result state and caller expansion so an eligible omission is marked as declared subset while its normal diagnostic remains present. Run the focused structural tests:

       cargo test --lib analyzer::structural::search

   Expect an exhaustive traversal with an omitted declaration to remain incomplete and the subset traversal to expose the same diagnostic plus declared scope.

3. Add `ProvenSubset` policy completion, declared-non-exhaustive diagnostic impact, evaluator projection, coordinator reliability semantics, and all render/editor handling. Run:

       cargo test --test policy_match_evaluation --test policy_rendering --test policy_sarif_rendering
       npm --prefix editors/vscode test -- --runInBand

   Expect the subset policy’s exit status to be 1 when it has findings, and its serialized output to say `proven_subset`; exhaustive control stays exit 2.

4. Add minimized inline policy projects and fixture-based adapter coverage for Java, Python, JavaScript, and TypeScript. Include direct and depth-two callers, one omitted/dynamic candidate, recursion, ambiguity, and no callers. Run the targeted tests from step 3, then:

       cargo fmt --check
       cargo clippy --all-targets --all-features -- -D warnings

5. Update this plan’s progress, discovery evidence, decision log, outcomes, and artifact notes with test results. Review the diff for accidental changes to unresolved-call semantics from #1249.

## Validation and Acceptance

The principal end-to-end test will write the issue’s Java source and two otherwise-identical policy files using the shared inline-project harness. The exhaustive RQL selector uses `(callers :depth 2 :proof proven ...)` and must retain the two findings but serialize `completion.type` as `inconclusive`, include `partial_discovery`, and return exit 2. The subset selector adds `:completeness proven-subset`; it must return the same two findings, serialize a distinct `proven_subset` completion and declared non-exhaustive diagnostic, include the omitted-candidate evidence, and return exit 1.

JSON, human, and SARIF tests must each assert the visible `proven_subset` wording/type. TypeScript tests must parse it and show a warning-style status that says it is not exhaustive. Direct, depth-two, recursive, ambiguous, and empty-result cases must prove that the option never invents callers and never turns budget, parse, capability, cancellation, or ambiguity-related incompleteness into a successful subset.

## Idempotence and Recovery

The implementation is additive and test-driven. Re-running formatting and test commands is safe. If a focused test leaves build artifacts, use the repository’s normal target directory; use `scripts/with-isolated-cargo-target.sh` only when an isolated build is needed, because it removes its temporary target automatically. Do not delete existing project caches or the active branch. If the design reveals that a direct query cannot express declared scope without a broader result-model change, retain the exhaustive behavior and extend the typed result model rather than bypassing diagnostics in the policy renderer.

## Artifacts and Notes

Initial diagnostic trace:

    CallTraversalFilter -> call_declaration_expansions ->
    CALL_RELATION_CANDIDATES_OMITTED (incomplete) ->
    PolicyIncompleteReason::PartialDiscovery -> exit status 2

The chosen replacement is:

    explicit :completeness proven-subset + :proof proven ->
    preserved omission diagnostic + declared non-exhaustive policy completion ->
    exit status 1 only when findings meet the requested threshold

## Interfaces and Dependencies

At completion, `src/analyzer/structural/query/ir.rs` will expose a call-traversal completeness enum and `CallTraversalFilter` will contain it. `src/analyzer/policy/finding.rs` will expose a serialized `PolicyRunCompletion::ProvenSubset` variant and a `PolicyDiagnosticImpact::DeclaredNonExhaustive` variant. `PolicyRunCompletion` will provide separate methods for “reliable for batch exit status” and “exhaustive enough for a negative conclusion”; callers must not infer either property from the enum spelling alone.

The implementation uses existing Rust, Serde, and repository test helpers only; it introduces no third-party dependency.

Revision note (2026-07-28 14:19Z): created after diagnosing #1233 and choosing an explicit typed proven-subset contract.

Revision note (2026-07-28 15:12Z): implemented the Java end-to-end slice, public renderers, editor parsing, and focused validation; recorded the remaining cross-language matrix as a separate unfinished milestone.
