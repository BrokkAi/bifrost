# Define the internal finite-state protocol IR and reusable typestate client for issue #822

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` current as implementation
proceeds. This document follows `.agents/PLANS.md` and is self-contained for a
reader who has not read the umbrella roadmap.

## Purpose / Big Picture

Bifrost already lowers supported source languages into one normalized semantic
IR, materializes context-respecting ICFG topology, resolves value/dispatch/heap
facts through bounded oracles, and runs finite distributive data-flow clients
through bounded snapshot and recursive summary solvers. What is missing is the
client layer that describes a finite-state object protocol once and applies it
without teaching the solver or a language adapter about typestate.

After this work, an embedding can construct or deserialize one internal,
versioned resource-lifecycle protocol, validate and compile it deterministically,
bind its neutral semantic events to structured program facts, run it through the
shared solver for equivalent TypeScript and Java projects, and receive
diagnostic-neutral violations with proof, completeness, and bounded witness
metadata. The same compiled protocol hash is independent of language, policy
identity, messages, classifications, report limits, and run-local dense IDs.

The first independently reviewable checkpoint is smaller: freeze the internal
protocol IR, validation rules, canonical bytes/hash, deterministic rendering,
and a standalone `open -> use* -> close` fixture. No solver propagation is
required for that checkpoint.

## Progress

- [x] (2026-07-25 10:28+02:00) Fetched the live remote, fast-forwarded the
  issue branch to `origin/master` commit `d8e3e15f`, verified issue #822 and its
  prerequisite/coordination issues, and confirmed the worktree was otherwise
  clean.
- [x] (2026-07-25 10:28+02:00) Audited the landed semantic IR, value/heap
  oracles, bounded solver, recursive summary solver, direct client, public
  policy typestate scaffolding, and existing umbrella roadmap.
- [x] (2026-07-25 10:28+02:00) Identified active solver children #1171
  (bounded witness reconstruction, already checked out in another worktree) and
  #1172 (IDE edge-function/value propagation). Removed generic witness
  implementation from #822 and recorded an explicit solver-backend gate before
  client propagation.
- [x] (2026-07-25 10:28+02:00) Wrote this issue-specific ExecPlan.
- [x] (2026-07-25 10:31+02:00) Committed the plan as `ea604505` after
  fast-forwarding the issue branch to the fetched `origin/master`.
- [x] (2026-07-25 11:08+02:00) Implemented the bounded, versioned internal
  protocol model, dense compiled IDs, validation diagnostics, linear guard
  determinism checks, canonical rendering/hash, and the policy-layer hash
  compatibility re-export. Existing policy hash tests and strict library
  clippy pass.
- [x] (2026-07-25 11:16+02:00) Added and validated the language-neutral
  resource-lifecycle fixture plus behavior tests covering canonical
  order-independence, explicit violations, non-absorbing error states, normal
  and exceptional exits, invalid bindings/graphs, and hard source bounds.
- [x] Implement and validate the internal protocol model, compiler,
  canonicalization, typed hash, deterministic rendering, and lifecycle fixture.
- [ ] Run the guided specialist review over the first protocol checkpoint and
  resolve every actionable finding.
- [ ] Define the pre-resolved subject/event binding plan and choose the
  fact-product or IDE client representation after synchronizing the live #1172
  result.
- [ ] Implement typestate propagation, diagnostic-neutral findings, explicit
  uncertainty semantics, and consumption of #1171's generic witness API.
- [ ] Add controlled-graph and equivalent TypeScript/Java conformance fixtures,
  complete repository validation, and final guided review.

## Surprises & Discoveries

- Observation: the generic summary solver is present even though epic #820
  remains open.
  Evidence: commits `201770cd` and `3e94f809` added the bounded and recursive
  summary solvers under `src/analyzer/dataflow/`; the current module exports
  `solve`, `solve_with_summaries`, `DirectFlowProblem`, proof/completeness
  frontiers, and deterministic work budgets.

- Observation: solver callbacks cannot safely discover semantic bindings while
  propagating.
  Evidence: `DistributiveDataflowProblem` callbacks receive `&self`, one
  `DataflowEdge`, one finite fact, and a bounded output sink. They have no
  mutable `SemanticRequest` or oracle budget and must be finite, repeatable, and
  independent of invocation order. Object and event resolution therefore
  belongs in a pre-solve binding phase.

- Observation: #709 already exposes typestate authoring and reporting shapes,
  but those are deliberately not the internal solver model.
  Evidence: `src/analyzer/policy/definition.rs` owns
  `TypestateAutomatonSpec`, while the umbrella roadmap and issue #822 assign
  internal `ProtocolSpec` and diagnostic-neutral `TypestateFinding` ownership
  to #822. Importing policy identity, messages, severity, loading, or SARIF
  would reverse the dependency.

- Observation: the canonical protocol digest domain was reserved before the
  internal protocol compiler existed.
  Evidence: `src/analyzer/policy/future_evidence.rs` defines
  `TypestateProtocolHash::from_canonical_bytes` using
  `bifrost-typestate-protocol/v1`. The digest implementation must move to, or
  be owned by, the internal typestate layer while the policy module keeps a
  compatible re-export/adapter surface.

- Observation: generic witness reconstruction is already active parallel work.
  Evidence: issue #1171 owns a language-neutral predecessor/evidence IR,
  bounded iterative reconstruction across summary replay, and a downstream
  adapter seam for #822 and #709. Its branch is checked out in
  `/Users/dave/.codex/worktrees/1b57/bifrost`. #822 must consume the landed API,
  not edit the same solver tables independently.

- Observation: #1172 may offer a more compact protocol-state representation but
  is not required to define protocol semantics.
  Evidence: the current fact-only solver can encode `(abstract object,
  protocol state, uncertainty)` as a finite fact product. #1172 separately owns
  value lattices and edge-function composition. The protocol checkpoint can
  proceed independently; client representation is a named gate after syncing
  the live solver work.

- Observation: the shell resolves `cargo` and `rustc` through rustup but
  resolves `clippy-driver` from Homebrew, producing an incompatible-crate
  failure despite matching version strings.
  Evidence: both isolated and ordinary `cargo clippy` failed in `build.rs`
  until the rustup toolchain directory was prepended to `PATH`; the corrected
  strict library clippy invocation then passed.

## Decision Log

- Decision: keep the internal typestate module independent of
  `analyzer::policy`.
  Rationale: #822 owns executable protocol semantics; #709 owns public
  authoring, diagnostic authority, and rendering; #824 owns lowering and
  adapters between them. Dependency flow is `policy/compiler -> typestate`,
  never `typestate -> policy`.
  Date/Author: 2026-07-25 / Codex

- Decision: use durable validated string keys in `ProtocolSpec` and assign
  compact numeric IDs only in `CompiledProtocol`.
  Rationale: authored/order-independent protocol identity must survive run-local
  interning and support deterministic validation diagnostics. Dense IDs are
  execution details and cannot enter canonical bytes or persisted keys.
  Date/Author: 2026-07-25 / Codex

- Decision: separate `ProtocolHash` from a later binding-plan hash.
  Rationale: the same language-neutral automaton must run over TypeScript and
  Java and over different selected subjects. Protocol semantics determine the
  protocol hash; resolved program identities, endpoint dominance, and selected
  event sites determine a separate binding identity owned at the #822/#824
  seam.
  Date/Author: 2026-07-25 / Codex

- Decision: canonicalize semantically unordered sets and relations before
  rendering or hashing.
  Rationale: state, event, transition, accepting/error-set, and expectation
  declaration order must not change the compiled protocol hash or validation
  result. Validation occurs before dense assignment, and canonical order is
  defined explicitly rather than inherited from hash-map iteration.
  Date/Author: 2026-07-25 / Codex

- Decision: accepting and error states are observable classifications, not
  implicit absorbing states.
  Rationale: the issue explicitly requires continued tracking so later events
  can expose use-after-close, double-close, recovery, or repeated violation
  behavior. Only declared transitions change state.
  Date/Author: 2026-07-25 / Codex

- Decision: terminal expectations remain separate from transitions.
  Rationale: “still open at normal analysis-root exit” is an observation over a
  terminal state set, not a fabricated semantic event or transition to an error
  state. Normal and exceptional root exits remain distinct.
  Date/Author: 2026-07-25 / Codex

- Decision: protocol event predicates refer to neutral semantic event classes
  and typed observation phases, not source syntax or policy selectors.
  Rationale: #824 resolves public endpoint selectors to these classes. #822
  consumes structured allocations, calls, returns, field operations, escapes,
  and procedure exits without scanning text or branching on language.
  Date/Author: 2026-07-25 / Codex

- Decision: do not implement generic predecessor/witness storage in this
  branch.
  Rationale: active issue #1171 owns exactly that solver infrastructure.
  #822's finding layer will consume its generic result and translate it into
  diagnostic-neutral typestate witnesses without importing public policy
  types.
  Date/Author: 2026-07-25 / Codex

- Decision: defer the fact-product versus IDE representation choice until the
  protocol checkpoint is reviewed and the live #1172 state is synchronized.
  Rationale: both representations can implement the same `CompiledProtocol`
  semantics. Choosing before the generic IDE contract stabilizes risks either
  duplicating #1172 or constraining it from a single client.
  Date/Author: 2026-07-25 / Codex

- Decision: commit after every plan step and review-fix checkpoint, fetch
  `origin/master` frequently, and merge it without rebasing or switching the
  issue branch.
  Rationale: this is the user's explicit execution instruction and preserves
  inspectable milestones while respecting the repository's current-branch
  workflow.
  Date/Author: 2026-07-25 / Codex

## Outcomes & Retrospective

Implementation has not started. The starting branch is
`822-epic-define-finite-state-protocol-ir-and-a-reusable-typestate-client`
at `d8e3e15f`, equal to the fetched `origin/master` and ahead of its existing
issue-branch upstream only by the two fast-forwarded upstream commits.

Update this section after each reviewed checkpoint with exact commits, test
commands, remaining acceptance gaps, and any changes to issue boundaries.

## Context and Orientation

`src/analyzer/semantic/ir/model.rs` defines normalized `SemanticEffect` rows.
Each `ProgramPoint` owns a finite event slice. Effects include entry, normal
and exceptional exit, allocation, assignment/value flow, memory load/store,
invoke, call continuation, procedure return, throw, async operations, and
explicit semantic gaps.

`src/analyzer/semantic/ir/artifact.rs` owns immutable `SemanticArtifact` and
`ProcedureSemantics` values. `ProcedureHandle`, `ProgramPointHandle`,
`CallSiteHandle`, value handles, and memory-location handles pair local dense
IDs with one artifact instance. Protocol execution must keep these scoped
identities intact.

`src/analyzer/semantic/oracle/traits.rs` exposes bounded dispatch, value-flow,
call-binding, points-to/location, alias, and update-eligibility operations.
These operations return explicit proof/completeness outcomes. A binding phase
uses them before solver callbacks begin.

`src/analyzer/dataflow/problem.rs` defines `DistributiveDataflowProblem` and
`BoundedSnapshotDataflowProblem`. A client fact is finite, copyable, hashable,
and ordered. Five unary transfer families cover local normal, call, matched
return, explicit call-to-return, and exceptional flow. The solver preserves a
distinguished zero fact and canonicalizes bounded callback outputs.

`src/analyzer/dataflow/summary.rs` runs the same transfer relation from a root
`ProcedureHandle` through query-local recursive fixed points. Its
`TabulationEndSummary` is solver-internal reachability evidence, not the
cross-query `ProtocolSummary` owned by #823.

`src/analyzer/policy/definition.rs`, `resolved.rs`, and
`future_evidence.rs` own public policy-authoring and reporting-projection
contracts. They may consume internal protocol hashes and findings through
#824, but the internal module must not consume them.

In this plan:

- a protocol key is a durable validated string used by a declarative spec;
- a compiled ID is a compact numeric index assigned after canonicalization;
- a semantic event class is a language-neutral description such as allocation,
  resolved receiver call, return, field access, escape, or procedure exit;
- an observation phase says whether an event is inspected at a match, before a
  call, after a normal return, or after an exceptional return;
- a subject binding pairs one abstract object/fact identity with an initial
  protocol state;
- a terminal expectation requires a non-empty state set at a distinct normal
  or exceptional analysis-root exit;
- a diagnostic-neutral finding describes an analysis fact and witness, not a
  message, severity, CWE, CVSS score, or SARIF result.

## Plan of Work

### Milestone 1: freeze the internal protocol contract

Create `src/analyzer/typestate/mod.rs`, `protocol.rs`, and `hash.rs`, and export
the module from `src/analyzer/mod.rs`.

`ProtocolSpec` is a versioned deserializable declarative shape containing
durable state/event/expectation keys, initial state, accepting/error sets,
neutral event predicates, typed observation phases, guarded transitions over
finite structured conditions, terminal expectations, and explicit uncertainty
behavior. The first schema supports only finite guards expressible from
structured binding facts; arbitrary predicates and SMT expressions are
rejected.

`CompiledProtocol` owns canonical dense state/event/expectation IDs, transition
rows, state classifications, terminal rows, canonical bytes, deterministic
rendering, and `TypestateProtocolHash`. It exposes lookup operations needed by
the future client without exposing hash-map iteration or source declaration
order.

Validation is deterministic and bounded. It rejects unsupported schema
versions, invalid/oversized keys, duplicate states/events/expectations,
missing initial or referenced states/events, duplicate conflicting
transitions, empty/invalid terminal expectations, unsupported event/phase or
binding/guard combinations, unstable durable identities, and unreachable
states under the declared reachability policy. Diagnostics are sorted by a
stable field/key order and carry bounded paths into the internal spec.

Canonical bytes are produced only from a valid normalized protocol. Sets and
relations are sorted explicitly. The schema version and every
semantics-affecting uncertainty/guard value participate. Dense IDs, source
file paths, policy metadata, display messages, and binding-plan identities do
not. The existing `bifrost-typestate-protocol/v1` digest domain moves to the
internal hash type; the policy layer imports or re-exports that type without
changing the digest.

Add `tests/fixtures/typestate/resource-lifecycle.protocol.json` and
`tests/typestate_protocol.rs`. The fixture declares `unallocated`, `open`,
`closed`, and violation-capable behavior for acquire, use, and close events.
Tests cover valid compilation, declaration-order invariance, stable canonical
rendering/hash, duplicate/missing/unreachable/invalid rows, accepting/error
non-absorption, normal versus exceptional terminal expectations, and a
degenerate one-state protocol.

Run the guided specialist review in branch-vs-merge-base mode after the
checkpoint commit. Resolve actionable findings in a separate review-fix
commit, then rerun the focused tests and strict Clippy.

### Milestone 2: define execution bindings without public policy coupling

Synchronize `origin/master` and inspect #1172 before editing. Create
`src/analyzer/typestate/binding.rs` with a finite pre-resolved plan:

- stable subject classes and run-local subject/object IDs;
- explicit initial object/state seeds;
- event observations keyed by scoped program point/call identity and phase;
- neutral event IDs already resolved against `CompiledProtocol`;
- object roles such as allocation result, receiver, argument, formal, return,
  field location, or escaped object;
- proof/completeness and ambiguity for every retained binding;
- distinct normal/exceptional terminal observations;
- a separate canonical binding-plan hash that excludes policy presentation.

The production binding builder consumes semantic artifacts and bounded oracle
outcomes before the solver starts. It never stores raw syntax names as exact
dispatch evidence and never calls an oracle from a transfer callback. #824 may
later construct the same plan from resolved public endpoints without importing
policy types into `typestate`.

Focused tests use structured semantic fixtures and explicit fake/bounded
oracles to prove deterministic plan identity, alias-preserving object identity,
same-name false-positive rejection, incomplete dispatch retention, and
independence from protocol declaration order.

### Milestone 3: implement the solver client and findings

At this gate, choose and record one of:

1. a finite IFDS-style fact product over object, protocol state, and uncertainty
   using the existing solver; or
2. the landed #1172 IDE layer with object facts and protocol-state values.

The choice must preserve the same `CompiledProtocol`, binding plan, finding,
and test contracts. It must not add typestate branches to `dataflow`.

Create `src/analyzer/typestate/client.rs` and `finding.rs`. The client applies
event observations at their declared phases across local, call, matched-return,
call-to-return, and exceptional transfer families. Accepting/error states
continue propagating unless a transition changes them. Ambiguous dispatch,
unknown external calls, escape, cleanup, and incomplete semantic inputs obey
the protocol's explicit conservative-transition, preserve-uncertainty, or
abstain/inconclusive behavior.

Post-solve aggregation emits:

- error-transition violations;
- invalid-event-in-state violations when declared;
- unmet normal or exceptional terminal expectations;
- may findings when at least one retained valid-path state violates;
- must findings only when complete discovery/propagation proves every relevant
  retained state violates;
- explicit inconclusive outcomes when coverage, binding, escape, budgets, or
  uncertainty cannot support a complete negative or must result.

Consume #1171's generic witness reconstruction once it lands. Translate generic
solver steps into bounded, source-backed diagnostic-neutral typestate witness
steps. Witness truncation downgrades witness/finding evidence but does not
change solver reachability, termination, or protocol state.

Controlled-graph tests cover local transitions, branches, helper calls,
aliases, normal and exceptional matched returns, explicit call-to-return
boundaries, direct/mutual recursion, summary reuse without cross-return,
ambiguous/unknown dispatch, escape, cancellation, all applicable budgets, and
permutation determinism.

### Milestone 4: prove cross-language reuse and downstream seams

Add `tests/typestate_language_contract.rs` using `InlineTestProject` and the
real workspace semantic provider/oracles. Equivalent TypeScript and Java
fixtures use the same `CompiledProtocol` and assert equal protocol hashes.
They cover acquire/open, repeated use, close, use-before-open, use-after-close,
double-close, branch-dependent close, helper calls/returns, an alias, recursive
helper reuse, normal exit while open, and one exceptional path.

Language-specific code may lower syntax into the already shared semantic IR and
oracles, but neither the protocol nor client may branch on language. Exact
same-name calls outside the bound endpoint identity and unresolved field/name
guesses do not fire proven transitions.

Update the sealed policy adapter seam only as needed so #824 can later lower
`ResolvedTypestatePolicySpec` into the same internal canonical protocol and
binding hash. Do not implement RQL/CodeQuery typestate syntax, policy loading,
SARIF, `ProtocolSummary`, or persistence here.

Run focused tests, formatting, strict all-feature Clippy, the full
`nlp,python` suite, and a final guided branch-vs-merge-base review. Commit every
review fix separately and leave the branch clean.

## Concrete Steps

Work only on the already checked-out branch:

    /Users/dave/.codex/worktrees/00be/bifrost
    822-epic-define-finite-state-protocol-ir-and-a-reusable-typestate-client

Before each milestone and before each guided review:

    git status --short --branch
    git fetch origin
    git rev-list --left-right --count origin/master...HEAD

If `origin/master` is ahead and the worktree is clean, merge it on the current
branch without switching branches or rebasing:

    git merge origin/master

After writing this plan, stage and commit only this file:

    git add .agents/plans/issue-822-finite-state-protocol-typestate-client.md
    git commit

For the protocol checkpoint:

    cargo fmt
    cargo test --test typestate_protocol
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

For the binding/client checkpoint:

    cargo fmt
    cargo test --test typestate_protocol --test typestate_binding --test typestate_client
    cargo test --test dataflow_clients --test dataflow_tabulation --test dataflow_summaries

For cross-language and final acceptance:

    cargo fmt
    cargo test --test typestate_protocol --test typestate_binding --test typestate_client --test typestate_language_contract
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

The exact test counts are recorded after the test binaries exist. Every focused
command must end with `test result: ok`; strict Clippy must emit no warnings.
The full feature suite must not download models or start semantic indexer
threads.

At every checkpoint:

1. inspect `git diff --check`, `git status`, and the exact files to stage;
2. stage only files changed for that milestone;
3. create a multiline commit explaining the behavior and why the boundary is
   placed there;
4. fetch and reconcile `origin/master`;
5. run guided review when the checkpoint is named above;
6. apply and commit review fixes separately.

## Validation and Acceptance

The protocol checkpoint is accepted when:

- equivalent declaration orders compile to identical canonical bytes and hash;
- all durable IDs and references validate deterministically;
- invalid, conflicting, unreachable, and unsupported rows produce bounded,
  stable diagnostics;
- accepting/error states do not become implicitly absorbing;
- terminal expectations remain distinct normal/exceptional observations;
- the one-state protocol compiles without a special case;
- `typestate` has no dependency on `policy`, source-language modules, or RQL.

The client checkpoint is accepted when:

- one client-supplied automaton runs without typestate-specific solver code;
- helpers, branches, aliases, recursion-safe summary replay, normal returns,
  exceptional returns, and call-to-return boundaries behave context-respectingly;
- ambiguity, unknown calls, escape, cleanup, and incomplete inputs never
  silently disappear;
- must findings require complete evidence and incomplete runs never become
  complete-no-finding;
- bounded witnesses preserve exact call/return matching and report truncation
  independently from solver completeness.

The language checkpoint is accepted when:

- equivalent TypeScript and Java fixtures use one internal protocol and hash;
- exact structured identities fire transitions while same-name/unresolved
  guesses do not become proven events;
- violations retain source locations, proof/completeness, and a bounded witness;
- the internal fixture supplies the canonical target needed by #824 without
  importing policy identity or serialization shapes;
- all focused, lint, and full feature gates pass after final review.

## Idempotence and Recovery

Protocol compilation, canonical rendering, hashing, formatting, and tests are
safe to rerun. New caches or persisted rows are out of scope.

If validation or canonicalization changes after a checkpoint, increment the
internal protocol schema/hash domain only when semantics changed; do not
silently reinterpret existing canonical bytes. Record the migration and reason
in this plan.

If #1171 or #1172 changes overlapping solver APIs, stop client edits, fetch and
merge their landed commits through `origin/master`, update this plan's
decision/progress record, and adapt at the public solver seam. Do not copy
unmerged code from another worktree.

If a language fixture exposes a real structured capability gap, preserve the
explicit incomplete outcome and fix the shared semantic/oracle source when it
is in scope. Do not add regex, substring, delimiter-scanning, or source-text
fallbacks.

Do not create branches, switch branches, rebase, or stage unrelated files.
Generated `.brokk/` cache files are not source changes and must not enter a
commit.

## Artifacts and Notes

- Issue #822: internal finite-state protocol and reusable typestate client.
- Issue #1171: generic bounded witness reconstruction; active parallel
  dependency.
- Issue #1172: generic IDE edge-function/value propagation; representation
  gate before client implementation.
- Issue #823: reusable cross-query semantic/taint/protocol summaries; excluded.
- Issue #824: public CodeQuery/RQL compiler, registry, and policy adapters;
  excluded except for preserving the internal seam.
- `.agents/plans/language-agnostic-composable-typestate-platform.md`: umbrella
  architecture and issue ownership.

Record milestone commit hashes, review outcomes, and exact final test counts
here as work proceeds.
