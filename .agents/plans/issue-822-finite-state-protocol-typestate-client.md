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
- [x] (2026-07-25 12:04+02:00) Ran the first guided specialist review over
  `origin/master...7bc66c0c`; it produced two high, seven medium, and three low
  findings. The user authorized automatic triage, and all twelve were judged
  relevant and tractable.
- [x] (2026-07-25 12:20+02:00) Resolved the review's input/shared-infrastructure
  findings: bounded-only top-level deserialization, fixed-domain guard
  normalization, randomized untrusted-key maps, escaped diagnostics, durable
  expectation lookup, and shared policy-neutral identifier/hash primitives.
- [x] (2026-07-25 12:44+02:00) Resolved the public-lowering blockers by
  separating neutral event occurrence from object binding, covering
  receiver/argument/return endpoint phases and procedure exits, allowing
  terminal checks at bound events as well as analysis-root exits, widening
  resolved positional bindings to `u32`, and deriving violation identity from
  transition tuples/expectation IDs instead of free-form strings.
- [x] (2026-07-25 12:58+02:00) Made uncertainty semantics executable:
  ambiguous dispatch resolves to a reflexive one-event state relation;
  unknown/external calls, escape, and incomplete analysis resolve to a
  reflexive transitive relation; preserve and abstain are explicit outcomes.
  The compiled iterative traversal is bounded by protocol states/transitions.
- [x] (2026-07-25 13:09+02:00) Added exact compact-canonical,
  pretty-rendering, and SHA-256 golden fixtures for the schema-v1 lifecycle
  protocol. All twelve first-review findings are now addressed; strict
  checkpoint validation and the automatic follow-up review remain.
- [x] (2026-07-25 13:42+02:00) Strict all-target/all-feature Clippy passed
  through the isolated-target helper after correcting the local rustup
  `clippy-driver` path.
- [x] (2026-07-25 14:18+02:00) Ran the automatic follow-up guided review. It
  found six remaining actionable issues: binding-specific identities in the
  protocol hash, unscoped uncertainty transitions, an aggregate expectation
  allocation bound, equivalent full-domain guard identity, Windows golden
  line endings, and raw JSON error rendering.
- [x] (2026-07-25 14:41+02:00) Resolved all six follow-up findings. Protocol
  observations now contain occurrence only; uncertainty accepts an explicit
  bounded eligible-event set; expected-state memberships have a shared
  aggregate budget; full-domain guards canonicalize to `always`; canonical
  fixtures are LF-pinned; and parse errors retain bounded escaped text plus
  separate line/column metadata. All 12 focused protocol tests and strict
  all-target/all-feature Clippy pass.
- [x] (2026-07-25 14:58+02:00) Fetched `origin/master` after the reviewed
  checkpoint and confirmed this branch contains it. Live coordination shows
  substantial uncommitted #1171 witness work isolated in its own worktree,
  while #1172 has no active branch or worktree.
- [x] (2026-07-25 15:17+02:00) Chose the existing finite IFDS fact-product
  representation for the typestate client. Moved
  `TypestateBindingPlanHash` ownership to the internal typestate layer while
  preserving the policy re-export.
- [x] (2026-07-25 15:21+02:00) Defined the bounded pre-resolved binding-plan
  contract: deterministic subject IDs, semantic object roles, exact
  point/call/context indexes, proof/completeness/multiplicity retention, and a
  separate schema-v1 canonical binding hash. Stable subject, site, and context
  identity is derived from validated semantic handles rather than accepted
  from callers. Focused behavior tests and strict all-feature Clippy pass.
- [x] (2026-07-25 15:38+02:00) Implemented the first reusable
  `DistributiveDataflowProblem` client over the finite subject/state/uncertainty
  fact product. Ordered bindings execute at local, before-call,
  actual-to-formal, return, and continuation phases; partial evidence remains
  explicit; proven escape obeys protocol uncertainty semantics; and a binding
  plan cannot execute against a different protocol hash. All 27 protocol,
  binding, and client tests plus strict focused all-feature Clippy pass.
- [x] (2026-07-25 15:47+02:00) Exercised the same client through the real
  recursive-summary runner over TypeScript helper calls. Added a stable
  call-program-point index so unresolved/origin-less continuation edges still
  execute bound before/after endpoint phases, while materialized calls retain
  their exact-origin call/return behavior. All 16 binding/client tests and
  strict focused all-feature Clippy pass.
- [x] (2026-07-25 16:01+02:00) Added bounded diagnostic-neutral finding
  aggregation for exact error transitions and root/event terminal
  expectations. Non-propagating marker facts preserve exact binding identity;
  may results survive incomplete coverage; must results require complete,
  proven, uncertainty-free reached state sets; and incomplete successful
  terminal observations become explicit inconclusive findings. All 29 focused
  tests and strict client all-feature Clippy pass.
- [x] (2026-07-25 17:08+02:00) Ran the client/finding guided review. It found
  context flattening, skipped procedure exits, unreachable unknown/external
  semantics, incomplete quality composition, cross-plan dense-ID confusion,
  callback expansion, conservative error-state loss, incorrect May/Must
  classification, and quadratic/unbounded post-processing. All findings were
  accepted under the user's automatic-fix policy.
- [x] (2026-07-25 17:46+02:00) Hardened the execution contract: official
  summary runs/results and every nonzero fact are binding-plan branded;
  context-specific plans are rejected rather than flattened; analysis-root
  ownership and exact exit kinds are validated; summary call-to-return edges
  retain structured dispatch-boundary causes; and subject/row quality is
  composed. Focused typestate and all generic dataflow regressions pass.
- [x] (2026-07-25 18:13+02:00) Replaced repeated callback-wide
  flat-map/sort/dedup cycles with a deterministic relation bounded by retained
  facts and expansion attempts. Overflow collapses to an explicit abstained
  incomplete state. Conservative uncertainty now retains canonical
  error-transition witnesses, so possible error reachability remains
  reportable.
- [x] (2026-07-25 18:48+02:00) Replaced per-marker/per-terminal result rescans
  with two bounded linear passes plus bounded candidate sorting. Finding
  post-processing has explicit limits and cancellation; May requires a proven
  uncertainty-free violating path; event-specific Must remains inconclusive
  without universal marker proof; and terminal quality affects certainty and
  end-to-end completeness. All 75 focused typestate/generic dataflow tests and
  strict targeted Clippy pass.
- [x] (2026-07-25) Completed the automatic follow-up review over the
  client/finding checkpoint. It found stale exit observations, cross-path
  evidence contamination, no universal error-transition proof for Must mode,
  collapsed conservative error witnesses, dense-ID fact laundering,
  cancellation/budget gaps, and bounded-snapshot boundary loss. The
  source-backed path-witness finding remains dependency-blocked on #1171; every
  other finding was accepted under the user's automatic-fix policy.
- [x] (2026-07-25) Applied return/boundary effects before exit observations,
  retained every distinct conservative error transition, and added
  non-propagating safe-transition facts. May findings retain an independently
  clean violating path, while Must findings now require complete proven paths
  and the absence of any safe outcome for the same event binding.
- [x] (2026-07-25) Made typestate facts opaque and changed the public entry-fact
  constructor to resolve durable `TypestateSubjectKey` and `ProtocolStateKey`
  values. Added cooperative callback checkpoints and one hard finding budget
  across violation, safe-outcome, event-terminal, and root-state aggregates.
- [x] (2026-07-25) Preserved typed dispatch boundaries through bounded ICFG
  edges and `DataflowEdge::from_snapshot`; a deferred Rust conformance case now
  proves bounded and summary clients receive the same structured cause.
- [x] (2026-07-25) Added controlled source-backed TypeScript/Java conformance.
  One compiled lifecycle protocol and one transfer client execute the same
  pre-resolved reference-alias subject and reach the same closed state without
  language branches.
- [x] (2026-07-25) Merged the landed #1171 witness implementation from
  `origin/master` (`c8df49d3`, PR #1176) and consumed its index-based bounded
  reconstruction API. Typestate finding projection now attaches bounded
  state-keyed source witnesses without rescanning the reached relation.
- [x] (2026-07-25) Bounded witness reporting to 16 witnesses per finding, 64
  steps and 4,096 reconstruction expansions per witness, 65,536 retained
  relations, 64 MiB of retained sidecar evidence, and aggregate finding-level
  expansion/byte budgets. Best-effort witness exhaustion cannot change solver
  reachability or termination.
- [x] (2026-07-25) Ran the final client/witness guided review and automatically
  fixed every accepted finding: proven-partial May evidence, semantic
  May/Inconclusive merging, request/byte/relation preflight, lazy full-slot
  admission, and truthful duplicate-versus-truncation metadata.
- [x] (2026-07-25) Strengthened the TypeScript/Java conformance fixture so a
  reference alias and observable `use -> used -> close` path must produce the
  same canonical exit-state/path-quality frontier. The fixture rejects any
  violation row, requires fixed-point termination, and records the current
  conservative TypeScript coverage gap explicitly.
- [x] (2026-07-26 00:18+02:00) Added direct client acceptance fixtures for a
  branch-dependent close/May finding, recursive Java helper summary replay,
  and an event on an exceptional matched return. Focused typestate tests pass
  28/28 and generic summary-dataflow tests pass 27/27.
- [x] (2026-07-26 00:44+02:00) The final intent recheck found that the first
  recursive fixture could observe its state change without recursive carryback
  and that the exceptional-return fixture used same-procedure synthetic
  topology. Commit `321e160f` now changes state only in the recursive base
  case, consumes it after recursive return, reaches `closed` at lifecycle exit,
  and verifies a real callee exceptional-exit witness to the exact caller
  handler. The focused 28-test client suite and strict client Clippy pass; the
  specialist recheck reports no remaining finding.
- [x] Implement typestate propagation, diagnostic-neutral findings, and
  explicit uncertainty semantics.
- [x] Consume #1171's generic witness API after it lands on `origin/master`.
- [x] Add controlled-graph and equivalent TypeScript/Java conformance fixtures.
- [ ] Complete repository validation and final guided review (completed:
  guided architecture/intent/robustness pass, automatic fixes, and post-fix
  intent recheck; remaining: final all-target/all-feature Clippy and full
  `nlp,python` test gate).

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
  adapter seam for #822 and #709. It landed through PR #1176 at `c8df49d3`;
  #822 consumes the result-owned, index-based reconstruction seam rather than
  duplicating solver predecessor tables.

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

- Observation: call-site subject selection is part of the resolved binding
  plan, not the protocol event definition.
  Evidence: a named argument may occupy different concrete positions at
  different call sites while representing the same public binding. Retaining
  `actual[index]` in `ProtocolObservationSpec` made that call-site detail alter
  the otherwise language-neutral protocol hash. The reviewed schema-v1
  protocol now records only occurrence and phase.

- Observation: uncertainty cannot conservatively mean every event in the
  protocol.
  Evidence: an ambiguous call at one site may conceal only the endpoint events
  resolved for that site; treating allocation, field, escape, and unrelated
  call events as candidates invented transitions. The executable API now
  requires a bounded eligible-event slice supplied by the binding/client layer.

- Observation: #1172 is not an implementation dependency for the first
  reusable client.
  Evidence: its issue remains open with no active branch/worktree, while the
  current summary solver already accepts finite copyable ordered client facts.
  A fact product over object, protocol state, and uncertainty implements the
  required semantics without solver changes and without waiting on an
  unstarted generic IDE layer.

- Observation: Bifrost structured symbol/source reads succeeded, but the
  related-file ranking and a later broad symbol search each timed out at the
  five-minute MCP limit and created a local `.brokk/` cache.
  Evidence: both calls returned `timed out awaiting tools/call after 300s`.
  Their generated caches were moved out of the worktree and no generated files
  were retained or staged.

- Observation: accepting caller-supplied semantic locators beside runtime
  handles makes a canonical binding hash unsound even when scope validation
  succeeds.
  Evidence: a locator can belong to the same artifact yet name a different
  value, point, call, or context than the paired handle. The binding contract
  now derives a stable structural object/site/context key from each validated
  handle, including call-result contexts and source-backed capture ports.

- Observation: semantic effect order and protocol/plan pairing are executable
  binding semantics, not incidental serialization details.
  Evidence: sorting co-located events by event ID can change a non-commutative
  automaton, while pairing compiled event IDs with a different protocol can
  silently reinterpret them. Event bindings now carry a per-subject/site
  ordinal with collision rejection, and canonical binding identity includes
  the compiled protocol hash.

- Observation: a source call is not guaranteed to appear as an origin-bearing
  ICFG edge.
  Evidence: the real summary provider represents unresolved call boundaries as
  origin-less local continuation edges; exact call handles therefore cannot be
  recovered from `DataflowEdge::origin`. The binding plan now derives a second
  index from each validated call handle to its program point and uses it only
  on origin-less normal/exceptional transfers.

- Observation: the current summary transfer descriptor is procedure-local and
  deliberately omits a dynamic call-stack context.
  Evidence: executing exact context-indexed bindings through its prior
  all-context lookup produced cross-context false transitions. The client now
  accepts only root-context plans and returns a typed error for context-specific
  plans, leaving exact context execution to a future context-aware backend.

- Observation: proof/completeness of the generic solver is necessary but not
  sufficient for a complete typestate result.
  Evidence: partial subject, event, or terminal bindings and runtime
  uncertainty can coexist with a fixed-point solver result. The branded
  typestate result now composes binding quality, uncertainty, abstention, and
  solver coverage into end-to-end completeness.

- Observation: solver callback and solver-state budgets do not bound work done
  before the first `DataflowOutput::emit`.
  Evidence: conservative closure expansion and repeated event/terminal rows
  could materialize and repeatedly sort a large intermediate relation inside
  one callback. The client now counts candidate expansions and retained facts
  in its own deterministic scratch relation and collapses overflow explicitly.

- Observation: snapshot and summary clients previously received different
  dispatch-boundary evidence.
  Evidence: `ProcedureIcfgEdge` retained `DispatchBoundaryKind`, but
  `SnapshotBuilder::link` dropped it when constructing `IcfgEdge`, so
  `DataflowEdge::from_snapshot` could expose only proof/completeness. Bounded
  ICFG edges now own the typed boundary and validate that it appears only on
  call-to-continuation edges.

- Observation: a finite may-analysis result needs separate aggregate evidence
  for clean and uncertain paths.
  Evidence: unioning uncertainty before classification caused one uncertain
  path to downgrade an independently proven violation. Aggregates now retain
  an explicit clean-proven frontier while still unioning all uncertainty for
  reporting and Must-mode conservatism.

- Observation: Must error-transition findings need explicit safe outcomes, not
  merely the absence of another error marker.
  Evidence: the distributive solver retains may facts. Exact non-error
  transitions now emit a non-propagating safe marker for the same event
  binding; complete analysis can promote an error marker to Must only when no
  such marker reaches the observation point.

- Observation: witness reconstruction is a best-effort reporting sidecar, so
  its admission path must not allocate after any witness budget is exhausted
  or change semantic reachability when evidence cannot be retained.
  Evidence: request-level relation capacity, per-result retained-byte/relation
  limits, and per-finding reconstruction budgets are checked before candidate
  construction. A borrowed exact-derivation match distinguishes replay of an
  already retained witness from a genuinely dropped alternative, preserving
  truthful truncation metadata without cloning.

- Observation: one witness slot cannot represent every evidentiary purpose of
  a finding.
  Evidence: a proven-partial clean path is sufficient to support a May finding,
  while Must needs proven-complete evidence and an uncertain proven-complete
  path may be the best explanation of an inconclusive result. Finding
  aggregation therefore retains separate definitive, May-supporting, and
  uncertain witness candidates.

- Observation: equivalent canonical state outcomes do not imply equivalent
  whole-program coverage across language frontends.
  Evidence: the controlled TypeScript and Java fixtures reach the same
  `used -> closed` state/path-quality frontier with the same protocol hash, but
  TypeScript still exposes conservative unresolved-call coverage while Java is
  complete. The fixture asserts both the shared outcome and each frontend's
  current completeness explicitly.

- Observation: a recursive carryback fixture must make the post-recursion
  observation depend on state produced in the recursive base case.
  Evidence: placing `use` before recursion allowed the outer frame to satisfy
  the test without consuming a recursive summary. The final Java fixture puts
  `use` only in the base branch, observes `used` at the outer close point, and
  observes `closed` at the lifecycle exit. Its incomplete-analysis behavior
  preserves explicit uncertainty because the current recursive semantic
  coverage is intentionally not claimed complete.

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

- Decision: object roles and concrete receiver/argument/formal/return
  selections exist only in the binding plan.
  Rationale: protocol identity describes when a neutral event is observed,
  while the binding plan describes which resolved program object that
  observation applies to. Keeping these separate makes named arguments and
  language-specific call layouts hash-independent.
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

- Decision: terminal expectations remain separate from transitions and carry a
  neutral observation trigger.
  Rationale: “still open at normal analysis-root exit” and “not closed after
  this bound endpoint” are observations over the current state set, not
  fabricated transitions to an error state. Root exit kinds and reusable bound
  event observations remain explicit.
  Date/Author: 2026-07-25 / Codex

- Decision: protocol event predicates refer to neutral semantic event classes
  and typed observation phases, not source syntax or policy selectors.
  Rationale: #824 resolves public endpoint selectors to these classes. #822
  consumes structured allocations, calls, returns, field operations, escapes,
  and procedure exits without scanning text or branching on language.
  Date/Author: 2026-07-25 / Codex

- Decision: do not implement generic predecessor/witness storage in this
  branch.
  Rationale: issue #1171 owns exactly that solver infrastructure.
  #822's finding layer will consume its generic result and translate it into
  diagnostic-neutral typestate witnesses without importing public policy
  types.
  Date/Author: 2026-07-25 / Codex

- Decision: consume #1171 through the result-owned O(1) reached-index API and
  keep typestate witness projection read-only over generic summary evidence.
  Rationale: per-finding linear rediscovery of reached rows can multiply into
  billions of comparisons, while separate typestate predecessor storage would
  duplicate the generic solver and risk divergent call/return matching.
  Date/Author: 2026-07-25 / Codex

- Decision: make witness retention and reconstruction semantically optional.
  Rationale: relation, byte, request, per-witness, aggregate-expansion, or
  aggregate-byte exhaustion may truncate/drop the reporting sidecar, but must
  never alter solver facts, reachability, completeness, or termination.
  Date/Author: 2026-07-25 / Codex

- Decision: retain purpose-specific definitive, May-supporting, and uncertain
  witness candidates before deterministic finding merge.
  Rationale: the evidence lattice for certainty is not one total ordering. A
  clean proven-partial path can justify May even beside uncertain evidence,
  while Must and inconclusive explanations require different qualities.
  Date/Author: 2026-07-25 / Codex

- Decision: test TypeScript/Java reuse with a pre-resolved alias identity and
  do not claim that #822 resolves source aliases itself.
  Rationale: #822 consumes a bounded binding plan; #824 owns public endpoint
  lowering and oracle-backed binding construction. The conformance test proves
  language-neutral protocol/client execution at that seam.
  Date/Author: 2026-07-25 / Codex

- Decision: check borrowed derivation equality before witness capacity checks
  and owned candidate construction.
  Rationale: exact replay is not a dropped alternative and must not set
  truncation. Comparing every constructor field against retained alternatives
  first avoids both false metadata and allocation on a full best-effort slot.
  Date/Author: 2026-07-25 / Codex

- Decision: defer the fact-product versus IDE representation choice until the
  protocol checkpoint is reviewed and the live #1172 state is synchronized.
  Rationale: both representations can implement the same `CompiledProtocol`
  semantics. Choosing before the generic IDE contract stabilizes risks either
  duplicating #1172 or constraining it from a single client.
  Date/Author: 2026-07-25 / Codex

- Decision: use an IFDS-style finite fact product for the #822 client.
  Rationale: #1172 is open and inactive, while the existing solver can encode
  `(object, protocol state, uncertainty)` directly. This preserves the
  protocol/binding/finding contracts and avoids either blocking on or
  duplicating the generic IDE work. A future IDE adapter may reuse the same
  contracts without changing schema-v1 identity.
  Date/Author: 2026-07-25 / Codex

- Decision: make semantic runtime handles the sole source of canonical binding
  identity.
  Rationale: independently supplied locators allow a valid runtime index and a
  different persisted identity to coexist, which can cause cache collisions or
  stale-plan reuse. Deriving source locators, port keys, and bounded call
  contexts from validated handles makes the runtime and canonical domains agree
  by construction.
  Date/Author: 2026-07-25 / Codex

- Decision: keep uncertainty in the client fact domain rather than inferring it
  only during finding projection.
  Rationale: ambiguous dispatch, incomplete edges, escape, unmatched events,
  and abstention change which state transitions are sound during propagation.
  Retaining a compact uncertainty set and abstention bit on each finite fact
  makes those semantics distributive and prevents incomplete paths from later
  appearing definitive.
  Date/Author: 2026-07-25 / Codex

- Decision: publish violation and event-terminal observations as finite
  non-propagating solver facts.
  Rationale: transfer callbacks cannot mutate a finding sink, and reconstructing
  the responsible event from a later error-state fact would lose the exact
  binding site. Marker facts preserve distributivity and boundedness, are
  retained at the immediate target for finding aggregation, and deliberately
  disappear on the next transfer.
  Date/Author: 2026-07-25 / Codex

- Decision: brand typestate facts and summary results with the exact canonical
  binding-plan hash.
  Rationale: subject, event-binding, and terminal-binding IDs are dense and
  run-local. Branding prevents a valid result or entry fact from being
  reinterpreted under another plan whose IDs happen to be in range.
  Date/Author: 2026-07-25 / Codex

- Decision: reject non-root binding contexts in the current summary client.
  Rationale: the procedure-local summary callback has no exact dynamic
  `OracleCallContext`; flattening would be unsound, while pretending the plan
  is context-insensitive would make its canonical identity dishonest.
  Date/Author: 2026-07-25 / Codex

- Decision: bound callback expansion and finding post-processing independently
  of generic solver budgets.
  Rationale: both phases can perform substantial work before or after generic
  propagation. Explicit deterministic caps and cancellation prevent valid
  worst-case protocols/results from bypassing the solver's operational
  envelope.
  Date/Author: 2026-07-25 / Codex

- Decision: keep public typestate facts opaque and accept durable keys at the
  entry-fact seam.
  Rationale: plan, subject, state, event, and terminal IDs are compact
  execution indexes. Allowing external enum construction or accepting numeric
  IDs and then stamping the current plan hash lets unrelated run-local
  identities appear valid. Durable keys are resolved only by the owning
  protocol and binding plan.
  Date/Author: 2026-07-25 / Codex

- Decision: represent exact safe event outcomes with finite non-propagating
  facts.
  Rationale: the may solver cannot infer universal violation from error markers
  alone. A bounded safe marker preserves distributivity, is deduplicated by the
  solver, and gives finding projection the negative evidence required for a
  complete Must proof.
  Date/Author: 2026-07-25 / Codex

- Decision: treat the finding candidate limit as a hard shared aggregation
  budget rather than partial truncation.
  Rationale: counting only error rows allowed terminal and root-state maps to
  bypass the limit, while counting omitted reached rows did not describe
  unique findings. Hard failure is deterministic and prevents a partial report
  from misrepresenting which identities were dropped.
  Date/Author: 2026-07-25 / Codex

- Decision: commit after every plan step and review-fix checkpoint, fetch
  `origin/master` frequently, and merge it without rebasing or switching the
  issue branch.
  Rationale: this is the user's explicit execution instruction and preserves
  inspectable milestones while respecting the repository's current-branch
  workflow.
  Date/Author: 2026-07-25 / Codex

- Decision: guided-review findings are automatically fixed when they are
  relevant blockers or reasonably scoped improvements; only dependency-blocked
  or genuinely out-of-scope findings are deferred, with the reason recorded.
  Rationale: this is the user's requested review policy. It preserves
  adversarial review value without pausing for finding-by-finding confirmation.
  Date/Author: 2026-07-25 / Codex

## Outcomes & Retrospective

The protocol, pre-resolved binding plan, reusable summary client, uncertainty
execution, bounded diagnostic-neutral finding aggregation, generic bounded
source witnesses, and controlled TypeScript/Java reuse case are implemented.
#1171 landed through PR #1176 and the client consumes its result-owned
reconstruction seam without typestate-specific predecessor storage. Protocol,
client/finding, and witness checkpoints completed guided specialist review;
every relevant blocker and reasonably scoped finding was fixed and committed.

Focused typestate, protocol, binding, generic dataflow, ICFG, deferred-call,
branch, recursion, and real exceptional-return conformance suites pass, as does
strict focused Clippy. The only remaining work is the final isolated
all-target/all-feature Clippy and full `nlp,python` repository test gate,
followed by recording exact evidence and a final remote-state check.

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
- a subject binding, owned by the later binding plan rather than the protocol,
  pairs one abstract object/fact identity with an initial protocol state;
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
guard combinations, unstable durable identities, aggregate collection bounds,
and unreachable states under the declared reachability policy. Diagnostics are
sorted by a stable field/key order and carry bounded paths into the internal
spec.

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

Consume #1171's landed generic witness reconstruction. Translate generic
solver steps into bounded, source-backed diagnostic-neutral typestate witness
steps. Witness truncation downgrades witness/finding evidence but does not
change solver reachability, termination, or protocol state.

Controlled-graph tests cover local transitions, branches, helper calls,
aliases, normal and exceptional matched returns, explicit call-to-return
boundaries, direct/mutual recursion, summary reuse without cross-return,
ambiguous/unknown dispatch, escape, cancellation, all applicable budgets, and
permutation determinism.

### Milestone 4: prove cross-language reuse and downstream seams

Use `tests/typestate_client.rs` with `InlineTestProject` and the real workspace
semantic provider/oracles. Equivalent TypeScript and Java fixtures use the same
`CompiledProtocol` and assert equal protocol hashes.
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
    cargo test --test typestate_protocol --test typestate_binding --test typestate_client --test dataflow_summaries --no-default-features
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

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
- Issue #1171 / PR #1176 / commit `c8df49d3`: landed generic bounded witness
  reconstruction consumed by this client.
- Issue #1172: generic IDE edge-function/value propagation; evaluated as a
  future representation option, not an implementation dependency for #822.
- Issue #823: reusable cross-query semantic/taint/protocol summaries; excluded.
- Issue #824: public CodeQuery/RQL compiler, registry, and policy adapters;
  excluded except for preserving the internal seam.
- `.agents/plans/language-agnostic-composable-typestate-platform.md`: umbrella
  architecture and issue ownership.

Record milestone commit hashes, review outcomes, and exact final test counts
here as work proceeds.

Revision note (2026-07-26): updated the plan after #1171 landed and the
client/witness milestones completed. Recorded the bounded witness architecture,
specialist-review fixes, cross-language coverage boundary, branch/recursion/
exceptional acceptance fixtures, and the remaining final repository gates so
the living plan matches the implemented branch.
