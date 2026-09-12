---
title: Dataflow Engine
description: How Bifrost lowers semantic IR, materializes bounded ICFGs, and runs IFDS-family and IDE-style analyses.
---

Bifrost's dataflow engine separates language semantics from propagation. A
language adapter lowers source into a validated, evidence-bearing semantic IR.
An interprocedural provider turns that IR into a bounded control-flow view.
Language-neutral kernels then propagate client facts and values across
provider-supplied call and return matches.

The engine executes forward and backward fact propagation, query-local
summaries, reusable summary gates, IDE-style edge functions, and bounded
witnesses. The public capability remains experimental; [maturity and
limits](#maturity-and-limits) states the tested scope.

![Language front ends lower source into immutable semantic artifacts. A demand ICFG provider supplies either a bounded snapshot or procedure-at-a-time summary mode. IFDS-family fact propagation and an IDE-style value layer power value flow, taint, typestate, and class-set type flow while preserving termination, coverage, path quality, and bounded witnesses.](../../../assets/design-dataflow-engine.svg)

## From source to executable semantics

Each supported language has a lowerer behind the shared program-semantics
provider contract. The lowerer interprets language-specific syntax and runtime
rules, then publishes one language-neutral vocabulary. A semantic artifact
contains one or more procedures with:

- stable procedure locators and properties;
- basic blocks, program points, and intraprocedural control edges;
- values, allocations, memory locations, captures, and call sites;
- value-flow, memory, call, return, exceptional, cleanup, and asynchronous
  effects;
- source mappings and evidence rows; and
- explicit semantic gaps for ambiguous, unknown, unsupported, unproven, or
  budget-exhausted facts.

Construction validates dense IDs, source scope, call and continuation
contracts, control topology, value-flow contracts, evidence links, and resource
limits before publishing the artifact as immutable. A partially understood
construct retains its facts and records a scoped gap; missing edges remain
explicit.

A declaration's body does not always describe the callable exposed to its
callers. Python decorators can replace that callable, changing its arguments
and results. Decorated bodies remain available for analysis, but their call
boundaries stay open: the oracle withholds argument and return bindings until
the callable's behavior is established. Decorator names and copied metadata
alone do not establish that behavior.
The modeled built-in `staticmethod` and `classmethod` descriptors retain their
supported bindings when their identities and class namespace are proven.

Artifact keys are durable validity identities. Handles used inside one
materialization also retain artifact-instance identity. This prevents a dense
value or program-point ID from being paired with rows from another partial
materialization. Dense IDs are compact implementation coordinates; artifact
keys provide the public cross-run identity.

## Demand-materialized ICFG

Procedure CFGs remain immutable and local. The ICFG provider consults the
workspace semantic oracle to resolve calls and bind arguments, receivers,
normal results, exceptional results, and continuations. It stitches only the
interprocedural slice demanded by the request.

The ICFG vocabulary includes:

| Edge or boundary | Meaning |
| --- | --- |
| Intraprocedural edge | Normal, conditional, switch, loop, exceptional, cleanup, or async control inside a procedure |
| Call edge | Caller call site to a materialized callee entry |
| Normal or exceptional return | Callee exit to the matching caller continuation |
| Call-to-continuation | Caller-side flow around a boundary, deferred call, or a client-declared resolved-call bypass |
| Dispatch boundary | Unresolved, truncated, external, unmaterialized, or deferred call behavior remains open |
| Limit or continuation boundary | Call depth, node, edge, or continuation semantics stopped complete expansion |

Every edge carries its own proof and evidence completeness. Boundaries are
first-class graph rows. A solver may report positive reachability from a partial
graph alongside the boundaries that prevent a complete-model claim.

## Two execution modes

Bifrost exposes two execution shapes over the same transfer contracts.

### Bounded snapshot mode

Snapshot mode first expands a context-specific ICFG under explicit call-depth,
node, and edge limits. The frozen snapshot has dense forward and reverse
adjacency, so deterministic forward or backward worklist propagation is cheap
after materialization. It gives direction planning and related operations a
reusable bounded graph slice.

The snapshot retains the semantic outcome that created it as a separate input
status. A traversable partial snapshot is still partial input. A snapshot with
no available value produces a typed error.

### Summary mode

Summary mode starts from a root procedure and asks the provider for
procedure-local edges, call transfers, and exit profiles as they become
necessary. It tabulates reached states relative to exact procedure-entry facts
and creates query-local entry-to-exit summaries. Incoming-call rows reconnect
callee-relative facts and witnesses to their realizable caller context.

When recursion revisits an entry, the solver converges through the same
query-local end-summary relation.
Provider outcomes are cached within the request, and a later incoming call can
apply an end summary that was already discovered.

An optional cross-query repository may supply a complete reusable procedure
summary. Reuse is fail-closed: the relation must match the procedure and entry
fact, reserve its publication work, exclude a call cycle containing the solve
root, and state that its validity contract covers every analyzed procedure the
summarized body may call. If any gate fails, Bifrost solves the body directly.

## IFDS-family fact kernel

The fact-only problem contract follows the IFDS family. A client
declares a finite fact domain, a distinguished zero fact, and unary transfer
relations for normal, call, return, call-to-continuation, and exceptional
edges. Mapping each input fact independently to zero or more output facts makes
the relation distributive over union.

The kernel interns facts and propagates exploded states of the form
`(program point, fact)`. The zero fact is preserved by the kernel, client
outputs are deduplicated and canonicalized, and deterministic worklist order
produces deterministic result order. Transfer callbacks must be finite and
repeatable; the callback output itself is bounded so a client cannot make an
otherwise finite graph unbounded by emitting rows indefinitely.

"IFDS-family" identifies the finite, distributive exploded-graph and
summary-tabulation model. Bifrost extends the result with semantic gaps,
per-edge proof and completeness, explicit resource budgets, optional witnesses,
and more than one ICFG delivery mode. Path feasibility and textbook-compatible
client semantics remain separate claims.

## IDE-style value layer

Some analyses need a value attached to each reached fact. The IDE-style layer
couples each emitted fact transition to a client edge function. The client
supplies:

- a value meet that is associative, commutative, and idempotent;
- edge-function composition in path order;
- function application;
- pointwise meet of edge functions; and
- identity and zero values.

The solver canonicalizes edge functions and values, composes jump functions,
meets alternatives, and propagates concrete root values. The reachable closure
of values and functions must be finite or stabilize before the request's
separate IDE budgets are exhausted. Composition, meet, function interning,
value interning, and propagation are all independently accounted.

Production taint analysis uses this layer. Its value is a set of taint classes;
edge functions can preserve, generate, transform, or kill classes, including
sanitizer behavior, while fact topology tracks carriers and sink meetings.

## Clients of the shared engine

| Client | Domain and kernel use | Public interpretation |
| --- | --- | --- |
| Value flow | Fact propagation over values, ports, and abstract locations; supports forward and backward plans | A sink is reached, not reached only under complete coverage, or inconclusive |
| Taint | Set-oriented sources and sinks over the IDE-style class-set domain; compatible policies can share one solve | A finding requires a propagated source-to-sink meeting; selector co-presence alone is insufficient |
| Typestate | Finite protocol states and uncertainty over bound subjects; forward and backward execution share semantic edges | Findings retain protocol state, certainty, analysis completion, and witnesses |
| Class-set type flow | Seeds class atoms and explicit unknown atoms, then reuses the value-flow solver for receiver propagation | Unknown or incomplete class sets remain typed unknown or incomplete results |

Class-set dispatch feedback can close a resolved receiver call's dynamic-dispatch
remainder when the complete receiver set names exactly the declarations already
selected by the resolver and all targets materialize with complete evidence.
The refinement preserves those declarations and their proofs. Partial receiver
sets, open member lookups, uncovered declarations, and interrupted materialization
leave the remainder open. Class-qualified calls keep the class-selected callable;
the explicit receiver argument does not select a different method. Feedback runs
under the request's existing iteration, work, and cancellation limits.

Python member absence needs more than a declaration lookup: another procedure
can install an instance attribute. The class-set engine consults the cached
workspace store survey before accepting declaration-only absence. Attributed
writes are keyed by class and member; writes with an unknown receiver keep the
named member open. For an unknown attribute name, a preliminary class-flow survey retains the
receiver and mutation site. It composes caller bindings with ordered local
writes, then opens only the possible receiver classes. Declared receiver bounds
include known subclasses; unbound entry parameters contribute only the classes
supplied by workspace callers. An unbounded receiver or an incomplete survey
keeps the surface open with an explicit reason naming the mutation site.
The preliminary survey does not use member absence to exclude classes. It
repeats as affected field slots open until the effects stabilize, within shared
semantic and solver budgets. Member guards such as `hasattr` consult that same survey
before excluding a receiver class. A possible store does not invent a callable declaration
or an exhaustive dispatch target. The syntactic survey shares the field-slot index's validity, bounded persistence,
and replay accounting. Surveys requiring dynamic receiver propagation remain
request-local; their additional solver work is not covered by artifact-only
persistent replay.

Class sets follow ordered binding writes, including writes to parameters,
receivers, loop targets, and unpacking targets. A guard on a saved read can
constrain the current binding only while that read still names its current
value. For ordinary receiver fields, a procedure-local analysis tracks stores
and guards across control-flow joins. Calls and potentially effectful lookups
invalidate those field constraints; they retain explicit uncertainty.

Boolean flags can also preserve a local relationship between branch-specific
assignments. The engine excludes a class on a flag's guard edge only when every
reaching definition carrying that class has the opposite boolean value. These
bounded refinements use preliminary value-flow evidence and repeat when one
field store depends on another refined load. Preliminary or exhausted results
cannot publish complete summaries. Procedures whose refinements depend on that
evidence retain their bodies instead of publishing reusable body cuts.

An `isinstance` guard whose class or instance relation cannot be modeled adds
an explicit `unmodeled_guard:<class>` remainder when an undecidable candidate
reaches the predicate's true edge.
Incoming classes remain useful positive evidence, but the remainder prevents
an absent-member proof on that path. The false edge retains its previous
evidence. Negation and short-circuit expressions use the predicate's structured
edge mapping, so the remainder follows the arm conditioned on the unmodeled
check. The temporary remainder on the guarded binding ends when control
reaches the false arm or the branches rejoin; assignments can replace it
earlier. Class-set rows and explanations retain the named reason, separately
from dynamic-attribute uncertainty. Policy candidate explanations can replay
the corresponding class-set projection within their query budget to show
these reasons without changing the policy verdict.

A class check that does resolve states what its true arm proves about a value
the class domain could not name. Narrowing classifies named candidates, and a
remainder is not a class, so an arm that establishes the runtime class replaces
the remainder there instead of carrying it through. The replacement is the
exact class set when the check names the runtime class outright or every named
class is closed under the known workspace hierarchy, and the named classes with
an open bound otherwise, because a subclass satisfies the same check with a
member surface the named class does not describe. A receiver whose only
evidence was the remainder is then named rather than emptied. The false arm
keeps the remainder, a predicate that proves no class keeps it on both arms,
and the replacement ends with the arm exactly as the unmodeled remainder does.

Python also derives member-guard summaries from ordinary workspace module
functions called by an unqualified name, including explicit from-imports,
with one parameter, local assignments, and one final return. The body must use
supported, unshadowed builtins and structural boolean expressions: `hasattr`,
`getattr` with a literal member and `None` default, `callable` on the retrieved
value, and class-object checks. Unknown calls, side effects, rebinding, and
ambiguous callable identities prevent summarization. A missing member can
disprove the helper's true arm; a declared member alone does not prove that its
value is callable. Class-object checks remain unknown when the class domain
cannot decide them, preserving both outcomes. These summaries are derived
from current indexed syntax during plan construction. Their edge removals
participate in the existing reusable solver identity; no separate guard-summary
table is persisted.

Each client keeps separate plans and result types. A taint class, protocol
state, and inferred class identity retain distinct types. Language-specific
facts outside the semantic IR remain behind narrow adapter contracts.

## Fixed point and coverage

Each result records:

1. **Semantic input status:** complete, ambiguous, unproven, unknown,
   unsupported, budget-exhausted, or cancelled.
2. **Solver termination:** fixed point, cancelled, or the exact exhausted work
   dimension with attempted and allowed counts.
3. **Coverage:** reachable unproven edges, partial edges, and dispatch, limit,
   or continuation boundaries.
4. **Path quality:** the proof and completeness of each concrete retained path.

Those are internal engine dimensions. A public `flow_endpoint` projects them to
one documented status and optional reason: semantic and solver limits stay
distinguishable, while internal termination enum names are not exposed as the
wire contract. Reachability, exact/may certainty, and ambiguity remain separate
facts about the endpoint. The endpoint has no `must` field until a must analysis
exists.

Path alternatives follow the shared
[proof and completeness contract](../evidence-and-results/#proof-and-completeness):
the solver keeps incomparable concrete paths separate. Only a concrete
proven-complete path dominates the whole frontier.

A solver fixed point exhausts the graph supplied to the solver. A complete
result also requires complete semantic input, edges, and boundaries. Those
conditions keep `not reached` and `inconclusive` as distinct client outcomes.

## Budgets and cancellation

Semantic materialization, ICFG construction, solver propagation, and witness
reconstruction have separate controls. The solver ledger independently bounds
fact interning, reached states, flow evaluations, callback rows, propagated
outputs, end summaries, incoming calls, provider materializations, summary
applications, coverage rows, witness relations, and the IDE-specific function,
value, algebra, and propagation work.

Charges are staged and committed atomically. A failed charge identifies one
dimension and leaves the request ledger unchanged. Cancellation is
cooperative and checked around materialization, staging, callbacks, and
propagation. Cancellation and budget exhaustion preserve retained positive
states and yield typed incomplete outcomes.

## Optional witnesses

Summary solves can retain predecessor relations and reconstruct root-relative
source-backed witnesses. A witness records seed, semantic edge, or explicit
end-summary-gap steps together with call origin, boundary, proof,
completeness, and input/output fact identity. Incoming-call evidence composes a
callee's local path with the caller path that supplied its entry fact.

Retention is opt-in. Strict retention can make witness-budget exhaustion stop
the solve. Best-effort retention may drop the entire witness sidecar when its
relation or byte cap is reached; semantic reachability remains unchanged and
the result records that truncation. Reconstruction separately bounds steps and
evidence expansions, and a result distinguishes a truncated retained path from
unretained sibling alternatives.

## Summary lifetimes

"Summary" changes meaning with lifetime:

| Summary | Lifetime | Role |
| --- | --- | --- |
| Query-local end summary | One solve | Correctness-critical tabulation state used to match returns and converge recursion |
| Reusable solver summary | Across compatible solves in a bounded repository | A complete relative fact or IDE relation admitted only through strict validity gates |
| Authored semantic procedure summary | Activated semantic-model scope | Reviewed external call behavior such as parameter, return, receiver, heap, escape, or exceptional transfer |

Source bodies are analyzed directly. An external summary enters the solver only
after exact procedure binding and coverage checks. Missing, conflicting,
incompatible, or partial models produce open boundaries. See
[Source and model precedence](../semantic-models/#source-and-model-precedence)
for the activation rules.

## Maturity and limits

**Implemented scope:** validated semantic IR, demand ICFG construction,
snapshot and summary fact solvers, forward and backward execution, IDE-style
taint propagation, typed coverage, direction planning, reusable-summary
guards, and bounded witnesses execute in the repository. Cross-language
conformance fixtures exercise a shared helper-flow baseline and selected
advanced semantics.

**Evaluation boundary:** those fixtures establish adapter wiring and precise
contracts for the covered cases. They do not establish compiler-complete
semantics for every language feature, complete external-library modeling, or
representative real-project precision, recall, memory, and latency.
The corresponding roadmap item is
[Add stable public analysis capabilities](../decisions-and-outlook/#add-stable-public-analysis-capabilities).

The documented claims exclude SMT-backed path feasibility, complete
whole-program points-to, general unbounded alias sets, and universal soundness
or completeness. Dynamic dispatch, reflection, metaprogramming,
concurrency, exceptions, generated code, and external dependencies remain as
precise as the active language adapter and semantic models can justify.

[Decisions and Outlook](../decisions-and-outlook/#active-directions) collates
planned work on source semantics, summary coverage, path refinement, and larger
reusable-summary domains. Broader accuracy or performance claims require
representative pinned evaluations.

For the supported user surface, see
[Data Flow, Taint, and Typestate](/data-flow-and-typestate/). The
[Related Work](../related-work/) chapter places the IFDS, IDE, incremental
analysis, and evidence-carrying result choices in context.

[DataFlowBench](https://dataflowbench.brokk.ai/) provides versioned,
analyzer-neutral evaluation for value-flow, taint, typestate, witness, and
performance tracks. It preserves `reached`, `not-reached`, `inconclusive`,
`unsupported`, and runner-error outcomes as separate categories. The
[Evidence and Evaluation Methodology](/evaluation-evidence/) page defines the
publication and claim boundaries for those results.
