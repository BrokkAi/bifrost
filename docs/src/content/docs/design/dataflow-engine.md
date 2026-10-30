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

### Rust tuple binding initialization

The Rust hook admits flat, by-value identifier bindings from captured tuple
literals or proved typed binding reads. It schedules the initializer once,
captures all components before writing a leaf, and publishes a separate
assignment and ownership transfer for each binding. Literals use their captured
child values; typed aggregates use distinct ordinal field projections. Component
types retain their declaration scope, including the defining scope of a
same-file type alias, and ownership evidence is available before cleanup scopes
are registered.

Conditional standard `Option<T>` copyability requires the exact standard type
identity and an independently proved `Copy` payload. Inert drop glue alone does
not prove `Copy`. Unknown ownership, unsupported moves or cleanup, nested or
by-reference patterns, rest and capture patterns, refutable patterns, and explicit
target-type annotations retain scoped gaps. The shared decomposition planner
preserves source order, cancellation and work accounting; each language supplies its own
projection, transfer and failure semantics. Initialization consumers continue to
require real establishments and complete relevant evidence.

### Java expression results

A Java expression that evaluates operands gives its result a value relation
from them or a scoped gap, never neither. A result with no producer would let a
tainted operand vanish while the run still reported complete evidence.

A parenthesized expression hands its operand on unchanged, as a local copy
plus the identity assignment. Every other cast, whether a reference cast, a
narrowing, a boxing or an unboxing, derives its result from the operand with a
language-defined flow, which claims dependence and not identity, as Kotlin and
C/C++ do. The flow is published after the cast's check, so a
`ClassCastException` or an unboxing `NullPointerException` does not
manufacture a normal result. Only a primitive cast that is an identity or a
widening of a binding keeps the local copy. An `instanceof` test, an embedded
string expression and a dimension expression derive their result the same way,
and an `instanceof` boolean follows the comparison operators.

A value-position `&&` or `||` is its left operand when that operand decides the
outcome and its right operand otherwise, so each way out carries one flow. The
left operand is lowered as control flow, and a nested short-circuit,
conditional or parenthesized operand has no value of its own; the leaves that
can decide it feed the result. Each switch-expression rule, and each `yield`,
copies its operand into the value of the switch expression it completes. The
copy precedes any `finally` on the way out, because Java evaluates the operand
first. A `yield` finds its switch through the target of its completion route,
not through the enclosing syntax, so a `yield` inside a nested switch
statement reaches the right expression.

A fresh `new T[n]` is an allocation whose length derives from its dimension
expressions. An array initializer is an allocation whose element `i` is stored
as if by `array[i] = element`, at the same canonical index value a later
`array[i]` read uses, so a constant-index read finds the store and returning or
passing the whole array carries its elements. An initializer stores at most 1024
elements. The rest leave a write-only gap that a consumer discharges when
nothing reads or publishes the array.

Some parts stay open on purpose. A string template keeps the flow of its
embedded expressions and carries a `Calls` gap, because the processor call is
not lowered. A pattern variable bound by `instanceof` or a record pattern has
no lowered binding, so a bare reference to its name that resolves to no local or
parameter carries a gap. The test itself carries none, and an unreferenced
binder adds none. The missing-`yield` gap is emitted only when the last
statement of a rule block or statement group is not provably a `yield` or
`throw` on every path, since a block that can complete normally is a
compile-time error.

### Semantic rows and file windows (#5113)

Between converted RQL steps, semantic rows carry references: workspace file,
content revision and procedure locator, plus a point or call-site ordinal when
needed. They do not retain `ProcedureHandle`, `ProgramPointHandle`,
`CallSiteHandle` or `Arc<SemanticArtifact>`. Python `procedure-of` inventories
references without executable lowering. Each consuming step groups its own
input by file, resolves one file through the shared artifact cache, projects
artifact-free results, and closes that file window before the next file.
Executor stage batching stays unchanged; adjacent steps are not fused. A changed
revision produces a structured row failure instead of silently resolving again.

Witnesses and pipeline provenance project to identity/location snapshots at
emission with the existing step/byte limits and truncation metadata. Root-local
handle-keyed solver caches clear on file-window close; reusable cross-root
summaries use references and handle-free payloads. Nonmechanical legacy
consumers (value-flow/taint and handle-backed guard/control/state/flow payloads)
retain their existing lifetimes until explicitly converted; accepting a
reference alone does not establish artifact release.

The field-slot prepass likewise collects facts one file at a time and retains
plain class/field identities, procedure references and write-site ordinals,
never a workspace vector of procedure handles. Cross-file dynamic-write
observations resolve against each root's discovered closure, preserving exact
allocation identity after eviction. The index is one query's result and drops
with that query. Persisting Python executable IR remains a measurement-driven
option rather than a prerequisite for file windows.

Complete semantic artifacts and prepared workspace dispatch sessions each have
an explicit 2 GiB cache cap, independent of the global memo budget. This is a
provisional owner decision for the current Python semantic path, to revisit
when Python moves to the native engine (#5113). The former roughly 32 MiB cap
caused hours of repeated lowering on elasticsearch-py; 2 GiB eliminated repeat
lowering in the measured replay. Other caches keep their existing budgets.
Cross-root entries must use references or include every pinned artifact and
arena in their byte weight; logical eviction alone does not establish physical
release.

### Module initializers and source ownership

Python gives module statements a synthetic `<file>` initializer when a module
contains a direct statement other than a function or class definition. Decorated
definitions are still definitions, and comments do not count. Imports,
assignments and control-flow statements do count. This makes module-level calls
available to the same value-flow and taint analyses as calls inside functions,
without adding a frame to files that contain only definitions.

Top-level definitions and the initializer are siblings under the file root.
The initializer is not the lexical parent of a top-level function: making it
one would incorrectly turn the function into a nested local function and change
closure and `nonlocal` behavior. Module names are locals within the initializer.
Sibling functions retain their structured proofs about module globals, such as
an unchanged global initializer or a known global callable. This does not imply
general flow of mutable global state between procedures. Analyses specific to
function locals, such as uninitialized-local detection, keep their function and
method scope.

Imports and definition-time expressions retain explicit semantic gaps. The
initializer does not simulate module loading, decorator execution, default
argument or annotation evaluation, or class creation. The guard
`if __name__ == "__main__":` is an ordinary conditional; there is no separate
script or import execution mode. A policy that distinguishes those contexts
must establish the distinction from the available structure.

Python class bodies are not lowered. Their execution needs class-namespace and
metaclass semantics beyond the module initializer's local bindings. Methods
remain separate procedures, so a call inside a method has that method as its
owner even though a call directly in the class body has no enclosing procedure.

A procedure owns its source span minus the holes declared by its language
adapter for nested bodies it does not lower. The inventory carries these holes
into the in-memory artifact, and shared source-range lookup respects them
before choosing the enclosing procedure. Python excludes class-body blocks and
nested callable bodies from ancestor ownership. Independently lowered nested
procedures can still own their bodies; a class-body call cannot fall back to an
outer function or the file initializer. A range wholly inside a hole is excluded,
while a surrounding call or declaration that contains the hole can still belong
to the enclosing procedure. These ownership facts do not change the persisted
IR format.

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

A language resolver can also close a resolved member call by itself. It
publishes the selection as a bound receiver with closed dispatch extensibility.
The shared exact-member discharge then answers the call's dynamic-dispatch gap,
provided every retained target materializes as a proven, complete member body
and no boundary remains. Java uses this for nonvirtual `super` calls and Rust
for concrete receivers. Ruby uses it for an exact receiver whose method table
is closed within the caller's file and the files that declare the receiver's
ancestry. The proof names its scope, so mutation spelled elsewhere is a stated
limit, not a hidden assumption.

Class membership and evidence of a value alternative are distinct. A guard
can establish a class conditional on entering its arm even when its input
comes from an unmodeled load or call. That class remains useful for member
lookup and dispatch, but a guard-only origin cannot support a Proven
missing-member finding. The finding client requires an independent same-class
source or an unconstrained entry parameter that admits the guarded class. For
Conditional findings, Python may also admit a declared parameter whose
annotation names one workspace class with no workspace subclasses, unresolved
or unmodeled external bases, or dynamic-attribute hooks; the finding states
that annotated-type premise. Conditional origins stay conditional through
later guards; when independent and conditional sources meet, the independent
origin takes precedence.
The raw receiver result retains this source provenance. The `class_set`
projection exposes `guard_only: true` for such class rows and preserves it on
persistent replay. Unknown rows omit that field. Its `known` status reports
membership; `guard_only: false` does not prove a realizable full runtime path. Neither interface claims general runtime path feasibility.

Python member absence needs more than a declaration lookup: another procedure
can install an instance attribute. The class-set engine consults the cached
workspace store survey before accepting declaration-only absence. Attributed
writes are keyed by class and member; writes with an unknown receiver keep the
named member open. For an unknown attribute name, a preliminary class-flow survey retains the
receiver and mutation site. It composes caller bindings with ordered local
writes, then opens only the possible receiver classes. Declared receiver bounds
include known subclasses; unbound entry parameters contribute only the classes
supplied by workspace callers. An unbounded receiver or an incomplete survey
keeps the surface open with an explicit reason naming the mutation site. A
Conditional absent-member finding may carry that uncertainty only when every
matching global dynamic write has no receiver bound and an Any member-name set; its
condition names each possible write site. Bounded writes and other incomplete
surveys still block the finding.
The preliminary survey does not use member absence to exclude classes. It
repeats as affected field slots open until the effects stabilize, within shared
resident semantic and per-root solver budgets. Member guards such as `hasattr` consult that same survey
before excluding a receiver class. A possible store does not invent a callable declaration
or an exhaustive dispatch target. The syntactic survey shares the field-slot index's validity, bounded persistence,
and replay accounting. Surveys requiring dynamic receiver propagation remain
request-local; their additional solver work is not covered by artifact-only
persistent replay.

The dynamic-write survey discovers only from roots that can reach a write
site. Structured incoming caller lookup includes conservative same-name
candidates when dispatch is unresolved. It accepts target batches, builds the
Python project graph once per batch and walks each candidate file once, while
preserving each target's alias/re-export seeds, proof states, limits and omitted
counts. The single-target API is a singleton batch. Other language scanners
retain their existing behavior where they cannot share that walk.

The reverse survey walks breadth-first, one batch per level, so depth is the
shortest distance from a write. Each write has its own completed frontier and
failure evidence, with an incoming retention bound of 4,096 candidates per
procedure per level, independent of editor projection limits. An incomplete
lookup, omitted caller, missing index or refused depth makes that write
caller-unbounded and opens its affected slots with a diagnostic naming the
site, procedure and reason. It never falls back to discovering every root.
Only completed walks contribute candidate roots; failures of disjoint skipped
roots do not open unrelated writes. Candidate-root materialization failures
remain incomplete-root evidence with the exact refusal and allow the survey to
continue. Batch graphs, trees and caller memos drop before forward discovery.
Batched scans address repeated tree walks without a new caller table; call-site
rows remain an option for interactive find-references latency.

Python conditional expressions copy the selected arm's value to their result
when that arm completes normally. Short-circuit `and` and `or` similarly
return the selected operand value, including when that operand is itself a
conditional or boolean expression. Each operand is evaluated once; an
exceptional exit bypasses the result assignment. Known literal truth values
control which operand can run, and unmodeled value alternatives remain open.

Class sets follow ordered binding writes, including writes to parameters,
receivers, loop targets, and unpacking targets. A guard on a saved read can
constrain the current binding only while that read still names its current
value. For ordinary receiver fields, a procedure-local analysis tracks stores
and guards across control-flow joins. Calls and potentially effectful lookups
invalidate those field constraints; they retain explicit uncertainty.

Indexed loads retain an unknown value remainder unless a separate proof shows
that modeled stores account for all possible values. Python can certify
supported constant-index reads from fully initialized local lists whose aliases
never escape. The proof retains the ordinary heap transfers and overwrites;
it does not infer an element class from the container class. Expanded
initialization, deletion, escaped mutation, and custom indexing remain open.

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
member surface the named class does not describe. An open subclass bound alone
does not prove that the named class lacks a member. A receiver whose only
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

### Python module-global seeds and `with` suppression

These rules define observable Python analyzer behavior, so they belong in this
human-facing dataflow contract. A function, class body, or lambda can receive an
exact class seed from a module global only when the name has one binding
statement, and that statement is a single `NAME = value` assignment (possibly
inside module-level `if`, `try`, `with`, or `for` bodies). No function,
lambda, or class body may declare it `global`. The module may not write through
`globals()` or no-argument `vars()` (subscript assignment, deletion, `update`,
`setdefault`, `pop`, or `clear`), use `exec`, or import a wildcard after the
assignment. Count every binding form: other assignments,
augmented or annotated assignments, deletion, imports, definitions, loop and
`with` targets, and walrus bindings; comprehension targets do not count. No
other workspace file may write that module attribute through an imported
module alias, including assignment, deletion, `setattr`, `__dict__`, or patch
APIs. The initializer uses the same classifier as a local assignment; an
unrecognized value remains unknown.

`sys.modules` is a registry of module objects, not module namespaces. A literal
lookup through subscription, `get`, `pop`, or `setdefault` can alias module M
only when its key is M's name (or `__name__` inside M); another literal is
unrelated. A dynamic-key read may alias M. Track that value through existing
alias rules: reads are harmless, but writing through it or letting it escape
keeps the module-global proof open. A dominating `if`/`elif` consequence, or a
prior same-block `if not condition` that exits via `continue`, `return`, `raise`,
or `break`, may prove the key cannot be M's name. Evaluate supported literal
string comparisons, membership, substring, prefix, and suffix tests with
three-valued logic over `and`, `or`, and `not`; unknown predicates and a key
rebound between guard and read remain conservative. A subscript assignment,
`setdefault`, or `update` blocks only when the stored value is or may be M.
Deleting an entry, an unused `pop`, or clearing the registry does not change M's
globals. Escaping the registry itself remains conservative.

For a `with` item, keep the suppression-resume edge unless every possible
manager class has a resolved `__exit__` proven to return `None`. A workspace
method qualifies only when it has no decorator and every return is bare or
returns `None`; an external method needs a declared `None` return. A generator
containing `yield`, decorated method, bool or other possibly truthy return,
missing declaration, or unknown manager keeps the edge. The `__exit__` result
remains unused, and return, break, and continue routes keep their existing
semantics.

Each client keeps separate plans and result types. A taint class, protocol
state, and inferred class identity retain distinct types. Language-specific
facts outside the semantic IR remain behind narrow adapter contracts.

## Composed taint over stored partial flows

Rust taint policies can run on a second engine, the composition engine. It
answers the same policy questions as the ICFG engine, but it does the
per-procedure work once per file content instead of once per query. After an
edit, only the changed files' rows are rewritten, and a diff-scoped query
searches only from the sinks in the edited procedures.

An explicit rule chooses the engine once per policy compile, and the run's
execution record names the choice. A policy with bound sinks uses composition
when every sink is in Rust, every sink's file carries complete, current rows,
and the policy uses no store ends, entry points, or flow-candidate pass.
Otherwise it uses the ICFG engine. A changed-range request that binds no sink,
in a policy without those features, is recorded as an empty composition result
and runs no search. The rule is not a fallback: a composition that cannot
finish reports an incomplete result and never restarts on the other engine.

### What each file stores

When a Rust file is parsed, its semantic IR is written as rows keyed by the
file's blob ID, in the same transaction as its name-resolution rows. Like every
content fact, these rows depend only on the file's bytes and the producer
version. The lowerer therefore does not consult semantic models. Where a model
contract such as collection flow or a deferred factory once applied during
lowering, the IR records the call's shape (the written receiver type segments
and the member name), and the contract is applied when a query reaches that
call.

The same transaction stores each procedure's partial flows. A partial flow is
the fact that a value at port A can reach port B inside the procedure when
every call is treated as a boundary. A port is a place where a value enters or
leaves the procedure or one of its calls:

- the receiver, a parameter, a return, the thrown value, or a capture slot;
- a call site's receiver, arguments, result, or thrown value;
- a value captured into a child closure;
- a heap location rooted at a receiver, parameter, or capture slot.

A heap location rooted at the receiver or a parameter is an input as well as an
output: the stored fixpoint seeds it at entry. A value that a caller stores in
an argument's field therefore reaches the callee's read of that field. The
stored fixpoint does not seed capture-rooted heap locations; a query-time
interior run can seed one explicitly.

A file-local fixpoint computes the partial flows. Its result must equal the
solver's own propagation inside one procedure, and a differential test over the
fixtures compares the two. The relation projection that the fixpoint reads
uses a file-local host that answers every workspace question conservatively. No
store counts as a strong update, and a gap whose discharge needs the workspace
stays open. The stored relation is therefore a superset of what the workspace
would prove. A query recomputes the openness of each procedure it visits with
the workspace's gap predicates. Each stored flow also records which call sites
its path crossed, as a minimal set of crossed-call sets, so a finding's
certainty can follow the ICFG engine's continuation rule. The set is capped at
16 classes. Past the cap, classes are merged into their union, which is
conservative but can report lower quality than the ICFG engine.

The fixpoint processes points in reverse postorder from the shared iterative
graph traversal. A priority queue lets acyclic predecessors contribute before
their successors, while loop back edges can schedule earlier points again.
The traversal includes disconnected seeded points, and all scheduling state
lives only for the procedure's computation. Bounded widening and query witness
selection can depend on visitation order: changing the schedule preserves the
conservative evidence rules, but need not retain identical path-class precision
or choose the same valid witness.

Some values are deliberately not stored:

- Flows from an interior value, such as a sensitive read in the middle of a
  body, to the procedure's ports. A query derives them from that procedure's
  rows when it needs them.
- Witnesses. A query rebuilds one only for a reported finding, by rerunning the
  fixpoint on that procedure.
- Request answers: findings, composed cross-procedure flows, and their
  witnesses.
- A crate-level taint summary. The unit of reuse is each file's procedures
  and their partial flows. A summary over a crate's internal flows would have
  to be re-derived whenever any body in the crate changed, which is the cost
  this design avoids.

The rule behind these choices: store a derived value when deriving it costs
much more per file than a keyed read and more than one query shape reads it.
Otherwise, derive it per query from rows that the query already reads.

### Value-type barriers

A taint policy may declare a separate `:barriers` endpoint set. A barrier
names a type predicate, such as `(intrinsic bool)`, `(intrinsic numeric)`, or
`(enum :fieldless true)`,
rather than a call transfer or a label removal. A proven matching value stops
all taint facts observed at that node, including sources, interior values,
procedure boundaries and sink operands. Language support classifies the type;
the shared propagation algorithm consumes its proof. Rust proves Boolean
identity from native primitive resolution and proves a fieldless enum only
from a complete inventory of lowered variants. A payload variant is a
non-match. Unknown or ambiguous types, incomplete or macro-generated variant
surfaces, and unavailable observations remain undecided.

`(intrinsic numeric)` covers Rust integer and floating-point primitives. In Go
it covers the predeclared integer and floating-point types (including `byte`
and `rune`) and named types with one of those underlying types. Complex types
are excluded: this predicate describes integer and floating-point carriers,
not every arithmetic type. Untyped constants match only after conversion to a
numeric type. Interface carriers remain undecided, so they keep the flow and
make its proof incomplete. Go uses the existing ICFG refinement; eligibility
requires the language's request-local value-type barrier context. The barrier
belongs to its policy and cannot remove labels tracked by another policy.

Classification runs at query time through a native resolver operation and
request-owned value and type memos. It publishes no policy-specific
partial-flow rows and retains no workspace-sized cache after the query.
Classification is demand-driven by live fact carriers: creating a seed,
propagating a relation with a tainted source, or observing a tainted output.
Visiting a program point does not classify unrelated live values. Only the
policy's declared predicates run, and the first proven match stops checking.
Lenient and strict replays share the request's decisions.

Within one query, a native `BudgetExceeded` answer is memoized per value
handle, predicate and full receiver-analysis budget. Different budgets retry;
cancellation is never cached. Row/byte refusals retain their controlling
semantic and shared traversal limits as well. A cached refusal is undecided
with the `lookup budget` note: lenient propagation keeps the fact. This
intentionally forgoes a retry that might succeed after native caches warm.
It can retain an extra finding or note, but never proves a barrier or hides
a finding. This conservative precision tradeoff bounds repeated native work.

Policies without barriers use ordinary stored summaries. A barrier policy
first runs that same search. If it finds no candidates, it performs no type
lookups. Otherwise, it recomputes only the source-to-sink chop: procedures
whose recorded port edges can support a candidate source/sink connection.
Filtered port flows must be a subset of their stored flows.

The first search records all alternative derivation supports within its
existing budgets. Refinement rewalks that request-local proof graph; it never
adds a procedure or taint-port edge. This boundary matters when the first
search was truncated: filtering an early path must not free a fresh budget to
explore a previously unexpanded path. Refined findings are a subset of the
baseline findings and retain its truncation and cancellation reasons even
when all observed candidates disappear. Unexpanded paths remain unclassified.

Two implementations of the observation filter share the same fixpoint and
leave the fact lattice unchanged. The lenient filter blocks proven matches
and permits undecided observations. If its witness crosses an undecided
observation, a strict filter also blocks those observations and replays that
pair's recorded chop. Projection applies the existing public finding grouping
before choosing evidence. If any concrete pair in a group survives strict
filtering, the finding contains only strict-surviving origins, labels, quality
and witnesses, with no barrier notes. Otherwise it contains the lenient pairs
and their undecided observations. Notes retain value identity and reason,
with a 64-entry and 16-KiB bound and explicit truncation.

Graph topology is frozen, but surviving edge evidence is refreshed. A barrier
can remove the support with the smallest crossed-call set. The filtered
fixpoint then supplies the surviving crossed calls and quality; continuation
proofs are requested for those calls through the same provider. Such proof
lookups do not expand the taint graph. Open or unavailable continuation proof
lowers certainty or completeness instead of removing the edge or retaining an
obsolete clean witness. Query profiling counts graph supports and edges,
reached and chop procedures, filtered fixpoints, strict replays, classification
calls, extra continuation-proof lookups and changed edge qualities.

Production summary ICFG supports these filters for Rust in the forward
direction only. Its first solve exposes the existing immutable transfer trace
and direct, call and matched-return supports. Request-local refinement
reconstructs local alternatives from the immutable `TaintAnalysisPlan` through
the same taint transfer implementation used by discovery, and admits only
outputs already recorded for that exact transfer key. It adds
no call context or interprocedural edge. Distinct label contributions remain
separate until filtering, including empty contributions that can generate a
fresh source later. A debug assertion checks that unfiltered alternatives meet
to each recorded output function. Replay is limited to the frozen candidate
chop, retains the original transfer rule order, and uses the request's existing
budgets.

Both passes share the native classification service and its request-local
decision and failure memos with composition. Budget-exhaustion failures are
memoized per value, predicate and budget; cancellation is never memoized.
Classification runs outside IDE callbacks, only for observations that carry
live taint after a real source-to-sink candidate exists.
Concrete loads, stores, arguments and results provide the observed value;
abstract heap locations never substitute their owner's type. Filtered
reconstruction supplies origins, observer candidates, labels and witnesses.
Witness carrier fact IDs are normalized in the pair report; concrete endpoint
and observation identities remain intact. First-discovery completion reasons
remain authoritative even when filtering removes every candidate.

Unsupported languages retain a structured unsupported analysis result.
Backward, unrefined forward and reusable-summary APIs reject barrier requests
with `TaintSolveError::UnsupportedValueTypeBarriers`. Its diagnostic is
`value-type barriers are unsupported for {operation}; use request-local forward ICFG refinement`,
where the operation is `backward taint`, `unrefined forward taint`, or
`reusable taint summaries`. Filtered results never enter a shared summary
repository. An empty selection that executes no solver retains its ordinary
empty result.

### Validity

The rows are published under a semantic producer epoch. The epoch is derived
from the adapter identity, the configuration, the IR version, and the
semantic IR rows version. The rows version covers both the row encoding and the
partial-flow derivation. Any change to the port vocabulary, the kill rules, or
the fixpoint bumps it, so rows that the old derivation wrote stop validating. A
blob whose rows are missing or carry an older epoch counts as a missing complete
analysis, and the startup reconcile reparses and republishes it. Resolution
bundles follow the same rule.

Only parse-time persistence writes rows. An overlay, or a blob without a
current publication, is lowered on demand in memory, and that lowering writes
no IR or partial-flow rows. A query reads such a procedure's partial flows by
running the same file-local fixpoint.

### The search

A composed policy is one backward search from its bound sinks over a graph
whose nodes are pairs of a procedure and a port. The edges come from:

- the stored partial flows;
- interior runs in a procedure that holds a sink or a source;
- dispatch: a call's argument into each candidate's parameter, and a
  candidate's return back to that call's result;
- callers: a parameter back to every call that dispatches to it;
- closure captures;
- models at call ports.

The search follows the solver's call-return matching. A demand that entered a
callee through a call's result returns only to that call. Only a demand that
started in a procedure climbs to that procedure's callers. Paths are keyed by
their label function, so a sanitized path cannot hide an unsanitized path to
the same sink.

The search runs in three stages. The first finds reachability and ignores
classes. The second evaluates labels along each retained path, applying
sanitizers, transforms, and model transfers in path order. The third reports
through the existing taint finding report.

Sinks are bound before the search starts. Sources, sanitizers, and transforms
are not. Each is matched when the search first enters a procedure, by
evaluating its selector on that procedure's file alone, and the match is
memoized for the run. A matched-value source is judged complete from its
file-local value observations, not from points-to coverage.

The reverse call inventory supplies caller candidates; forward dispatch
decides membership. A retained site is a caller only if dispatching that site
names the procedure. A complete dispatch that does not name it refutes the
site. An incomplete dispatch that does not name it leaves the caller set
incomplete, because the site might still call the procedure.

A caller site whose file is not compiled in the selected configuration is
skipped. Rust reports such a file as inactive: none of its placements is
active, and every route that would place it carries a cfg predicate that is
false under the selected cfg atoms. A file whose activity cannot be decided is
explored as usual. A skipped site is outside the analyzed configuration, so it
does not make the result incomplete. The composition's profiling counts list
every skipped site. Reverse selection itself keeps such callers, because
find-usages and incoming-call tools should show them.

When the request has more than one worker thread, the caller step resolves the
native call targets of each caller file concurrently, one task per file. The
parent still materializes semantic artifacts and performs semantic dispatch at
the original demand points, and it charges work there too. A runtime identity
is a per-operation alias of a content digest, so the parent merges worker
answers by re-interning their digests, without coordinating identity numbers.
With one worker, a store with a single connection, an unavailable operation,
or cancellation, the work stays on the serial demand path. The composition
prefetch golden compares the complete reports at widths 1 and 4 with each other
and with a stored expected report.

Openness uses one shared gap classifier with the ICFG engine, including its
call-target refinement rule. A refinement gap on a call counts as answered when
the composition's dispatch of that call is complete or a model covers the call.
A blocked gap, an incomplete residual dispatch, an unproven or incomplete
relation, or an open value-flow capability keeps a procedure open. At a call
with no model and no candidate body, the composition applies the policy's
unmodeled-call behavior, as the ICFG engine does.

### Diff-scoped runs

A diff-scoped run binds a sink only in a changed file, and only when the
sink's innermost enclosing procedure overlaps a changed hunk. Every sink in
such a procedure is bound, including sinks outside the edited lines. The run
reports the findings at those sinks, names the procedures it examined, and
marks its result as range-scoped. It makes no claim about sinks in other
procedures, so an empty diff-scoped result is not a claim of absence. A flow
through a changed procedure to a sink elsewhere is outside the contract. When
the engine rule selects the ICFG engine, the run widens to the whole
workspace. The whole-workspace mode binds every sink and is the reference for
equivalence tests.

### Completeness and reporting

A composed finding is certain only when its path is proven and the search
reached a fixed point. A finding that groups several origins of one source
is certain when the run's derivation was complete and every path meeting the
sink is proven, or when at least one origin has a certain path at the fixed
point: one established path proves the finding, and an uncertain sibling
origin does not negate it (#5597). An origin whose value also meets the sink
with an unproven fact, such as through an unproven transform selection, is not
certain.
Each reported origin carries its own certainty, so a certain finding does not
claim that every listed origin is certain. A finding
is complete when the run's derivation was complete and the path was complete,
or when every origin has a certain path at the fixed point, so an incomplete
run keeps a complete finding only through certain paths. A certain path is
proven and complete at every hop. A complete,
exactly bound authored transfer from an active pack can establish certainty,
with its closure retained as provenance, by the same rule the ICFG engine uses
(#5218, #5306).

A finding retains the authored summary that closes an endpoint's dispatch,
even when its witness crosses no model transfer. This dependency records the
dispatch proof rather than only the transfer relation (#4429, #4499, #5306).

An incomplete batch reports with the ICFG engine's diagnostic families. The
first cause is ranked: cancellation and budget exhaustion come first, then an
open procedure (ordered by artifact, locator, and procedure), then other causes,
and source or sink evidence last. Source-evidence diagnostics can appear beside
the first cause, and endpoint refusals are reported separately. The
`taint.compose.counts` profiling note carries the full list. When a run
concludes but a finding is partial, the finding's cause is also emitted as a run
diagnostic. For an open procedure, the cause names that procedure, not the call
in a caller that enters it.

The composition differs from the ICFG engine in two recorded ways. Heap
components and bounded globals are not smeared at paranoid unmodeled calls. A
source that the search reached but that lies on no reported path is not judged.

All composition search state belongs to one query: the frontier, the memos, the
prefetched dispatch answers, and the caller file map end with the policy
compile. Outside the search, the analyzer keeps the stored rows, a byte-capped
cache of complete semantic artifacts (decoded from rows or lowered on demand),
and bounded source-identity bookkeeping.

## Semantic residency and work accounting

Semantic lane limits bound retained source and rows, including `SourceBytes`
and `NestedEntries`. Releasing a holder refunds its resident census. Source
scans, lowering traversal, and visits to existing events or mappings never
refuse. They add to cumulative telemetry and the current root's work balance;
receipts report the largest root balance and resident peak per lane. Cumulative
telemetry includes admissions plus work, so holding and scanning the same bytes
can count them twice. Replay admits the retained census and imports work
telemetry without checking a work grant. Solver step limits and discovery's
procedure limit remain independent bounds on the analysis.

Replay records keep cumulative work, largest root or prepass work and retained
census per lane. Changed persisted shapes are versioned and SQL-readable.
Cache-only holders in complete-artifact and prepared-session caches do not count
in a root's resident balance; live root/window pins do. Reconciliation follows
actual allocation ownership rather than content equality or logical eviction.
Work is telemetry even when recomputation is caused by cache eviction, so warm
and cold completion cannot differ because of a semantic work grant.

Cached refinements admit the measured returned value only. Fixpoint scratch is
admitted during derivation and refunded on every exit; scans and comparisons
are work. Identical fact replacements leave residency unchanged. Class-set
type-flow roots start from a fresh ledger under an engine-owned root allotment
(owner decision, 2026-10-26, #2445). Other root children inherit live resident
census and start work at zero. Root returns fold cumulative work and
component-wise peaks; continuations transfer actual surviving admissions.
Failed staged publication preserves performed work while discarding unpublished
admissions.

Inside a value-flow plan, kill and trigger lists use dense insertion-order
source IDs and shared interned ID lists. Public identities, digests, witnesses
and persisted rows resolve those IDs back to event keys. This avoids replicating
locator-bearing keys across every guard edge. A witnessless trial result is
released before the witness solve begins; witness arenas remain one root's
working set under solver limits, rather than cross-root retention.

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
| Stored partial flow | One file content under one semantic producer epoch | A procedure's port-to-port flows with calls treated as boundaries; the input of [composed taint](#composed-taint-over-stored-partial-flows) |
| Authored semantic procedure summary | Activated semantic-model scope | Reviewed external call behavior such as parameter, return, receiver, heap, escape, or exceptional transfer |

Source bodies are analyzed directly. An external summary enters the solver only
after exact procedure binding and coverage checks. Missing, conflicting,
incompatible, or partial models produce open boundaries. See
[Source and model precedence](../semantic-models/#source-and-model-precedence)
for the activation rules.

Taint propagation lazily computes backward may liveness within one solve,
including exceptional edges and reads introduced by the query's transfers and
observations. It prunes only dead procedure-local value carriers at edge
targets. Formal ports, locations, captures, returned and thrown values, and
exceptional-exit facts remain available. The procedure receiver is also exempt
from pruning so callee effects remain visible to callers. Refinable snapshots
are eligible because their only remaining gaps concern call targets, whose
receiver and argument operands are already lowered as uses.
Missing operand semantics, exhausted
liveness budgets, or cancellation disable pruning; unresolved call targets do
not hide already-lowered receiver and argument operands. Reusable taint
transfers include the query's local-value read points in propagation validity,
while sink identities, accepted labels, and presentation remain observer
overlays. These liveness results are never persisted or retained across queries.

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
