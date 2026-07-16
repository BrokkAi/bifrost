# Build a language-agnostic, composable typestate analysis platform

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current as implementation proceeds. Follow `.agents/PLANS.md` when revising it.

The GitHub roadmap is rooted at [issue #813](https://github.com/BrokkAi/bifrost/issues/813). Its native subissues are #814 through #826. This plan is the durable architectural and execution record behind that issue tree; the issues remain the unit of implementation and review.

## Purpose / Big Picture

Bifrost already answers structural, reference, call, and bounded receiver questions across several languages. The goal of this roadmap is to turn those components into a language-agnostic platform for interprocedural data flow and typestate without collapsing them into a monolithic code property graph or committing to SMT-backed symbolic execution.

After the first vertical slice, a rule author should be able to describe a finite-state resource protocol once, select relevant program entities through `CodeQuery` or RQL, run the protocol across matched calls and returns in TypeScript and Java, and receive a bounded source-backed may finding that says which facts and summaries supported it and whether ambiguity or budgets made the analysis incomplete. A trivial one-state client should use the same substrate for direct and indirect data flow, and a source/sink/sanitizer client should use it for taint-style propagation.

The initial target is meet-over-valid-interprocedural-paths analysis. “Valid” means call and return edges are matched rather than traversed as unrelated graph edges. The first solver accepts finite distributive may problems whose reachable facts join with set union, plus bounded-height IDE edge values that satisfy the laws specified below. A must claim requires a separately defined and validated problem; it is not obtained by relabeling a may result. The first platform does not use SMT to prove arbitrary branch feasibility.

The implementation should feel modular in the same way that Boomerang, IDEal, and synchronized pushdown systems separate concerns: language semantics, control-flow construction, dispatch/value oracles, solver mechanics, client rules, summary storage, and query presentation each have an explicit boundary. Bifrost’s usage analysis is an oracle and reusable component in this design, not something to discard and not something to turn into the entire solver.

## Progress

- [x] (2026-07-16 09:30+02:00) Audited the current repository, completed issue and source-architecture audits, fetched `origin/master`, and based this work on commit `4051809a` (PR #802).
- [x] (2026-07-16 09:51+02:00) Created root epic #813 and thirteen dependency-ordered native subissues #814 through #826.
- [x] (2026-07-16 09:52+02:00) Cross-linked #813 with the existing structural-query epic #328, policy issue #709, and typed set-composition issue #720.
- [x] (2026-07-16 09:58+02:00) Wrote this living ExecPlan with architecture, lifecycle, milestone, validation, and recovery contracts.
- [ ] Complete #814: define the language-neutral semantic IR, stable identities, capabilities, uncertainty, and an inspectable renderer.
- [ ] Complete #815 and the first adapter children: build equivalent per-callable CFGs for TypeScript and Java.
- [ ] Complete #816 in parallel: expose reusable dispatch, value, heap, and bounded access-path oracles for the reference languages.
- [ ] Complete #818: stitch CFG fragments through existing call relations into a demand-materialized ICFG.
- [ ] Complete #819 as needed: add iterative reachability, reverse postorder, SCC, and loop utilities; add dominators only after a named client justifies them.
- [ ] Complete #820: implement an iterative, summary-driven IFDS/IDE-shaped solver with budgets, cancellation, uncertainty, and witnesses.
- [ ] Complete #821 and #822: prove simple data-flow/taint reuse, then add the finite-state protocol IR and typestate client.
- [ ] Complete #823 and #817 promotion work: compose summaries in memory first, then persist only measured expensive and reusable artifacts.
- [ ] Complete #824: expose typed, bounded CFG/data-flow/typestate domains through `CodeQuery` and RQL.
- [ ] Complete #825: deliver and benchmark one TypeScript/Java resource-lifecycle protocol end to end.
- [ ] Complete #826 only after #825: decide, with evidence, whether WPDS weights or synchronized call/field pushdown precision should be implemented.
- [ ] Open per-language rollout children under #815 and #816 only after the reference adapters stabilize the neutral contracts.

## Surprises & Discoveries

- Observation: There is no general CFG, ICFG, basic-block, dominator, IFDS/IDE, WPDS, access-path, or typestate implementation in the repository today.
  Evidence: repository search found only syntax-level control-flow kinds and complexity calculations; public capability text explicitly says general control flow and data flow are unsupported.

- Observation: `StructuralSpec` and `FileFacts` are a strong language-neutral syntax boundary, but they are not an execution-semantic IR.
  Evidence: `src/analyzer/structural/facts.rs` stores normalized syntax nodes, containment, and role spans; it has no basic-block, value, memory-location, or normal/exceptional edge identity.

- Observation: the shared receiver provider is strongest in JavaScript/TypeScript; other languages still retain related object-sensitive logic inside language-specific usage graph implementations.
  Evidence: `src/analyzer/usages/receiver_query.rs` routes the shared query service to JS/TS, while the language-specific graphs contain their own receiver and return-type resolution.

- Observation: the existing call relation already carries much of the ICFG call-site boundary—caller, callee, proof, receiver, arguments, and formal binding—but it is demand-driven query infrastructure, not a persistent call graph or matched-call solver.
  Evidence: `src/analyzer/usages/call_relations.rs` defines `CallSite` and binding operations; `src/analyzer/structural/search.rs` consumes them for bounded call traversal.

- Observation: PR #802 demonstrates the desired hybrid storage policy rather than merely adding another cache.
  Evidence: structural facts are stored as versioned packed SQLite payloads, validated against the analyzer generation, and hydrated into compact in-memory rows for hot traversal.

- Observation: `CodeQuery` is already a typed unary pipeline over syntax, declarations, references, calls, expressions, receiver results, and files. It is not yet a recursive path-query or automaton engine.
  Evidence: `QueryValueKind`, `QueryStep`, and `validate_query_steps` in `src/analyzer/structural/query/ir.rs` enforce one typed transition at a time.

- Observation: GitHub supports native subissues in this repository, so #814 through #826 can be attached directly to #813 while retaining explicit dependency text in each body.
  Evidence: the live `subIssues` query for #813 returned all thirteen children.

## Decision Log

- Decision: target meet-over-valid-interprocedural-paths analysis rather than SMT-backed path feasibility.
  Rationale: the requested product needs scalable conservative flow and typestate, explicit joins, and reusable summaries; arbitrary path predicates would make the architecture and cost model substantially different.
  Date: 2026-07-16.

- Decision: treat a finite-state automaton as an analysis-client description, not as the solver itself.
  Rationale: the same solver should support a one-state reachability client, data flow, taint, and richer protocol state. Automaton state can participate in exploded facts without coupling adapters or the solver to one rule.
  Date: 2026-07-16.

- Decision: begin with an IFDS/IDE-shaped iterative tabulation kernel and keep WPDS/SPDS behind an optional backend boundary.
  Rationale: IFDS/IDE directly addresses distributive finite-fact problems and valid call/return paths. Weighted or synchronized pushdown machinery should be added only when the pilot identifies a concrete composition or access-path precision gap.
  Date: 2026-07-16.

- Decision: use TypeScript and Java as the first adapter pair.
  Rationale: TypeScript exercises Bifrost’s strongest shared receiver provider and dynamic dispatch surface; Java forces the neutral contract to serve a materially different typed language with exceptions and overload-aware calls.
  Date: 2026-07-16.

- Decision: keep AST containment, CFG, call relations, value flow, and typestate as typed facets rather than one eager universal CPG.
  Rationale: these relations have different identities, lifetimes, payloads, invalidation rules, and materialization costs. Query composition can provide a CPG-shaped experience without duplicating all facts into one graph.
  Date: 2026-07-16.

- Decision: treat dominators and post-dominators as lazy derived analyses, not prerequisites.
  Rationale: IFDS/IDE and pushdown reachability do not require dominance. Dominance becomes worthwhile only for a concrete SSA, control-dependence, strong-update, or pruning client.
  Date: 2026-07-16.

- Decision: freeze hot immutable base relations into dense IDs plus CSR/CSC, while persisting only stable, expensive, reusable artifacts in SQLite.
  Rationale: this matches the successful compact structural snapshot pattern from PR #802 and avoids persisting query-specific product states or maintaining rich and compact duplicate graphs.
  Date: 2026-07-16.

- Decision: keep language-semantic summaries separate from rule-specific protocol summaries.
  Rationale: adapter/call/value effects can be reused by several clients, while a protocol summary must include its rule hash and map incoming client state to outgoing client state and effects.
  Date: 2026-07-16.

- Decision: extend #328, #709, and #720 through cross-links rather than duplicate or absorb them.
  Rationale: #328 owns structural querying, #709 owns policy/SARIF presentation, and #720 owns typed set algebra. The new epic supplies semantic-analysis domains that integrate with each boundary.
  Date: 2026-07-16.

## Outcomes & Retrospective

The planning milestone produced root epic #813, thirteen native subissues, and this repository-local ExecPlan. The issue tree now separates the critical path from parallel and evidence-gated work:

    #814 semantic contract
      -> #815 callable CFGs
      -> #818 ICFG
      -> #820 solver
      -> #822 protocol client
      -> #823 summaries
      -> #825 cross-language pilot

    #816 value/heap oracles feeds #818, #820, #822, and #825
    #817 artifact lifecycle and persistence follows measured artifact shapes
    #819 graph algorithms is non-blocking; dominance is conditional
    #821 proves simple flow/taint reuse
    #824 exposes typed query facets
    #826 evaluates WPDS/SPDS after pilot evidence

No implementation milestone is complete yet. Update this section after each issue closes with actual behavior, measurements, architectural deviations, and follow-up issue numbers. In particular, record whether TypeScript/Java remained the right reference pair, which artifacts earned SQLite persistence, and whether #826 concluded that a pushdown extension was justified.

## Context and Orientation

### Terms

A control-flow graph (CFG) represents possible execution transfers within one procedure. Its nodes are basic blocks or program points; its edges include fallthrough, branch, loop, return, and exceptional transfers.

An interprocedural control-flow graph (ICFG) joins callable CFGs with call-to-entry and exit-to-return-site relations. A context-respecting path returns from a callee to the return site of the call that entered it, including correct handling of recursion and multiple call sites.

A code property graph (CPG) is a query experience that combines syntax, control flow, calls, and data flow. This plan provides that experience as typed composable facets; it does not require one physical graph that owns every fact.

A finite-state automaton (FSA) describes a protocol: states such as `unallocated`, `open`, and `closed`, and transitions caused by semantic events. The FSA is a client input. It does not by itself decide how program paths are explored.

IFDS is a tabulation framework for distributive interprocedural finite-set data-flow problems. It solves reachability over an exploded graph of program points and facts while respecting calls and returns. IDE generalizes this by associating values and composable edge functions with facts. In this plan, “IFDS/IDE-shaped” means the kernel exposes facts, flow/edge functions, summaries, valid-path handling, and the explicit laws below. The interface sketches in `Interfaces and Dependencies` are the initial implementation contract; changing them requires a Decision Log update.

A weighted pushdown system (WPDS) associates composable weights with pushdown transitions. A synchronized pushdown system (SPDS) can coordinate a call stack with a field/access-path stack. These are later optional mechanisms, not synonyms for an FSA and not prerequisites for the first typestate client.

CSR (compressed sparse row) stores each node’s outgoing adjacency in flat target rows plus offsets. CSC is the analogous incoming view. They provide low-overhead immutable traversal after a mutable builder interns identities and sorts/deduplicates edges.

A summary is a dynamic-programming result for reusing procedure behavior. A language-semantic summary describes client-independent effects. A client summary relates incoming facts or protocol states to outgoing facts or states and effects. A complete summary can be reused; an incomplete or budget-truncated summary must never masquerade as complete.

A fact is one abstract proposition propagated by the solver, such as “allocation A may be held by local x” or “object A is in protocol state open.” The fact domain is finite for one run because values are interned and every source of growth has a configured bound.

A lattice orders abstract information and defines how paths join. A may problem uses union: an outcome is reachable if any modeled valid path reaches it. A must problem needs a separately validated intersection-like abstraction and can claim an outcome only when every modeled alternative supports it.

A transfer function maps input facts to output facts at a semantic edge. Distributivity means applying the function to a union of facts produces the same result as applying it to each fact separately and unioning the results. IFDS relies on this law. An IDE edge function transforms a bounded abstract value attached to a fact; its value lattice must have finite height so repeated joins terminate.

A strong update replaces the previous abstract value of one proven-unique memory location. A weak update joins a new value with previous values because several concrete locations may be represented. An access path is a bounded root plus field/index sequence such as `parameter0.connection.state`.

A context abstraction is the bounded distinction the solver retains between callers, for example a call-site or object-sensitive key. It is part of a summary identity. An SCC, or strongly connected component, is a cycle-equivalent group of graph nodes used to reason about recursion. Reverse postorder is a deterministic CFG traversal order that usually accelerates fixed points. Dominance means every path to one node passes through another node.

A packed DTO is a versioned serialization object designed for stable storage rather than Rust’s in-memory layout. An overlay is the analyzer’s unsaved-buffer view and has its own generation. SARIF is the standard JSON result format consumed by code-scanning tools.

### Analysis result and soundness contract

Every solver/client result uses one of these top-level outcomes:

- `complete_finding`: the declared analysis scope and capabilities completed, and at least one abstract valid path reached an error transition. The first pilot reports `certainty: may`; this means the finding is possible in the over-approximated model and may be a false positive. A later `must` result is legal only for a separately validated must problem.
- `complete_no_finding`: the declared scope completed without reaching an error transition and without unsupported semantics, truncated candidate sets, unknown external effects, unresolved escapes, or exhausted budgets that could hide one. User-facing text says “no finding in the modeled scope,” not “the program is safe.”
- `inconclusive`: the analysis cannot make a complete absence claim because a required adapter capability, dispatch/value fact, external summary, exceptional edge, escape policy, or budget is missing. It may carry partial findings, but absence of a partial finding has no safety meaning.
- `unsupported`: the requested language or semantic facet is unavailable before meaningful propagation begins. This is a specialized inconclusive result with a stable capability reason.

The first may client applies these conservative rules:

- At a branch join, union all reachable fact and protocol states.
- For ambiguous dispatch within the target bound, union every candidate’s effects. If candidates are truncated or an unknown target could affect the tracked object, retain any known partial finding and return `inconclusive`.
- For an external call, apply a validated external summary. Without one, preserve the tracked fact, mark a possible escape/effect, and return `inconclusive`; never assume a no-op.
- For an object escape or ownership transfer, follow the protocol’s explicit `on_escape` action. The pilot protocol uses `inconclusive` unless a modeled return/transfer event establishes the new owner.
- Follow exceptional edges when the adapter declares them complete. If a reachable construct’s exceptional or cleanup semantics are unsupported, the overall result is `inconclusive`.
- A budget exit or cancellation returns `inconclusive` with the exact exhausted bound. It cannot populate a complete-summary cache.

Each result also carries `proof` for the structured edges it used, `completeness`, a work report, and optional bounded witness data. These fields are independent: a source-backed witness can be exact while the overall analysis remains inconclusive elsewhere.

### Existing seams

`src/analyzer/structural/spec.rs`, `extract.rs`, and `facts.rs` are the existing language-adapter-to-neutral-syntax boundary. `FileFacts` uses flat `u32` identities and `CompactRows<RoleTarget>` but represents syntax rather than values or control flow.

`src/analyzer/structural/rune_ir.rs` renders normalized structural facts for review and query-by-example. The semantic IR and CFG should gain an analogous bounded renderer early, before solver output makes adapter mistakes difficult to inspect.

`src/analyzer/usages/call_relations.rs` defines `CallRelationService`, `CallSite`, `CallArgument`, receiver ranges, proof tiers, and lazy actual/formal binding. The ICFG must consume this boundary instead of resolving calls again.

`src/analyzer/usages/receiver_analysis.rs` defines explicit outcomes, abstract receiver values, budgets, cache keys, and `ReceiverFactProvider`. `src/analyzer/usages/js_ts_graph/receiver_analysis.rs` is the first shared implementation. #816 generalizes this capability without turning it into solver state.

`src/analyzer/structural/query/ir.rs` and `schema.rs` are the typed query and declarative vocabulary authorities. `src/analyzer/structural/search.rs` executes bounded transformations and retains provenance. #824 extends these instead of adding a separate graph-query parser.

`src/compact_graph.rs` provides `CompactRows`, `CompactRowsBuilder`, and `CompactDirectedGraph`. `src/analyzer/store/mod.rs`, `src/analyzer/structural/provider.rs`, and `migrations/cache/0007-structural-facts-snapshots.sql` establish generation-aware, corruption-safe, versioned packed persistence with lazy hot hydration.

### Architectural flow

    tree-sitter AST and existing analyzer facts
                    |
          language semantic adapters
                    |
       per-callable semantic IR + CFG
                    |
       +------------+-------------+
       |                          |
    call/dispatch oracles      value/heap oracles
       |                          |
       +------------+-------------+
                    |
          demand-materialized ICFG
                    |
       iterative tabulation + summaries
                    |
       +------------+-------------+
       |            |             |
    direct flow    taint       typestate FSA
       +------------+-------------+
                    |
       typed findings and witnesses
                    |
      CodeQuery/RQL -> policy/SARIF

Storage is orthogonal to this flow. Mutable builders construct facts; immutable compact snapshots serve hot reads; SQLite stores only versioned artifacts that demonstrate expensive reconstruction and meaningful reuse.

## Plan of Work

### Milestone 0: preserve the roadmap and baseline

This milestone is complete when #813–#826 exist, the plan is committed and linked from #813, and the current source/storage/query boundaries are recorded. Do not implement speculative APIs in this milestone.

### Milestone 1: define semantic identities and adapter contracts (#814)

Create `src/analyzer/semantic/mod.rs`, `ids.rs`, `ir.rs`, `capabilities.rs`, `provider.rs`, and `render.rs` without expanding `StructuralSpec` into an execution-semantic catch-all. Define typed semantic effects and control edge kinds, source/proof/completeness metadata, and language capability discovery.

Keep three identity layers distinct:

1. `SemanticLocator` is a source-facing locator: workspace-relative path, language, enclosing declaration identity, semantic role, and source anchor. It lets findings and overlays refer back to code and may be remapped after an edit, but it is never sufficient to prove cache validity.
2. `SemanticArtifactKey` owns one immutable materialization: workspace mount identity, source/blob identity, overlay generation when applicable, adapter version, semantic-IR version, configuration, and dependency fingerprint. Changing any validity input creates a different artifact key.
3. `ProcedureId`, `BlockId`, `ProgramPointId`, `ValueId`, `AllocationId`, `CallSiteId`, and `MemoryLocationId` are typed dense `u32` IDs meaningful only inside the artifact that owns them.

Duplicate blobs mounted at different workspace paths may share content-derived extraction payloads, but their source locators remain distinct. Never serialize a dense ID as a globally meaningful identity without its artifact key.

Add a bounded semantic renderer analogous to Rune IR. Build equivalent TypeScript and Java inline fixtures before there is a solver. Their rendered neutral events should agree where language semantics agree and differ through explicit capability or edge labels where they do not.

### Milestone 2: build per-callable CFGs and reusable oracles (#815, #816)

In #815, add `src/analyzer/semantic/cfg.rs`, `src/analyzer/js_ts/semantic.rs`, and `src/analyzer/java/semantic.rs`. Adapters use structured tree-sitter fields and existing analyzer facts to create a mutable per-callable graph builder. The builder validates entry/exit nodes, edge endpoints, source mappings, and deterministic ordering, then freezes into compact topology. Edge payloads and semantic identities stay in typed side tables. Choose CSR-only, CSR+CSC, or functional reverse arrays per relation after measuring expected traversal directions.

The TypeScript and Java reference fixtures cover straight-line flow, branches, merges, loops, early returns, nested calls, throw/catch/finally, closures, and explicit unsupported constructs. Keep extraction iterative and use `InlineTestProject` for small projects.

In parallel, #816 adds `src/analyzer/semantic/oracle.rs` and language implementations adjacent to the two semantic adapters. It extracts `DispatchOracle`, `ValueFlowOracle`, and `HeapOracle` contracts from the receiver and language usage implementations. The contracts cover locals, parameters, receivers, returns, allocations, fields, statics, indexes, captures, bounded access paths, aliases, and strong/weak-update eligibility. They preserve `Precise`, `Ambiguous`, `Unknown`, `Unsupported`, and `ExceededBudget` outcomes.

### Milestone 3: assemble the ICFG and graph utilities (#818, #819)

Add `src/analyzer/semantic/icfg.rs`. The ICFG provider views per-callable CFG snapshots through existing call and dispatch relations. Its topology contains control only: call-to-entry, normal exit-to-the-originating-return-site, exceptional exit-to-the-originating-exceptional-return-site, and explicit call-to-return bypass edges for modeled external or summary behavior. Multiple targets and unresolved/external calls remain explicit.

Receiver-to-`this`/`self`, actual-to-formal, and callee-return-to-result are not ICFG control edges. They are typed `CallBindings` metadata supplied by `ValueFlowOracle` and consumed by the solver’s call and return transfer functions. Keeping them in a separate value-flow facet prevents control topology from depending on one client’s fact representation.

Return-site identity is essential: a solver returning from procedure `P` must resume at the site of the call that entered `P`, not every site that calls `P`. The provider exposes enough call-site metadata for a solver to match those transitions without eagerly enumerating all contexts.

Begin with demand materialization and generation-local memoization. Measure repeated call resolution before deciding whether a workspace-wide call topology should be frozen or persisted.

#819 supplies iterative forward/reverse reachability, reverse postorder, SCC, and loop utilities through iterator-oriented graph views. A dominance implementation is added only if a named client records why it needs dominance and benchmarks the cost/benefit.

### Milestone 4: implement the tabulation kernel and simple clients (#820, #821)

Create `src/analyzer/dataflow/mod.rs`, `problem.rs`, `tabulation.rs`, `summary.rs`, `outcome.rs`, and `witness.rs`. The solver operates over immutable base graph relations and generates the exploded product `(program point, fact, optional client state, context abstraction)` on demand. It never stores every possible product edge up front.

The dynamic-programming tables include:

- reached/path-edge state, so the same state is not propagated repeatedly;
- end summaries from incoming procedure fact/state to outgoing fact/state/effect;
- incoming call records that can consume newly discovered summaries;
- recursion/SCC fixed-point work;
- compact predecessor choices for bounded witness reconstruction;
- proof and completeness state, so incomplete computation cannot be reused as complete.

The first accepted problem contract is `DistributiveMayProblem`. For one run it must provide a finite interned fact domain including a distinguished zero fact, finite protocol/client state, a bounded context abstraction, and normal/call/return/call-to-return/exceptional transfer functions that distribute over union. Termination follows because the product of program points, facts, client states, and contexts is finite and propagation is monotone. Tests generate small fact subsets and verify `f(A union B) == f(A) union f(B)` for every transfer family.

An optional `IdeProblem` adds canonical edge functions over a finite-height value lattice. Identity, composition, and meet must be associative where required; identity must behave as identity; and repeated ascending joins must stabilize within the declared height bound. Property tests exercise these laws. A client that cannot state or pass the distributivity and termination laws is rejected by the IFDS/IDE entry point. It may later implement a separately named `MonotoneProblem` backend with its own fixed-point proof; it is never disguised as IFDS. The initial platform does not expose a generic must mode.

The kernel supplies deterministic worklists, budgets, cancellation, internal `TabulationEndSummary` composition, and the result algebra above. `TabulationEndSummary` is correctness-critical solver state mapping an entry fact/context to reached exits. It is distinct from the public/reusable semantic and protocol summaries introduced later.

Validate the algorithm on tiny generated ICFGs against an intentionally simple exhaustive reference that enumerates only bounded valid paths. Then add deep call chains, recursion, mutual recursion, multiple targets, exceptions, cancellation, and fact-growth cases.

#821 proves reuse with a one-state/direct value-flow client and a source/sink/sanitizer client. Missing generality is fixed at the shared solver/oracle boundary rather than by introducing a second worklist engine.

### Milestone 5: compile finite-state protocols and compose summaries (#822, #823)

Create `src/analyzer/typestate/mod.rs`, `protocol.rs`, `client.rs`, and `summary.rs`. The protocol IR is versioned and canonically hashable. It defines states, initial states, accepting/error states, semantic event predicates, guarded transitions limited to structured facts, object/fact binding, and finding behavior. Validation rejects duplicate or missing states, invalid transitions, unreachable states where required, unstable identities, and unsupported event selectors.

The first protocol is a resource lifecycle with states such as `unallocated`, `open`, and `closed`. It binds events to resolved allocations and receiver calls. It defines conservative behavior for unknown dispatch, escapes, exceptions, and incomplete analysis. The same protocol runs over TypeScript and Java.

The typestate client adds protocol state to interned facts or associates an equivalent client value through the solver interface. It does not add language branches to the kernel. A degenerate protocol should collapse naturally to reachability/data flow.

#823 adds `SemanticProcedureSummary` and `ProtocolSummary` above the solver’s existing `TabulationEndSummary`; it does not redesign or replace the correctness-critical tabulation cache. `SemanticProcedureSummary` packages reusable client-independent procedure effects. `ProtocolSummary` packages one protocol hash’s entry-state-to-exit-state/effect relation. In-memory dynamic-programming reuse comes first. Each summary records context abstraction, proof, completeness, exceptional effects, and dependency identity. Library summaries are validated and marked as external rather than inferred.

### Milestone 6: apply the artifact lifecycle policy (#817)

Maintain an artifact matrix while the preceding milestones establish real data shapes:

| Artifact | Initial representation | Persistence default | Promotion test |
| --- | --- | --- | --- |
| Per-callable semantic events | Dense arena and compact rows | Candidate | Persist only if extraction is expensive and content/version keys are stable. |
| Per-callable CFG topology | Immutable CSR or CSR+CSC | Candidate | Persist only if cold reconstruction dominates and packed hydration is faster. |
| ICFG stitch relations | Demand materialized generation cache | No | Persist only if repeated call resolution remains a measured bottleneck and invalidation is tractable. |
| Exploded solver states/worklists | Sparse ephemeral tables | Never by default | Query/client specific; retain only within an analysis session. |
| Language-semantic summaries | In-memory memoization | Candidate | Promote after cross-query and cross-process reuse is measured. |
| Protocol summaries | In-memory memoization keyed by rule hash | Candidate | Promote only with rule/config/version keys and measurable reuse. |
| Witness predecessor data | Compact ephemeral parents | No | Reconstruct bounded witnesses; do not serialize full paths. |
| Query results/truncations | Ephemeral typed rows | No | They are seed-, budget-, and presentation-specific. |

Every persisted artifact uses a packed versioned DTO, generation/content validation, corruption-as-miss behavior, lazy hydration, payload cost accounting, cascade cleanup, and tests for source, adapter, solver, configuration, protocol, dependency, and overlay changes. Coordinate visible store failures with #695.

### Milestone 7: expose typed query and policy boundaries (#824, #720, #709)

Extend `QueryValueKind` and the declarative query schema with source-backed `procedure`, `program_point`, `flow_endpoint`, `typestate_finding`, `typestate_witness`, and `flow_witness` domains. The initial operations are fixed by this plan:

| Operation | Accepted input | Output | Required bound/behavior |
| --- | --- | --- | --- |
| `procedure_of` | structural match or declaration | procedure | Exact enclosing callable or an explicit no-procedure diagnostic. |
| `cfg_entry` / `cfg_exits` | procedure | program point | Exits include normal/exceptional kind. |
| `cfg_successors` / `cfg_predecessors` | program point | program point | Positive finite `depth`, default 1; provenance carries each control edge. |
| `flows_to` / `flows_from` | expression site, program point, or flow endpoint | flow endpoint | Positive finite `depth` or explicit sink/source selector; valid-path semantics and work budget. |
| `typestate` | structural match, call site, expression site, or flow endpoint | typestate finding | Protocol ID, bind selector, may mode, solver budget. |
| `witness` | typestate finding or flow endpoint | typed witness | Positive finite maximum steps and bytes. |

The JSON `protocol_files` field and RQL `with-protocol` wrapper load protocol documents before typed step validation; they are query wrappers, not pipeline value transitions.

Actual/formal/receiver/return bindings appear in flow provenance and solver transfers rather than as control edges. New names or different type transitions require a Decision Log update and the complete schema/editor test surface.

Each operation has a finite work budget, explicit capability diagnostics, deterministic endpoint identity and ordering, cancellation, and proof/completeness semantics. A witness is a bounded supporting derivation, not proof that all alternatives were enumerated. The planner evaluates cheap structural seeds before materializing expensive semantic facets.

For the pilot, use this concrete author-to-query contract. Store the canonical protocol document at `tests/fixtures/typestate/resource-lifecycle.rqlp`. The file is JSON so it can share the canonical schema/validation path with #709; RQL remains the query expression language and may gain authoring sugar later.

`typestate::protocol::ProtocolRegistry` loads only files explicitly named by the query or bytes explicitly registered by an embedding application. JSON schema version 3 adds a top-level `protocol_files` array of workspace-relative paths. RQL adds a `(with-protocol "path" query)` wrapper. File loading rejects paths outside the workspace, duplicate protocol IDs, files above the configured byte limit, and parse/validation errors. The registry keys compiled protocols by canonical protocol hash. There is no implicit directory scan.

```json
{
  "schema_version": 1,
  "policy": {
    "id": "bifrost.test.resource-lifecycle",
    "severity": "error",
    "message": "Resource is used outside its open lifecycle"
  },
  "protocol": {
    "states": ["unallocated", "open", "closed", "error"],
    "initial_state": "unallocated",
    "error_states": ["error"],
    "on_unknown": "inconclusive",
    "on_escape": "inconclusive",
    "events": [
      {
        "name": "acquire",
        "declarations": {
          "languages": ["typescript", "java"],
          "match": {"kind": "method", "name": "open"},
          "inside": {"kind": "class", "name": "Resource"},
          "steps": [{"op": "enclosing_decl"}]
        },
        "at_calls": true,
        "bind": "return_value"
      },
      {
        "name": "use",
        "declarations": {
          "languages": ["typescript", "java"],
          "match": {"kind": "method", "name": "use"},
          "inside": {"kind": "class", "name": "Resource"},
          "steps": [{"op": "enclosing_decl"}]
        },
        "at_calls": true,
        "bind": "receiver"
      },
      {
        "name": "close",
        "declarations": {
          "languages": ["typescript", "java"],
          "match": {"kind": "method", "name": "close"},
          "inside": {"kind": "class", "name": "Resource"},
          "steps": [{"op": "enclosing_decl"}]
        },
        "at_calls": true,
        "bind": "receiver"
      },
      {"name": "scope_exit", "semantic_event": "procedure_exit", "bind": "tracked_object"}
    ],
    "transitions": [
      {"from": "unallocated", "event": "acquire", "to": "open"},
      {"from": "open", "event": "use", "to": "open"},
      {"from": "open", "event": "close", "to": "closed"},
      {"from": "unallocated", "event": "use", "to": "error"},
      {"from": "unallocated", "event": "close", "to": "error"},
      {"from": "closed", "event": "use", "to": "error"},
      {"from": "closed", "event": "close", "to": "error"},
      {"from": "open", "event": "scope_exit", "to": "error"},
      {"from": "closed", "event": "scope_exit", "to": "closed"}
    ]
  }
}
```

The declaration selectors are structural seeds that must resolve to exact indexed declarations before they become protocol events. A same-name method outside `Resource`, an unresolved call, or a name-only guess never fires an exact transition.

The canonical JSON invocation increments `CodeQuery` to schema version 3 and introduces `typestate` followed by `witness`:

```json
{
  "schema_version": 3,
  "protocol_files": ["tests/fixtures/typestate/resource-lifecycle.rqlp"],
  "languages": ["typescript"],
  "match": {"kind": "call", "callee": {"name": "open"}},
  "steps": [
    {
      "op": "typestate",
      "protocol": "bifrost.test.resource-lifecycle",
      "bind": "return_value",
      "mode": "may"
    },
    {"op": "witness"}
  ]
}
```

The equivalent RQL is:

```lisp
(with-protocol "tests/fixtures/typestate/resource-lifecycle.rqlp"
  (witness
    (typestate :protocol "bifrost.test.resource-lifecycle"
               :bind return-value
               :mode may
      (language typescript
        (call :callee "open")))))
```

For a `use()` after `close()`, the typed result has this minimum observable shape; exact line/column values come from the fixture:

```json
{
  "results": [{
    "result_type": "typestate_witness",
    "protocol_id": "bifrost.test.resource-lifecycle",
    "outcome": "complete_finding",
    "certainty": "may",
    "error_state": "error",
    "violation_event": "use",
    "path": "resource.ts",
    "range": {"start_line": 12, "end_line": 12},
    "witness": {
      "complete": true,
      "steps": ["acquire", "close", "use"]
    }
  }],
  "truncated": false
}
```

Changing this pilot wire shape requires an entry in the Decision Log plus canonical JSON, RQL lowering, validation, rendering, editor, and end-to-end test updates. Java uses the same protocol and query shape with only the language/fixture path changed.

All vocabulary enters through `src/analyzer/structural/query/schema.rs`, then receives canonical IR, JSON and RQL decoding, validation ranges, hover/completion, rendering, TextMate grammar updates, execution tests, and executable documentation recipes. #720 combines only compatible typed endpoints. #709 maps stable findings into policy identity, severity, messages, and SARIF rather than treating every query match as a diagnostic.

### Milestone 8: run the cross-language pilot and decide extensions (#825, #826)

Build equivalent TypeScript and Java inline projects plus a larger representative or generated corpus. The resource protocol exercises allocation/open, use, close, aliases, factories, helpers, actual/formal and return flow, branches, recursion-safe summaries, multiple targets, normal exits, and an exceptional path. Gold expectations distinguish complete-no-finding, complete-finding, inconclusive, and unsupported results.

Record true/false positives and negatives, abstention, cold construction, warm in-process summary reuse, warm cross-process hydration for promoted artifacts, retained bytes or RSS, graph/fact/summary counts, query latency, witness payload, hit/miss rates, and targeted invalidation. Every report includes the Bifrost commit, fixture revision, features, environment, and machine metadata.

#826 then evaluates two separate questions. First, whether WPDS-style weights materially improve summary or proof composition. Second, whether a synchronized field/call pushdown component materially improves access-path precision beyond #816. The legitimate outcome is “not yet”; no extension is accepted without exact correctness and resource evidence, and baseline clients must not pay a material disabled cost.

After the pilot, open adapter rollout children under #815 and #816 using the stabilized conformance contract. Do not make every language a prerequisite for shipping the first useful typestate analysis.

## Concrete Steps

Run every command from the repository root. From any clone or worktree, locate it with:

    git rev-parse --show-toplevel

At the start of each issue, confirm the exact branch, remote, and base before editing:

    git status --short --branch
    git fetch origin
    git log --oneline --decorate -5

Do not create or switch branches unless the user explicitly requests it. Keep each issue narrow. For significant implementation issues, update this ExecPlan before the first code milestone and after benchmark or design decisions.

For #814, begin by reading the current provider and identity boundaries:

    sed -n '1,260p' src/analyzer/structural/spec.rs
    sed -n '1,460p' src/analyzer/structural/facts.rs
    sed -n '1,430p' src/analyzer/usages/receiver_analysis.rs
    sed -n '1,280p' src/analyzer/usages/call_relations.rs
    sed -n '1,280p' src/compact_graph.rs

Prefer the shared inline project harness for small conformance projects:

    sed -n '1,280p' tests/common/inline_project.rs

The reference implementation creates this repository-relative module and test layout. A later Decision Log entry may split a file, but must preserve the boundaries:

    src/analyzer/semantic/
      mod.rs ids.rs ir.rs capabilities.rs provider.rs render.rs
      cfg.rs icfg.rs oracle.rs
    src/analyzer/js_ts/semantic.rs
    src/analyzer/java/semantic.rs
    src/analyzer/dataflow/
      mod.rs problem.rs tabulation.rs summary.rs outcome.rs witness.rs
    src/analyzer/typestate/
      mod.rs protocol.rs client.rs summary.rs
    tests/
      semantic_ir_contract.rs semantic_cfg_contract.rs
      semantic_oracle_contract.rs icfg_contract.rs
      semantic_graph_algorithms.rs dataflow_tabulation.rs
      dataflow_clients.rs typestate_protocol.rs analysis_summaries.rs
      semantic_artifact_store.rs code_query_typestate.rs
      typestate_pilot.rs
    tests/fixtures/typestate/resource-lifecycle.rqlp

Each milestone creates and runs its named behavior test. A missing test binary is not a passing milestone.

For #814:

    cargo test --test semantic_ir_contract

Expected: `test result: ok`; TypeScript and Java equivalent fixtures produce the asserted identity layers, semantic events, capability rows, and deterministic renderer output.

For #815 and #816:

    cargo test --test semantic_cfg_contract --test semantic_oracle_contract

Expected: `test result: ok`; CFG invariants and equivalent branch/loop/exception fixtures pass, and precise/ambiguous/unknown/unsupported/budget oracle outcomes are distinct.

For #818 and #819:

    cargo test --test icfg_contract --test semantic_graph_algorithms

Expected: `test result: ok`; returns resume only at their originating call sites, recursion remains finite to represent, and deep/cyclic graph algorithms remain iterative.

For #820 and #821:

    cargo test --test dataflow_tabulation --test dataflow_clients

Expected: `test result: ok`; bounded exhaustive-reference cases match tabulation, distributivity/property tests pass, recursion converges, and direct/taint clients share the kernel.

For #822 and #823:

    cargo test --test typestate_protocol --test analysis_summaries

Expected: `test result: ok`; the canonical protocol validates, TypeScript and Java share its hash, internal tabulation summaries remain distinct from semantic/protocol summaries, and incomplete summaries are not reused as complete.

For #817 after an artifact is promoted:

    cargo test --test semantic_artifact_store

Expected: `test result: ok`; version, corruption, generation, overlay, dependency, rule-hash, concurrent access, and GC cases either hydrate the exact artifact or produce a safe miss.

For #824:

    cargo test --test code_query_typestate

Expected: `test result: ok`; the schema-version-3 JSON and RQL examples above lower to one canonical query, invalid domain transitions have path-specific errors, and output matches the minimum tagged result shape.

For #825:

    cargo test --test typestate_pilot

Expected: `test result: ok`; both languages produce gold complete-finding, complete-no-finding, inconclusive, and unsupported cases, including helper, alias, recursion, and exceptional flow. The ignored benchmark mode prints one machine-readable record containing commit, fixture, counts, cold/warm elapsed times, memory, summary hits, and invalidation result.

Focused tests should prove behavior rather than mirror implementation-shaped registry lists.

At every Rust milestone, run formatting and a focused test first. Then run the CI lint gate through the isolated target helper:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Before pushing an implementation milestone that changes analyzer behavior, run the full feature-enabled suite when practical:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Tests must not download semantic models or start real indexer threads. Use the existing no-semantic-index and fake-engine patterns.

For benchmark milestones, capture commands and outputs in the issue or an `.agents/docs/` experiment note. Include exact commits, fixture revisions, feature flags, environment variables, counts, elapsed times, memory measurements, and a recommendation. Avoid manually named persistent Cargo targets under `/tmp` or `/private/tmp`.

## Validation and Acceptance

### Contract and adapter validation

- Equivalent TypeScript and Java fixtures render equivalent neutral semantics where expected.
- `SemanticLocator` remains source-facing, `SemanticArtifactKey` changes on validity inputs, and dense IDs are deterministic only inside their owning artifact; duplicate names and mounted duplicate blobs remain exact.
- CFG invariants cover entry/exit, edge endpoints, predecessor/successor symmetry, exceptional exits, disconnected/unreachable nodes, deep nesting, cycles, and deterministic rendering.
- Unsupported features are capability results, not missing rows that look like “no flow.”

### ICFG and solver validation

- Direct, virtual/multiple-target, recursive, mutually recursive, helper, external, and exceptional calls preserve call-site-matched returns.
- Tiny problems match a bounded exhaustive valid-path reference.
- Generated transfer sets satisfy the distributivity laws, IDE edge functions satisfy their algebraic laws, and bounded-height joins stabilize.
- The same reached state is not processed indefinitely; summaries demonstrably reduce repeated work.
- Cancellation and each budget return explicit incomplete outcomes.
- Deep and cyclic fixtures remain stack-safe.
- Non-distributive clients cannot silently use the IFDS contract.

### Typestate and client validation

- One resource protocol definition runs on both reference languages.
- Valid, use-before-open, use-after-close, double-close, leak/escape, alias, helper, branch, recursion, ambiguous dispatch, unsupported, and exceptional cases have gold outcomes.
- A one-state/direct-flow client and taint client run through the same ICFG and solver.
- Witnesses are source-backed, bounded, context-respecting, and labeled with proof/completeness.

### Storage and performance validation

- Compact representations are compared against behavior-equivalent reference relations.
- Every persisted format has version, corruption, stale-generation, targeted invalidation, overlay, concurrent access, and GC tests.
- Benchmarks distinguish mutable construction, freeze, cold hydration, warm reuse, traversal/query execution, rendering, and serialized payload.
- A cache is promoted only with measurable reuse and without eager whole-workspace hydration.

### Query and product validation

- Typed validation rejects incompatible query-domain compositions before execution.
- At least one JSON and one RQL query returns a typestate finding and bounded witness.
- Explicit protocol files load identically through JSON `protocol_files`, RQL `with-protocol`, and the embedding registry; traversal or duplicate-ID attempts fail deterministically.
- Set composition, policy conversion, ordering, limits, truncation, diagnostics, and capability behavior are deterministic.
- Every new public term has schema, parser/decoder, validation-range, hover/completion, grammar, execution, and documentation coverage.

The epic is accepted when #825 demonstrates the root issue’s end-to-end criteria with reproducible correctness and performance evidence. Full language rollout and #826 are follow-on outcomes, not blockers for the first platform milestone unless the pilot proves the baseline architecture unsound.

## Idempotence and Recovery

Semantic extraction, CFG freezing, summary composition, and snapshot serialization must be deterministic for the same source, adapter version, configuration, and dependencies. Re-running a build or analysis may replace a rebuildable cache row but must not accumulate alternate versions indefinitely.

Mutable builders are private construction phases. Publish an immutable snapshot only after all identity, boundary, and edge validations pass. If construction, cancellation, or a budget fails, discard the partial snapshot or mark the result incomplete; never install it as a complete cache entry.

SQLite migrations are additive and versioned. A stale or corrupt packed payload is an ordinary cache miss and should be rebuilt from source facts. Use transactions and existing generation checks so interrupted writes cannot leave a valid-looking partial artifact. Preserve old rebuildable rows only as long as the migration/GC policy requires; do not write ad hoc recovery parsers.

Solver summaries include completeness. On cancellation or budget exhaustion, keep partial data only for the current diagnostic/witness if useful; do not admit it to the complete reusable-summary cache. Recursive fixed points can be restarted safely from seeds and complete lower-level summaries.

If an implementation experiment performs poorly, retain the benchmark and decision in this plan or `.agents/docs/`, then remove the unused representation cleanly. Do not keep full rich and compact graphs side by side as an unmeasured fallback.

Issue and plan updates are safe to repeat after checking current state. Before creating a new child issue, search #813 and the repository issue index to avoid duplication. When a contract changes, update dependent issue bodies, this plan’s Decision Log, and any persisted schema/version before continuing.

## Artifacts and Notes

Roadmap artifacts created on 2026-07-16:

- Epic: https://github.com/BrokkAi/bifrost/issues/813
- Semantic contract: https://github.com/BrokkAi/bifrost/issues/814
- Callable CFG epic: https://github.com/BrokkAi/bifrost/issues/815
- Value/dispatch/heap oracle epic: https://github.com/BrokkAi/bifrost/issues/816
- Compact storage and persistence: https://github.com/BrokkAi/bifrost/issues/817
- ICFG epic: https://github.com/BrokkAi/bifrost/issues/818
- CFG algorithms and optional dominance: https://github.com/BrokkAi/bifrost/issues/819
- Solver epic: https://github.com/BrokkAi/bifrost/issues/820
- Simple data-flow/taint clients: https://github.com/BrokkAi/bifrost/issues/821
- Protocol/typestate epic: https://github.com/BrokkAi/bifrost/issues/822
- Semantic and protocol summaries: https://github.com/BrokkAi/bifrost/issues/823
- CodeQuery/RQL integration epic: https://github.com/BrokkAi/bifrost/issues/824
- Cross-language pilot: https://github.com/BrokkAi/bifrost/issues/825
- WPDS/SPDS evaluation: https://github.com/BrokkAi/bifrost/issues/826

Existing integration anchors:

- Structural query epic #328
- Policy/SARIF format #709
- Typed set composition #720
- Receiver facts/object sensitivity #393 and #394
- Call and receiver query traversal #719 and #718
- Compact graph experiment #748 / PR #798
- SQLite-backed compact structural snapshots PR #802
- Store failure reporting #695

Add the plan PR and merged commit here after publication. Add benchmark tables or links to `.agents/docs/` notes after each experimental milestone; include a recommendation, not only raw percentages.

## Interfaces and Dependencies

The names below are the initial implementation contract. They are not a long-term compatibility promise, but an implementation must either follow them or first record a replacement and migration in the Decision Log.

Providers return a value only with explicit completeness:

    enum AnalysisOutcome<T> {
        Complete { value: T, work: WorkReport },
        Inconclusive {
            partial: Option<T>,
            reason: IncompleteReason,
            work: WorkReport,
        },
        Unsupported { capability: SemanticCapability },
    }

The solver returns findings separately from run completion:

    struct AnalysisRun<F> {
        completion: AnalysisCompletion,
        findings: Vec<F>,
        work: WorkReport,
        witnesses: WitnessStore,
    }

    enum AnalysisCompletion {
        Complete,
        Inconclusive(IncompleteReason),
        Unsupported(SemanticCapability),
    }

`Complete` plus non-empty `findings` renders as `complete_finding`. `Complete` plus empty `findings` renders as `complete_no_finding`. The other variants render as specified in the soundness contract and may include partial findings.

The semantic adapter boundary is:

    trait ProgramSemanticsProvider {
        fn capabilities(&self) -> SemanticCapabilities;
        fn artifact_key(&self, procedure: &SemanticLocator) -> AnalysisOutcome<SemanticArtifactKey>;
        fn procedure(
            &self,
            key: &SemanticArtifactKey,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<Arc<ProcedureSemantics>>;
    }

`ProcedureSemantics` owns dense local IDs, source mappings, semantic effects, and an immutable CFG. It does not own solver facts or protocol states.

The interprocedural boundary contains control and call metadata, not value bindings:

    trait IcfgProvider {
        fn procedure(
            &self,
            key: &SemanticArtifactKey,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<Arc<ProcedureSemantics>>;

        fn call_control(
            &self,
            caller: &SemanticArtifactKey,
            call: CallSiteId,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<CallControlTargets>;
    }

`CallControlTargets` identifies candidate callee entries, the originating normal and exceptional return sites, proof, and unresolved/external status. It consumes existing call relations and dispatch evidence and never resolves syntax independently.

Value capabilities remain separate even if one implementation serves several traits:

    trait DispatchOracle {
        fn callees(
            &self,
            caller: &SemanticArtifactKey,
            call: CallSiteId,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<CalleeTargets>;
    }

    trait ValueFlowOracle {
        fn call_bindings(
            &self,
            caller: &SemanticArtifactKey,
            call: CallSiteId,
            callee: &SemanticArtifactKey,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<CallBindings>;
    }

    trait HeapOracle {
        fn locations(
            &self,
            value: ValueId,
            max_access_path: usize,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<AbstractLocations>;
    }

All candidate sets, contexts, facts, and access paths have positive finite limits recorded in `SemanticBudget` or `SolverBudget`.

The first solver client contract is:

    trait DistributiveMayProblem {
        type Fact: Copy + Eq + Hash;

        fn zero_fact(&self) -> Self::Fact;
        fn configuration_hash(&self) -> [u8; 32];
        fn max_interned_facts(&self) -> usize;
        fn seeds(&self, out: &mut Vec<(ProgramPointId, Self::Fact)>);

        fn normal_flow(
            &self,
            edge: ControlEdgeId,
            fact: Self::Fact,
            out: &mut Vec<Self::Fact>,
        );
        fn call_flow(
            &self,
            call: &CallTransfer,
            fact: Self::Fact,
            out: &mut Vec<Self::Fact>,
        );
        fn return_flow(
            &self,
            ret: &ReturnTransfer,
            fact: Self::Fact,
            out: &mut Vec<Self::Fact>,
        );
        fn call_to_return_flow(
            &self,
            call: &CallTransfer,
            fact: Self::Fact,
            out: &mut Vec<Self::Fact>,
        );
        fn exceptional_flow(
            &self,
            edge: ControlEdgeId,
            fact: Self::Fact,
            out: &mut Vec<Self::Fact>,
        );
    }

The implementation checks the configured fact limit before interning and returns `inconclusive` on overflow. Tests, not runtime sampling alone, establish that every flow family distributes over union. Context and work limits make the exploded domain finite.

An IDE client extends that contract:

    trait IdeProblem: DistributiveMayProblem {
        type Value: Clone + Eq;
        type EdgeFunction: Clone + Eq;

        fn lattice_height_bound(&self) -> usize;
        fn identity_edge(&self) -> Self::EdgeFunction;
        fn compose(
            &self,
            first: &Self::EdgeFunction,
            second: &Self::EdgeFunction,
        ) -> Self::EdgeFunction;
        fn meet_edges(
            &self,
            left: &Self::EdgeFunction,
            right: &Self::EdgeFunction,
        ) -> Self::EdgeFunction;
        fn apply(&self, edge: &Self::EdgeFunction, value: &Self::Value) -> Self::Value;
    }

Property tests cover identity, associative composition, commutative/idempotent meet where the chosen algebra requires it, distributivity, and stabilization within `lattice_height_bound`. Non-distributive clients cannot implement the IFDS/IDE entry point merely by declaration; they use a separately reviewed backend.

The kernel must support:

- a zero/identity reachability fact;
- direct and indirect value-flow facts;
- taint facts with source/sink/sanitizer events;
- typestate facts paired with protocol state;
- an IDE-style value client without changing ICFG or adapter code.

Summary ownership is explicit:

- `TabulationEndSummary` is private to `dataflow::tabulation` and required for IFDS/IDE correctness and recursion convergence.
- `SemanticProcedureSummary` is a reusable client-independent projection owned by `dataflow::summary`.
- `ProtocolSummary` is owned by `typestate::summary` and includes the protocol hash.

A `SummaryStore` may memoize either reusable type in memory and optionally SQLite, but the solver accepts an in-memory implementation and does not require persistence to be correct. Incomplete `TabulationEndSummary` values never enter a complete reusable summary.

Public query changes depend on the declarative schema registry in `src/analyzer/structural/query/schema.rs`. Do not add private keyword lists, editor-only vocabulary, or source-text path parsing. Existing Rust dependencies should be preferred for the first implementation; any new solver or graph crate requires a measured build/runtime benefit and an explicit Decision Log entry.

Plan revision note (2026-07-16): Initial roadmap written after auditing the post-PR-#802 codebase and creating epic #813 with native subissues #814–#826. The initial plan deliberately makes TypeScript/Java the reference pair, IFDS/IDE the baseline solver shape, compact memory plus selective SQLite the lifecycle policy, dominance optional, and WPDS/SPDS evidence-gated.
