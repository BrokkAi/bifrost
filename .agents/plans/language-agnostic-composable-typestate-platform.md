# Build a language-agnostic, composable typestate analysis platform

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current as implementation proceeds. Follow `.agents/PLANS.md` when revising it.

The GitHub roadmap is rooted at [issue #813](https://github.com/BrokkAi/bifrost/issues/813). Its native subissues are #814 through #826. This plan is the durable architectural and execution record behind that issue tree; the issues remain the unit of implementation and review.

## Purpose / Big Picture

Bifrost already answers structural, reference, call, and bounded receiver questions across several languages. The goal of this roadmap is to turn those components into a language-agnostic platform for interprocedural data flow and typestate without collapsing them into a monolithic code property graph or committing to SMT-backed symbolic execution.

After the first vertical slice, a rule author should be able to describe a finite-state resource protocol once, select relevant program entities through `CodeQuery` or RQL, run the protocol across matched calls and returns in TypeScript and Java, and receive a bounded source-backed may finding that says which facts and summaries supported it and whether ambiguity or budgets made the analysis incomplete. A trivial one-state client should use the same substrate for direct and indirect data flow, and a source/sink/sanitizer client should use it for taint-style propagation.

The public policy model must also avoid the narrow-rule trap of enumerating every source/sink pair as a separate vulnerability rule and solver run. Human-authored diagnostic-neutral endpoint leaves attach typed bindings, opaque categories, display phrases, and source/sink semantics to native RQL matches. A taint policy explicitly selects endpoint sets by category or exact identity, runs one multi-source/multi-sink propagation, and reports a meeting whenever a compatible reached source label arrives at a sink. One uniquely dominant intentional combination may replace the fixed generated source-to-sink presentation; otherwise the broad finding remains. Specific CWE classifications refine rather than create that finding. Procedure summaries describe propagation independently of concrete seed/sink lists, categories, messages, and classifications so policies can reuse the same dynamic-programming work.

The initial target is meet-over-valid-interprocedural-paths analysis. “Valid” means call and return edges are matched rather than traversed as unrelated graph edges. The first solver accepts finite distributive may problems whose reachable facts join with set union, plus bounded-height IDE edge values that satisfy the laws specified below. A must claim requires a separately defined and validated problem; it is not obtained by relabeling a may result. The first platform does not use SMT to prove arbitrary branch feasibility.

The implementation should feel modular in the same way that Boomerang, IDEal, and synchronized pushdown systems separate concerns: language semantics, control-flow construction, dispatch/value oracles, solver mechanics, client rules, summary storage, and query presentation each have an explicit boundary. Bifrost’s usage analysis is an oracle and reusable component in this design, not something to discard and not something to turn into the entire solver.

## Progress

- [x] (2026-07-16 09:30+02:00) Audited the current repository, completed issue and source-architecture audits, fetched `origin/master`, and based this work on commit `4051809a` (PR #802).
- [x] (2026-07-16 09:51+02:00) Created root epic #813 and thirteen dependency-ordered native subissues #814 through #826.
- [x] (2026-07-16 09:52+02:00) Cross-linked #813 with the existing structural-query epic #328, policy issue #709, and typed set-composition issue #720.
- [x] (2026-07-16 09:58+02:00) Wrote this living ExecPlan with architecture, lifecycle, milestone, validation, and recovery contracts.
- [x] (2026-07-16 10:27+02:00) Published the plan from checkpoint commit `41f1e88b` for review.
- [x] (2026-07-16 10:35+02:00) Made #709 the early public policy/API contract gate for #824 and #825 while keeping #814 through #823 free to build diagnostic-neutral internal analysis services.
- [x] (2026-07-16 11:43+02:00) Defined and published set-oriented taint policies, compatible multi-policy batching, symbolic taint summaries, broad meeting-point findings, exact cache layers, and evidence-backed CVSS classification across #709, #813, #821, #823, and #824.
- [x] (2026-07-16 12:39+02:00) Moved the publication thread to neutral branch `dave/composable-typestate-roadmap` and draft PR [#828](https://github.com/BrokkAi/bifrost/pull/828).
- [x] (2026-07-16 14:39+02:00) Diagnosed #814 in detail and added the focused implementation plan `.agents/plans/issue-814-semantic-ir-contract.md`, including corrected artifact/ID scopes and explicit nested-callable, capture, method-reference, and source-position contracts.
- [x] (2026-07-16 15:32+02:00) Implemented #814's identities, capabilities, outcomes/budgets, immutable artifact/procedure IR, invariant validation, scoped handles, bounded renderer, and TypeScript/Java contract fixtures.
- [x] (2026-07-16 18:01+02:00) Completed #814 after specialist review and final invariant audits; all focused tests, the complete `nlp,python` suite, all-target/all-feature clippy, formatting, and diff checks passed, and the reviewed implementation was checkpointed as `296c1de1` after rebasing onto current `master`.
- [x] (2026-07-16 19:20+02:00) Addressed all guided-review findings in `1faf8b9b`, including converged typed continuations, targetless uncertain callable creation, and shared bounded-renderer/registry utilities; all repository gates passed.
- [x] (2026-07-17 10:10+02:00) Started #815 execution with the focused living plan `.agents/plans/all-language-cfg-icfg-rollout.md`, spanning callable CFGs, the #816 dispatch prerequisite, one #818 ICFG, all eleven analyzable-language adapters, and the evidence-gated CFG/ICFG slice of #817.
- [x] (2026-07-17 11:40+02:00) Completed #815 Milestone 1a: canonical rich control-edge IDs, immutable bidirectional adjacency, storage-independent predecessor/successor traversal, corruption validation, bounded schema-v2 rendering, shared CFG contract tests, full repository gates, and post-milestone specialist review are green.
- [x] (2026-07-17 14:34+02:00) Completed #815 Milestones 1b and 1c: the atomic file/dialect-aware provider, bounded exact source snapshots, complete-only semantic cache, private iterative CFG builder, real TypeScript/TSX callable lowering, source-backed adjacency harness, full repository gates, and specialist review are green.
- [x] (2026-07-17 16:05+02:00) Completed the TypeScript/TSX and Java reference callable-CFG checkpoints under #815, including the shared inline topology harness, typed advanced-feature gaps, differential cases, representation benchmark, strict repository gates, and post-milestone reviews. The all-language #815 rollout remains open behind the reference ICFG contract.
- [x] (2026-07-17 16:54+02:00) Completed the #816 dispatch prerequisite and #818 TypeScript/Java vertical slice: exact whole-call resolution, one bounded context-bearing ICFG, matched normal/exceptional returns, typed incomplete boundaries, source-generation validation, shared inline assertions, and post-milestone review are complete. The shared adapter contract is frozen for the remaining #815 languages.
- [x] (2026-07-17 17:00+02:00) Created and natively attached the nine remaining #815 rollout children: #887 JavaScript/JSX, #886 C#, #888 Python, #889 Go, #891 Rust, #890 PHP, #892 Scala, #893 Ruby, and #894 C/C++, each cross-linked to #816 and #818.
- [x] (2026-07-18 10:45+02:00) Completed #815 Milestone 4a: JavaScript and JSX now share the structured TypeScript lowering core behind exact flavor identities and pass the common direct-call CFG/ICFG conformance contract with point-scoped advanced-feature gaps.
- [x] (2026-07-18 11:52+02:00) Completed #815 Milestone 4b: C# now supplies real callable CFGs and direct matched-return ICFGs through the frozen shared provider, builder, dispatch, and snapshot boundary; independent review fixed indexed-call evaluation, target-typed object-initializer order, and conditional-compilation gaps before checkpoint validation.
- [x] (2026-07-18 12:06+02:00) Validated the reviewed C# checkpoint with formatting, diff checks, strict all-target/all-feature clippy, and the complete host-access `nlp,python` repository suite (1,053 library tests passed, 4 ignored, plus every binary, integration, and doc-test target).
- [x] (2026-07-18 13:11+02:00) Completed and validated #815 Milestone 4c: Python now supplies real callable CFGs and direct matched-return ICFGs through the shared engine, with deferred coroutine/generator invocation modeled explicitly; specialist review fixes, 37 CFG, 17 ICFG, 28 language-conformance, 11 provider tests, strict clippy, and the complete host-access feature suite are green.
- [x] (2026-07-18 14:17+02:00) Completed and validated #815 Milestone 4d: Go now supplies real callable CFGs and matched-return ICFGs through the shared engine; specialist review made selected-call omissions and partially unspecified evaluation order explicit, proved shadowed `panic`/`recover` dispatch, and passed 37 CFG, 17 ICFG, 37 language-conformance, 11 provider tests, strict clippy, and the complete host-access feature suite.
- [x] (2026-07-18 15:52+02:00) Completed and validated #815 Milestone 4e: Rust now supplies real callable CFGs and matched-return ICFGs through the shared engine; specialist review made parameter, lexical, pattern-binding, assignment-replacement, and abrupt-path RAII/Drop omissions exact, prevented fabricated try-block and macro control, exposed implicit trait-call gaps, corrected labeled-block break routing and generic dispatch, and passed 39 CFG, 17 ICFG, 55 language-conformance, 11 provider, and 483 definition tests plus strict clippy and the complete host-access feature suite.
- [x] (2026-07-18 17:20+02:00) Completed and validated #815 Milestone 4f: PHP now supplies real callable CFGs and matched-return ICFGs through the shared engine; specialist review corrected whole-chain nullsafe and nullish control, loop and switch grammar, first-class callable classification, method-return dispatch, bounded candidate selection, zero-target ambiguity, and exact `finally` routing, then passed 39 CFG, 18 ICFG, 10 semantic-IR, 73 language-conformance, 11 provider, and 486 definition tests plus strict clippy and the complete host-access feature suite.
- [x] (2026-07-18 19:00+02:00) Completed #815 Milestone 4g: Scala now supplies real callable CFGs and matched-return ICFGs through the shared engine; specialist review corrected partial-function and initializer ownership, non-local closure return, curried constructor collapse, parameter-list arity and primary-constructor shape, generic wrapper and operator dispatch, nested-call pruning, structured-argument cardinality, and by-name/implicit-operation gaps, then passed 39 CFG, 18 ICFG, 10 semantic-IR, 93 language-conformance, 11 provider, and 497 definition tests plus focused call-site/call-relation suites.
- [x] (2026-07-18 19:12+02:00) Validated the final reviewed #815 Milestone 4g tree with formatting, diff checks, strict all-target/all-feature clippy, and the complete host-access `nlp,python` suite across every library, binary, integration, and doc-test target.
- [x] (2026-07-18 21:27+02:00) Completed #815 Milestone 4h: Ruby now supplies real callable CFGs and matched-return ICFGs through the shared engine; specialist review corrected pattern evaluation, callable-table mutation, destructured writers, bounded collection, non-local cleanup, operator and callable-object dispatch, lifecycle-block ownership, and parser-ordered local activation and closure capture, then passed 39 CFG, 18 ICFG, 10 semantic-IR, 111 language-conformance, 11 provider, 497 definition, and 17 Ruby library/dispatch tests.
- [x] (2026-07-18 21:46+02:00) Validated the final reviewed #815 Milestone 4h tree with formatting, diff checks, strict all-target/all-feature clippy, and the complete host-access `nlp,python` suite (1,079 library tests passed, 4 ignored, plus every binary, integration, and doc-test target).
- [x] (2026-07-19 00:48+02:00) Completed #815 Milestone 4i and the all-language adapter rollout: C and C++ now supply real callable CFGs and matched-return ICFGs through the same shared engine as the other nine rollout targets; C/C++ and cross-language specialist reviews closed with no P0/P1 findings after correcting structured linkage, implicit-object and late-static dispatch, path-sensitive return evidence, unresolved-boundary quality, and caller-side implicit evaluation gaps.
- [x] (2026-07-19 00:48+02:00) Passed the reviewed all-language focused gates: 39 CFG, 25 ICFG, 129 language-conformance, 10 semantic-IR, 11 provider, 9 ICFG-unit, 14 call-relation-unit, and 498 definition tests.
- [x] (2026-07-19 01:06+02:00) Validated the final reviewed #815 Milestone 4i tree with formatting, diff checks, strict all-target/all-feature clippy, and the complete host-access `nlp,python` suite (1,094 library tests passed, 4 ignored, plus every binary, integration, and doc-test target). The focused #817 persistence measurement remains open.
- [x] (2026-07-20 09:23+02:00) Completed the focused #817 semantic/CFG lifecycle slice with nine-process release matrices over generated graphs, inline TypeScript/Java fixtures, pinned VS Code, and pinned Spring PetClinic. Bidirectional edge-ID rows remain the hot layout; production SQLite is a measured no-go because the optimistic packed control/call projection failed the VS Code absolute write-overhead gate. Later value-flow, solver, and summary lifecycle decisions remain open under #817.
- [x] (2026-07-20 09:23+02:00) Completed a post-rollout semantic architecture audit. It confirmed one shared language-neutral ICFG, identified repeated point/effect/call emission and procedure-driver mechanics across adapters, and recommended a dedicated no-semantic-change extraction before #816 value/heap and data-dependence work; no source refactor is implicitly authorized by this planning observation.
- [x] (2026-07-20 09:59+02:00) Validated the exact final #815/#817 tree with focused representation and persistence tests, formatting and diff checks, strict isolated all-target/all-feature clippy, and the complete host-access `nlp,python` repository suite (1,094 library tests passed, 4 ignored, plus every binary, integration, and doc-test target).
- [x] (2026-07-17 10:18+02:00) Diagnosed #709 and added `.agents/plans/issue-709-static-analysis-policy-format.md`, selecting a distinct S-expression `.rqlp` authoring language with native versioned RQL selectors and canonical JSON only as generated interchange.
- [x] (2026-07-17 15:14+02:00) Synchronized compatible omitted policy/RQL versions, diagnostic-neutral categorized endpoint leaves, explicit match-directory manifests, generated/default versus superseding combination presentation, and resolved endpoint-driven typestate terminal expectations from the clarified #709 workflow.
- [ ] Complete #816 in parallel: expose reusable dispatch, value, heap, and bounded access-path oracles for the reference languages.
- [x] Complete #818's internal TypeScript/Java control-topology slice: stitch CFG fragments through existing call relations into a demand-materialized ICFG. Public query exposure and value/heap transfers remain in their owning issues.
- [ ] Complete #819 as needed: add iterative reachability, reverse postorder, SCC, and loop utilities; add dominators only after a named client justifies them.
- [ ] Complete #820: implement an iterative, summary-driven IFDS/IDE-shaped solver with budgets, cancellation, uncertainty, and witnesses.
- [ ] Complete #821 and #822: prove simple data-flow/taint reuse, then add the finite-state protocol IR and typestate client.
- [ ] Complete #823 and #817 promotion work: compose summaries in memory first, then persist only measured expensive and reusable artifacts.
- [ ] Complete #709 before #824 freezes its public surface: establish `.rqlp`, `PolicyDefinition`, `PolicyFinding`, and shared human/SARIF rendering without waiting for the typestate solver.
- [ ] Complete #824: expose typed, bounded CFG/data-flow/taint/typestate domains through `CodeQuery` and RQL, then adapt diagnostic-neutral findings to #709's policy boundary.
- [ ] Complete #825: deliver and benchmark one TypeScript/Java resource-lifecycle protocol through internal, query, `.rqlp`, human, and SARIF paths.
- [ ] Complete #826 only after #825: decide, with evidence, whether WPDS weights or synchronized call/field pushdown precision should be implemented.
- [x] Opened and natively attached per-language rollout children under #815 after the reference CFG/ICFG contract stabilized; their ordered implementation remains tracked in the focused rollout plan.

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

- Observation: `CodeUnit` is not an exhaustive executable-procedure identity for nested callables, and current line metadata is not one uniform durable coordinate contract.
  Evidence: Java creates synthetic lambda units that call relations exclude, other adapters do not index every nested callable, nested-call traversal is deliberately pruned, and declaration versus call-site `Range` construction uses different line bases.

- Observation: capture storage crosses procedure scopes in one direction: creation bindings belong to the lexical parent, while the slot loaded by the body belongs to the child procedure.
  Evidence: #814 validation and fixtures require creator-local values/environments to target child-local capture locations, including several static creation sites feeding one body slot.

- Observation: partial semantic artifacts need typed missing-control states and exact reverse correlations, not optional targets plus advisory gaps.
  Evidence: #814 review introduced typed continuations, exact invoke/suspend outgoing topology, subject-scoped gaps/evidence, and constrained unmaterialized direct-child targets so incomplete adapters cannot fabricate or contradict control flow.

- Observation: semantic resource bounds must cover nested retained payload and streamed output, not merely top-level row counts.
  Evidence: #814 construction now accounts atomically for every retained entry and owned byte, validation is indexed and linear, and the renderer emits complete records transactionally within its byte budget.

- Observation: GitHub supports native subissues in this repository, so #814 through #826 can be attached directly to #813 while retaining explicit dependency text in each body.
  Evidence: the live `subIssues` query for #813 returned all thirteen children.

- Observation: #815's predecessor/successor contract requires a rich-edge graph shape that the existing payloadless compact graph cannot directly supply.
  Evidence: semantic CFGs preserve parallel source-target edges with different kinds or evidence, so one canonical `ControlEdge` table plus edge-ID adjacency is required. The focused implementation and rollout are tracked in `.agents/plans/all-language-cfg-icfg-rollout.md`.

- Observation: #815 Milestone 1a validated the initial bidirectional shape without freezing later adapter or ICFG boundaries.
  Evidence: schema-v2 `ControlFlowGraph` introduced canonical rich edges, outgoing offsets, and incoming edge-ID rows; exact traversal and rendering are deterministic under permuted construction and corrupted incoming order is rejected. At that checkpoint, TypeScript/Java lowering and the provider boundary remained intentionally deferred to the next focused milestones.

- Observation: #815 Milestones 1b and 1c proved that exact source identity, publication, and dead-code isolation are part of the semantic contract rather than adapter conveniences.
  Evidence: the provider atomically snapshots bounded disk or overlay content with dialect and monotonic overlay revision, caches only complete immutable artifacts by retained bytes, and lowers TypeScript/TSX through an iterative builder whose reachability seal preserves dead internal topology without permitting dead-to-live or dead-to-exit reconnections.

- Observation: the TypeScript/Java differential checkpoint forced one additional neutral completion kind but did not require language-specific CFG storage or a universal syntax-lowering IR.
  Evidence: Java switch-expression `yield` now uses a shared cleanup-safe yieldable continuation, while Java syntax still maps structured tree-sitter fields directly into the private sequence, branch, loop, call, handler, cleanup, and abrupt-completion builder operations. Java executable initializer fragments are real procedures with scoped deferred-scheduling gaps rather than fabricated constructor flow.

- Observation: bidirectional adjacency remains the measured hot layout even though outgoing-only CSR saves 22-30% retained bytes in representative cases.
  Evidence: the release matrix measured reverse traversal rising from roughly one millisecond to 6.5-8.5 seconds on 100k-edge synthetic graphs and by 5-7x on TypeScript/Java corpus artifacts. Flat edges made both directions linear scans. The canonical edge table plus outgoing offsets plus incoming edge-ID rows therefore survives the Milestone 2 representation gate.

- Observation: the TypeScript/Java ICFG slice requires context-bearing snapshot nodes even though callable CFG nodes remain context-free.
  Evidence: two call sites entering one callee share the immutable procedure artifact, but their callee exits must return to different continuations. Interning `(program point, exact bounded call stack)` in the ephemeral snapshot preserves that distinction without cloning or persisting the base CFG.

- Observation: the first post-reference rollout did not require a second adapter engine or ICFG implementation.
  Evidence: JavaScript/JSX reuse the TypeScript structured lowerer with explicit grammar-flavor branches and unchanged TypeScript fingerprints, while the existing location-first dispatch facade and context-bearing `WorkspaceIcfgProvider` materialize their cross-file calls without language-specific stitching.

- Observation: the first independently implemented post-reference adapter also fit the frozen graph and dispatch boundary, while exposing why conformance must exercise grammar-specific evaluation shapes.
  Evidence: C# direct calls use the existing dispatch oracle and shared ICFG unchanged. Review-driven tests were still needed to prove indexed delegate evaluation, conditional element binding, target-typed object initializers, and terminal configuration-dependent `#if` boundaries, because those shapes use different tree-sitter fields than superficially similar member and object-creation expressions.

- Observation: async and generator flags are insufficient to determine call-to-body control across languages.
  Evidence: Python coroutine/generator calls, JavaScript generators, and C# iterators create suspended objects, while JavaScript and C# async calls begin synchronously. The common procedure contract now records invocation timing independently, and the single ICFG represents deferred targets as typed boundaries with explicit caller-continuation models rather than false body entry.

- Observation: deterministic semantic topology and language-defined evaluation order are separate contracts.
  Evidence: Go fully orders calls, method calls, receives, and logical operations but leaves some surrounding operands and composite-literal elements unordered. The Go adapter retains deterministic source-order rows for identity and rendering while attaching source-backed control gaps to the exact parents whose relative order is incomplete.

- Observation: scheduled or selected calls can be syntactically identifiable without being valid immediate ICFG transfers.
  Evidence: Go `defer` and `go` evaluate function values and arguments immediately but schedule the outer call for later or concurrent execution; `select` evaluates communication operands before choosing one case. Omitting only the non-immediate or selected-only calls and reporting typed call/scheduling gaps preserves known evaluation without fabricating control.

- Observation: a shared cleanup-continuation stack can represent language-specific destructor uncertainty without inventing destructor bodies or calls.
  Evidence: Rust parameter, lexical, and pattern scopes use opaque cleanup markers so normal and abrupt exits carry exact cleanup/resource/call/exception gaps at real transfer points, while assignment replacement has its own point-scoped omissions and shared CFG/ICFG destinations remain unchanged.

- Observation: conservative structured lowering sometimes requires suppressing apparently traversable syntax.
  Evidence: lowering `?` inside an unsupported Rust try block through the procedure completion scope fabricated a return. Treating the try block and macro expansion as terminal typed boundaries is more accurate than plausible-looking inner topology, while operators, indexing, autoderef, and await retain known prefixes with implicit-call gaps.

- Observation: language-local short-circuit scope can be broader than one AST operator node.
  Evidence: PHP's nullsafe operator skips the remainder of one complete access chain, including later calls, properties, arguments, dynamic names, and subscripts, but nested subexpressions start independent nullsafe scopes. An adapter-owned chain continuation expresses that rule without changing common graph or ICFG mechanics.

- Observation: exact call-expression identity is sufficient for an incomplete dispatch outcome even when no separate callee-leaf span exists.
  Evidence: unresolved and bounded ambiguous PHP sites retain exact call handles but may have no publishable leaf. Requiring every completed dispatch to retain a target or typed boundary preserves the outcome without fabricated syntax; intermediate nullsafe properties remain definition candidates but no longer consume immediate-call budgets.

- Observation: Scala callable ownership and call completeness cannot be inferred from a node kind or argument delimiter alone.
  Evidence: standalone `case_block`s are deferred partial-function bodies while match/catch cases execute immediately; initializer subtrees own nested closures but not member methods; parentheses do not prove strict parameters and braces do not prove by-name parameters. The adapter therefore keys partial execution by the current procedure body, preserves synthetic initializer ownership only through executable subtrees, retains one actual per structured argument, and publishes exact deferred/implicit-call/exception gaps whenever signatures or runtime protocols are unresolved.

- Observation: Ruby local-versus-call classification requires a parser-ordered binding timeline, including the source position where each nested callable is created.
  Evidence: a bare name before its first structured assignment is a call while the same name after that assignment is local; assignment targets activate before their right-hand side, and closures inherit only outer bindings already active at their syntax position. Exact semantic dispatch can apply this timeline, while legacy outgoing-call discovery remains intentionally narrow until it shares the same callable context.

- Observation: the final C/C++ adapter did not require a second graph or ICFG, but it did require link-unit identity and caller-side uncertainty to remain separate from control topology.
  Evidence: compatible declarations and definitions coalesce through structured C/C++ resolution while configuration, default arguments, implicit conversions/calls, temporaries, RAII, exceptions, spawn, coroutines, and `noexcept` remain exact gaps. The same location-first oracle and context-bearing ICFG then preserve proven targets with partial transfer evidence where appropriate.

- Observation: context-matched return topology alone does not prove complete completion transfer.
  Evidence: reachable cleanup, exceptional, or non-local gaps on a callee entry-to-exit path can alter whether or how that exit is reached. A bounded iterative forward/reverse path mask now weakens only affected returns, so disconnected omissions no longer contaminate an otherwise exact call while every unresolved dispatch boundary remains incompatible with a complete snapshot.

- Observation: the focused #817 benchmark distinguishes traversal layout from persistence lifecycle and rejects promotion on the conjunction of predeclared gates.
  Evidence: bidirectional rows traverse the generated 100k branch graph in 0.566/0.566 ms versus outgoing-only 0.559/4,467.02 ms and flat 4,450.98/4,438.78 ms. The optimistic SQLite projection hydrated pinned VS Code in 207.05 ms versus a 24,614.13 ms rebuild and pinned Spring PetClinic in 0.79 ms versus 58.21 ms, but VS Code build-plus-write added 1,275.69 ms and failed the 250 ms absolute-overhead gate. Production storage therefore remains unchanged for this artifact slice.

- Observation: the eleven language adapters share graph and ICFG mechanics but still duplicate a lower-level semantic emission substrate.
  Evidence: `src/analyzer/semantic/icfg.rs` owns the one generic ICFG, while the language `semantic.rs` modules repeat point allocation, source/evidence mapping, values, effects, gaps, call scaffolding, budget staging, and finalization. The highest-value cleanup is a source-anchor-aware `ProcedureLoweringSession` plus a shared call scaffold and procedure batch driver, not a universal syntax visitor. The generic ICFG also contains two C++-specific gap checks that should become typed gap-impact metadata before value/heap work expands the dependency surface.

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

- Decision: execute #815, the dispatch slice of #816, #818, and all remaining language adapters through one focused living plan while retaining issue-sized checkpoint reviews.
  Rationale: TypeScript and Java must pressure-test both intraprocedural lowering and matched interprocedural transfers before the contract freezes, while one continuous record keeps all-language capability gaps and the CFG/ICFG lifecycle slice of #817 coherent. Later value-flow, solver, and summary persistence decisions remain in the broader roadmap. The implementation still preserves issue ownership and excludes public query, solver, value/heap, and typestate work.
  Date: 2026-07-17.

- Decision: publish semantic artifacts only from one bounded, origin- and overlay-revision-aware syntax snapshot, and cache only complete values by conservative retained bytes with per-key single flight.
  Rationale: key/artifact races, entry-count-only memory bounds, duplicate concurrent lowering, and reuse of cancelled or partial work would all undermine later ICFG and solver correctness. Exact complete artifacts may be reused across analyzer updates when their full source identity is unchanged.
  Date: 2026-07-17.

- Decision: enforce dead-source isolation with a shared iterative CFG seal after language lowering.
  Rationale: language adapters retain syntactically present unreachable points for diagnostics and analysis, but those points must never reconnect to entry-reachable control or either real exit. Enforcing the invariant at the graph boundary keeps future adapters honest without replacing their structured completion semantics.
  Date: 2026-07-17.

- Decision: keep Java switch-expression `yield` distinct from procedure return and loop/switch break in the neutral completion vocabulary.
  Rationale: yield targets the nearest switch-expression merge and must preserve that destination through intervening cleanup. A dedicated completion kind prevents cross-return and avoids mislabeling language semantics while remaining dormant for adapters that do not emit it.
  Date: 2026-07-17.

- Decision: retain canonical bidirectional control-edge rows after the TypeScript/Java representation benchmark.
  Rationale: outgoing-only storage achieved meaningful memory savings but failed the reverse-traversal contract decisively; rebuilding or lazily retaining a reverse index would either reintroduce the same state or make traversal latency unpredictable. Flat storage failed both directions. Persistence remains a separate #817 lifecycle decision.
  Date: 2026-07-17.

- Decision: confirm bidirectional control-edge rows with the final generated and representative-corpus matrix, and record a no-go for production persistence of the current semantic/CFG control-and-call slice.
  Rationale: both traversal directions remain hot contractual APIs, and the final matrix reproduced the reverse-traversal penalty of leaner layouts at corpus scale. Although an optimistic packed SQLite DTO demonstrated large hydration savings, it failed the predeclared VS Code absolute write-overhead gate; a fuller equivalent artifact would add payload and invalidation cost. Per-file semantic artifacts remain immutable and byte-bounded in memory, ICFG stitches remain generation-local, and bounded snapshots remain ephemeral. This does not prejudge later value-flow or reusable-summary persistence candidates.
  Date: 2026-07-20.

- Decision: freeze one exact-location dispatch facade and one context-bearing demand-materialized ICFG as the cross-language control boundary.
  Rationale: existing query and LSP resolution remains authoritative for candidate discovery, while the ICFG provider alone owns invoke-scaffold suppression, bounded call contexts, matched returns, typed incomplete boundaries, and dense traversal snapshots. This prevents each language adapter from inventing a second resolver or ICFG.
  Date: 2026-07-17.

- Decision: reuse the JavaScript/TypeScript structured lowering core through flavor-specific semantic providers while preserving separate durable adapter/configuration fingerprints.
  Rationale: shared control mechanics eliminate drift, but exact prepared-language validation and JavaScript-specific fields, resource declarations, and JSX gaps keep each grammar honest. JSX remains a JavaScript source flavor rather than a new persisted semantic dialect.
  Date: 2026-07-18.

- Decision: keep C# as a structured language adapter over the shared iterative CFG/ICFG mechanics, and represent unavailable conditional-compilation selection as a terminal source-backed control gap.
  Rationale: C# callable identity and syntax require an adapter, not another graph or resolver. Selecting a preprocessor arm without compilation symbols would fabricate control, while silently filtering the node would hide incompleteness; the typed boundary preserves both the common contract and honest uncertainty.
  Date: 2026-07-18.

- Decision: keep Go on the shared CFG/ICFG boundary by modeling `defer`, `go`, and `select` as exact known prefixes plus typed incomplete points, and by qualifying deterministic source-order linearization wherever Go leaves relative operand order unspecified.
  Rationale: an outer `defer` or goroutine call is not an immediate call-to-entry transfer, a selected case cannot be chosen statically, and nondeterministic graph construction would destabilize identities. Existing scheduling, call, control, cleanup, spawn, and exceptional capability gaps preserve these distinctions without a Go-specific ICFG or false topology.
  Date: 2026-07-18.

- Decision: keep Rust on the shared CFG/ICFG boundary by using opaque cleanup markers for unknown Drop behavior, terminal boundaries for unsupported try blocks and macros, and point-scoped gaps for implicit trait calls.
  Rationale: these constructs pressure completion scope, cleanup, and hidden-call completeness but do not justify Rust-specific graph or ICFG mechanics. Known evaluation prefixes remain structured; unknown destructor, residual, expansion, autoderef, operator, and polling behavior is never fabricated.
  Date: 2026-07-18.

- Decision: keep PHP on the shared CFG/ICFG boundary with adapter-owned chain-scoped nullsafe control and a dispatch invariant based on retained targets or typed boundaries rather than optional callee-leaf spans.
  Rationale: complete-chain skipping and nullish coalescing are PHP syntax semantics, while unresolved or bounded exact calls are shared dispatch outcomes. Keeping both distinctions explicit prevents false control and silent loss without introducing a PHP graph, resolver, or ICFG.
  Date: 2026-07-18.

- Decision: keep Scala on the shared CFG/ICFG boundary with adapter-owned callable-body identity and parameter-list metadata, while treating unproven grouping, strictness, and implicit operations as scoped incompleteness.
  Rationale: partial functions, synthetic initializers, curried applications, right-associative operators, by-name parameters, extractors, auto-application, and interpolation need Scala syntax mapping but not another graph or ICFG. Known evaluation and dispatch use the common builder and oracle; compound infix precedence, prefix dispatch breadth, implicit protocols, and deferred timing remain exact typed boundaries.
  Date: 2026-07-18.

- Decision: keep Ruby on the shared CFG/ICFG boundary with adapter-owned parser-ordered binding activation and exact dynamic-operation gaps, while leaving legacy outgoing-call discovery conservative.
  Rationale: bare identifiers, implicit returns, non-local block control, `ensure`, safe navigation, callable-table mutation, and overrideable operators require Ruby syntax and scope mapping but not another graph or ICFG. Exact semantic sites have the callable and source-position context needed for sound call classification; broadening the older outgoing path without that context would fabricate local reads as calls.
  Date: 2026-07-18.

- Decision: keep language-semantic summaries separate from rule-specific protocol summaries.
  Rationale: adapter/call/value effects can be reused by several clients, while a protocol summary must include its rule hash and map incoming client state to outgoing client state and effects.
  Date: 2026-07-16.

- Decision: extend #328, #709, and #720 through cross-links rather than duplicate or absorb them.
  Rationale: #328 owns structural querying, #709 owns policy/SARIF presentation, and #720 owns typed set algebra. The new epic supplies semantic-analysis domains that integrate with each boundary.
  Date: 2026-07-16.

- Decision: make #709 a prerequisite for finalizing the stable policy-facing API in #824 and for the public vertical-slice acceptance in #825, but not for semantic IR, CFG/ICFG, solver, or internal typestate milestones.
  Rationale: policy identity, severity, messages, loading, and human/SARIF rendering should be designed before taint or typestate becomes a public diagnostic surface. Conversely, forcing CFG and tabulation work to wait on a file/reporting format would couple independent concerns and leave #709 guessing at solver internals. #709 owns `.rqlp`, `PolicyDefinition`, public `TaintPolicySpec`/`TypestatePolicySpec`, and `PolicyFinding`; #821 owns internal taint plans/findings, #822 owns the internal `ProtocolSpec`/`TypestateFinding`, #823 owns reusable summaries, and #824 owns the compilers/adapters between those models.
  Date: 2026-07-16.

- Decision: identify compiled protocols by canonical hash and an execution-scoped `ProtocolHandle`, with human-readable `ProtocolRef` aliases resolved only through an explicit query-analysis context.
  Rationale: a global protocol ID can silently collide when two policies declare different bodies under the same name. Registration must reject one reference mapping to different hashes. Different references may share one hash/compiled automaton, and persisted summaries remain keyed by the canonical hash rather than the alias or handle slot.
  Date: 2026-07-16.

- Decision: use `analysis.type` as the public `.rqlp` discriminator, with distinct `match`, `taint`, and `typestate` authoring types.
  Rationale: sources, sinks, sanitizers, protocol automata, and structural-match reporting have different required fields and validation laws. A tagged public union keeps these requirements explicit while lowering each type into diagnostic-neutral internal services.
  Date: 2026-07-16.

- Decision: author `.rqlp` in a separate S-expression grammar with native independently versioned RQL child expressions; retain canonical JSON only as generated machine interchange and hashing input.
  Rationale: the shared byte-spanned parser, formatter, comments, and direct AST-to-CodeQuery lowering give precise nested diagnostics without quoted selector strings, YAML block-scalar offset maps, indentation sensitivity, aliases, or implicit typing. One file contains either a runnable `(policy ...)` or diagnostic-neutral `(endpoint ...)` document. Policy/endpoint and RQL `:schema-version` fields are optional conveniences resolved through separate compiled-in source-and-semantic-compatible lineages; explicit values remain exact pins. `.agents/plans/issue-709-static-analysis-policy-format.md` owns the exact syntax, resolution, and implementation contract. Generated JSON is never accepted `.rqlp` authoring.
  Date: 2026-07-17.

- Decision: compose human-authored reusable matches as diagnostic-neutral endpoint leaves selected from explicit capability-rooted directories or by exact ID.
  Rationale: each endpoint leaf has one source/sink role, stable identity/hash, RQL selector, typed matched-value/receiver/return/argument binding, exact categories, display phrase, optional taint semantics, and explicit `supersedes` IDs. Endpoint matches are dependencies rather than findings. Directory traversal occurs only for an authored match-directory reference, is bounded/transactional/manifested, and never becomes ambient project scanning. #824 alone decides same-semantic-event dominance after binding resolution; neither RQL textual shape nor file order implies specificity.
  Date: 2026-07-17.

- Decision: evaluate taint policies as sets, not as a Cartesian product of one-source/one-sink rules.
  Rationale: one solver run can seed every selected source, propagate finite source-class label sets, and observe every selected sink. A meeting is reported when reached labels intersect the sink's accepted labels after sanitizer semantics. #709 then projects actual endpoint pairs: a unique explicit superseding combination replaces the fixed generated `{source display} can reach {sink display}` presentation, otherwise the generated default remains. Specificity is an explicit acyclic relation, not RQL/file order, and never creates a second solver run.
  Date: 2026-07-16.

- Decision: let typestate policies reuse resolved endpoint leaves for subjects, events, and explicit terminal observations while retaining distinct implicit normal/exceptional exit expectations.
  Rationale: known API receiver/return/argument positions belong on reusable endpoint definitions. #709 composes and stores a complete `ResolvedTypestatePolicySpec`; #824 lowers it into semantic binding classes and #822's protocol. An unmet terminal expectation is distinct from an error transition. Categories, directories, display phrases, messages, and presentation precedence never enter protocol/summary keys.
  Date: 2026-07-17.

- Decision: keep `TaintTransferSummary` symbolic and independent of concrete source selectors, sink selectors, policy IDs, classification rules, and CVSS configuration.
  Rationale: the reusable result is how taint on interface/heap positions and classes moves through a procedure, including sanitization and uncertainty. Concrete seeds, sink observers, finding aggregation, CWE refinement, and scoring are cheap run/presentation overlays. Summary keys include propagation/sanitizer semantics and taxonomy versions only when they change transfer behavior.
  Date: 2026-07-16.

- Decision: derive CVSS v4.0 only from explicit metric evidence and publish a numerical score only with a complete Base vector.
  Rationale: source exposure and sink impact can support some metrics, but static reachability alone cannot safely invent every exploitability or vulnerable/subsequent-system impact metric. Each metric records a structured evidence basis and provenance; incomplete Base evidence produces an unrated finding with an `Unscored` assessment. A complete result includes the canonical vector, applicable component scores/severities, nomenclature, and scoring provenance. CVSS severity remains distinct from analyzer certainty and organization-specific risk.
  Date: 2026-07-16.

- Decision: make `SemanticArtifactKey` identify one mounted source snapshot, with artifact-local `ProcedureId`s and procedure-local block, point, value, allocation, call-site, memory-location, capture, source-mapping, evidence, and gap IDs.
  Rationale: this matches file-oriented adapter extraction, gives nested callable bodies an exhaustive home, avoids reparsing per callable, and prevents bare dense IDs from crossing provider or oracle boundaries. Provider-boundary handles retain the owning immutable artifact/procedure while hot rows remain compact IDs.
  Date: 2026-07-16.

- Decision: model nested callable bodies, callable values, capture environments, method references, and invocations separately.
  Rationale: lexical nesting is not execution; a lambda or method reference creates a callable value and may bind captures or a receiver, while only later invocation creates a call site and eventual ICFG edge. Captures must distinguish value/move semantics from shared or mutable memory locations.
  Date: 2026-07-16.

- Decision: scope capture bindings to the creator and capture slots to the child, with explicit lexical cells for location-backed local captures.
  Rationale: procedure-local dense IDs remain compact and safe, multiple creation sites can populate one static child slot, and mutable lexical captures no longer need to masquerade as indexed or language-defined memory.
  Date: 2026-07-16.

- Decision: make semantic capability declarations construction invariants rather than renderer-only metadata.
  Rationale: exact rows for an unsupported feature and unsupported gaps for a complete feature are contradictions; ambiguity, unknown facts, unproven facts, and exhaustion remain separate proof/completeness outcomes.
  Date: 2026-07-16.

- Decision: make semantic source byte spans authoritative and define display line/column coordinates as zero-based, rather than reusing `analyzer::Range` as a durable locator.
  Rationale: current analyzers construct `Range` lines with different bases, `usize` is not a portable persisted width, and exact anchors need columns as well as bytes.
  Date: 2026-07-16.

- Decision: encode unavailable call and async control arms as typed continuations, require exact per-event outgoing topology, and correlate every incomplete subject with exact gap and evidence rows.
  Rationale: later CFG and ICFG consumers must be able to distinguish absent control from unknown, unsupported, unproven, or exhausted analysis without traversing invented edges.
  Date: 2026-07-16.

- Decision: separate provider operational failure from semantic uncertainty, bound all retained construction/rendering payload, validate with indexed linear passes, and scope handles to one artifact materialization.
  Rationale: invalid input or I/O is not program ambiguity; adversarial payload must respect finite budgets; and two partial materializations of one durable key must not alias.
  Date: 2026-07-16.

- Decision: complete the all-language CFG/ICFG contract with one C/C++ adapter family and one shared ICFG, retaining dialect, linkage, preprocessing, lifetime, and implicit-evaluation uncertainty as typed adapter or dispatch evidence.
  Rationale: these are real C/C++ semantic distinctions, but none requires different graph mechanics. Structured declaration/definition coalescing plus exact gaps preserves what is known without inventing a whole-program linker, preprocessor configuration, destructor schedule, or implicit call graph.
  Date: 2026-07-19.

- Decision: let matched-return evidence describe complete completion transfer, not merely the conditional exit-to-continuation mapping, and calculate that evidence from bounded path-relevant gaps.
  Rationale: callers need to know whether all modeled behavior on the callee path is represented. Cleanup, exceptional, and non-local gaps on the relevant path therefore make the edge partial; dead disconnected gaps do not. Every unresolved dispatch arm also makes the enclosing snapshot non-complete, with its exact capability preserved.
  Date: 2026-07-19.

- Decision: tolerate conservative dynamic-dispatch false-partials until #816 exposes explicit closed-dispatch proof.
  Rationale: current Java, Go, C#, and related receiver adapters cannot always distinguish final, static, nonvirtual, or otherwise closed calls at the semantic-adapter boundary. A false partial is preferable to false completeness; precision tests should assert closure directly once resolver metadata supports it.
  Date: 2026-07-19.

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
    #821 set-oriented taint client -> #823 symbolic summaries -> #824 query/policy adapter
    #709 public policy contract -> #824 stable query/policy adapter -> #825 public pilot
    #826 evaluates WPDS/SPDS after pilot evidence

Issue #814 is the first completed implementation milestone. Checkpoint `296c1de1` plus guided-review fixes `1faf8b9b` provide the immutable language-neutral IR/event contract, durable and dense identities, total capabilities, typed outcomes and errors, finite budgets, provider boundary, invariant validation, scoped handles, and bounded renderer. TypeScript and Java remained the right contract fixtures, but they intentionally build neutral artifacts rather than claiming real adapters. The file-level artifact and procedure-local row model survived review without prematurely selecting CSR/CSC or persistence.

The handoff remains narrow: #815 builds real TypeScript/Java callable CFG adapters, #816 refines dynamic dispatch plus value/heap targets, #818 adds matched ICFG call/return edges, and #817 measures lifecycle/storage before persisting anything. Review made this boundary stricter by introducing typed unavailable continuations, exact invoke/suspend outgoing topology, exact gap/evidence correlations, constrained partial local targets, bounded atomic construction, streaming rendering, and materialization-scoped handles.

All nine post-reference rollout checkpoints validate that boundary from reuse and independent-adapter directions. JavaScript/JSX share the TypeScript lowering family; C#, Python, Go, Rust, PHP, Scala, Ruby, and C/C++ map their own structured syntax into the same builder, exact-location dispatch oracle, and context-bearing ICFG. Python and Rust use orthogonal invocation timing so deferred coroutine/generator construction never becomes false immediate body entry. Go keeps scheduled and selected work distinct from immediate calls, Rust uses shared cleanup markers to expose unknown Drop behavior without fabricating destructor topology, PHP owns whole-chain nullsafe continuations, Scala preserves partial-function and curried-application distinctions, Ruby uses parser-ordered binding activation, and C/C++ adds structured link-unit identity plus caller-side implicit-evaluation gaps without changing graph mechanics. Conformance now covers direct calls, common control, nested callables, handlers and cleanup, advanced-feature gaps, grammar-specific evaluation order, deferred call boundaries, scheduling boundaries, destructor uncertainty, nullish flow, chain-scoped short circuiting, expression-valued control, parameter-list dispatch, and matched-return evidence across every analyzable language without adding language-specific graph services.

#815 Milestone 4e completes the Rust adapter checkpoint. Functions, associated and nested functions, closures, async and generator bodies, common control, labels, match guards, calls, semicolonless tails, `?`, await, yield, and dead syntax now use the same immutable CFG, exact-location dispatch, and context-bearing ICFG as the previous languages. Rust-specific uncertainty remains explicit through deferred invocation, terminal try/macro boundaries, implicit-trait gaps, and RAII/Drop gaps for parameter, lexical, pattern-bound, replaced, normal, and abrupt values. Generic free and method calls resolve through the shared oracle, including turbofish syntax, without regressing grouped imports. Focused validation passes 39 CFG, 17 ICFG, 55 language-conformance, 11 provider, and 483 definition tests.

#815 Milestone 4f completes the PHP adapter checkpoint. Functions, methods, constructors, nested functions, closures, arrows, property hooks, common control, numeric break/continue, switch, match, nullish and full-chain nullsafe flow, calls, explicit throw, and cleanup now use the same immutable CFG, exact-location dispatch, and context-bearing ICFG as the previous languages. PHP-specific uncertainty remains explicit for generator suspension, include/require, goto, resource behavior, implicit calls and exceptions, and dynamic runtime protocols. Review proves matched free, typed-method, and nullsafe cross-file returns plus exact normal, handled, and unmatched `finally` paths. Focused validation passes 39 CFG, 18 ICFG, 10 semantic-IR, 73 language-conformance, 11 provider, and 486 definition tests.

#815 Milestone 4g completes the Scala adapter checkpoint. Functions, methods, local definitions, primary and secondary constructors, lambdas, partial functions, givens, synthetic initializers, expression-valued control, ordered guarded match, generic and curried calls, constructors, infix/postfix operators, explicit throw, and cleanup now use the same immutable CFG, exact-location dispatch, and context-bearing ICFG as the previous languages. Scala-specific uncertainty remains explicit for by-name timing, `for` desugaring, implicit selection/pattern/interpolation behavior, non-local return propagation, compound infix grouping, and prefix-operator dispatch breadth. Review proves nested callable ownership, one-site curried returns, fail-closed arity, matched cross-file calls, and braced or Scala 3 indented cleanup. Focused validation passes 39 CFG, 18 ICFG, 10 semantic-IR, 93 language-conformance, 11 provider, and 497 definition tests plus 25 call-site and 5 call-relation unit tests.

#815 Milestone 4h completes the Ruby adapter checkpoint. Top-level and type initializers, instance and singleton methods, constructors, lambdas, attached blocks, common control, implicit returns, `case`, calls, safe navigation, explicit throw, rescue/else/ensure, retry, yield, and non-local block completion now use the same immutable CFG, exact-location dispatch, and context-bearing ICFG as the previous languages. Ruby-specific uncertainty remains explicit for metaprogramming, callable-table mutation, implicit pattern/operator protocols, resources, fibers, threads, ractors, generators, and dynamic invocation. Review proves parser-ordered local activation, creation-time closure capture, exact cleanup routing, matched bare and singleton calls, and typed callable-object boundaries. Focused validation passes 39 CFG, 18 ICFG, 10 semantic-IR, 111 language-conformance, 11 provider, 497 definition, and 17 Ruby library/dispatch tests.

#815 Milestone 4i completes the C/C++ checkpoint and therefore the eleven-language adapter rollout. C and C++ functions, methods, constructors, destructors, operators, lambdas, common control, switch fallthrough, goto, calls, C VLA bounds, explicit throw, handlers, and known cleanup now use the same immutable CFG, exact-location dispatch, and context-bearing ICFG as every other analyzable language. Structured declaration/definition and template-qualified resolution preserve exact cross-file transfers; preprocessing, linkage uncertainty, default arguments, conversions, temporary/RAII cleanup, implicit calls and exceptions, spawn, coroutines, `noexcept`, evaluation-order latitude, and platform extensions remain exact gaps. Cross-language review also made matched-return evidence path-sensitive and budgeted, made every unresolved boundary non-complete, and preserved exact unsupported capabilities. Focused validation passes 39 CFG, 25 ICFG, 10 semantic-IR, 129 language-conformance, 11 provider, 9 ICFG-unit, 14 call-relation-unit, and 498 definition tests.

The focused #817 lifecycle slice now also completes the all-language rollout ExecPlan. Provenance-recorded release matrices retain bidirectional edge-ID rows and reject production SQLite for the current control/call artifact even though packed hydration is much faster: the large TypeScript corpus failed the absolute build-plus-write gate. `.agents/docs/semantic-cfg-lifecycle-benchmark-2026-07-20.md` preserves every retained sample, median, retained size, gate, and provenance record. Production keeps immutable byte-bounded per-file artifacts, generation-local ICFG stitching, and ephemeral bounded slices. The broader roadmap still owns value/heap oracles, data dependence, solver tables, and reusable summary measurements. A read-only architecture audit found one shared ICFG rather than per-language implementations, but also found roughly 4,000-6,000 lines of conservatively removable adapter substrate; the recommended next planning checkpoint is a shared lowering-session/call-scaffold extraction plus a generic dispatch-oracle/ICFG-stitcher split before those layers widen.

#815 Milestone 1a is the first implementation checkpoint after #814. It preserves the rich edge payload once, assigns canonical procedure-local edge IDs, and supplies exact outgoing and incoming views without selecting persistence or exposing query vocabulary. Specialist review corrected topology counting for provenance-parallel edges, made invalid procedure-local point IDs fail explicitly, required canonical incoming hydration order, and strengthened renderer-schema assertions. The complete feature suite and strict all-feature clippy pass; production semantic lowering remains the next checkpoint rather than an implied capability of this graph substrate.

#815 Milestones 1b and 1c provide the first production semantic materialization path and real language adapter. The provider routes exact files through analyzer delegates, atomically snapshots bounded disk or overlay source with dialect identity, publishes only validated artifacts, and retains complete values in a byte-weighted cancellation-aware single-flight cache. TypeScript and TSX now lower callable-local control, expression-level calls, handlers and cleanup, supported async flow, and disconnected dead source through an iterative builder; unsupported advanced semantics remain capability- and point-scoped. The multiline graph harness asserts source-backed predecessor/successor topology and bounded deterministic rendering. Focused tests, strict clippy, the complete `nlp,python` suite, and post-milestone review pass. Java remains the second reference adapter before dispatch and matched ICFG stitching freeze the shared contract.

#815 Milestone 2 completes the second reference adapter. Java lowers methods, constructors, lambdas, executable field/interface/enum initializers, branches, loops, calls, switch statements and expressions, explicit throw, catch/finally, and cleanup relays, while try-with-resources, monitor behavior, implicit exceptions, initializer scheduling, and other omissions remain typed and point-scoped. The differential suite introduced a neutral cleanup-safe switch-yield channel and verified label-equivalent TypeScript/Java core topology. A provenance-recorded release benchmark kept bidirectional edge-ID rows: outgoing-only storage saved memory but made reverse traversal orders of magnitude slower at scale, and flat rows made both directions unacceptable. All focused tests, strict all-feature clippy, the complete `nlp,python` suite, and specialist review pass. The next contract pressure is the location-first dispatch slice and one matched TypeScript/Java ICFG.

#815/#818 Milestone 3 completes that contract pressure. Exact whole-call source locations now flow through the established call resolver, preserving every proof and incomplete outcome. One generation-local provider lazily materializes callees and builds bounded dense slices whose nodes carry exact call-site contexts, so two callers of one procedure and recursive calls return only to their own normal or exceptional continuations. Root and target source identities are checked atomically, unknown calls terminate at typed boundaries, and limits cannot publish orphan graph nodes. The inline harness asserts predecessor/successor topology using source aliases and call contexts rather than dense IDs. Focused tests, strict clippy, the complete `nlp,python` repository suite, and specialist review pass. Remaining language adapters now depend on this frozen boundary rather than creating per-language ICFGs.

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

A taint source class is a reusable semantic label such as `attacker_controlled`, not one concrete source/sink pair. A run may retain bounded concrete origin IDs for witnesses while propagating compact sets of source-class IDs. A taint sink declares security impacts and the source labels it accepts.

A taint meeting point is a resolved sink binding where the reached source-label set intersects the sink's accepted-label set after modeled sanitizers and barriers. It is a sink-level finding with aggregated contributing classes/origins, not one separate solver result for every source/sink permutation.

A lattice orders abstract information and defines how paths join. A may problem uses union: an outcome is reachable if any modeled valid path reaches it. A must problem needs a separately validated intersection-like abstraction and can claim an outcome only when every modeled alternative supports it.

A transfer function maps input facts to output facts at a semantic edge. Distributivity means applying the function to a union of facts produces the same result as applying it to each fact separately and unioning the results. IFDS relies on this law. An IDE edge function transforms a bounded abstract value attached to a fact; its value lattice must have finite height so repeated joins terminate.

A strong update replaces the previous abstract value of one proven-unique memory location. A weak update joins a new value with previous values because several concrete locations may be represented. An access path is a bounded root plus field/index sequence such as `parameter0.connection.state`.

A context abstraction is the bounded distinction the solver retains between callers, for example a call-site or object-sensitive key. It is part of a summary identity. An SCC, or strongly connected component, is a cycle-equivalent group of graph nodes used to reason about recursion. Reverse postorder is a deterministic CFG traversal order that usually accelerates fixed points. Dominance means every path to one node passes through another node.

A packed DTO is a versioned serialization object designed for stable storage rather than Rust’s in-memory layout. An overlay is the analyzer’s unsaved-buffer view and has its own generation. SARIF is the standard JSON result format consumed by code-scanning tools.

CVSS is a standardized vulnerability-severity framework, not a complete organizational risk model. For CVSS v4.0, all Base metrics are required for a Base score. Threat and Environmental metrics can refine severity, while business, regulatory, customer, monetary, safety, and reputation considerations remain separate risk inputs. Published CVSS data includes the vector and score with the applicable nomenclature.

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

The set-oriented taint client adds these rules:

- A selected endpoint/query match is a diagnostic-neutral candidate. Source/sink co-presence never establishes that one can reach the other; only a complete or explicitly partial structured propagation meeting can support that relation.
- Compile all source selectors into one finite seed set and all sink selectors into one finite observer set. Do not schedule a separate solver run for each pair.
- Propagate finite source-class label sets with union. Retain concrete source-origin IDs only in a bounded provenance side table used for witnesses and grouping.
- A sink meeting is a may finding when reached labels intersect the sink's accepted labels. Ambiguous dispatch or incomplete propagation may still produce a partial meeting, but the overall completion remains `inconclusive`.
- A sink definition identifies the exact dangerous operand or receiver. A database call is not one undifferentiated sink: SQL structure, a safely bound value parameter, a connection selector, and an options object have different semantics.
- Sanitizers and barriers are typed transfer functions over declared label classes. An unrecognized or partially modeled sanitizer cannot erase taint optimistically.
- The diagnostic-neutral client aggregates by sink event, semantic scenario, reached source classes, and completion. It does not depend on CWE or CVSS. #824 supplies exact typed scenario/evidence projection facts plus bounded origins/witnesses; #709's generic reducer alone turns those inputs into classification/CVSS assessment variants.
- A broad `attacker_controlled` to `security_sensitive` meeting is reportable even if no more specific CWE rule matches. Specific classification refines rather than creates the underlying security finding.
- Project each actual meeting through resolved endpoint identity. One uniquely dominant explicit combination may replace the generated presentation for that pair; the generic presentation is suppressed only for that same pair inside that aggregate policy. Incomparable winners are configuration failure, and unrelated policies are never globally suppressed.
- CVSS Base metrics that are not supported by structured evidence or explicit catalog/policy declarations remain unknown. Unknown Base metrics prevent a numerical score; they do not suppress the vulnerability finding.
- Incomplete source discovery, sink discovery, dispatch, external-call modeling, or transfer propagation makes an empty result `inconclusive`. A complete superset run can answer a subset policy only when it retained the required source classes and sink observations without lossy truncation.
- Solver completeness and witness/provenance budgets are independent. Truncating stored origins or a displayed path never changes reachability, suppresses a finding, or licenses a complete negative.

Each result also carries `proof` for the structured edges it used, `completeness`, a work report, and optional bounded witness data. These fields are independent: a source-backed witness can be exact while the overall analysis remains inconclusive elsewhere.

### Existing seams

`src/analyzer/structural/spec.rs`, `extract.rs`, and `facts.rs` are the existing language-adapter-to-neutral-syntax boundary. `FileFacts` uses flat `u32` identities and `CompactRows<RoleTarget>` but represents syntax rather than values or control flow.

`src/analyzer/structural/rune_ir.rs` renders normalized structural facts for review and query-by-example. The semantic IR and CFG should gain an analogous bounded renderer early, before solver output makes adapter mistakes difficult to inspect.

`src/analyzer/usages/call_relations.rs` defines `CallRelationService`, `CallSite`, `CallArgument`, receiver ranges, proof tiers, and lazy actual/formal binding. The ICFG must consume this boundary instead of resolving calls again.

`src/analyzer/usages/receiver_analysis.rs` defines explicit outcomes, abstract receiver values, budgets, cache keys, and `ReceiverFactProvider`. `src/analyzer/usages/js_ts_graph/receiver_analysis.rs` is the first shared implementation. #816 generalizes this capability without turning it into solver state.

`src/analyzer/structural/query/ir.rs` and `schema.rs` are the typed query and declarative vocabulary authorities. `src/analyzer/structural/search.rs` executes bounded transformations and retains provenance. #824 extends these instead of adding a separate graph-query parser.

#709 is the public diagnostic boundary. It owns the versioned `.rqlp` envelope, policy identity and reporting metadata, public analysis-authoring types such as `TaintPolicySpec` and `TypestatePolicySpec`, classification/scoring declarations, policy evaluation, `PolicyFinding`, and human/SARIF rendering. Internal `TaintFinding`, `ProtocolSpec`, `TypestateFinding`, and `CodeQueryMatch` values remain diagnostic-neutral until #824 lowers/adapts them through that public model.

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
    diagnostic-neutral findings and witnesses
                    |
       +------------+-------------+
       |                          |
  CodeQuery/RQL exploration    #709 PolicyEvaluator
                                  |
                         PolicyFinding -> human/SARIF

Storage is orthogonal to this flow. Mutable builders construct facts; immutable compact snapshots serve hot reads; SQLite stores only versioned artifacts that demonstrate expensive reconstruction and meaningful reuse.

## Plan of Work

### Milestone 0: preserve the roadmap and baseline

This milestone is complete when #813–#826 exist, the plan is committed and linked from #813, and the current source/storage/query boundaries are recorded. Do not implement speculative APIs in this milestone.

### Milestone 1: define semantic identities and adapter contracts (#814)

Create `src/analyzer/semantic/mod.rs`, `ids.rs`, `ir.rs`, `capabilities.rs`, `provider.rs`, and `render.rs` without expanding `StructuralSpec` into an execution-semantic catch-all. Define typed semantic effects and control edge kinds, source/proof/completeness metadata, and language capability discovery.

Keep the durable artifact identity, artifact-local procedure identity, and procedure-local row identities distinct:

1. `SemanticLocator` is a source-facing locator: workspace-relative path, language, enclosing declaration identity, semantic role, and source anchor. It lets findings and overlays refer back to code and may be remapped after an edit, but it is never sufficient to prove cache validity.
2. `SemanticArtifactKey` owns one immutable mounted source materialization, normally one file: workspace mount identity, workspace-relative path, language/parser dialect, source/blob identity, an opaque overlay snapshot token when applicable, adapter version, semantic-IR version, semantic configuration, and dependency fingerprint. Changing any validity input creates a different artifact key.
3. `ProcedureId` is a typed dense `u32` meaningful only inside its artifact. `BlockId`, `ProgramPointId`, `ValueId`, `AllocationId`, `CallSiteId`, `MemoryLocationId`, and related side-table IDs are meaningful only inside one procedure. Provider and oracle boundaries pair them with an owning artifact/procedure handle.

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

#821 proves reuse with a one-state/direct value-flow client and a set-oriented source/sink/sanitizer client. Compile all resolved sources into one seed relation and all resolved sinks into observers for one analysis run. Partition runs only when propagation semantics differ, such as context/access-path precision, external models, unknown-call behavior, sanitizer/transform semantics, or heap abstraction; policy IDs, messages, classifications, and scoring never partition propagation.

Create `src/analyzer/taint/mod.rs`, `model.rs`, `plan.rs`, `client.rs`, `summary.rs`, `finding.rs`, and `provenance.rs`. `model.rs` owns stable source-class, sink-event, sanitizer, transform, and external-model identities; `plan.rs` owns propagation-semantics keys and set-oriented batch partitions; `client.rs` lowers one partition into the shared solver; `summary.rs` owns symbolic transfer summaries; `finding.rs` owns only diagnostic-neutral meetings and proof metadata; and `provenance.rs` keeps concrete origins outside the fixed point.

Use the abstract value/location as the exploded carrier fact and an IDE-style finite `TaintClassSet` bitset as its value. `SourceClassId` distinguishes propagation or sanitization behavior, not each concrete source site. A run-local interner maps stable class IDs to dense bits; any persisted bitset includes a `TaintUniverseHash` and stable IDs because dense bit positions are not durable identities. Concrete `SourceEventKey` origins stay outside the fixed point in a bounded provenance/witness side table.

A meeting-point aggregator groups reached source classes/origins at each sink and hands diagnostic-neutral `TaintFinding` values to #824. A valid meeting agrees on carrier/location, matched call/return context, access-path abstraction, exceptional state, and taint-transform state; sharing only an AST or CFG node is insufficient and would create impossible Frankenpaths. The first implementation remains multi-source forward tabulation. Bidirectional forward/backward meeting is an optimization behind the same semantic key, not a different result contract.

This finite class-set domain does not express relational rules such as “two distinct inputs must meet” or same-origin correlation. Such rules require a separately named and bounded relational client. Missing generality is fixed at the shared solver/oracle boundary rather than by introducing a second worklist engine.

### Milestone 5: compile finite-state protocols and compose summaries (#822, #823)

Create `src/analyzer/typestate/mod.rs`, `protocol.rs`, `client.rs`, and `summary.rs`. The protocol IR is versioned and canonically hashable. It defines states, initial states, non-absorbing accepting/error states, semantic event predicates, guarded transitions limited to structured facts, object/fact binding, typed at-match/before-call/normal-return/exceptional-return observations, explicit terminal observations, distinct implicit normal/exceptional analysis-root exit expectations, and diagnostic-neutral violation kinds. Terminal expected-state sets are non-empty subsets of accepting states, but entering an accepting state does not stop tracking. Validation rejects duplicate or missing states, invalid binding/phase combinations, invalid transitions/expectations, unreachable states where required, unstable identities, and unsupported event selectors. A helper/factory return is an interprocedural transfer rather than an implicit terminal; escape beyond the analysis root is inconclusive. An unmet terminal expectation is not lowered as a fake transition to an error state.

The first protocol is a resource lifecycle with states such as `unallocated`, `open`, and `closed`. #824 binds #709's resolved categorized subject/source and call/sink endpoint sets—including their receiver/return/argument positions and observation phases—to neutral allocation/event classes. A close-like explicit endpoint can transition to `closed`; a same-phase terminal expectation observes the post-transition state, while normal and exceptional analysis-root exit can require an accepting state. #824 resolves same-site endpoint dominance and pair restrictions before computing the compiled binding-plan hash. The protocol defines conservative behavior for unknown dispatch, escapes, cleanup, exceptions, and incomplete analysis. The same protocol runs over TypeScript and Java.

The typestate client adds protocol state to interned facts or associates an equivalent client value through the solver interface. It does not add language branches to the kernel. A degenerate protocol should collapse naturally to reachability/data flow.

#823 adds `SemanticProcedureSummary`, `TaintTransferSummary`, and `ProtocolSummary` above the solver’s existing `TabulationEndSummary`; it does not redesign or replace the correctness-critical tabulation cache. `SemanticProcedureSummary` packages reusable client-independent procedure effects. `TaintTransferSummary` symbolically relates taint classes on interface/heap inputs to outputs, escapes, sanitization, and uncertainty without containing concrete source/sink selectors or reporting rules. `ProtocolSummary` packages one protocol hash’s entry-state-to-exit-state/effect relation. In-memory dynamic-programming reuse comes first. Each summary records context abstraction, proof, completeness, exceptional effects, and dependency identity. Library summaries are validated and marked as external rather than inferred.

The taint cache identities are deliberately split:

    CarrierSummaryKey =
        procedure SemanticArtifactKey
        + ICFG/call-binding dependency fingerprint
        + adapter and semantic-IR versions
        + dispatch/value/heap oracle versions and configuration
        + context and access-path abstraction
        + exceptional, escape, and unknown-call semantics
        + solver-summary schema version

    TaintPropagationEventMatchKey =
        procedure SemanticArtifactKey
        + canonical source-generator, sanitizer/transform, and external-model selector hash
        + matcher/compiler version

    TaintSinkObserverMatchKey =
        procedure SemanticArtifactKey
        + canonical sink-selector and dangerous-operand hash
        + matcher/compiler version

    TaintTransferSummaryKey =
        CarrierSummaryKey
        + taint-algebra version
        + propagation-relevant model hash
        + TaintPropagationEventMatchKey dependency when local event ports are embedded
        + callee/SCC summary dependency fingerprint

    BatchRunKey =
        workspace snapshot and analysis scope
        + analysis-semantics key
        + canonical selected SourceClassId universe
        + canonical selected source-event seeds
        + canonical selected sink-observer set
        + completeness-affecting budgets

    FindingProjectionKey =
        completed BatchRunKey result
        + per-policy source/sink compatibility selection hash
        + classification/scorer/version hash
        + assessment-evidence profile snapshot

The propagation-relevant model hash includes only class behavior, sanitizer/transform rules, and external/unknown-call models that can change transfer. It excludes policy ID, messages, CWE taxonomy, report limits, sink presentation, CVSS, Threat, and Environmental overlays. Concrete source occurrences and the unioned sink-observer set key `BatchRunKey`; changing only sinks can reuse transfer summaries but requires a new run unless a completed run explicitly retained the full pointwise closure needed to apply those observers afterward.

The two model-match keys map reusable model definitions to stable symbolic event ports without letting a sink-only catalog edit invalidate transfer. A `SourceEventKey` is its owning `SemanticArtifactKey`, deterministic local semantic-event ordinal and role, and `SourceClassId`; a `SinkEventKey` uses the same artifact/ordinal/role identity plus its sink-model ID. `TaintUniverseHash` covers canonical stable class IDs and their propagation/sanitization semantics, never run-local dense-bit order. The summary exposes boundary input/output relations plus local source-generator and internal sink-observation ports, so a source and sink wholly inside a summarized callee are not skipped. If source/sanitizer/transform matching is compiled into the summary, that exact `TaintPropagationEventMatchKey` is a dependency; sink-observer matching remains separate and never enters the transfer-summary key.

`TaintFindingKey` is the analyzed workspace snapshot plus stable `SinkEventKey` and semantic-scenario identity. It excludes the optimizer's chosen forward/backward meeting node, concrete origin occurrences, witness/report limits, policy ID, message, CWE, and CVSS. `FindingProjectionKey` caches only a classified/scored semantic projection. A final `PolicyFinding` is either rebuilt cheaply or separately keyed by policy/message/report identity. Its assessment-evidence snapshot includes Threat feed revision/time, Environmental profile, analyst assertions, system-of-interest boundary, affected configuration, and scorer/version so changed evidence cannot reuse stale CVSS.

Recursive SCC summaries publish atomically only after convergence. An incomplete or dependency-stale summary can support an explicitly inconclusive partial finding, but never a complete negative or a complete reusable cache entry.

### Milestone 6: apply the artifact lifecycle policy (#817)

Maintain an artifact matrix while the preceding milestones establish real data shapes:

| Artifact | Initial representation | Persistence default | Promotion test |
| --- | --- | --- | --- |
| Per-callable semantic events | Dense arena and compact rows | Candidate | Persist only if extraction is expensive and content/version keys are stable. |
| Per-callable CFG topology | Immutable CSR or CSR+CSC | Candidate | Persist only if cold reconstruction dominates and packed hydration is faster. |
| ICFG stitch relations | Demand materialized generation cache | No | Persist only if repeated call resolution remains a measured bottleneck and invalidation is tractable. |
| Exploded solver states/worklists | Sparse ephemeral tables | Never by default | Query/client specific; retain only within an analysis session. |
| Language-semantic summaries | In-memory memoization | Candidate | Promote after cross-query and cross-process reuse is measured. |
| Symbolic taint-transfer summaries | In-memory memoization keyed by transfer semantics | Candidate | Exclude concrete source/sink sets and classification/CVSS; promote after reuse across materially different policies is measured. |
| Protocol summaries | In-memory memoization keyed by rule hash | Candidate | Promote only with rule/config/version keys and measurable reuse. |
| Witness predecessor data | Compact ephemeral parents | No | Reconstruct bounded witnesses; do not serialize full paths. |
| Query results/truncations | Ephemeral typed rows | No | They are seed-, budget-, and presentation-specific. |

Every persisted artifact uses a packed versioned DTO, generation/content validation, corruption-as-miss behavior, lazy hydration, payload cost accounting, cascade cleanup, and tests for source, adapter, solver, configuration, protocol, dependency, and overlay changes. Coordinate visible store failures with #695.

### Milestone 7: stabilize the public policy contract and expose typed query facets (#709, #824, #720)

#709 should proceed early and establish the public envelope before #824 freezes stable policy-facing names. It is not a prerequisite for #814 through #823: those milestones operate on diagnostic-neutral semantic facts, `AnalysisRun`, `TaintFinding`, `TypestateFinding`, and witnesses. The dependency is asymmetric: #709 must not encode solver worklists, summary tables, or automaton internals, and #824/#825 must not invent a second policy identity, loading, severity, message, classification, or SARIF model.

#709 owns:

- the compatibility-resolved `.rqlp` policy/endpoint document union, explicit workspace-safe file/directory loading, and policy/endpoint/category identities, manifests, and metadata;
- `PolicyDefinition`, diagnostic-neutral `MatchEndpointDefinition`, a tagged `PolicyAnalysis` boundary selected by the public `analysis.type` field, stored `ResolvedTaintPolicySpec`/`ResolvedTypestatePolicySpec`, explicit supersedes/presentation rules, generated messages, and authoring types designed without exposing solver/client storage types;
- `PolicyFinding`, broad and refined classifications, optional evidence-backed CVSS assessment, stable locations and related locations, result completeness, and human/SARIF rendering;
- the rule that a `CodeQueryMatch`, `FlowFinding`, `TaintFinding`, or `TypestateFinding` is not itself a diagnostic.

#821 owns the internal set-oriented `TaintAnalysisPlan`, `TaintFinding`, and transfer semantics. #823 owns symbolic `TaintTransferSummary`. #709 owns typed catalog/endpoint registration, category/directory content identity, deterministic authoring-level composition and presentation precedence, complete public endpoint-pair projection inputs, and the generic classification/CVSS reducer. #824 owns `TaintPolicyCompiler`: it resolves composed catalog/local/endpoint selectors and typed bindings, proves same-event endpoint dominance, constructs one bounded plan, supplies complete analysis-specific projection evidence, and maps meeting-point findings into #709's public model without rerunning propagation per endpoint pair or classification.

#822 owns the versioned internal `ProtocolSpec`, automaton/terminal-expectation compilation, and diagnostic-neutral error-transition/terminal-expectation findings. #824 owns `TypestatePolicyCompiler`, typed query domains, endpoint binding classes, and adapters from analysis services to query rows and complete #709 projection facts. The compiler consumes #709's stored `ResolvedTypestatePolicySpec` without rescanning and lowers it into #822's internal `ProtocolSpec`; neither model embeds the other. #824 may build internal result domains before #709 closes, but it cannot declare the policy-facing wire shape stable until the #709 envelope and finding model are accepted. #825 requires both paths: diagnostic-neutral query exploration and `.rqlp` policy execution.

Extend `QueryValueKind` and the declarative query schema with source-backed `procedure`, `program_point`, `flow_endpoint`, `taint_finding`, `typestate_finding`, `taint_witness`, `typestate_witness`, and `flow_witness` domains. The initial operations are fixed by this plan:

| Operation | Accepted input | Output | Required bound/behavior |
| --- | --- | --- | --- |
| `procedure_of` | structural match or declaration | procedure | Exact enclosing callable or an explicit no-procedure diagnostic. |
| `cfg_entry` / `cfg_exits` | procedure | program point | Exits include normal/exceptional kind. |
| `cfg_successors` / `cfg_predecessors` | program point | program point | Positive finite `depth`, default 1; provenance carries each control edge. |
| `flows_to` / `flows_from` | expression site, program point, or flow endpoint | flow endpoint | Positive finite `depth` or explicit sink/source selector; valid-path semantics and work budget. |
| `taint` | structural match, expression site, or flow endpoint | taint finding | Execution-scoped compiled taint plan, one finite multi-source/multi-sink run, solver budget. |
| `typestate` | structural match, call site, expression site, or flow endpoint | typestate finding | Execution-scoped protocol reference, bind selector, may mode, solver budget. |
| `witness` | taint finding, typestate finding, or flow endpoint | typed witness | Positive finite maximum steps and bytes. |

Actual/formal/receiver/return bindings appear in flow provenance and solver transfers rather than as control edges. Each operation has a finite work budget, explicit capability diagnostics, deterministic endpoint identity and ordering, cancellation, and proof/completeness semantics. A witness is a bounded supporting derivation, not proof that all alternatives were enumerated. The planner evaluates cheap structural seeds before materializing expensive semantic facets.

Keep these canonical fixtures:

- `tests/fixtures/typestate/resource-lifecycle.protocol.json` contains only #822's internal `ProtocolSpec` and can be tested before #709 exists.
- `tests/fixtures/policies/resource-lifecycle.rqlp` contains #709's public policy envelope, categorized endpoint subject/event sets, transitions, and explicit/implicit terminal expectations. A #824 conformance test lowers the resolved public rule and requires it to compile to the same internal protocol/binding-plan hash as the #822 fixture without requiring their serialized shapes to match.
- `tests/fixtures/policies/attacker-controlled-to-sensitive-sinks.rqlp` contains one public `TaintPolicySpec` with source/sink catalog, endpoint-directory, exact endpoint, and local sets plus generated/default and explicit combination presentation. It must compile to one `TaintAnalysisPlan`, not a Cartesian product of pair plans.
- `tests/fixtures/policies/endpoints/` contains one diagnostic-neutral source or sink `(endpoint ...)` leaf per file with categories, display phrase, selector, typed binding, optional taint semantics, and explicit supersedes IDs.

The `.rqlp` pilot authoring contract is the S-expression grammar specified normatively by `.agents/plans/issue-709-static-analysis-policy-format.md`, with native `(rql [:schema-version N] QUERY)` or workspace-safe `(rql-file ...)` selectors. Policy/endpoint and RQL omissions resolve independently through compatible implicit lineages; explicit values pin. Parsing/loading lowers each selector once into canonical `CodeQuery` IR and stores resolved schema/dependency manifests; evaluators never reparse or rescan during analysis. This umbrella deliberately does not mirror a pseudo-wire JSON shape: checked fixtures are exact authoring examples, and the issue-specific plan owns generated canonical JSON.

This is a public resolved typestate authoring specification, not a serialized `ProtocolSpec`. `TypestatePolicyCompiler` validates state/event/expectation names, consumes already selected endpoint dependencies, resolves exact indexed declarations and receiver/return/argument bindings into semantic event classes, preserves normal versus exceptional terminal events, lowers uncertainty choices, and produces #822's canonical `ProtocolSpec`. A same-name method outside the resolved endpoint, an unresolved call, or a name-only guess never fires a transition.

`PolicyRegistry` loads explicitly requested runnable `.rqlp` paths/bytes and any endpoint dependency directories/IDs named by those policies. Endpoint traversal is workspace-rooted, bounded, transactional, symlink-free, manifestable, and never ambient. The registry rejects paths outside the workspace, duplicate/colliding policy or endpoint IDs, oversized files/closures, changed directory snapshots, and parse/validation/precedence errors. It stores complete `ResolvedTaintPolicySpec`/`ResolvedTypestatePolicySpec` values before compiler capability exists; evaluation then returns `unsupported`, not a partly interpreted rule or an adapter-side rescan.

When the typestate capability is present, #824 lowers the resolved public rule and registers the internal automaton/binding plan by canonical hash in `ProtocolRegistry`, receiving an execution-scoped `ProtocolHandle`. `QueryAnalysisContext` maps a human-readable `ProtocolRef` to that handle. A policy uses `policy:<policy-id>`; embeddings may register an explicitly namespaced reference. Registering the same reference with a different hash is an error, while different references may share one compiled hash. Handle slots are never serialized or used as summary keys. Only #709's explicit capability-rooted match-directory surface loads endpoint leaves; `CodeQuery`/RQL cannot load arbitrary endpoint or protocol paths.

The taint public shape uses the same policy envelope but declares sets rather than a source/sink pair. The checked `attacker-controlled-to-sensitive-sinks.rqlp` fixture and the issue-specific #709 plan are the exact authoring/schema examples; generated JSON appears only in #709 conformance golds, never as a competing roadmap sketch.

`include_sets` names versioned source, sink, and sanitizer catalogs; `include_matches` selects explicit endpoint directories or IDs; `entries` adds policy-local structured selectors. A reusable model pack may be source-only, sink-only, sanitizer-only, or mixed, but a policy composes those packs explicitly and its resolved source and sink sets must both be non-empty. #709's authoring-level composition is deterministic, records schema/catalog/endpoint/directory manifests and precedence, and rejects duplicate/cyclic/ambiguous definitions. #824's compiler resolves composed selectors and bindings to semantic identities before propagation; a same-name text guess never becomes a seed, sink, or sanitizer. Analysis keys use endpoint projection hashes and behavior semantics, not directory/category/display/message data. Every sink names its dangerous receiver or operand, so an SQL-structure argument is not confused with a safe bound-value parameter.

`TaintCatalogRegistry` owns versioned machine source, sink, sanitizer/transform, and external-model documents. Built-in catalogs have stable names and content hashes; embedding applications explicitly register bytes or workspace-safe paths under a namespace. Human endpoint traversal occurs only through an authored match-directory; there is no ambient scan or network load. Canonical composition records catalog versions, endpoint IDs/hashes, and directory manifests, rejects identity collisions/incompatible class semantics, and produces `ResolvedTaintPolicySpec`, not solver keys. #824's `TaintPolicyCompiler` produces the exact `TaintPropagationEventMatchKey` and `TaintSinkObserverMatchKey` inputs. A catalog/directory may legitimately omit a role; the non-empty-both-sides requirement applies after authoring-level composition and is rechecked during compilation.

`TaintPolicyCompiler` creates one plan containing all seeds, sinks, sanitizer transfers, label IDs, catalog hashes, budgets, and completeness. It must not emit one plan per source/sink pair. The solver propagates compact label sets and consults each procedure's `TaintTransferSummary`; sink observers do not change transfer summaries. Adding a sink or changing CWE/CVSS classification can reuse existing propagation summaries. Changing a sanitizer or label-transfer rule invalidates affected taint summaries because it changes flow semantics.

`TaintBatchPlanner` also accepts several compiled policies. It partitions them by exact propagation semantics plus compatible workspace snapshot, analysis scope, and completeness-affecting budgets, unions compatible source seeds and sink observers, retains each policy's source/sink compatibility projection, and executes one superset run per partition. A broader scope or larger budget can answer a narrower policy only when that substitution is explicitly authorized and the projection retains the narrower policy's completion semantics; otherwise the policies remain separate partitions. A completed superset can answer a subset policy only when all required source classes, matched events, and sink observations remain distinguishable and complete. It then projects diagnostic-neutral meetings back to policy IDs; it never makes message, CWE, CVSS, or other presentation metadata part of solver state. This is the cross-policy counterpart to avoiding the source-by-sink Cartesian product within one policy.

At a sink, a meeting exists when `reached_source_labels ∩ accepted_source_labels` is non-empty. The diagnostic-neutral `TaintFinding` contains the sink, reached classes, bounded contributing origins, proof/completeness, and witnesses. The fallback classification is applied first, so attacker-controlled data reaching an otherwise security-sensitive database/control sink remains a vulnerability even when no specific CWE refinement matches. Refinements add taxonomy such as CWE; they do not decide whether the meeting exists.

CVSS assessment happens after the meeting and classification. The engine accepts metric values with provenance, never an author-supplied numeric score. `CvssMetricEvidence` contains `metric`, `value`, `basis` (`static_witness`, `policy_assertion`, `environment_profile`, `threat_feed`, or `analyst_override`), `evidence_refs`, `rationale`, `assumptions`, `assessor_or_tool`, `assessed_at`, and `system_scope`. Catalog and policy assertions lower to this same record with their content hash and authored provenance; run-scoped Environmental profiles, time-scoped Threat intelligence, and analyst assertions arrive through `AnalysisContext` overlays rather than being embedded as changing facts inside the reusable policy file.

Static evidence may support some metrics but does not get to infer the rest. `AV:N` requires evidence that the vulnerable system itself is bound to a network stack; content delivered as a downloaded file or malicious document does not become `AV:N` merely because a network transported it. A sink may establish which security property can be affected, but does not establish Low/High magnitude, exploit prerequisites, or the vulnerable-versus-subsequent-system boundary without evidence. Conflicting evidence produces explicit assessment variants when each scenario is coherent, otherwise `Unscored`; provider order never silently resolves a conflict.

The CVSS v4.0 Base metrics are `AV`, `AC`, `AT`, `PR`, `UI`, `VC`, `VI`, `VA`, `SC`, `SI`, and `SA`; they have no “Not Defined” value. The exact assessment/variant/evidence/provenance wire algebra lives only in the #709 ExecPlan. At the architecture level, a scored assessment publishes the canonical vector/nomenclature and every applicable B/BT/BE/BTE component result, while the complete report/evidence graph preserves scorer version, assessment time, system boundary, affected configuration, policy/content/analyzer hashes, bounded witnesses, assumptions, and FIRST attribution in their #709-owned fields. The engine canonicalizes the vector and recomputes scores; a supplied vector/score mismatch is rejected.

Unknown Base metrics yield `Unscored`, not `None` metric values or worst-case guesses. `X`/Not Defined is accepted only for the Threat, Environmental/Modified, and Supplemental metrics for which CVSS v4.0 defines it, using the specified defaults; it is rejected for Base metrics. Missing or non-comprehensive threat intelligence remains `E:X`, never `E:U` just because a feed has no match. Threat and Environmental evidence is a time/environment-scoped overlay and never enters reusable flow-summary keys. A complete assessment whose vulnerable/subsequent-system impact metrics are all `None` is a valid scored `0.0`/CVSS-None result; preserve the policy finding, map CVSS-derived report severity to `note`, and do not reinterpret it as contradictory or unscored. CVSS severity, analyzer certainty, and organization-specific risk remain separate fields.

When several source classes reach one sink, group scenarios only when they represent the same vulnerability identity and their system boundary, prerequisite evidence, completion, classification, and complete CVSS vector match; retain all contributing source classes and bounded witnesses. Different metric vectors remain assessment variants. Never union CIA impacts across mutually incompatible witnesses, sum or average scores, or splice exploitability metrics from one path with impacts from an incompatible path. An explicit vulnerability chain preserves its component vulnerability identities. If a UI displays one score, it may select the highest defensible complete variant while preserving every variant and identifying the supporting witness and assumptions.

The diagnostic-neutral taint query consumes an execution-scoped compiled plan reference. It can restrict which already-declared sink observers are projected, but it cannot introduce text-matched seeds or load a policy/model file:

```json
{
  "schema_version": 3,
  "languages": ["typescript"],
  "match": {"kind": "call", "callee": {"name": "execute"}},
  "steps": [
    {
      "op": "taint",
      "plan_ref": "policy:bifrost.security.attacker-controlled-to-sensitive-sinks",
      "at": "sink"
    },
    {"op": "witness"}
  ]
}
```

The equivalent diagnostic-neutral RQL is:

```lisp
(witness
  (taint :plan-ref "policy:bifrost.security.attacker-controlled-to-sensitive-sinks"
         :at sink
    (language typescript
      (call :callee "execute"))))
```

The result contains sink identity, reached source classes, bounded origins, proof/completeness, and a witness, but no policy message, CWE, severity, or CVSS. `PolicyEvaluator` supplies those only when projecting the same `TaintFinding` through its `PolicyDefinition`.

The diagnostic-neutral JSON query increments `CodeQuery` to schema version 3 and introduces `typestate` followed by `witness`. Its `QueryAnalysisContext` must resolve the reference before validation/execution:

```json
{
  "schema_version": 3,
  "languages": ["typescript"],
  "match": {"kind": "call", "callee": {"name": "open"}},
  "steps": [
    {
      "op": "typestate",
      "protocol_ref": "policy:bifrost.test.resource-lifecycle",
      "bind": "return_value",
      "mode": "may"
    },
    {"op": "witness"}
  ]
}
```

The equivalent diagnostic-neutral RQL is:

```lisp
(witness
  (typestate :protocol-ref "policy:bifrost.test.resource-lifecycle"
             :bind return-value
             :mode may
    (language typescript
      (call :callee "open"))))
```

For a `use()` after `close()`, the typed analysis result has this minimum observable shape. It deliberately carries no severity or diagnostic message:

```json
{
  "results": [{
    "result_type": "typestate_witness",
    "protocol_ref": "policy:bifrost.test.resource-lifecycle",
    "protocol_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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

`protocol_hash` is serialized as exactly 64 lowercase hexadecimal characters; the illustrative value above is replaced by the fixture's actual canonical hash in gold output.

Evaluating the `.rqlp` policy maps that result into a `PolicyFinding` with `policy_id`, severity/unrated state, message, primary/related locations, analysis type, classification, optional CVSS assessment, proof/completeness, and the bounded witness. The same `PolicyFinding` feeds human and SARIF renderers; renderers never reinterpret raw query matches or solver facts.

Changing either pilot wire shape requires an entry in the Decision Log plus canonical policy, JSON query, RQL lowering, validation, rendering, editor, and end-to-end test updates. Java uses the same policy/protocol definition with only the analyzed fixture changing.

All query vocabulary enters through `src/analyzer/structural/query/schema.rs`, then receives canonical IR, JSON and RQL decoding, validation ranges, hover/completion, rendering, TextMate grammar updates, execution tests, and executable documentation recipes. All policy vocabulary enters through #709's declarative policy schema rather than private lists in #824. #720 combines only compatible typed endpoints.

### Milestone 8: run the cross-language pilot and decide extensions (#825, #826)

Build equivalent TypeScript and Java inline projects plus a larger representative or generated corpus. The resource protocol exercises allocation/open, use, close, aliases, factories, helpers, actual/formal and return flow, branches, recursion-safe summaries, multiple targets, normal exits, and an exceptional path. Gold expectations distinguish complete-no-finding, complete-finding, inconclusive, and unsupported results. Run the same analysis through internal APIs, diagnostic-neutral JSON/RQL exploration, and #709's `.rqlp` policy evaluator; require the human and SARIF renderers to agree on policy identity, primary location, related witness locations, and completeness.

Record true/false positives and negatives, abstention, cold construction, warm in-process summary reuse, warm cross-process hydration for promoted artifacts, retained bytes or RSS, graph/fact/summary counts, query latency, witness payload, hit/miss rates, and targeted invalidation. Every report includes the Bifrost commit, fixture revision, features, environment, and machine metadata.

#826 then evaluates two separate questions. First, whether WPDS-style weights materially improve summary or proof composition. Second, whether a synchronized field/call pushdown component materially improves access-path precision beyond #816. The legitimate outcome is “not yet”; no extension is accepted without exact correctness and resource evidence, and baseline clients must not pay a material disabled cost.

After the TypeScript/Java CFG and ICFG reference contract passes its focused review, begin the per-language #815/#816 rollout recorded in `.agents/plans/all-language-cfg-icfg-rollout.md`. That rollout may proceed alongside the solver and TypeScript/Java typestate pilot: all languages are required by the focused CFG/ICFG plan, but they do not block shipping the first useful TypeScript/Java typestate analysis.

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
    src/analyzer/taint/
      mod.rs model.rs plan.rs client.rs summary.rs finding.rs provenance.rs
    src/analyzer/typestate/
      mod.rs protocol.rs client.rs summary.rs
    src/analyzer/policy/
      mod.rs definition.rs evaluator.rs finding.rs catalog.rs taint.rs classification.rs cvss.rs
      render/mod.rs render/human.rs render/sarif.rs
    tests/
      semantic_ir_contract.rs semantic_cfg_contract.rs
      semantic_oracle_contract.rs icfg_contract.rs
      semantic_graph_algorithms.rs dataflow_tabulation.rs
      dataflow_clients.rs taint_policy_sets.rs taint_summary_reuse.rs
      typestate_protocol.rs analysis_summaries.rs semantic_artifact_store.rs
      static_analysis_policy.rs cvss_classification.rs
      code_query_taint.rs policy_taint_integration.rs
      code_query_typestate.rs policy_typestate_integration.rs typestate_pilot.rs
    tests/fixtures/typestate/resource-lifecycle.protocol.json
    tests/fixtures/policies/resource-lifecycle.rqlp
    tests/fixtures/policies/attacker-controlled-to-sensitive-sinks.rqlp

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

    cargo test --test dataflow_tabulation --test dataflow_clients --test taint_policy_sets --test taint_summary_reuse

Expected: `test result: ok`; bounded exhaustive-reference cases match tabulation, distributivity/property tests pass, recursion converges, and direct/taint clients share the kernel. One multi-source/multi-sink run has the same meetings as the union of bounded per-pair reference runs without executing the Cartesian product; equivalent origins aggregate; incomplete discovery cannot produce a complete negative; and witness limits do not change reachability.

For #822 and #823:

    cargo test --test typestate_protocol --test analysis_summaries --test taint_summary_reuse

Expected: `test result: ok`; the canonical protocol validates, TypeScript and Java share its hash, internal tabulation summaries remain distinct from semantic/taint/protocol summaries, and incomplete summaries are not reused as complete. Taint transfer summaries are reused when only sink selection, message, CWE refinement, or CVSS evidence changes, and are invalidated when sanitizer, transform, heap/access-path, or unknown-call semantics change.

For #817 after an artifact is promoted:

    cargo test --test semantic_artifact_store

Expected: `test result: ok`; version, corruption, generation, overlay, dependency, rule-hash, concurrent access, and GC cases either hydrate the exact artifact or produce a safe miss.

For #709 and #824:

    cargo test --test static_analysis_policy --test taint_policy_sets --test cvss_classification --test code_query_taint --test policy_taint_integration --test code_query_typestate --test policy_typestate_integration

Expected: `test result: ok`; the policy envelope and `PolicyFinding` contract pass independently, `analysis.type` selects `match`, `taint`, or `typestate`, compatible omitted/pinned RQLP versions resolve exactly as specified, and #824's schema-version-3 JSON/RQL analysis examples lower to diagnostic-neutral queries. The taint fixture compiles to one plan, keeps a broad finding when no CWE refinement matches, rejects missing/conflicting catalog sides and ambiguous sink operands, maps incomplete Base evidence to `Unscored`, computes scores rather than accepting authored numbers, and preserves metric provenance and compatible assessment variants in matching human/SARIF findings.

For #825:

    cargo test --test typestate_pilot

Expected: `test result: ok`; both languages produce gold complete-finding, complete-no-finding, inconclusive, and unsupported cases, including helper, alias, recursion, and exceptional flow. The same result is available through internal, query, and `.rqlp` policy paths, with equivalent human/SARIF identity and locations. The ignored benchmark mode prints one machine-readable record containing commit, fixture, counts, cold/warm elapsed times, memory, summary hits, and invalidation result.

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
- `SemanticLocator` remains source-facing, `SemanticArtifactKey` changes on validity inputs, `ProcedureId` is deterministic only inside its owning artifact, and procedure-row IDs are deterministic only inside their owning procedure; duplicate names and mounted duplicate blobs remain exact.
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

### Taint, typestate, and client validation

- One resource protocol definition runs on both reference languages.
- Valid, use-before-open, use-after-close, double-close, leak/escape, alias, helper, branch, recursion, ambiguous dispatch, unsupported, and exceptional cases have gold outcomes.
- A one-state/direct-flow client and taint client run through the same ICFG and solver.
- One set-oriented taint run matches the bounded per-pair reference union while performing shared propagation. Different source classes meet the same sink without creating duplicate source-instance-by-sink findings.
- A three-source/four-sink fixture invokes one solver run, and several compatible policies union into one batch partition before projecting findings back to each policy. Incompatible transfer semantics form distinct partitions.
- Selective sanitization removes only the declared compatible classes. Changing run-local dense-bit order preserves stable class identities, and persisted universes remap through `TaintUniverseHash` rather than reusing raw bit positions.
- A broad attacker-controlled-to-security-sensitive meeting remains a finding without a narrow CWE refinement. The sink identifies its dangerous operand, and a safely bound value does not inherit the SQL-structure sink rule.
- Meeting tests reject same-node intersections with incompatible carriers, call/return contexts, access paths, exceptional states, or transform states.
- Source/sink discovery gaps, unknown calls, lossy class truncation, or incomplete summaries prevent a complete negative. Bounded origins and witnesses never truncate reachability.
- Flow summaries are reused across sink, message, classification, and CVSS-only policy changes; transfer-changing sanitizer, model, context, heap, and access-path changes invalidate the affected summaries.
- Cache tests cover safe hits for reporting-only changes and safe misses for artifact, matcher, sanitizer/transform, oracle, external-model, context/access-path, exceptional/unknown-call, and callee/SCC dependency changes.
- CVSS conformance tests use official FIRST v4.0 reference vectors to cover canonical metric order and score recomputation; all 11 Base metrics; one missing Base metric becoming `Unscored`; rejection of Base `X`; valid Not-Defined defaults outside Base; `E:X` versus evidence-backed `E:U`; and Base, Base+Threat, Environmental, and final component publication for `CVSS-B`, `CVSS-BT`, `CVSS-BE`, and `CVSS-BTE`.
- Assessment tests distinguish a network-bound vulnerable system (`AV:N`) from a downloaded file/document case, turn contradictory/conflicting evidence into variants or `Unscored`, group identical coherent scenarios, retain different vectors, and justify any highest-score display selection. CVSS severity, analyzer certainty, and organizational risk remain distinct.
- Witnesses are source-backed, bounded, context-respecting, and labeled with proof/completeness.

### Storage and performance validation

- Compact representations are compared against behavior-equivalent reference relations.
- Every persisted format has version, corruption, stale-generation, targeted invalidation, overlay, concurrent access, and GC tests.
- Benchmarks distinguish mutable construction, freeze, cold hydration, warm reuse, traversal/query execution, rendering, and serialized payload.
- A cache is promoted only with measurable reuse and without eager whole-workspace hydration.

### Query and product validation

- Typed validation rejects incompatible query-domain compositions before execution.
- At least one JSON and one RQL query returns a set-oriented taint finding with reached source classes, a bounded origin set, completeness, and a witness.
- At least one JSON and one RQL query returns a typestate finding and bounded witness.
- `.rqlp` loading is owned by `PolicyRegistry` and taint model catalogs by `TaintCatalogRegistry`; `CodeQuery`/RQL cannot load arbitrary policy, catalog, model, or protocol paths, and traversal, oversized-file, identity-collision, or duplicate-policy-ID attempts fail deterministically.
- The public `TypestatePolicySpec` lowers to the same canonical internal hash as the independently serialized #822 protocol fixture; their wire shapes are not required to match.
- Registering one `ProtocolRef` with two different hashes fails deterministically; different references for the same hash share the compiled automaton, and stale handles fail after their context generation changes.
- A raw query/analysis finding has no policy severity or diagnostic message; only `PolicyEvaluator` produces `PolicyFinding`.
- One `.rqlp` taint policy composes versioned source/sink catalogs, compiles to one analysis plan, and produces equivalent broad/refined classifications and scored/unscored assessment data in human and SARIF output.
- Human and SARIF renderers preserve vector, all applicable component scores/severities, nomenclature, `Scored`/`Unscored`, missing metrics/reasons, provenance, completion/certainty, all assessment variants, and the chosen display variant. Neither renderer recomputes or reinterprets CVSS.
- One `.rqlp` typestate policy produces equivalent human and SARIF policy identity, primary location, related witness locations, and completeness.
- Set composition, policy conversion, ordering, limits, truncation, diagnostics, and capability behavior are deterministic.
- Every new public term has schema, parser/decoder, validation-range, hover/completion, grammar, execution, and documentation coverage.

The epic is accepted when #821/#823/#824 demonstrate the set-oriented taint, summary-reuse, query, and policy criteria above and #825 demonstrates the typestate criteria with reproducible correctness and performance evidence. Full language rollout and #826 are follow-on outcomes, not blockers for the first platform milestone unless either client proves the baseline architecture unsound.

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
- Living-plan draft PR: https://github.com/BrokkAi/bifrost/pull/828
- Initial plan commit: `41f1e88b`

Existing integration anchors:

- Structural query epic #328
- Policy/SARIF format #709
- Typed set composition #720
- Receiver facts/object sensitivity #393 and #394
- Call and receiver query traversal #719 and #718
- Compact graph experiment #748 / PR #798
- SQLite-backed compact structural snapshots PR #802
- Store failure reporting #695

Normative CVSS references checked for the policy/scoring contract:

- FIRST CVSS v4.0 Specification Document, document version 1.2: https://www.first.org/cvss/v4.0/specification-document
- FIRST CVSS v4.0 User Guide: https://www.first.org/cvss/v4.0/user-guide
- FIRST CVSS v4.0 Data Representations: https://www.first.org/cvss/data-representations

Add the merged commit here after publication completes. Add benchmark tables or links to `.agents/docs/` notes after each experimental milestone; include a recommendation, not only raw percentages.

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

#709 establishes the public policy boundary independently of any one analysis client. The exact, versioned `PolicyDefinition`, `LoadedPolicy`, `PolicyReportDocument`, `PolicyRun`, `PolicyFinding`, evidence, identity, budget, and evaluator types live only in `.agents/plans/issue-709-static-analysis-policy-format.md`; this umbrella intentionally does not mirror them. That plan requires `analysis.type` to select the tagged public variant, one canonical report document for every renderer, and context-requiring evaluation against a fully resolved `LoadedPolicy`. #824 consumes those public contracts and must not create renamed or reduced copies.

The #821/#823/#824 taint bridge is also explicit:

    struct TaintAnalysisPlan {
        semantics_key: TaintPropagationSemanticsKey,
        universe: TaintUniverse,
        seeds: Vec<SourceEventKey>,
        sink_observers: Vec<SinkObserver>,
        propagation_event_matches: Vec<TaintPropagationEventMatchKey>,
        sink_observer_matches: Vec<TaintSinkObserverMatchKey>,
        budgets: TaintBudgets,
        discovery: DiscoveryCompleteness,
    }

    struct TaintFinding {
        key: TaintFindingKey,
        sink: SinkEventKey,
        scenario: TaintSemanticScenario,
        reached_source_classes: TaintClassSet,
        contributing_origins: BoundedOrigins,
        proof: ProofMetadata,
        completeness: FindingCompleteness,
        witness_refs: Vec<WitnessId>,
    }

    struct TaintTransferSummary {
        key: TaintTransferSummaryKey,
        boundary_relation: SymbolicTaintRelation,
        local_source_ports: Vec<SymbolicSourcePort>,
        internal_sink_ports: Vec<SymbolicSinkObservation>,
        exceptional_and_escape_effects: TaintEffects,
        proof: ProofMetadata,
        completeness: SummaryCompleteness,
    }

    trait TaintPolicyCompiler {
        fn compile(
            &self,
            policy: &LoadedPolicy,
            spec: &ResolvedTaintPolicySpec,
            context: &mut QueryAnalysisContext,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<CompiledTaintPolicy>;
    }

    trait TaintBatchPlanner {
        fn partition(
            &self,
            policies: &[CompiledTaintPolicy],
        ) -> AnalysisOutcome<Vec<TaintBatchPartition>>;
    }

`CompiledTaintPolicy` contains one policy's set-oriented plan plus compatibility and the exact typed scenario/evidence projection metadata needed by #709's generic classification/CVSS/report reducer. `TaintBatchPlanner` groups equal propagation-semantics keys only when workspace snapshot, scope, and completeness-affecting budgets are also compatible, unions seeds/observers while preserving stable class and event identities, and returns a projection map from each batch meeting to the policies it can answer. It does not union incompatible sanitizer, transform, heap, access-path, context, external-model, exceptional, unknown-call, scope, or completion semantics.

The #824 bridge between the public and internal typestate models is explicit:

    struct CompiledPolicyProtocol {
        reference: ProtocolRef,
        handle: ProtocolHandle,
        protocol_hash: TypestateProtocolHash,
        binding_plan_hash: TypestateBindingPlanHash,
    }

    trait TypestatePolicyCompiler {
        fn compile(
            &self,
            policy: &LoadedPolicy,
            spec: &ResolvedTypestatePolicySpec,
            context: &mut QueryAnalysisContext,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<CompiledPolicyProtocol>;
    }

`ResolvedTypestatePolicySpec` carries only #709's pre-semantic authoring-projection hash. `TypestatePolicyCompiler` resolves exact event/binding classes and same-site endpoint dominance, remaps dominated subject/event/expectation and pair-restriction identities to their unique live winners, and computes `TypestateBindingPlanHash` only after that normalization. `ProtocolHandle` is opaque and valid only for one `QueryAnalysisContext`; it contains a context generation, dense slot, and the canonical compiled protocol/binding-plan hashes. Registration atomically binds `ProtocolRef("policy:<policy-id>")` to that pair and rejects an existing reference with a different pair. Protocol summaries and persisted artifacts key on the compiled hashes plus matcher/compiler version, workspace/analyzer snapshot, solver configuration, and completeness-affecting semantics, never the pre-semantic authoring hash, reference, dense slot, categories, directory paths, display names, messages, or classifications.

The initial #709 implementation may execute only `PolicyAnalysis::Match`, but it parses compatible-versioned policy/endpoint documents and retains public taint/typestate authoring values without importing `TaintAnalysisPlan`/`ProtocolSpec` or inventing solver semantics. It resolves catalog/endpoint/category/manifest/precedence composition into stored `ResolvedTaintPolicySpec` and `ResolvedTypestatePolicySpec` values before producing `LoadedPolicy`. #824 supplies the compilers above plus adapters from `AnalysisRun<FlowFinding>`, `AnalysisRun<TaintFinding>`, and `AnalysisRun<TypestateFinding>` after those clients exist. Compilers consume already-lowered selectors, exact endpoint bindings/hashes, behavior rules, and policy identity without reopening files or duplicating #709's generic precedence/classification/report reducer. Adapters produce complete endpoint-pair or typestate-violation projection facts before report truncation. There is no context-free conversion from `CodeQueryMatch`, endpoint match, or analysis finding into `PolicyFinding`: evaluation always requires a `LoadedPolicy`. Human, canonical JSON, and SARIF renderers consume only one `PolicyReportDocument`, whose descriptors preserve metadata and schema manifests even for failed or zero-finding runs.

The semantic adapter boundary materializes a mounted source artifact once from one prepared syntax snapshot and resolves procedures inside it:

    trait ProgramSemanticsProvider {
        fn materialize(
            &self,
            file: &ProjectFile,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError>;
    }

    struct SemanticRequest<'a> {
        budget: &'a mut SemanticBudget,
        cancellation: &'a CancellationToken,
    }

The provider derives the source revision, dialect-sensitive artifact key, parsed tree, and lowered artifact from the same `TreeSitterAnalyzer::prepared_syntax` value. This atomic operation replaces the earlier split key/artifact sketch, which could race a source or overlay update. Complete artifacts alone enter the bounded per-analyzer cache; cancellation and incomplete outcomes remain explicit and are never cached as complete.

`SemanticArtifact` owns a dense procedure table. `ProcedureHandle` retains an `Arc<SemanticArtifact>` plus its artifact-local `ProcedureId`; local value, point, call, and memory IDs cross provider/oracle boundaries only together with that procedure scope. `ProcedureSemantics` owns dense local IDs, source mappings, semantic effects, and an immutable CFG. It does not own solver facts or protocol states.

The interprocedural boundary contains control and call metadata, not value bindings:

    trait IcfgProvider {
        fn procedure(
            &self,
            locator: &SemanticLocator,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<ProcedureHandle>;

        fn call_control(
            &self,
            caller: &ProcedureHandle,
            call: CallSiteId,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<CallControlTargets>;
    }

`CallControlTargets` identifies candidate callee entries, the originating normal and exceptional return sites, proof, and unresolved/external status. It consumes existing call relations and dispatch evidence and never resolves syntax independently.

Value capabilities remain separate even if one implementation serves several traits:

    trait DispatchOracle {
        fn callees(
            &self,
            caller: &ProcedureHandle,
            call: CallSiteId,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<CalleeTargets>;
    }

    trait ValueFlowOracle {
        fn call_bindings(
            &self,
            caller: &ProcedureHandle,
            call: CallSiteId,
            callee: &ProcedureHandle,
            budget: &mut SemanticBudget,
        ) -> AnalysisOutcome<CallBindings>;
    }

    trait HeapOracle {
        fn locations(
            &self,
            procedure: &ProcedureHandle,
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
        fn initial_value(&self, seed: Self::Fact) -> Self::Value;
        fn identity_edge(&self) -> Self::EdgeFunction;
        fn normal_edge_function(
            &self,
            edge: ControlEdgeId,
            fact: Self::Fact,
        ) -> Self::EdgeFunction;
        fn call_edge_function(
            &self,
            call: &CallTransfer,
            fact: Self::Fact,
        ) -> Self::EdgeFunction;
        fn return_edge_function(
            &self,
            ret: &ReturnTransfer,
            fact: Self::Fact,
        ) -> Self::EdgeFunction;
        fn call_to_return_edge_function(
            &self,
            call: &CallTransfer,
            fact: Self::Fact,
        ) -> Self::EdgeFunction;
        fn exceptional_edge_function(
            &self,
            edge: ControlEdgeId,
            fact: Self::Fact,
        ) -> Self::EdgeFunction;
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
- `TaintTransferSummary` is owned by `taint::summary`; it carries symbolic boundary transfer plus local source and internal sink ports, keyed by exact propagation and dependency semantics.
- `ProtocolSummary` is owned by `typestate::summary` and includes the protocol hash.

A `SummaryStore` may memoize any reusable summary type in memory and optionally SQLite, but the solver accepts an in-memory implementation and does not require persistence to be correct. Incomplete `TabulationEndSummary`, `TaintTransferSummary`, or recursive-SCC values never enter a complete reusable summary; SCC members publish atomically after convergence.

Public query changes depend on the declarative schema registry in `src/analyzer/structural/query/schema.rs`. Public policy changes depend on the versioned schema and finding model established by #709. Neither side may add private keyword lists, editor-only vocabulary, source-text path parsing, or an implicit conversion from query matches to diagnostics. Existing Rust dependencies should be preferred for the first implementation; any new solver or graph crate requires a measured build/runtime benefit and an explicit Decision Log entry.

Plan revision note (2026-07-16): Initial roadmap written after auditing the post-PR-#802 codebase and creating epic #813 with native subissues #814–#826. The initial plan deliberately makes TypeScript/Java the reference pair, IFDS/IDE the baseline solver shape, compact memory plus selective SQLite the lifecycle policy, dominance optional, and WPDS/SPDS evidence-gated. Draft PR #828 is the current publication thread for the initial checkpoint and subsequent revisions. A later same-day revision made #709 the early public policy/API gate, separated `.rqlp`/`PolicyFinding` from the internal protocol and analysis result models, and required the #825 pilot to validate query, human, and SARIF surfaces from one analysis result. This revision also made `analysis.type: taint` set-oriented end to end: one compatible multi-source/multi-sink batch, stable class-set propagation with bounded origins, symbolic taint summaries and exact cache layers, broad findings before CWE refinement, and evidence-backed CVSS v4.0 variants that never fabricate a score from incomplete Base evidence.

Plan revision note (2026-07-17): Reconciled the roadmap with the detailed #709 plan. `.rqlp` is explicitly authored as a separate S-expression policy language with native versioned RQL selectors. A later same-day adversarial pass removed the temporary conceptual JSON sketches entirely so this roadmap cannot be mistaken for a second wire contract.

Plan revision note (2026-07-16): Issue #814 diagnosis corrected the original procedure-shaped artifact sketch. A semantic artifact now owns one mounted source snapshot and an artifact-local procedure table; procedure rows own their block, point, value, call, memory, capture, provenance, evidence, and gap IDs. Provider and oracle interfaces use scoped procedure handles. The same revision records nested callable bodies as separate procedures, callable references and captures as creation-time semantics rather than eager calls, and byte-authoritative source positions with explicit zero-based display coordinates. The focused implementation plan is `.agents/plans/issue-814-semantic-ir-contract.md`.

Plan revision note (2026-07-16): Completed #814 at reviewed checkpoint `648a9fec`. The final contract uses typed continuations and exact outgoing topology, bidirectional subject-scoped gaps/evidence, direct-child unmaterialized targets, separate provider errors and semantic outcomes, atomic total-payload budgets, indexed validation, streaming bounded rendering, portable shared language/path identity, and materialization-scoped handles. Validation passed 59 semantic unit tests, 10 TypeScript/Java contract tests, the complete `nlp,python` suite, all-target/all-feature clippy with warnings denied, formatting, and diff checks. #815, #816, and #818 retain adapter/CFG, oracle/refinement, and matched-ICFG ownership respectively.

Plan revision note (2026-07-17): Synchronized the #709 boundary with its detailed ExecPlan: `.rqlp` authoring is S-expression-only, JSON is generated interchange, #709 owns syntactic catalog composition and the generic classification/CVSS reducer, and #824 consumes resolved `LoadedPolicy` inputs for semantic compilation/adaptation. Removed non-normative JSON pseudo-wire examples and the stale duplicate public report type mirror so the issue-specific plan is the single policy wire contract.

Plan revision note (2026-07-16): Guided review against rebased `origin/master` produced and resolved four findings in `1faf8b9b`. Edge-typed normal and exceptional arms may now converge; recognized callable creation retains typed target uncertainty without requiring a locator; balanced bounded rendering is shared with Rune IR; and registry counting is centralized. The corrected complete `nlp,python` suite and all-feature clippy passed before publication.

Plan revision note (2026-07-17): Began #815 implementation through `.agents/plans/all-language-cfg-icfg-rollout.md`. The focused plan carries the TypeScript/Java CFG reference slice through the dispatch prerequisite, one matched-return ICFG, all eleven analyzable-language adapters, and a measured CFG/ICFG lifecycle decision under #817 while keeping public query, solver, value/heap, and typestate layers outside its scope.

Plan revision note (2026-07-17): Pre-checkpoint review clarified that remaining adapter children begin after the TypeScript/Java CFG/ICFG contract review and may run alongside later solver/pilot work, rather than waiting until after #825. This preserves the focused plan's all-language endpoint without making that rollout a prerequisite for the first TypeScript/Java typestate release.

Plan revision note (2026-07-17): Recorded completion of #815 Milestone 1a. The language-neutral semantic contract now includes canonical procedure-local rich-edge IDs, immutable outgoing/incoming adjacency, exact traversal, defensive hydration checks, scoped handles, and bounded schema-v2 rendering. This is only the CFG storage substrate; the file-aware provider, iterative builder, TypeScript/TSX lowering, Java differential contract, and shared ICFG remain tracked in the focused all-language plan.

Plan revision note (2026-07-17): Recorded completion of #815 Milestones 1b and 1c. Semantic materialization now uses one bounded exact source snapshot with disk/overlay origin, overlay revision, and dialect identity; complete artifacts alone enter a retained-byte single-flight cache. The private iterative builder and first real TypeScript/TSX adapter cover the common callable-control core, preserve dead source behind a generic isolation seal, and expose source-backed predecessor/successor tests. Java, layout measurement, dispatch, and the shared ICFG remain in the focused rollout plan.

Plan revision note (2026-07-17): Recorded completion of #815 Milestone 2. The Java reference adapter now passes the common and extended differential CFG contract, including cleanup-safe switch yield and executable initializer fragments with exact gaps. The measured hot representation remains one canonical edge table with outgoing offsets and incoming edge-ID rows; outgoing-only memory savings did not justify multi-second reverse traversal. Location-first dispatch and the matched TypeScript/Java ICFG are now the next focused checkpoint.

Plan revision note (2026-07-17): Recorded completion of the #816 dispatch prerequisite and #818 TypeScript/Java internal control slice. Exact call expressions reuse the existing resolver, while one bounded context-bearing provider owns generation validation, invoke expansion, matched returns, typed boundaries, and dense predecessor/successor snapshots. The reviewed cross-language adapter boundary is frozen; value/heap transfer, public query exposure, and solver work remain outside the focused rollout.

Plan revision note (2026-07-18): Recorded completion of #815 Milestone 4a. JavaScript and JSX now pass the same source-backed callable CFG and matched-return ICFG contract as the reference pair through a flavor-aware shared JS/TS lowerer. JavaScript resource management, generator suspension, and JSX uncertainty remain exact point-scoped gaps; the remaining adapters continue in the focused rollout plan.

Plan revision note (2026-07-18): Recorded completion of #815 Milestone 4b after specialist review. C# now passes the shared callable-CFG and matched-return ICFG contract with structured control, handlers, cleanup, async points, nested callable identity, and exact advanced-feature gaps. Review corrected grammar-sensitive indexed-call, target-typed-initializer, and conditional-compilation omissions; Python is the next adapter checkpoint in the focused rollout plan.

Plan revision note (2026-07-18): Recorded completion of #815 Milestone 4c after specialist review. Python now passes the shared callable-CFG and matched-return ICFG contract with exact loop-else, nested callable ownership, handlers and cleanup, typed protocol gaps, and deferred coroutine/generator invocation. Review corrected comprehension eager evaluation, comparison short-circuiting, assertion failure routing, loop-target evaluation, and truth-protocol gaps; Go is the next adapter checkpoint in the focused rollout plan.

Plan revision note (2026-07-18): Recorded completion of #815 Milestone 4d after specialist review. Go now passes the shared callable-CFG and matched-return ICFG contract across functions, methods, literals, branches, loops, calls, range, channel operands, deferred calls, and goroutine creation. Review made selected-only call omissions and partially unspecified evaluation order explicit and proved shadowed `panic`/`recover` dispatch; Rust is the next adapter checkpoint in the focused rollout plan.

Plan revision note (2026-07-18): Recorded completion of #815 Milestone 4e after specialist review. Rust now passes the shared callable-CFG and matched-return ICFG contract across functions, methods, nested callables, labels, match, loops, calls, semicolonless tails, `?`, await, and generators. Review made parameter, lexical, pattern-binding, assignment-replacement, and abrupt-path RAII omissions exact; stopped unsupported try blocks and macros at typed boundaries; exposed implicit trait calls; corrected labeled-block break routing; and enabled generic/turbofish dispatch without regressing grouped imports. PHP is the next adapter checkpoint in the focused rollout plan.

Plan revision note (2026-07-18): Recorded completion of #815 Milestone 4f after specialist review. PHP now passes the shared callable-CFG and matched-return ICFG contract across functions, methods, nested callables, branches, loops, numeric control, nullish and nullsafe flow, switch, match, calls, explicit throw, handlers, and cleanup. Review corrected chain-scoped skipping, coalescing, grammar-sensitive loop and switch behavior, first-class callable recognition, method-return inference, bounded call selection, ambiguous boundaries, and cleanup specialization; Scala is the next adapter checkpoint in the focused rollout plan.

Plan revision note (2026-07-18): Recorded completion of #815 Milestone 4g after specialist review. Scala now passes the shared callable-CFG and matched-return ICFG contract across functions, methods, constructors, nested callables, expression-valued branches, loops, match, curried and generic application, operators, explicit throw, handlers, and cleanup. Review corrected callable ownership, non-local closure return, constructor/arity shape, wrapper resolution, nested-call pruning, structured-argument cardinality, and by-name or implicit-call completeness; Ruby is the next adapter checkpoint in the focused rollout plan.

Plan revision note (2026-07-18): Recorded completion of #815 Milestone 4h after specialist review. Ruby now passes the shared callable-CFG and matched-return ICFG contract across methods, initializers, lambdas, attached blocks, common control, implicit returns, calls, safe navigation, explicit throw, handlers, cleanup, and non-local block completion. Review corrected pattern evaluation, callable-table mutation, destructured writers, bounded binding collection, cleanup routing, overrideable dispatch, lifecycle blocks, dynamic callable boundaries, and parser-ordered binding/capture semantics; C/C++ is the final adapter checkpoint in the focused rollout plan.

Plan revision note (2026-07-19): Recorded completion of #815 Milestone 4i after C/C++ and all-language specialist review. Every analyzable language now supplies source-backed callable CFGs and matched calls through one exact-location dispatch facade and one context-bearing ICFG. C/C++ adds structured link-unit identity and caller-side implicit-evaluation gaps without introducing another graph or resolver, while shared return evidence is path-relevant and every unresolved boundary is non-complete.

Plan revision note (2026-07-20): Recorded completion of the focused #817 semantic/CFG lifecycle measurement. Fresh-process release matrices over generated shapes and pinned TypeScript/Java repositories confirm bidirectional rows and produce a measured SQLite no-go because the optimistic control/call projection misses the large-corpus absolute write-overhead gate. Aggregate schema v5 separates sample-time Bifrost identity, aggregation-time recommendation identity, and per-dataset repository identity. The same pass recorded the post-rollout architecture audit: preserve adapter-owned syntax semantics, extract their repeated emission and call scaffold into a shared lowering session, replace language checks in the generic ICFG with typed gap impacts, and separate workspace dispatch from language-neutral stitching before value/heap and data-dependence implementation. This is a recommendation for a dedicated follow-up ExecPlan, not an unreviewed source refactor.

Plan revision note (2026-07-17): Refined #709 around the intended reusable-model workflow. Omitted policy and RQL schema versions now select only a compiled-in source-and-semantics-compatible lineage head, while explicit pins remain exact. Diagnostic-neutral categorized endpoint leaves compose through authored bounded directory/ID references; actual taint meetings receive either the fixed generated presentation or one explicitly dominant combination. Resolved endpoint bindings are also the public inputs to typestate subject/event selection, accepting states, and distinct explicit/normal-exit/exceptional-exit terminal expectations. Presentation metadata remains outside propagation, protocol, and summary keys.
