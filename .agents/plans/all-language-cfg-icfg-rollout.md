# Deliver all-language callable CFGs and one shared ICFG

This ExecPlan is a living document. Keep the sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current while implementation proceeds. Maintain this file in accordance with `.agents/PLANS.md`.

This plan is the focused execution record for callable control-flow graphs from GitHub issue #815, the dispatch prerequisite from #816, the language-neutral interprocedural control-flow graph from #818, and the subsequent per-language adapter rollout. The broader architecture remains recorded in `.agents/plans/language-agnostic-composable-typestate-platform.md`; this file is deliberately complete enough to resume implementation without reading the broader plan first.

## Purpose / Big Picture

Bifrost already describes language-neutral semantic procedures, program points, calls, and typed control edges, but production analyzers do not yet lower real syntax into that representation. After this plan is complete, an internal analysis client can ask any of Bifrost's eleven analyzable languages for a callable control-flow graph (CFG), traverse exact predecessor and successor edges, and demand a bounded interprocedural control-flow graph (ICFG) slice that preserves matched calls and returns.

A CFG is the graph of possible control transfers within one callable. Its nodes are semantic program points, including entry, normal exit, exceptional exit, statements, and expression-level call or branch events. An ICFG joins those per-callable graphs with call-to-entry and callee-exit-to-the-originating-continuation transfers. A return must resume at the call that entered the callee; it must not return to every call site that happens to target the same procedure.

The behavior is demonstrated by multiline inline projects in `tests/`. Tests name source-backed points such as a branch condition or call, assert their exact predecessors and successors, and render bounded graph context when an assertion fails. The same common contract runs across Java, Go, C/C++, JavaScript, TypeScript, Python, Rust, PHP, Scala, C#, and Ruby. TypeScript and Java establish the contract first. Every language must implement the common control and direct-call core; language-specific exception, cleanup, async, generator, concurrency, destructor, or non-local-control omissions must be reported as typed capabilities and point-specific semantic gaps rather than silently guessed.

This plan keeps CodeQuery and RQL exposure out of scope because issue #824 owns that public surface. It also excludes the solver, full value and heap oracles, typestate, SSA, dominators, and arbitrary graph algorithms.

## Progress

- [x] (2026-07-17 10:10+02:00) Reconfirmed that the clean issue branch, its remote branch, and `origin/master` all point at `3bd7b75a`, with the #814 semantic IR contract already present.
- [x] (2026-07-17 10:10+02:00) Audited the #814 semantic IR, provider contract, compact graph rows, prepared syntax snapshot, call-relation service, supported language registry, and inline-project test harness.
- [x] (2026-07-17 10:10+02:00) Recorded the agreed all-language rollout, TypeScript/Java vertical slice, adjacency API, lazy ICFG, and evidence-gated persistence policy in this focused ExecPlan.
- [x] (2026-07-17 10:35+02:00) Passed the 10-test `semantic_ir_contract` baseline and completed two pre-checkpoint architecture reviews; resolved sequencing, matched-return, budget, interface, self-containment, per-language checkpoint, and benchmark-gate findings.
- [x] (2026-07-17 11:40+02:00) Milestone 1a: added procedure-local control-edge identities, immutable bidirectional adjacency, storage-independent traversal, defensive validation, bounded deterministic rendering, and focused graph-contract tests.
- [x] (2026-07-17 11:40+02:00) Closed all post-milestone invariant, architecture, and adversarial-test findings; passed 65 semantic unit tests, 10 semantic IR contract tests, 6 CFG contract tests, formatting, diff checks, strict all-target/all-feature clippy, and the complete elevated `nlp,python` suite (1,017 library tests passed, 4 ignored, plus every binary, integration, and doc-test target).
- [x] (2026-07-17 14:34+02:00) Milestone 1b: added the request-scoped, file-aware production semantic provider, exact bounded source snapshots, complete-artifact cache lifecycle, and private iterative CFG lowering engine.
- [x] (2026-07-17 14:34+02:00) Milestone 1c: implemented the TypeScript and TSX callable CFG adapter plus source-backed predecessor/successor assertion harness, typed advanced-control gaps, and disconnected dead-region sealing.
- [x] (2026-07-17 14:34+02:00) Closed the Milestone 1b/1c post-review findings and passed 88 semantic unit tests, 29 CFG contract tests, 11 provider contract tests, 10 semantic IR contract tests, formatting, diff checks, strict all-target/all-feature clippy, and the complete elevated `nlp,python` suite.
- [x] (2026-07-17 16:05+02:00) Milestone 2: implemented Java, passed labeled TypeScript/Java differential cases, measured all three physical adjacency choices, and stabilized the CFG lowering contract without declaring the cross-procedural contract frozen.
- [x] (2026-07-17 16:05+02:00) Closed the Milestone 2 specialist review with no remaining blocker; passed 37 CFG contract tests, 11 provider contract tests, 10 semantic IR contract tests, the representation self-test, formatting, diff checks, strict all-target/all-feature clippy, and the complete elevated `nlp,python` repository suite (1,046 library tests passed, 4 ignored, plus every binary, integration, and doc-test target).
- [x] (2026-07-17 16:54+02:00) Milestone 3: exposed the exact-location dispatch slice, implemented one demand-materialized context-bearing ICFG for TypeScript and Java, froze the shared CFG/dispatch/ICFG adapter contract, and closed the post-milestone specialist review findings.
- [x] (2026-07-17 17:05+02:00) Passed 17 ICFG contract tests, 37 CFG contract tests, 11 provider contract tests, formatting, diff checks, strict all-target/all-feature clippy, and the complete host-access `nlp,python` repository suite (1,053 library tests passed, 4 ignored, plus every binary, integration, and doc-test target).
- [x] (2026-07-17 17:00+02:00) Verified that #815 had no existing rollout children, then created and attached native subissues [#887](https://github.com/BrokkAi/bifrost/issues/887) JavaScript/JSX, [#886](https://github.com/BrokkAi/bifrost/issues/886) C#, [#888](https://github.com/BrokkAi/bifrost/issues/888) Python, [#889](https://github.com/BrokkAi/bifrost/issues/889) Go, [#891](https://github.com/BrokkAi/bifrost/issues/891) Rust, [#890](https://github.com/BrokkAi/bifrost/issues/890) PHP, [#892](https://github.com/BrokkAi/bifrost/issues/892) Scala, [#893](https://github.com/BrokkAi/bifrost/issues/893) Ruby, and [#894](https://github.com/BrokkAi/bifrost/issues/894) C/C++; every child cross-links #816 and #818 and records its rollout order and gap obligations.
- [ ] Milestone 4a: roll the common CFG and ICFG contract through JavaScript and JSX, then review and checkpoint it independently.
- [ ] Milestone 4b: roll the contract through C#, then review and checkpoint it independently.
- [ ] Milestone 4c: roll the contract through Python, then review and checkpoint it independently.
- [ ] Milestone 4d: roll the contract through Go, then review and checkpoint it independently.
- [ ] Milestone 4e: roll the contract through Rust, then review and checkpoint it independently.
- [ ] Milestone 4f: roll the contract through PHP, then review and checkpoint it independently.
- [ ] Milestone 4g: roll the contract through Scala, then review and checkpoint it independently.
- [ ] Milestone 4h: roll the contract through Ruby, then review and checkpoint it independently.
- [ ] Milestone 4i: roll the contract through C and C++, then review and checkpoint it independently.
- [ ] Milestone 5: benchmark construction, traversal, retained memory, serialization, and hydration; record the CFG/ICFG slice of #817 as a persistence promotion or measured no-go while leaving later value-flow, solver, and summary lifecycle decisions open.
- [ ] Run the focused tests, `cargo fmt`, all-target/all-feature clippy with warnings denied, and the complete `nlp,python` test suite at every relevant reviewed checkpoint.

## Surprises & Discoveries

- Observation: the #814 contract already models procedures, program points, rich control-edge kinds, typed continuations, calls, gaps, capabilities, evidence, validation, and bounded rendering.
  Evidence: `src/analyzer/semantic/ir.rs` and its sibling modules compile and `cargo test --test semantic_ir_contract` passes ten contract tests. The missing work is real lowering, indexed topology, production routing, and interprocedural stitching rather than a second semantic vocabulary.

- Observation: the frozen procedure currently stores a flat control-edge slice without predecessor or successor indexes.
  Evidence: `ProcedureSemantics::control_edges` returns `&[ControlEdge]`, while no adjacency traversal methods exist.

- Observation: `src/compact_graph.rs` cannot directly represent a semantic CFG because it deduplicates bare source-target pairs and owns no edge payload table.
  Evidence: CFGs may contain parallel edges with different `ControlEdgeKind` or evidence. Reverse rows therefore must store edge IDs that refer to one canonical rich-edge table.

- Observation: `TreeSitterAnalyzer::prepared_syntax` already returns one request-cached source, syntax tree, and line-start snapshot.
  Evidence: semantic lowering can consume this exact snapshot and avoid a source race caused by separately reading an artifact key and then reparsing changed overlay content.

- Observation: `CallRelationService` already normalizes callers, callees, receivers, arguments, proof tiers, budgets, and formal bindings, but it begins from `CodeUnit` and discards unresolved results.
  Evidence: the ICFG needs a location-first facade over the existing resolver so semantic call sites, synthetic nested callables, and unresolved/external outcomes remain typed without creating a second resolver.

- Observation: one provider can serve all languages, but TypeScript and TSX require file-aware dialect identity and C/C++ share one analyzer language.
  Evidence: `Language::ANALYZABLE` has eleven entries, `LanguageDialect::TypeScriptTsx` is distinct, JavaScript owns JSX, and `Language::Cpp` covers C and C++ extensions.

- Observation: source may contain deliberately unreachable statements and exceptional exits may be unreachable.
  Evidence: reachability cannot be a construction invariant. Adapters retain source-backed disconnected points and tests assert reachability only where the fixture requires it.

- Observation: rich edges with distinct provenance can represent one control-topology tuple, including at call continuations.
  Evidence: post-milestone review found that counting every rich edge made a provenance-parallel continuation appear to own several topological arms. `ControlEdgeIndex` now deduplicates `(source, target, kind)` for topology counts while the immutable edge table and adjacency rows preserve every exact rich edge.

- Observation: deterministic hydration requires validating incoming-row order, not only edge membership and symmetry.
  Evidence: `ControlFlowGraph::try_from_parts` now rejects incoming rows that are not strictly increasing by canonical `ControlEdgeId`; a reversed two-predecessor corruption fixture proves that persisted parts cannot change traversal or rendering order.

- Observation: this macOS host needs PyO3 dynamic symbol lookup, and several full-suite tests need host process, GPG, filesystem, and sidecar access.
  Evidence: the first isolated feature-suite attempt failed at unresolved `_Py*` symbols, and the sandboxed corrected attempt passed compilation but failed six permission-dependent tests. The pinned Rust 1.96 invocation with `RUSTFLAGS='-C link-arg=-undefined -C link-arg=dynamic_lookup'`, semantic indexing disabled, and the final host-access rerun passed the complete suite.

- Observation: a source-hash-only overlay key is insufficient even when adjacent overlay revisions contain identical bytes.
  Evidence: the production provider now obtains bounded disk or overlay source, monotonic overlay revision, origin, dialect, tree, and line starts as one exact snapshot. Tests prove that adjacent overlay generations do not reuse stale artifacts and that TS and TSX remain distinct.

- Observation: preserving syntactically present dead code requires a graph-level isolation rule in addition to syntax-specific abrupt-completion recognition.
  Evidence: exhaustive switches and compound dead tails exposed how a future construct could leave an unreachable region connected to a real exit. The iterative reachability seal keeps dead-to-dead topology but removes every edge from an entry-unreachable source to an entry-reachable point or either real exit.

- Observation: the current complete-artifact cache still prepares and parses syntax before it can discover a cache hit.
  Evidence: post-milestone review found no correctness issue, but identified this as a measurement target for #817; moving lookup earlier requires retaining exact snapshot identity without reintroducing a source race.

- Observation: Java switch-expression `yield` cannot share the procedure-return completion channel, especially when the yield crosses `finally`.
  Evidence: a distinct shared `Yield` completion now targets the nearest switch-expression merge, cleanup specialization keeps it separate from return/throw/break/continue, and the differential fixture proves the yield never becomes a predecessor of procedure exit.

- Observation: Java executable field, interface-constant, and enum-constant initializers are callable semantic fragments even though their scheduling relative to constructors and class initialization is not yet exact.
  Evidence: the Java adapter emits source-backed `Initializer` procedures and exact expression/call topology while attaching point-scoped `DeferredExecution` gaps for the unmodeled scheduling and source-order composition.

- Observation: outgoing-only rows save meaningful retained memory but make the contractual reverse traversal prohibitively expensive without another retained index.
  Evidence: on the Apple M4 release benchmark, outgoing-only storage saved about 22.1% for the 100k branch graph, 23.3% for the 100k call graph, and 29.5-29.8% for the TypeScript/Java corpora. Reverse traversal rose from about 1.08/0.84 ms to 8.50/6.51 seconds on the synthetic graphs and from 0.0073/0.0036 ms to 0.0525/0.0217 ms on the real corpora. Flat storage made both directions linear scans with the same multi-second synthetic cost.

- Observation: exact dispatch must key the whole semantic call expression, not merely the callee token or enclosing statement.
  Evidence: a nested `outer(inner())` fixture resolves two distinct call-site spans through structured tree-sitter ancestry, while the location-first facade still reuses the existing language resolver and preserves its proof and completeness outcomes.

- Observation: an external dispatch boundary can be authoritative without naming a declaration in a mounted source file.
  Evidence: package or runtime resolution can prove that control crosses the workspace boundary even when no `SemanticLocator` exists. Fabricating a file-wide locator would erase that distinction, so external boundaries carry an optional locator and always retain their proof origin.

- Observation: bounded snapshot publication must reserve a target node and its entering edge atomically.
  Evidence: specialist review found that publishing the node before charging edge capacity could leave an orphan node queued for expansion. `SnapshotBuilder::link` now stages the work budget, node capacity, edge capacity, and canonical edge before publishing either graph component; a one-edge regression fixture proves the partial snapshot remains closed under adjacency.

## Decision Log

- Decision: use semantic program points as canonical CFG nodes and derive basic blocks as maximal straight-line groups.
  Rationale: semantic effects, calls, source anchors, and ICFG attachment sites already live at program points. Making blocks canonical would either lose expression-level control or require another identity translation at every consumer.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: add a procedure-local `ControlEdgeId`, one canonical sorted edge table, outgoing row offsets, and incoming rows of edge IDs.
  Rationale: the shape supports constant-time predecessor and successor access without duplicating rich edge payloads, preserves parallel typed edges, and leaves callers independent of whether future measurements choose eager or lazy reverse rows.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: provide both predecessor and successor APIs as part of the semantic graph contract.
  Rationale: tests and later solvers need both directions. Storage experiments may change the physical layout but must not leak into consumers.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: adjacency traversal fails explicitly for a program-point ID outside its procedure, while a valid disconnected point returns an empty row.
  Rationale: silently treating an invalid scoped ID as disconnected can hide cross-procedure or stale-handle bugs. Membership assertions execute before row arithmetic, including for the maximum dense ID, and defensive hydration separately validates canonical row bounds and order.
  Date/Author: 2026-07-17 / Codex after specialist review.

- Decision: keep construction private, iterative, and continuation-driven.
  Rationale: language adapters need shared graph mechanics without a universal syntax mini-language. Explicit work and continuation stacks are stack safe and can correctly route return, throw, break, continue, handlers, and cleanup.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: retain unreachable syntax as disconnected semantic points rather than fabricating reachability or rejecting the artifact.
  Rationale: dead source is still relevant to diagnostics and later analyses. Reachability is a derived graph question, not an IR validity rule.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: lower from the exact `prepared_syntax` snapshot and make provider materialization file- and dialect-aware.
  Rationale: this prevents overlay races, preserves TS versus TSX identity, and keeps the provider cache keyed by the source snapshot actually lowered.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: discover source through a bounded atomic snapshot operation before parsing, and include source origin plus overlay revision in materialization identity.
  Rationale: budget rejection must happen before retaining or parsing an oversized file, while two overlays with the same bytes can still be distinct editor generations. The key and artifact must describe exactly the syntax that was lowered.
  Date/Author: 2026-07-17 / Codex after Milestone 1b implementation and review.

- Decision: cache only complete immutable artifacts in a conservative byte-weighted per-analyzer cache with cancellation-aware per-key single flight.
  Rationale: entry-count limits do not bound retained graph memory, partial or cancelled artifacts cannot satisfy later complete requests, and concurrent equal requests should lower once. Oversized artifacts are handed to current waiters without entering the cache, and content-valid entries survive analyzer updates.
  Date/Author: 2026-07-17 / Codex after Milestone 1b implementation and review.

- Decision: treat TypeScript call targets as unknown until the location-first dispatch slice lands.
  Rationale: syntax lowering can model evaluation, call events, and both continuations exactly, but claiming a name-only callee would duplicate or preempt the authoritative resolver. The ICFG milestone owns resolved, ambiguous, unresolved, external, truncated, cancelled, and exhausted dispatch outcomes.
  Date/Author: 2026-07-17 / Codex after Milestone 1c implementation.

- Decision: seal unreachable regions generically before CFG freeze while preserving their internal topology.
  Rationale: every adapter must retain dead source points, but no entry-unreachable point may reach live control or either actual procedure exit. A shared iterative graph rule enforces that acceptance invariant even when a language adapter encounters a newly abrupt construct.
  Date/Author: 2026-07-17 / Codex after Milestone 1c post-review.

- Decision: represent Java switch-expression `yield` as its own shared abrupt-completion kind and bind it to a switch-local yieldable continuation.
  Rationale: reusing procedure return would target the wrong exit, while reusing break would conflate two language constructs and their cleanup specialization. The neutral builder now routes yield through intervening cleanup to the nearest switch merge and keeps it unavailable to adapters that do not emit it.
  Date/Author: 2026-07-17 / Codex after TypeScript/Java differential lowering.

- Decision: retain the bidirectional edge-ID representation after the Milestone 2 measurement rather than switching to flat or outgoing-only storage.
  Rationale: outgoing-only rows met the memory-reduction signal but failed the contractual reverse-traversal gate by orders of magnitude on synthetic graphs and by 5-7x on the real TypeScript/Java corpora. Adding a lazy or rebuilt reverse index would either move the same memory back into retained state or make first reverse use unpredictable. Flat rows fail both traversal directions. The public traversal APIs remain unchanged.
  Date/Author: 2026-07-17 / Codex after the release representation matrix.

- Decision: use one neutral ICFG provider fed by language CFG and dispatch adapters.
  Rationale: call, normal-return, exceptional-return, recursion, multiple targets, and unresolved boundaries have the same graph semantics across languages. Language differences belong in syntax lowering and dispatch evidence rather than eleven ICFG implementations.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: freeze the shared adapter contract only after the TypeScript/Java ICFG vertical slice passes review.
  Rationale: TypeScript and Java intraprocedural lowering can stabilize the CFG builder in milestone 2, but location-first dispatch, call-edge suppression, context-bearing snapshots, and matched returns must also pressure-test the boundary before the remaining language adapters depend on it.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: freeze the reviewed adapter boundary as structured syntax-to-common-builder lowering plus one exact-location `DispatchOracle` and one language-neutral `IcfgProvider`.
  Rationale: the TypeScript/Java slice proved that language code owns callable discovery and structured control mapping, the established resolver owns candidate selection and proof, and the shared provider owns contexts, limits, adjacency, and matched returns. Remaining adapters can add language-specific gaps without implementing new graph or resolver mechanics.
  Date/Author: 2026-07-17 / Codex after Milestone 3 review.

- Decision: resolve semantic calls through a location-first facade over `CallRelationService`.
  Rationale: the existing resolver is the authoritative shared implementation. Refactoring its input/output boundary avoids duplicated call resolution while retaining unresolved, ambiguous, external, truncated, cancelled, and exhausted outcomes required by the ICFG.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: represent an external dispatch boundary as `External(Option<SemanticLocator>)` and never synthesize a locator when the resolver has no mounted declaration.
  Rationale: externality and source locatability are independent facts. The optional locator preserves an exact target when one exists while keeping unnamed package/runtime boundaries honest and distinguishable in bounded rendering.
  Date/Author: 2026-07-17 / Codex after Milestone 3 implementation.

- Decision: validate the root and every materialized target against one bounded exact source snapshot before traversing or correlating indexed ranges.
  Rationale: a call-free stale root otherwise appears valid, and an indexed target range from one generation can accidentally select a procedure from another. Source origin, revision, content identity, and dialect must agree before a graph handle participates in an ICFG slice.
  Date/Author: 2026-07-17 / Codex after Milestone 3 specialist review.

- Decision: keep actual-to-formal, receiver, return-value, and heap bindings outside ICFG control topology.
  Rationale: these are value-flow metadata for solver transfer functions. Making them graph edges would couple the ICFG to one client fact representation and blur issue #816's full oracle scope.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: filter a call site's required intraprocedural call-to-continuation CFG scaffolding from the expanded ICFG and add a call-to-continuation edge only for an explicit external or summary model.
  Rationale: #814 requires the local CFG to record typed normal and exceptional continuations, but retaining those edges beside call-to-entry and callee-return edges would create an unintended bypass around every expanded callee. An unresolved or unmodeled call instead terminates at a typed incomplete boundary; it is never silently treated as an exact no-op.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: make bounded ICFG snapshot nodes context-bearing by interning a program-point handle together with its exact bounded stack of originating call-site handles.
  Rationale: a plain shared callee exit with several return edges permits graph traversal to cross-return. Pushing the originating call on entry and popping that same call on return makes ordinary predecessor/successor traversal context-respecting. The call-depth and node budgets keep recursion finite; a limit produces a typed truncated boundary rather than merging contexts.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: require the common control and direct-call core in every analyzable language while representing advanced omissions through exact capabilities and gaps.
  Rationale: “adapter exists” must never mean an empty or silently approximate graph. The core makes the shared ICFG useful everywhere; typed gaps keep exception, cleanup, async, generator, spawn, destructor, and non-local-control limitations honest.
  Date/Author: 2026-07-17 / Codex and user.

- Decision: start with immutable demand-built in-memory artifacts and generation-local ICFG memoization; decide persistence only from #817 measurements.
  Rationale: CSR/CSC is a hot traversal layout while SQLite is a lifecycle mechanism. They are complementary. A measured no-go is acceptable, and a whole-workspace ICFG is never persisted or traversed through SQL.
  Date/Author: 2026-07-17 / Codex and user.

## Outcomes & Retrospective

Milestone 1a is complete. The #814 flat edge list is now frozen into one canonical rich-edge table with procedure-local `ControlEdgeId`s, source-sliced outgoing rows, incoming edge-ID rows, exact allocation-free predecessor/successor traversal, scoped edge handles, corruption checks, and atomic retained-work accounting. Rich parallel edges remain distinct even when they share topology, invalid point IDs fail explicitly, and incoming rows cannot hydrate in a noncanonical order. Schema version 2 introduced the edge-ID substrate and literal predecessor/successor rendering; schema version 3 appends the later capability vocabulary without changing those adjacency APIs.

The new `semantic_cfg_contract` multiline inline-project fixture proves exact successors and predecessors, adjacency symmetry, branches, cycles, disconnected points, parallel kinds and provenance, deterministic IDs under permuted construction, and source-backed rendering without asserting raw construction IDs as semantic identities. Post-milestone reviews found and verified fixes for topology over-counting, maximum-ID traversal, incoming-row ordering, and self-referential renderer assertions.

Milestones 1b and 1c are complete. `ProgramSemanticsProvider::materialize(file, request)` now routes through `AnalyzerDelegate` and `WorkspaceAnalyzer`, consumes one bounded disk-or-overlay syntax snapshot, preserves TS versus TSX dialect identity, and returns explicit complete, partial, cancelled, budget-exhausted, unsupported, or failed outcomes. Its byte-weighted complete-only cache deduplicates concurrent lowering, respects cancellation, hands oversized artifacts to current waiters without retaining them, and reuses content-valid entries across analyzer updates. Prospective builder accounting and one atomic publication charge keep budget failure and cancellation from publishing misleading complete work.

TypeScript and TSX now enumerate real functions, methods, constructors, lambdas, expression bodies, and static initializers, then lower sequencing, branches, switch flow, loops, labeled and abrupt completion, nested-call evaluation, optional and short-circuit control, throw/catch/finally, and supported async topology through the private iterative engine. Advanced or inexact behavior such as resource management, generators, implicit exceptions, deferred execution, and unknown control is represented by capability- and point-scoped gaps. A shared iterative seal preserves dead-region topology while preventing disconnected source from reaching either real exit. The inline semantic-graph harness resolves readable source-backed aliases and asserts exact predecessor/successor edges, symmetry, reachability, and deterministic bounded topology without exposing raw dense identities.

Post-milestone specialist review found no remaining blocker. All focused suites, strict clippy, formatting, diff checks, and the full `nlp,python` repository gate pass. The nonblocking follow-ups are to introduce a dedicated `ProcedureSelector` if later cross-language fixtures need more disambiguation than the current procedure qualifiers provide, and to measure whether exact cache identity can be obtained before syntax preparation. Milestone 2 now adds Java and uses the TypeScript/Java differential suite plus physical-layout measurements to stabilize the callable-CFG contract.

Milestone 2 is complete. Java now emits real callable-local CFGs for methods, constructors, lambdas, executable initializer fragments, branches, loops, switch statements and expressions, calls, abrupt completion, explicit throw, catch dispatch, and cleanup relays. Try-with-resources, synchronized monitor behavior, implicit exceptions, assertion enablement, initializer scheduling, and other incomplete semantics remain exact capability- and point-scoped gaps. The shared builder gained a cleanup-safe switch-yield channel, and TypeScript cleanup relays now preserve the originating completion edge kind.

The checked-in measurement harness compares flat edges, outgoing-only CSR, and canonical bidirectional edge-ID rows per procedure, validates rich-edge equivalence, and records machine/source provenance. The full release matrix rejected both alternatives: outgoing-only memory savings were real, but reverse traversal violated the acceptance gate by several orders of magnitude at scale; flat rows made both directions unacceptable. The bidirectional representation is therefore the reviewed CFG substrate entering Milestone 3.

Milestone 3 is complete. `CallRelationService` now accepts an exact semantic call location and preserves resolved, multi-target, unresolved, external, truncated, cancelled, and budget-exhausted outcomes without changing existing query or LSP call paths. `WorkspaceIcfgProvider` lazily materializes only the requested files and call contexts, suppresses local invoke scaffolding, pushes the exact originating call site on entry, and pops only that site for normal or exceptional return. Its bounded dense snapshots expose symmetric predecessor/successor rows and typed incomplete boundaries; they never treat an unknown external call as a no-op. The shared inline harness names source-backed points and call contexts rather than dense IDs, and its contract covers direct and cross-file calls, overloads, two sites to one callee, methods, recursion, exceptional returns, unresolved/external boundaries, cancellation, budgets, stale handles, and atomic limit publication. Specialist review corrected source-generation validation, complete work accounting, exact unmaterialized target locators, atomic node/edge limits, and boundary rendering before the contract froze for the remaining languages.

## Context and Orientation

The semantic subsystem lives under `src/analyzer/semantic/`. `ids.rs` defines durable mounted-source identities plus dense artifact- and procedure-local IDs. `capabilities.rs` states whether a semantic feature is complete, partial, or unsupported. `provider.rs` defines budgets, outcomes, cancellation, and the atomic file-aware `ProgramSemanticsProvider`; `service.rs` owns one-snapshot publication and complete-artifact caching, while `cfg.rs` owns private iterative graph construction. Routed analyzers without a real adapter return an explicit unsupported outcome, and TypeScript is the first production lowerer. `ir.rs` owns the immutable semantic artifact, procedure rows, program points, effects, calls, control edges, gaps, evidence, validation, and bounded rendering. `mod.rs` re-exports the supported surface.

`src/compact_graph.rs` contains checked compact row storage and a payloadless directed graph. Reuse or generalize its row primitives, but do not force rich CFG edges into the payloadless source-target abstraction.

`src/analyzer/tree_sitter_analyzer.rs` owns `TreeSitterAnalyzer`. Its `prepared_syntax(ProjectFile)` method returns an `Arc`-backed source snapshot, parsed tree, and line starts that agree with each other. Production semantic adapters must lower this snapshot rather than re-read source or parse text independently.

Language implementations live below `src/analyzer/` in modules such as `typescript`, `js_ts`, `java`, `python`, and their peers. `AnalyzerDelegate` and `WorkspaceAnalyzer` route files to concrete analyzers. Add semantic provider access through this delegation layer, keeping execution semantics out of `StructuralSpec`, `LanguageAdapter`, and the broad `IAnalyzer` trait unless the implementation proves a smaller non-monolithic route impossible.

`src/analyzer/usages/call_relations.rs` owns shared call relation construction. It is the starting point for the dispatch slice. Do not implement a new name resolver or use regex, splitting, delimiter scanning, or other source-text mini-parsers. Production lowering and call resolution must inspect tree-sitter node kinds and named fields or existing structured analyzer facts.

Tests that define small projects use `tests/common/inline_project.rs`. The new semantic graph harness composes over that fixture, so source files remain readable multiline strings and temporary project-root handling remains platform safe.

The eleven promised analyzable languages are Java, Go, C/C++, JavaScript, TypeScript, Python, Rust, PHP, Scala, C#, and Ruby. TypeScript also needs TSX coverage; JavaScript includes JSX; representative C and C++ extensions both exercise the `Cpp` adapter.

Compressed sparse row (CSR) means one contiguous value array plus offsets that delimit every outgoing row. Compressed sparse column (CSC) is the same organization for incoming rows. This plan's initial CFG layout uses source-sorted canonical edges as the outgoing CSR payload and incoming rows of edge IDs as the CSC view.

Dispatch means resolving one exact call expression to zero or more possible callable targets with proof and completeness. A generation is one immutable workspace-analyzer snapshot; generation-local memoization is discarded when that snapshot changes. A packed data-transfer object (packed DTO) is a versioned serialization record containing dense primitive arrays rather than Rust runtime objects. SQLite may store a packed DTO, but hot traversal always hydrates it into the in-memory CFG layout. An overlay is unsaved editor text retained by the analyzer; overlays are request-generation-local and remain memory-only even if disk-backed semantic artifacts later earn persistence.

## Plan of Work

### Milestone 1a: freeze indexed CFG topology

Add `ControlEdgeId` to `src/analyzer/semantic/ids.rs` with the same dense checked conversion and display behavior as other procedure-local IDs. The ID is the implicit index of an edge after freeze; do not add a redundant mutable `id` field to `ControlEdge`. In `src/analyzer/semantic/ir.rs`, introduce a `ControlFlowGraph` owned by each frozen `ProcedureSemantics`. It contains the canonical control-edge payload table, outgoing row bounds, and incoming rows of `ControlEdgeId`. Canonicalization sorts edges by source point, edge kind and payload, target point, provenance, and stable tie-breakers; exact duplicate rich edges remain invalid while parallel edges with different kinds or evidence remain valid.

Expose `ProcedureSemantics::cfg`, `control_edge`, `successor_edges`, and `predecessor_edges`, plus `ControlEdgeHandle` at scoped provider boundaries. Keep `ProcedureSemanticsParts::control_edges` and `ProcedureSemantics::control_edges()` as construction and compatibility views. Iterators return `(ControlEdgeId, &ControlEdge)` values without cloning. Validate that every row references an in-range edge, every outgoing row edge has the row's source, every incoming row edge has the row's target, every edge appears once in each direction, point IDs are dense, and opposite views are symmetric. Account for both adjacency offset arrays and incoming edge-ID rows in semantic retained-work budgets. Extend the bounded renderer with edge IDs and adjacency while retaining transactional byte-budget behavior. Because canonical edge IDs and ordering become observable, increment `SEMANTIC_IR_SCHEMA_VERSION` and update its digest/version test.

Add focused unit and integration tests before changing adapters. Cover straight lines, cycles, parallel typed edges, empty predecessor/successor rows, corrupted row rejection, deterministic freeze, bounded rendering, and disconnected points. Run `cargo test --test semantic_ir_contract` plus the new `semantic_cfg_contract` cases and expect all existing tests to remain green.

### Milestone 1b: add request-safe construction and provider routing

Create `src/analyzer/semantic/cfg.rs` for the private mutable `ProcedureCfgBuilder`, derived-block construction, and freeze path. The builder allocates dense points and edges, records source mappings/evidence/gaps, and uses explicit work stacks rather than recursive AST walking. Its continuation state has destinations for normal flow, return, throw, labeled break and continue, active handler, and cleanup. Cleanup regions are specialized and memoized by abrupt destination so one shared `finally` body cannot resume as the wrong completion kind.

Builder expansion maintains a prospective `SemanticWork` counter and compares it with `request.budget.remaining()` for early cutoff without mutating the caller's budget. Publication then calls `SemanticArtifact::try_new_with_budget` exactly once, which atomically charges the actual retained artifact after validation. A smaller incomplete artifact that deliberately stops, inserts exact gaps, validates, and fits may be returned and charged once, but is never cached as complete. Cancelled construction is discarded without publication or retained-payload charge. A partial value attached to a cancelled outcome is permitted only if it was already independently validated and charged; the initial provider returns no cancelled partial artifact. This rule prevents prospective builder checks and freeze charging from double counting.

Revise `src/analyzer/semantic/provider.rs` around a file-aware `materialize(file, request)` operation. `SemanticRequest` borrows the existing `crate::cancellation::CancellationToken` and a mutable `SemanticBudget`. Add `SemanticOutcome::Cancelled { partial: Option<T>, work: SemanticWork }`; `work` reports observed work, while only a validated published partial consumes retained budget. The materialization operation derives the artifact key and artifact from the same prepared source snapshot and returns `Arc<SemanticArtifact>`. Cancelled or partial materializations never populate a complete cache. `ProgramSemanticsProvider` remains `Send + Sync`.

Add a production semantic service/provider route through `AnalyzerDelegate` and `WorkspaceAnalyzer`. It selects the concrete language adapter from the requested file and preserves `LanguageDialect`, including TSX. Keep workspace call-resolution generation outside per-file artifact identity and include the language semantic-adapter version plus intrafile extraction configuration inside it.

Tests exercise disk source, overlay source, a revision change during adjacent requests, TS versus TSX identity, cancellation, total payload budget exhaustion, repeat complete-cache reuse, and non-caching of partial results.

### Milestone 1c: lower TypeScript and TSX

Implement the JavaScript/TypeScript family lowering core beside the existing analyzer, with a TypeScript provider entry point. The adapter uses tree-sitter node kinds and named fields to enumerate top-level and nested callable bodies. Every nested function, method, lambda, and arrow body becomes its own procedure and is skipped while lowering its lexical parent.

Cover entry, normal and exceptional exits, statement sequencing, expression-bodied functions, branches, switch and fallthrough, while/do/for/for-in/for-of loops, break, continue, return, explicit throw, nested call evaluation, logical short-circuiting, optional calls/chains, try/catch/finally, and async await topology already supported by the semantic IR. Preserve source-backed unreachable statements as disconnected points. Generator yield, class static blocks, explicit resource management, or other encountered constructs not yet exact must record an exact capability and point-scoped gap; do not invent fallthrough when control itself is unknown.

Create `tests/common/semantic_graph.rs` over `InlineTestProject`. A `ProcedureSelector` identifies a procedure by file, stable source locator, name/kind, and optional occurrence. A `PointSelector` uses a unique source substring solely in tests, plus optional procedure, effect, outgoing-edge kind, and occurrence qualifiers. Source substring scanning never enters production code. Ambiguity errors list candidate spans and bounded rendered context.

Provide `assert_successors`, `assert_predecessors`, `assert_adjacency_symmetric`, `assert_reachable`, `assert_unreachable`, and deterministic rendering checks. Tests never compare raw dense IDs. Add `.ts` and `.tsx` multiline fixtures for straight-line flow, branches and merges, loops and abrupt exits, dead statements, nested callable separation, nested calls, explicit throw/handler/finally, unsupported generators/resources, deep iterative lowering, and budget/cancellation behavior.

### Milestone 2: lower Java and stabilize the CFG contract

Add Java lowering beside the existing Java analyzer. Cover methods, constructors, compact constructors where supported by the grammar, lambdas, initializers, branches, switch statements and expressions, loops, early return, calls, explicit throw, and try/catch/finally. A Java switch-expression `yield` targets the switch merge and never the procedure exit. Try-with-resources, synchronized cleanup, implicit exceptions, or other inexact constructs report partial capabilities and point-scoped gaps.

Run one scenario specification against labeled TypeScript and Java programs and compare semantic topology by aliases and edge kinds rather than dense IDs or source offsets. Extract shared builder combinators only after both adapters need the same semantic operation: sequence, branch, multiway branch, loop, invocation, abrupt completion, handler, cleanup, and suspension. Language code owns AST interpretation and evaluation order; the common builder owns graph mechanics. This milestone stabilizes the per-callable CFG layer but does not freeze the shared language-adapter contract; milestone 3 must still pressure-test dispatch and matched returns.

Extend the capability vocabulary where needed so generator suspension, deferred execution, concurrent spawn, and non-local control are not mislabeled as async flow or immediate invocation. Add grammar-contract tests for every tree-sitter node kind and named field on which the two adapters depend.

Benchmark flat edge scans, outgoing-only CSR plus rebuilt/lazy reverse traversal, and bidirectional edge-ID rows using representative small, medium, branch-heavy, and call-heavy fixtures. Measure construction, freeze, forward traversal, reverse traversal, and retained bytes. Keep both public directions regardless of physical layout. Record any representation change in this Decision Log; the initial default is bidirectional rows because both directions are contractual.

### Milestone 3: build the TypeScript/Java ICFG vertical slice and freeze the shared contract

Refactor `src/analyzer/usages/call_relations.rs` so its existing structured resolver exposes a location-first operation accepting an exact file and semantic call span. Preserve resolved, ambiguous, unresolved, external, truncated, cancelled, and budget-exhausted outcomes. Existing query, LSP, and call-relation consumers reuse the facade.

Create `src/analyzer/semantic/icfg.rs`. Define scoped ICFG node handles, `IcfgEdgeKind`, `CallTransfer`, `ReturnTransfer`, `DispatchOracle`, `IcfgProvider`, and `IcfgSnapshot`. A `CallTransfer` retains the originating semantic call-site handle, candidate callee procedure, proof/completeness, callee entry, caller normal continuation, and caller exceptional continuation. `ReturnTransfer` is derived from one concrete `CallTransfer`, preventing cross-return when two sites call the same callee.

The provider materializes transfers and bounded slices on demand. Generation-local memoization keys include caller semantic artifact identity, semantic call-site identity, dispatch configuration/version, and workspace generation. `IcfgSnapshot` interns only the requested root/depth/node/edge-bounded slice into dense snapshot-local nodes and builds symmetric predecessor/successor rows for tests and rendering. Each interned node is an `IcfgNodeKey` containing a program-point handle and the exact bounded stack of originating call-site handles. Call expansion pushes the current call site; return expansion is legal only when it pops that same site. Recursion remains finite because reaching the call-depth, node, edge, or budget limit emits a typed truncated boundary and does not merge distinct call stacks. Never materialize or cache an eager whole-workspace ICFG.

ICFG edge kinds distinguish intraprocedural control, call-to-entry, normal exit-to-the-originating-normal-continuation, exceptional exit-to-the-originating-exceptional-continuation, and explicit summary/external call-to-continuation behavior. When a program point contains `SemanticEffect::Invoke`, the local normal and exceptional edges required by the per-callable CFG are continuation metadata, not automatically traversable ICFG edges. The snapshot suppresses those local edges whenever it considers the call. Resolved candidates receive call-to-entry and matched return edges; an explicit external or procedure-summary model may supply a typed call-to-continuation edge; an unresolved, exhausted, cancelled, or otherwise unmodeled candidate emits an incomplete boundary with no fabricated continuation. Mixed dispatch preserves each candidate outcome separately.

Expose `IcfgSnapshot::successor_edges` and `IcfgSnapshot::predecessor_edges` over snapshot-local edge IDs, plus accessors from a dense snapshot node to its `IcfgNodeKey`. The test fixture reuses ordinary point selectors and adds an optional call-context selector expressed as a sequence of previously bound call-site aliases. `assert_successors`, `assert_predecessors`, adjacency symmetry, reachability, and unreachable assertions work unchanged for ICFG nodes; ambiguity diagnostics print the point span and rendered call context. Tests must include two distinct calls to one callee and prove that each context-bearing callee exit has exactly one matching return successor and predecessor chain.

Add `tests/icfg_contract.rs` using the shared semantic graph assertions. Cover direct calls, methods, overloads and multiple candidate targets, two sites calling one callee, cross-file calls, recursion, bounded mutual recursion, unresolved/external boundaries, normal returns, exceptional returns, slice depth/size limits, deterministic rendering, cancellation, and adjacency symmetry.

After focused tests and specialist review pass, freeze the common boundary used by later adapters: structured AST lowering operations, provider materialization, dispatch outcomes, call transfers, call-edge suppression, context-bearing snapshot nodes, matched returns, capabilities, and scoped gaps. Any later incompatible change requires a Decision Log entry and rerunning TypeScript, TSX, Java, and all already landed languages.

### Milestones 4a through 4i: roll out all remaining analyzable languages

After the milestone 3 TypeScript/Java CFG/dispatch/ICFG contract passes review, create one #815 child issue per remaining language and cross-link #816/#818 work where dispatch changes are needed. The current instruction to implement this plan authorizes those child issues at that milestone; search the live issue tree first to avoid duplicates and record every created issue in `Progress`. Branch changes, pushes, and pull-request publication remain separately authorized actions.

Roll out in this order: 4a JavaScript, 4b C#, 4c Python, 4d Go, 4e Rust, 4f PHP, 4g Scala, 4h Ruby, and 4i C/C++. JavaScript reuses the JS/TS lowering family. C/C++ lands last because one adapter must handle C and C++ plus RAII, exceptions, goto, coroutines, and preprocessing/configuration pressure. Each numbered language milestone has its own focused tests, capability-matrix update, specialist review, and multiline checkpoint commit; a failure or design discovery in one language does not get hidden inside a nine-language diff.

Every adapter implements the common suite: procedure boundaries; straight-line sequencing; branch and merge; loop header/body/exit, back edge, break and continue; early return and a disconnected dead statement; expression-level call evaluation and normal continuation; nested callable separation; one same-file and one resolved cross-file direct helper call through the common ICFG; deterministic source-backed topology; symmetric adjacency; deep iterative lowering; and an encountered unsupported construct that produces a scoped gap without a fabricated edge.

Language-specific fixtures exercise and report support or gaps for C# using/lock/async/yield/goto, Python loop-else/match/try/with/generators, Go defer/go/panic/recover, Rust expression flow/question-mark/Drop/async/yield/macros, PHP match/goto/numeric break/generators, Scala expression-valued control/finally/non-local return, Ruby implicit return/rescue/ensure/non-local block control, and C++ RAII/destructors/exceptions/goto/coroutines/preprocessor configuration. Add `.js` and `.jsx`, `.ts` and `.tsx`, and representative `.c` and `.cpp` dialect cases.

Create `tests/semantic_language_conformance.rs`. It iterates behavior across every `Language::ANALYZABLE` value by materializing a real artifact and traversing a real direct-call ICFG scenario, rather than merely asserting registry membership or order. Update the capability matrix after every language and rerun all previously landed adapters before completing its checkpoint.

### Milestone 5: measure the CFG/ICFG lifecycle slice of #817

Keep mutable builders ephemeral, per-file semantic artifacts and callable CFGs immutable in memory, ICFG transfers generation-local, and bounded snapshots/query state ephemeral. Benchmark parse/lower time, validation, freeze, forward/reverse traversal, retained bytes, repeated materialization, packed serialization, cold hydration, warm in-process reuse, and warm cross-process hydration on representative repositories and generated control shapes.

Predeclare the measurement matrix before collecting candidate results. `tests/measure_semantic_cfg.rs` generates branch-heavy and call-heavy graphs at 10,000 and 100,000 program points and reads the checked-in `tests/fixtures/testcode-ts` and `tests/fixtures/testcode-java` corpora. `scripts/run-semantic-cfg-benchmarks.sh` also accepts pinned external worktrees through `BIFROST_SEMANTIC_TS_REPO` and `BIFROST_SEMANTIC_JAVA_REPO`: VS Code tag `1.100.0` at commit `19e0f9e681ecb8e5c09d8784acaa601316ca4571`, and Spring Petclinic commit `f182358d02e4a68e52bdbabf55ca7800288511e7`. For each representation or storage mode, run nine fresh release processes, discard the first two, and report all seven retained samples plus their median. Alternate mode order to reduce thermal/load bias.

Keep bidirectional edge-ID rows unless outgoing-only storage reduces estimated retained CFG bytes by at least 20 percent on both generated 100,000-point shapes and both real corpora, while its median full reverse traversal is no more than 10 percent slower and at most 10 milliseconds slower on each corpus; otherwise predecessor-heavy consumers justify the eager reverse rows. A flat-edge representation is evidence only and is never promoted if either full traversal direction becomes linear per node.

Promote disk-source per-file semantic/CFG artifacts to versioned SQLite packed DTOs only if all of these predeclared conditions hold: median warm cross-process hydration is at least 30 percent and 50 milliseconds faster than rebuilding on both pinned external corpora; peak RSS is no more than 10 percent higher; packed database bytes are no more than twice the estimated hydrated artifact bytes; cold build plus write is no more than 25 percent and 250 milliseconds slower; and every source, dialect, adapter version, configuration, corruption, generation, dependency, cleanup, and Windows-path invalidation test passes. Overlay artifacts are always memory-only and never written to SQLite. Hydration must reconstruct the same in-memory adjacency. Do not perform graph traversal through SQL and do not persist a whole-workspace ICFG. If any required condition fails, record a no-go for this slice of #817.

Record the datasets, machine/runtime context, raw elapsed times, retained sizes, decision threshold, and recommendation in this plan. A measured no-go is a successful outcome when persistence does not justify its cost. This milestone closes only the CFG/ICFG evidence requested by #817; value-flow artifacts, solver tables, language-semantic summaries, taint summaries, and protocol summaries remain later #817 decisions and the broader lifecycle issue stays open until those consumers exist.

Each milestone ends with focused validation, a multiline checkpoint commit containing only milestone files, and a post-milestone specialist review. Address blocking findings before recording the checkpoint as complete. Stay on the current branch; branching, rebasing, pushing, and PR publication require separate explicit authorization except where resolving an already-authorized milestone conflict is unavoidable. The current instruction authorizes the per-language child issues named in milestone 4 after its milestone 3 gate.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/42fd/bifrost` on the existing issue branch.

Before each milestone, confirm scope with:

    git status --short --branch
    git diff --check

For milestone 1a, inspect and edit:

    src/analyzer/semantic/ids.rs
    src/analyzer/semantic/ir.rs
    src/analyzer/semantic/mod.rs
    src/compact_graph.rs, only if checked row primitives need a reusable extension
    tests/semantic_ir_contract.rs
    tests/semantic_cfg_contract.rs

Run:

    cargo test --test semantic_ir_contract --test semantic_cfg_contract

For milestone 1b, create `src/analyzer/semantic/cfg.rs` and `src/analyzer/semantic/service.rs`; revise `src/analyzer/semantic/provider.rs`, `src/analyzer/semantic/mod.rs`, `src/cancellation.rs`, `src/analyzer/tree_sitter_analyzer.rs`, `src/analyzer/multi_analyzer.rs`, and `src/analyzer/workspace.rs`; and create `tests/semantic_provider_contract.rs`. Expose the existing cancellation token through the semantic provider surface, materialize from one prepared syntax snapshot, and test overlay identity, cancellation, budget charging, and cache publication. Run:

    cargo test --test semantic_ir_contract --test semantic_cfg_contract --test semantic_provider_contract

For milestone 1c, create `src/analyzer/js_ts/semantic.rs` and `tests/common/semantic_graph.rs`; revise `src/analyzer/js_ts/mod.rs` and `src/analyzer/typescript/mod.rs`; and extend `tests/semantic_cfg_contract.rs` with real `.ts` and `.tsx` multiline projects. Run:

    cargo test --test semantic_cfg_contract typescript
    cargo test --test semantic_provider_contract typescript

For milestone 2, create `src/analyzer/java/semantic.rs` and revise `src/analyzer/java/mod.rs`. Add Java and labeled TypeScript/Java differential cases to `tests/semantic_cfg_contract.rs`. Create the representation-neutral `tests/measure_semantic_cfg.rs` and `scripts/run-semantic-cfg-benchmarks.sh`; the test prints exactly one JSON object prefixed by `BIFROST_SEMANTIC_CFG_BENCHMARK=`. Validate with:

    cargo test --test semantic_cfg_contract java
    cargo test --test semantic_cfg_contract typescript_java
    cargo test --release --test measure_semantic_cfg -- --ignored --nocapture

For milestone 3, create `src/analyzer/semantic/icfg.rs`, revise `src/analyzer/semantic/mod.rs` and `src/analyzer/semantic/service.rs`, and refactor `src/analyzer/usages/call_relations.rs` behind its exact-location dispatch operation. Create `tests/icfg_contract.rs` and reuse `tests/common/semantic_graph.rs`. Run:

    cargo test --test semantic_cfg_contract --test semantic_provider_contract --test icfg_contract

For each language milestone 4a through 4i, create the named adapter file and revise its sibling `mod.rs`: `src/analyzer/js_ts/semantic.rs` for JavaScript/JSX reuse, then `src/analyzer/csharp/semantic.rs`, `src/analyzer/python/semantic.rs`, `src/analyzer/go/semantic.rs`, `src/analyzer/rust/semantic.rs`, `src/analyzer/php/semantic.rs`, `src/analyzer/scala/semantic.rs`, `src/analyzer/ruby/semantic.rs`, and `src/analyzer/cpp/semantic.rs`. Add that language's multiline cases to `tests/semantic_language_conformance.rs` and its direct-call cases to `tests/icfg_contract.rs`. At each independent checkpoint run, replacing `<language>` with the lowercase test filter:

    cargo test --test semantic_cfg_contract <language>
    cargo test --test icfg_contract <language>
    cargo test --test semantic_language_conformance <language>
    cargo test --test semantic_language_conformance all_languages

For milestone 5, extend `tests/measure_semantic_cfg.rs`, create `tests/measure_semantic_cfg_persistence.rs`, and extend `scripts/run-semantic-cfg-benchmarks.sh` with `layout` and `persistence` phases. The persistence test prints exactly one JSON object prefixed by `BIFROST_SEMANTIC_CFG_PERSISTENCE_BENCHMARK=`. If and only if the predeclared promotion gate passes, create `src/analyzer/semantic/storage.rs` and integrate its versioned packed DTO with the existing cache database through `src/analyzer/semantic/service.rs`; otherwise leave production storage untouched and record the no-go. The exact benchmark entry points are:

    git clone https://github.com/microsoft/vscode.git /Users/dave/Workspace/test-repos/vscode-semantic-cfg
    git -C /Users/dave/Workspace/test-repos/vscode-semantic-cfg checkout --detach 19e0f9e681ecb8e5c09d8784acaa601316ca4571
    git clone https://github.com/spring-projects/spring-petclinic.git /Users/dave/Workspace/test-repos/spring-petclinic-semantic-cfg
    git -C /Users/dave/Workspace/test-repos/spring-petclinic-semantic-cfg checkout --detach f182358d02e4a68e52bdbabf55ca7800288511e7

    BIFROST_SEMANTIC_CFG_LAYOUT=flat cargo test --release --test measure_semantic_cfg -- --ignored --nocapture
    BIFROST_SEMANTIC_CFG_LAYOUT=outgoing cargo test --release --test measure_semantic_cfg -- --ignored --nocapture
    BIFROST_SEMANTIC_CFG_LAYOUT=bidirectional cargo test --release --test measure_semantic_cfg -- --ignored --nocapture
    BIFROST_SEMANTIC_TS_REPO=/Users/dave/Workspace/test-repos/vscode-semantic-cfg BIFROST_SEMANTIC_JAVA_REPO=/Users/dave/Workspace/test-repos/spring-petclinic-semantic-cfg scripts/run-semantic-cfg-benchmarks.sh layout
    BIFROST_SEMANTIC_TS_REPO=/Users/dave/Workspace/test-repos/vscode-semantic-cfg BIFROST_SEMANTIC_JAVA_REPO=/Users/dave/Workspace/test-repos/spring-petclinic-semantic-cfg scripts/run-semantic-cfg-benchmarks.sh persistence

The runner verifies both repository paths, records `git rev-parse HEAD` for each, alternates candidate order, starts nine fresh release-test processes per mode, discards the first two samples, and writes the seven retained raw samples plus median to standard output. Do not promote from a debug build or a single process.

For milestones 1b through 4i, run the focused contract set after every coherent edit once all named test targets exist:

    cargo test --test semantic_cfg_contract --test icfg_contract --test semantic_language_conformance

Individual tests may not exist until their named milestone creates them. Until then, run every existing subset and record the exact passing count in `Progress` or `Surprises & Discoveries`.

At reviewed milestone checkpoints, run:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python
    git diff --check

The isolated target helper removes its generated build directory on success, failure, or interruption. Do not create manually named Cargo target directories under `/tmp` or `/private/tmp`.

Stage only files changed for the milestone and commit on the current branch with a multiline message that explains the semantic decisions and validation. Never use `git add -A`.

## Validation and Acceptance

Milestone 1a is accepted when the existing semantic contract plus new CFG tests prove canonical dense control-edge IDs, exact parallel edges, deterministic freeze, storage-independent predecessor/successor traversal, symmetric adjacency, disconnected points, and bounded rendering.

The TypeScript and Java reference milestones are accepted when real analyzer materialization from multiline `.ts`, `.tsx`, and `.java` files produces equivalent labeled common-control topology, exact language-specific topology or scoped gaps, and no recursive Rust AST traversal. Overlay, cancellation, budget, source-snapshot, and cache tests must pass.

The ICFG milestone is accepted when a bounded snapshot can traverse from a TypeScript or Java caller into resolved callees and back only to the originating normal or exceptional continuation. Multiple call sites, recursion, ambiguous targets, unresolved/external calls, cancellation, and budgets must remain typed and deterministic.

The all-language milestone is accepted when all eleven `Language::ANALYZABLE` values pass the common CFG and direct-call ICFG suite through one ICFG provider. Every encountered advanced construct is either modeled or matched by an exact capability and point-scoped gap; no adapter silently omits unknown control.

The storage milestone is accepted when #817 records reproducible measurements and either promotes a checked versioned per-file packed artifact or explicitly records why in-memory rebuilding remains preferable. Whole-workspace ICFG persistence and SQL edge traversal are never acceptable outcomes.

The entire plan is complete only after focused tests, formatting, all-target/all-feature clippy, and the complete `nlp,python` suite pass, specialist review has no unresolved blocking findings, all living sections reflect actual state, and `Outcomes & Retrospective` compares delivered behavior with this purpose.

## Idempotence and Recovery

All builders and tests operate on temporary or immutable inputs and are safe to rerun. A failed or cancelled semantic materialization must not publish a complete cache entry. A partially built procedure stays private and is discarded unless it freezes and validates successfully.

If a schema or adjacency change breaks existing semantic artifacts, update the in-memory construction path and tests together; backwards compatibility is not required. If a future SQLite DTO exists, bump its explicit schema/adapter version so old rows become cache misses rather than being interpreted under new semantics. Corrupt persisted rows are deleted or ignored as misses and rebuilt from source.

If a milestone uncovers a semantic contract problem, record the observation and revised decision here before changing direction. Keep additive old/new implementations only while needed to maintain passing tests, then remove the obsolete path in the same milestone. Do not use regex or source splitting to bypass missing AST support.

If the worktree contains unrelated user changes, leave them untouched and stage explicit milestone paths only. Do not reset, checkout, or clean broad paths. If a generated isolated Cargo target remains after interruption, use `scripts/cleanup-bifrost-tmp.sh` in dry-run mode before any apply action.

## Artifacts and Notes

The baseline at plan creation is:

    branch: 815-epic-build-normalized-per-callable-cfgs-and-an-adapter-conformance-harness
    HEAD:   3bd7b75aa1bb53ddd2476ab1b6617e391a4f95e9
    origin/master: same commit
    existing focused semantic test: 10 passed

The initial physical CFG shape is:

    ProcedureSemantics
      -> ControlFlowGraph
           -> canonical ControlEdge payload table indexed by ControlEdgeId
           -> outgoing row bounds into the canonical source-sorted table
           -> incoming CompactRows<ControlEdgeId> referencing that table

The lifecycle is:

    exact prepared source snapshot
      -> private iterative language lowering
      -> validated immutable per-file artifact and per-callable CFGs
      -> demand-resolved call transfers
      -> bounded generation-local ICFG snapshot
      -> later query/solver clients outside this plan

## Interfaces and Dependencies

The intended internal interface after milestone 1 includes these types and equivalent iterator-oriented methods. Exact lifetimes may change to satisfy Rust borrowing, but any replacement must preserve no-clone hot traversal and be recorded in the Decision Log.

    pub struct ControlEdgeId(u32);

    pub struct ControlFlowGraph {
        edges: Box<[ControlEdge]>,
        outgoing_row_offsets: Box<[u32]>,
        incoming: CompactRows<ControlEdgeId>,
    }

    impl ProcedureSemantics {
        pub fn cfg(&self) -> &ControlFlowGraph;
        pub fn successor_edges(
            &self,
            point: ProgramPointId,
        ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)>;
        pub fn predecessor_edges(
            &self,
            point: ProgramPointId,
        ) -> impl ExactSizeIterator<Item = (ControlEdgeId, &ControlEdge)>;
    }

The provider boundary becomes file-aware and request-scoped. Promote the existing `crate::cancellation::CancellationToken` and its `cancel`/`is_cancelled` methods to public visibility and re-export it from `analyzer::semantic`; no second cancellation implementation is introduced.

    pub struct SemanticRequest<'a> {
        pub budget: &'a mut SemanticBudget,
        pub cancellation: &'a CancellationToken,
    }

    pub trait ProgramSemanticsProvider: Send + Sync {
        fn materialize(
            &self,
            file: &ProjectFile,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<Arc<SemanticArtifact>>, SemanticProviderError>;
    }

`SemanticOutcome<T>` gains this operationally incomplete variant and updates `work`, `available_value`, and `map` exhaustively:

    Cancelled {
        partial: Option<T>,
        work: SemanticWork,
    }

The dispatch and ICFG boundary contains these minimum shapes. `SemanticOutcome::Complete` means the resolver has an authoritative result set; `Ambiguous` carries several plausible resolved candidates; `Unknown`, `Unsupported`, `ExceededBudget`, and `Cancelled` retain their existing meanings. Mixed resolved and non-resolved arms live inside one `DispatchResult` so no arm is dropped.

    pub struct DispatchCandidate {
        pub target: ProcedureHandle,
        pub proof: ProofStatus,
        pub completeness: EvidenceCompleteness,
    }

    pub enum DispatchBoundaryKind {
        External(SemanticLocator),
        Unresolved,
        Truncated,
    }

    pub struct DispatchBoundary {
        pub kind: DispatchBoundaryKind,
        pub proof: ProofStatus,
        pub completeness: EvidenceCompleteness,
    }

    pub struct DispatchResult {
        pub candidates: Box<[DispatchCandidate]>,
        pub boundaries: Box<[DispatchBoundary]>,
    }

    pub trait DispatchOracle {
        fn resolve_call(
            &self,
            call: &CallSiteHandle,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError>;
    }

    pub struct CallTransfer {
        pub origin: CallSiteHandle,
        pub callee: ProcedureHandle,
        pub callee_entry: ProgramPointHandle,
        pub normal_continuation: ControlContinuation,
        pub exceptional_continuation: ControlContinuation,
        pub proof: ProofStatus,
        pub completeness: EvidenceCompleteness,
    }

    pub struct CallBoundary {
        pub origin: CallSiteHandle,
        pub dispatch: DispatchBoundary,
        pub model: Option<CallToReturnModel>,
    }

    pub enum CallToReturnModel {
        Normal,
        Exceptional,
        NormalAndExceptional,
    }

    pub struct CallTransferSet {
        pub transfers: Box<[CallTransfer]>,
        pub boundaries: Box<[CallBoundary]>,
    }

    pub struct ReturnTransfer {
        pub origin: CallSiteHandle,
        pub callee_exit: ProgramPointHandle,
        pub continuation: ProgramPointHandle,
        pub kind: ReturnTransferKind,
    }

    pub enum ReturnTransferKind {
        Normal,
        Exceptional,
    }

    pub trait IcfgProvider {
        fn call_transfers(
            &self,
            caller: &ProcedureHandle,
            call: CallSiteId,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<CallTransferSet>, SemanticProviderError>;

        fn snapshot(
            &self,
            root: &ProcedureHandle,
            limits: IcfgSnapshotLimits,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<IcfgSnapshot>, SemanticProviderError>;
    }

    pub struct IcfgNodeKey {
        point: ProgramPointHandle,
        call_context: Box<[CallSiteHandle]>,
    }

    pub struct IcfgNodeId(u32);
    pub struct IcfgEdgeId(u32);

    pub enum IcfgEdgeKind {
        Intraprocedural(ControlEdgeKind),
        Call,
        NormalReturn,
        ExceptionalReturn,
        CallToNormalContinuation,
        CallToExceptionalContinuation,
    }

    pub struct IcfgSnapshotLimits {
        pub max_call_depth: u32,
        pub max_nodes: usize,
        pub max_edges: usize,
    }

`IcfgSnapshotLimits::default()` is call depth 8, 50,000 nodes, and 200,000 edges. Its checked constructor rejects any zero field. Reaching a limit returns an incomplete snapshot plus a typed truncated boundary; it never aliases or drops the context component of an already published node.

    pub struct IcfgEdge {
        pub source: IcfgNodeId,
        pub target: IcfgNodeId,
        pub kind: IcfgEdgeKind,
        pub origin: Option<CallSiteHandle>,
        pub proof: ProofStatus,
        pub completeness: EvidenceCompleteness,
    }

    impl IcfgSnapshot {
        pub fn successor_edges(
            &self,
            node: IcfgNodeId,
        ) -> impl ExactSizeIterator<Item = (IcfgEdgeId, &IcfgEdge)>;

        pub fn predecessor_edges(
            &self,
            node: IcfgNodeId,
        ) -> impl ExactSizeIterator<Item = (IcfgEdgeId, &IcfgEdge)>;
    }

`CallTransfer` keeps the originating call-site handle, candidate callee, proof/completeness, callee entry, and caller continuations. `ReturnTransfer` is derived from that transfer. Every call or return ICFG edge retains the originating call-site handle. `IcfgSnapshot` owns only its bounded, context-bearing, dense, traversal-ready slice.

Use existing Rust dependencies unless measurements prove a new graph or storage crate materially improves the design. Tree-sitter AST nodes and current analyzer resolution are authoritative. `InlineTestProject` is the default fixture substrate. Any public RQL vocabulary belongs to the declarative registries and issue #824, not this plan.

Plan revision note (2026-07-17): Created this focused living ExecPlan from the agreed #815/#816-dispatch/#818/all-language design. It fixes program points as canonical CFG nodes, edge-ID-based bidirectional adjacency as the initial physical shape, exact prepared syntax as the lowering input, one location-first resolver facade, one demand-materialized ICFG, source-backed multiline conformance assertions, and measurement-gated persistence.

Plan revision note (2026-07-17): Pre-checkpoint architecture review split the remaining language rollout into nine independently reviewed and committed milestones, made context-bearing bounded snapshot nodes the mechanism that prevents cross-return, suppressed local call-to-continuation scaffolding unless an explicit summary/external model supplies a bypass, added ICFG predecessor/successor and context-selector contracts, and narrowed milestone 5 to the CFG/ICFG slice of #817.

Plan revision note (2026-07-17): A second pre-checkpoint review moved contract freeze after the TypeScript/Java ICFG review; replaced placeholder provider types with the existing cancellation token and `Arc<SemanticArtifact>`; defined cancellation, dispatch, transfer, snapshot-limit, and edge shapes; made builder accounting prospective with one atomic publication charge; corrected source paths and terminology; added exact per-milestone files and commands; and predeclared benchmark datasets, repetitions, output markers, overlay policy, and representation/persistence thresholds.

Plan revision note (2026-07-17): Completed Milestone 1a after three specialist reviews. The semantic CFG now uses schema-v2 canonical rich-edge IDs, outgoing offsets, incoming edge-ID rows, exact bidirectional traversal, scoped handles, deterministic bounded rendering, and defensive corruption validation. Review tightened provenance-parallel topology accounting, invalid-ID behavior, canonical incoming hydration, and literal renderer-schema coverage. Focused tests, formatting, strict all-feature clippy, and the complete `nlp,python` suite pass; the latter requires the documented macOS PyO3 dynamic-lookup flags and host access for process-dependent tests.

Plan revision note (2026-07-17): Completed Milestones 1b and 1c after specialist cache/provider, TypeScript-control, and final adversarial reviews. The production provider now atomically lowers one bounded, origin- and overlay-revision-aware syntax snapshot; publishes only validated outcomes; and shares complete artifacts through a byte-weighted, cancellation-aware single-flight cache. The first real adapter covers TypeScript and TSX callable control, retains dead syntax behind a generic reachability seal, and reports advanced omissions as exact typed gaps. The inline graph harness asserts source-backed predecessor/successor topology. All focused and repository gates pass; Java is the next checkpoint.

Plan revision note (2026-07-17): Completed Milestone 2 after Java-semantic and measurement reviews. Java now covers the common callable-control core plus switch expressions, yield, handlers, cleanup relays, initializer fragments, and method-reference evaluation while advanced omissions remain point-scoped. The release matrix rejected flat and outgoing-only physical rows because their reverse traversal failed the contract despite outgoing-only memory savings, so canonical bidirectional edge-ID rows enter the ICFG checkpoint unchanged. All focused tests, strict clippy, and the complete `nlp,python` suite pass.

Plan revision note (2026-07-17): Completed Milestone 3 after dispatch, ICFG, harness, and adversarial reviews. Exact whole-call locations now enter the established resolver, one generation-local provider builds bounded context-bearing slices with matched normal and exceptional returns, and typed boundaries retain every incomplete dispatch arm. Post-review fixes made source identity checks generation-exact, work accounting complete, boundary rendering identifiable, and node-plus-edge publication atomic. The reviewed shared adapter contract is now frozen for the all-language rollout.
