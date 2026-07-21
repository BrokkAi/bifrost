# Generalize receiver facts into value, dispatch, and heap oracles

This ExecPlan is a living document. Keep `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` current as implementation proceeds. Follow `.agents/PLANS.md` when revising it. The broader platform roadmap is checked in at `.agents/plans/language-agnostic-composable-typestate-platform.md`; this issue plan is self-contained and narrows that roadmap to GitHub issue #816.

## Purpose / Big Picture

Bifrost already has a language-neutral semantic IR, callable CFGs for every supported language, and one demand-materialized control-only ICFG. It also has useful but language-shaped receiver inference. What is missing is one honest, bounded semantic boundary through which later direct-flow, taint, typestate, IFDS/IDE, and optional pushdown clients can ask about dispatch targets, value transfer, and heap locations without importing a JavaScript, Java, usage-graph, or tree-sitter implementation.

After this change, `brokk_bifrost::analyzer::semantic` exposes three related contracts: `DispatchOracle`, `ValueFlowOracle`, and `HeapOracle`. Results use scoped semantic handles, candidate-level evidence, explicit candidate-set coverage, bounded call contexts and access paths, typed aliases, and a conservative strong-update certificate. TypeScript/JavaScript and Java provide two deliberately dissimilar reference implementations. The existing receiver query remains compatible but becomes a projection over the neutral facts instead of the owner of a parallel semantic model.

The observable result is not a whole-program pointer-analysis engine and not a solver. It is a finite, evidence-backed fact vocabulary and provider boundary. A later IFDS/IDE solver can intern these facts; a typestate FSA can name events and bound subjects through them; an optional WPDS implementation can attach weights to stable relations; and an optional synchronized call/field pushdown implementation can interpret exact call sites and access selectors as stack alphabets. None of those clients, weights, automata, worklists, or protocol states belongs in this issue.

For terminology in this plan, a finite-state automaton (FSA) is a finite protocol-state machine whose transitions may consume oracle-backed events. Interprocedural Finite Distributive Subset (IFDS) analysis tabulates finite dataflow facts with distributive transfer functions across matched calls and returns; Interprocedural Distributive Environment (IDE) analysis generalizes that model by propagating finite-height values through composable edge functions. A weighted pushdown system (WPDS) associates composable weights with call-stack transitions, while a synchronized pushdown system (SPDS) coordinates more than one stack, such as call and field/access-path stacks. These are prospective consumers of the finite relations defined here, not implementations supplied by #816.

## Progress

- [x] (2026-07-21 11:03+02:00) Verified the issue branch and live GitHub dependency state. Issues #394, #718, #719, #814, #815, and #818 are complete; #818 deliberately left actual/formal, receiver, return-value, and heap bindings to #816.
- [x] (2026-07-21 11:03+02:00) Read the durable platform roadmap, the #814 semantic-IR plan, the #718 receiver-traversal plan, and the all-language CFG/ICFG rollout plan.
- [x] (2026-07-21 11:03+02:00) Audited receiver inference, exact call relations, formal binding, Java receiver/return inference, semantic adapters, semantic identities/outcomes/gaps, workspace routing, and the existing dispatch/ICFG implementation.
- [x] (2026-07-21 11:03+02:00) Completed parallel architecture audits for current source seams and future IFDS/IDE, FSA, WPDS, and synchronized call/field pushdown consumers.
- [x] (2026-07-21 15:30+02:00) Froze the oracle quality, identity, limits, boundary-port, access-path, alias, and update-eligibility vocabulary in `src/analyzer/semantic/oracle.rs`. Twenty-one adversarial synthetic contract tests now cover scoped relation arenas, exact query/context ownership, store/base/root identity, validated call ports and bindings, bounded paths and sets, proof quality, and conservative strong updates.
- [x] (2026-07-21 15:30+02:00) Separated `WorkspaceSemanticOracle` from ICFG stitching, added explicit target-set coverage, replaced generic language checks with typed semantic-gap impacts, validated complete artifact generations, and preserved partial dispatch artifacts with exact work/provenance accounting. Existing C++ gap and Ruby non-regression behavior remains covered.
- [x] (2026-07-21 17:10+02:00) Completed the Ultra contract/dispatch checkpoint and its post-commit adversarial review. The initial architecture landed in `0f39b450`; follow-up hardening landed in `547a3057` with every accepted relation-arena, componentwise-quality, grouped-binding, finite-limit, cancellation, and target-projection finding. Independent validation passed 127 semantic unit tests, 41 oracle-contract tests, 11 semantic-IR tests, 25 ICFG-contract tests, 129 language-conformance tests, and 11 provider tests, plus formatting/diff checks and isolated strict all-target/all-feature Clippy. The earlier host-access feature suite passed 1,484 library tests with four intentional ignores and every integration target through `get_definition_test`; that stale branch target passed 565/568 and failed only the three C++ regressions corrected by upstream `0955e1c7` / PR #1020. A final remote refresh shows the issue branch is now fifteen commits behind `origin/master`; rebasing remains intentionally out of scope without user authorization.
- [x] (2026-07-21 19:01+02:00) Extracted the no-semantic-change lowering substrate into `src/analyzer/semantic/lowering.rs` and migrated all ten adapter modules covering eleven languages. `ProcedureLoweringSession` now owns dense source/evidence/value/call/gap allocation, point metadata, exact mapping publication, events, edges, gaps, and common call rows; `lower_procedure_batch` owns the repeated budget/cancellation policy. Ruby retains its binding prepass, C++ retains its distinct unconditional-`noexcept` throw terminal, and every adapter retains syntax, anchors, evaluation order, control topology, and gap policy. Validation passed 133 semantic unit tests, 25 ICFG contracts, 39 CFG contracts, 129 language-conformance cases, 41 oracle contracts, 11 IR contracts, 11 provider contracts, formatting/diff checks, and isolated strict all-target/all-feature Clippy.
- [ ] Emit real parameter, receiver, local, allocation, assignment, call-actual/result, return, basic memory, and capture facts from the TypeScript/JavaScript and Java adapters.
- [ ] Implement `ValueFlowOracle` and candidate-specific `CallBindings` over those scoped facts.
- [ ] Implement `HeapOracle` points-to/location, alias, bounded access-path, and update-eligibility queries over those scoped facts.
- [ ] Refine closed dispatch only where explicit evidence proves exhaustive coverage; retain open target sets for dynamic/virtual cases.
- [ ] Route the existing receiver query through the neutral facade, preserve its public labels and DTO shape, and add Java coverage.
- [ ] Measure request-local/generation-local reuse, invalidation, candidate growth, and access-path growth before proposing persistence.
- [ ] Run full Rust gates, complete guided review, update the durable roadmap and issue record, and record the final outcome here.

## Surprises & Discoveries

- Observation: `DispatchOracle` already exists and performs exact source-location dispatch through `CallRelationService`; it is currently declared and implemented inside `src/analyzer/semantic/icfg.rs`.
  Evidence: `DispatchCandidate`, `DispatchBoundary`, `DispatchResult`, and `DispatchOracle` are defined near the top of that module, and `WorkspaceIcfgProvider::resolve_call` maps one scoped `CallSiteHandle` back to an `ExactCallLocation` before invoking `dispatch_at_bounded`.

- Observation: the semantic IR already has neutral rows for local/parameter/receiver/return values, allocations, field/static/index/lexical-cell/capture locations, capture bindings, calls, proof, completeness, and typed uncertainty.
  Evidence: `src/analyzer/semantic/ir.rs` and `provider.rs` already expose these rows plus materialization-scoped handles and `SemanticOutcome<T>`.

- Observation: the TypeScript and Java production adapters do not yet populate enough of those rows to answer sound value or heap questions. They create call-local placeholder values, but do not connect expression results to actuals, emit parameter rows, allocations, memory rows, or general value-flow effects.
  Evidence: the call lowering in `src/analyzer/js_ts/semantic.rs` and `src/analyzer/java/semantic.rs` creates receiver/argument/result temporaries at the invoke point; repository-wide searches find no production `SemanticEffect::ValueFlow`, `Allocation`, `MemoryLoad`, or `MemoryStore` emissions in those adapters.

- Observation: the repeated lowering mechanics had two genuine adapter-owned exceptions rather than ten identical copies.
  Evidence: Ruby charges a parser-ordered local-binding prepass before procedure emission, while unconditional C++ `noexcept` routes the function scope to a distinct terminal point. The shared batch driver accepts precomputed work, and the shared session offers an optional separate function-throw boundary, preserving both contracts without importing Ruby or C++ syntax.

- Observation: the existing receiver outcome conflates three independent properties: whether each candidate is proven, whether the candidate set is exhaustive, and whether one abstract object represents one or many runtime objects.
  Evidence: `ReceiverAnalysisOutcome::Precise(Vec<_>)` can contain several candidates, `ReceiverValue::InstanceType` is nominal rather than a heap identity, and one allocation-site candidate can represent repeated loop or recursive allocations.

- Observation: some current receiver caps silently lose coverage. The TypeScript type-annotation path takes the first `max_targets` values before classifying the result, so a bounded subset can appear precise.
  Evidence: `src/analyzer/usages/js_ts_graph/receiver_analysis.rs` applies `.take(max_targets)` in the annotation path without retaining a truncated-set marker.

- Observation: the advertised receiver context-depth limit is not operational. JavaScript uses a separate fixed recursion bound and Java return-chain inference uses another fixed bound.
  Evidence: `ReceiverAnalysisBudget::context_depth` participates in query/cache values but is not consumed by the provider; JavaScript and Java declare independent hard-coded recursion limits.

- Observation: shared formal binding is structurally valuable but is not yet a semantic binding. It maps source ranges and `CodeUnit`s, reparses callee source, and can report `Complete` while leaving a spread actual unmapped.
  Evidence: `bind_call_site_arguments` and `formal_parameter_slots` in `src/analyzer/usages/call_relations.rs` and `src/analyzer/lexical_definitions.rs`.

- Observation: generic dispatch still contains two C++ language tests to decide which gaps weaken a retained call target set. Repeating that pattern for value and heap queries would make every neutral consumer language-aware.
  Evidence: `scoped_cpp_preprocessor_call_gap` and `scoped_cpp_call_evaluation_gaps` in `src/analyzer/semantic/icfg.rs`.

- Observation: the first contract draft allowed unrelated dense relation IDs and subjectless alias/escape flags to justify a strong update, including at a point with no store event.
  Evidence: specialist review constructed collisions between relation `0` from independent materializations and identified the positive test's `Invoke` point as a non-store. The revised contract resolves every relation through one query-owned arena and requires a `MemoryStoreHandle`, store-bound alias witness, store-bound escape witness, and one exact strong-update arena owner.

- Observation: a source revision and workspace mount are not enough to validate a retained semantic handle against a provider generation.
  Evidence: `SemanticArtifactKey` also includes language/dialect, adapter semantics, IR schema, configuration, and dependency fingerprints. `ProgramSemanticsProvider::current_artifact_key` now derives that complete key from a bounded atomic syntax snapshot without lowering, and dispatch rejects any mismatch before source projection.

- Observation: dispatch work accounting originally mixed transient resolver rows with retained candidates and omitted final reason strings, cancellation partials, and relation provenance.
  Evidence: the extracted provider now charges resolver examination separately, then atomically charges the final candidate/boundary rows, their owned proof text, and their arena record/evidence/handle entries. A payload that cannot be charged is not published.

- Observation: matching only the final field or index selector lets an unrelated base value masquerade as the store's address.
  Evidence: the post-implementation contract review constructed two paths with the same final selector and different roots. `StoreAtPoint` now requires the exact pre-effect base observation, validates the structured root against that base, and accepts exactly one field or index selector. Nested paths remain conservative until the lowering can supply structured prefix proof.

- Observation: query-local relation IDs are still unsafe if the arena owner omits the full point, phase, context, or candidate subject.
  Evidence: the adversarial contract suite could otherwise reuse evidence between similar points-to, location, alias, call-binding, or strong-update observations. Every result now validates one arena, the exact structured owner, the expected relation kind, nonempty evidence, and proof/completeness no stronger than the underlying semantic evidence.

- Observation: capping raw resolver declarations before semantic projection undercounts useful unique dispatch procedures, while cancellation and caps are independent states.
  Evidence: workspace dispatch now budgets raw resolver exploration separately, applies `dispatch_targets` only after deduplicating materialized procedures, retains partial artifacts for non-complete outcomes, and reports inner `Truncated` coverage whenever any cap occurred even when the outer outcome remains `Cancelled`.

- Observation: this host exposes rustup and Homebrew Rust components with incompatible artifact identities, and macOS PyO3 extension tests need CI's dynamic-symbol lookup flags.
  Evidence: the initial Clippy attempt produced E0514 until `PATH` consistently selected rustup. The initial full `nlp,python` link failed on unresolved `_Py*` symbols; the corrected gate pins the same toolchain, selects Homebrew Python 3.14, and supplies `-undefined dynamic_lookup` as `.github/workflows/ci.yml` does.

- Observation: the issue branch's complete suite cannot be green without integrating a known upstream C++ navigation fix that is unrelated to #816.
  Evidence: the branch was eight commits behind `origin/master` during the recorded host-access run and is fifteen behind after the final remote refresh. Both that full run and a serial 87-test C++ rerun fail only `cpp_bare_call_prefers_callable_role_over_same_named_nested_type`, `cpp_macro_decorated_out_of_line_owner_prefers_canonical_included_class`, and `cpp_qpid_qualified_template_and_macro_class_shapes_resolve_exact_types`; upstream `0955e1c7` / PR #1020 changes `src/analyzer/usages/get_definition/cpp.rs` and those expectations specifically. No checkpoint file modifies that navigation implementation or test target, and repository instructions prohibit an unrequested rebase.

- Observation: Java is the strongest static reference language. Its usage graph already has bounded declared-type, local/parameter, allocation, factory-return, overload, shadowing, and same-name-negative behavior that differs materially from JavaScript.
  Evidence: `src/analyzer/usages/java_graph/inverted.rs`, `return_type.rs`, `local_inference.rs`, and their focused Java usage tests.

- Observation: proof and completeness must be checked componentwise; a proven-but-partial row and an unproven-but-complete row cannot jointly justify a proven-complete result.
  Evidence: the post-milestone audit constructed asymmetric evidence sets for dispatch, value flow, points-to, and call bindings. Relation records and result constructors now require every claimed axis from the same supporting evidence, and argument cardinality counts only proven mappings.

- Observation: a call-scoped relation kind is not enough to identify a dispatch arm, and one visible relation handle retains its entire arena through `Arc`.
  Evidence: review could reseal one candidate relation for a different procedure, reuse one boundary relation across contradictory boundary kinds, and publish a narrow result backed by an arena built under wider record/evidence limits. Candidate records now name the exact `ProcedureHandle`, boundary records name the full `DispatchBoundaryKind`, and every public result revalidates all distinct retained arenas against its query limits.

- Observation: the old `Box<[ValueId]>` call-argument vocabulary cannot state direct versus spread arguments or one-versus-rest formals without language-shaped side channels.
  Evidence: schema v5 adds structured argument expansion/domain and formal multiplicity, while grouped candidate-specific bindings retain evidence-backed member mappings and proof-aware cardinality. Existing adapters publish `Unclassified` rather than manufacturing direct/spread semantics; TypeScript/Java refinement remains a later milestone.

- Observation: finite post-publication validation is too late when a public constructor or CFG builder can allocate unbounded iterators or owned language-domain text first.
  Evidence: candidate provenance and argument-group iterators now use bounded lookahead, call bindings have an explicit entry cap, object/location sets have typed breadth constructors, and `ProcedureCfgBuilder` prospectively charges language-defined value/rest/argument text before retention.

- Observation: cancellation, truncation, and exact target projection must remain independent even in partial workspace answers.
  Evidence: cancelled dispatch now groups semantic target identities before applying caps, preserves resolved targets as typed unmaterialized boundaries, reports inner `Truncated` coverage for omissions, and keeps outer `Cancelled` precedence over simultaneous budget states. Late materialization cancellation projects the current and remaining known target groups with cap-aware one-item lookahead rather than collecting an unbounded tail. Named boundary provenance uses target evidence; gap evidence retains its kind before handle deduplication.

- Observation: preserving cancellation at workspace dispatch is insufficient if a downstream ICFG projection or snapshot finalizer can relabel the same interrupted operation as budget exhaustion.
  Evidence: a failed call-transfer payload charge and an already budget-limited snapshot both previously selected `ExceededBudget` before inspecting cancellation. Dedicated finalizers now keep the outer result `Cancelled`, retain only atomically charged partials, and preserve independent inner truncation evidence.

- Observation: a procedure-wide C++ syntax-error gap means the adapter may have omitted call sites; it does not invalidate a different exact call that was retained and resolved.
  Evidence: removing `DispatchCoverage` from that procedure-wide `Calls` gap leaves call-scoped uncertainty intact, and the focused C++ semantic regression keeps the unrelated exact call proven and exhaustive.

## Decision Log

- Decision: separate candidate proof, candidate-set coverage, and abstract-object cardinality.
  Rationale: `Proven`, `Exhaustive`, and `Singleton` answer different questions. An exhaustive set may contain several candidates; a proven nominal type may describe an open object set; and one allocation-site row may summarize many runtime objects. Strong updates require all relevant properties rather than inferring them from vector length or a `Precise` label.
  Date: 2026-07-21.

- Decision: retain `SemanticOutcome<T>` as the operation-level uncertainty algebra and add `CandidateCoverage::{Exhaustive, Open, Truncated}` inside candidate-set results.
  Rationale: cancellation, unsupported capability, budget exhaustion, partial values, and unproven work are operation states, while target-set closure is a property of the returned set. A successfully completed open-world query must not masquerade as exhaustive, and an exhaustive multi-candidate result remains representable.
  Date: 2026-07-21.

- Decision: use materialization-scoped semantic handles for live oracle operations. Persistent or summary keys must derive from the complete artifact validity key plus scoped semantic identity and oracle configuration; `Arc` pointer identity, `ProjectFile`, `CodeUnit`, FQN, range, or a bare dense ID is never a persistent key.
  Rationale: handles prevent cross-artifact and cross-procedure ID confusion in hot analysis. Exact artifact revision, adapter, configuration, dependencies, oracle limits, and oracle semantics version are required to reuse a canonical fact. Incomplete results may retain canonical-looking keys but never populate a complete cache entry.
  Date: 2026-07-21.

- Decision: model stable procedure boundary ports for receiver, formal parameter, normal return, exceptional return, and capture slot.
  Rationale: `CallBindings` and reusable summaries need symbolic endpoints that survive caller/callee rebasing. Actual-to-formal and return-to-result relations are value metadata, not ICFG control edges.
  Date: 2026-07-21.

- Decision: make `CallBindings` candidate-specific. One binding result names one exact call site and one candidate callee, then maps caller receiver/actual values to callee ports and callee return/throw ports back to caller result slots.
  Rationale: overloads and dynamic dispatch can select procedures with different formal layouts. Merging bindings before choosing a callee would manufacture cross-target parameter and return relations.
  Date: 2026-07-21.

- Decision: represent call arguments as structured direct, spread, or unclassified rows; represent formals as one or domain-specific rest slots; and bind them through evidence-backed argument groups.
  Rationale: rest/spread expansion is one-to-many and may be open or truncated, so a flat actual-to-formal pair list cannot distinguish an exact empty spread from an omitted mapping. Group coverage and proof-aware `Exact`, `Between`, or `AtLeast` cardinality preserve both axes without embedding JavaScript, Python, or Java rules in the neutral contract.
  Date: 2026-07-21.

- Decision: make dispatch provenance arm-specific and seal candidates only after the complete result validates the exact call, target, boundary fact, quality, uniqueness, and query limits.
  Rationale: call ownership alone allowed one valid relation to be reused for a contradictory target or boundary subtype. Full structured subjects make candidate-specific bindings and deferred ICFG projection consume the same exact fact that dispatch published.
  Date: 2026-07-21.

- Decision: apply oracle limits to the complete retained object graph, not only visible vectors, and bound iterator consumption before collection.
  Rationale: one relation handle retains every record and evidence handle in its arena. Result constructors therefore aggregate distinct arenas, candidates reject duplicate or over-limit provenance with one-item lookahead, call groups and bindings have an explicit entry limit, and typed object/location sets prevent selecting the wrong breadth dimension.
  Date: 2026-07-21.

- Decision: outer cancellation takes precedence over simultaneous budget interruption while inner coverage continues to record independent truncation.
  Rationale: operation timing must not flip an otherwise identical cancelled query into `ExceededBudget`, whether interruption occurs during target materialization, call-transfer projection, or snapshot finalization. Consumers need both facts: the operation stopped because of cancellation, and a finite cap may also have omitted target arms. Known resolver targets remain typed partial boundaries, but construction stops at the applicable target, record, or evidence cap and records the omission as `Truncated`.
  Date: 2026-07-21.

- Decision: define an access path as a symbolic root, a bounded sequence of typed selectors, and an explicit `Exact` or `Summary` tail.
  Rationale: allocation-only roots cannot represent reusable relations such as `parameter0.connection -> return.state`. When a path limit is reached, the result must preserve a wildcard/summary tail and incomplete coverage; silently shortening the path and calling it exact is unsound. Exact call-site identities and exact field/index selectors remain usable as future call- and field-stack alphabets without embedding a pushdown system here.
  Date: 2026-07-21.

- Decision: make value and access-path queries point-, phase-, and bounded-context-aware.
  Rationale: a bare value or location ID does not identify whether the query occurs before or after an assignment, store, call, or return. The context is language-neutral and bounded; it does not depend on an ICFG snapshot node or solver state.
  Date: 2026-07-21.

- Decision: make oracle relation identity a handle into one finite, query-owned arena rather than publishing a bare dense integer.
  Rationale: dense IDs are useful only inside their owner. Arena pointer identity prevents collisions between independent queries, a structured owner ties relations to the exact call, procedure, call/callee pair, heap observation, or store event, and resolvable evidence records let future clients intern facts without treating an integer as persistent provenance.
  Date: 2026-07-21.

- Decision: retain the complete query subject and bounded context in relation ownership and result wrappers, and expose only validated result construction.
  Rationale: a procedure or dense value ID alone cannot distinguish otherwise similar observations. `PointsToResult`, `LocationResult`, `AliasResult`, `ValueFlowSnapshot`, `CallBindings`, `DispatchResult`, and strong-update evidence reject mixed arenas, owners, contexts, kinds, empty evidence, contradictory coverage, and quality claims stronger than their IR witnesses.
  Date: 2026-07-21.

- Decision: bind strong-update provenance to an exact `MemoryStore` event, not merely a point, path, and value.
  Rationale: one point can contain several effects, and alias or escape evidence about another store must not authorize replacement. `MemoryStoreHandle` names the event index and validated IR location/value; the strong-update arena owner and subject-bearing witnesses repeat that exact identity.
  Date: 2026-07-21.

- Decision: preserve candidate proof when a dispatch-coverage gap opens the target set, and apply caller-side call-evaluation gaps only while constructing ICFG transfers.
  Rationale: proof that one target is real does not prove the set is closed, and uncertainty in argument/default/temporary evaluation does not invalidate the target identity. The direct dispatch oracle therefore retains proven candidates with `Open` coverage, while ICFG transfer completeness records evaluation uncertainty.
  Date: 2026-07-21.

- Decision: let finite caps take precedence for result-set coverage while preserving the operation-level outcome independently.
  Rationale: cancellation answers whether the operation finished; `Truncated` answers whether a known finite bound omitted candidates or boundaries. A capped cancelled query must retain both facts rather than relabeling the candidate set as merely open.
  Date: 2026-07-21.

- Decision: derive and compare the complete current `SemanticArtifactKey` before accepting a retained procedure handle in a workspace oracle.
  Rationale: matching source bytes cannot detect adapter, configuration, dependency, language, or IR-schema changes. The bounded identity-only provider path reuses atomic syntax preparation and the canonical key builder without lowering or populating caches.
  Date: 2026-07-21.

- Decision: expose `MustAlias`, `MayAlias`, and `Disjoint` as explicit evidence-backed results, and expose update eligibility as either `Strong(StrongUpdateCertificate)` or `Weak(reasons)`.
  Rationale: a strong update is a proof obligation, not a convenience inferred from one candidate. Its certificate is scoped to a store, context, and heap abstraction and requires exhaustive singleton-location coverage, singleton object cardinality, an exact path, complete alias/escape evidence, and proven evidence. The certificate contains no client fact set so solver transfer functions do not become silently non-distributive.
  Date: 2026-07-21.

- Decision: treat factory-return nesting as provenance on a returned object or relation, not as a second abstract object or memory location.
  Rationale: the factory call explains why an object candidate reached the receiver; it does not allocate another identity by itself.
  Date: 2026-07-21.

- Decision: relocate the public dispatch contract to `semantic::oracle` and bind a separate workspace oracle provider to one `WorkspaceAnalyzer` generation. `WorkspaceIcfgProvider` delegates to it and continues to own only call/return control stitching.
  Rationale: dispatch is a reusable semantic service for ICFG, CodeQuery, and later solvers. Reusing exact `CallRelationService` resolution avoids a second resolver while removing ICFG as the public owner of dispatch.
  Date: 2026-07-21.

- Decision: attach typed impacts to semantic gaps and make generic dispatch/return logic select gaps by impact and scope, not by language or detail text.
  Rationale: capability says what producer surface is incomplete; impact says which downstream inference may be weakened. A C++ preprocessing gap can affect dispatch coverage while a Ruby procedure-level `Calls` gap need not weaken a retained explicit call. This distinction must be authored structurally by adapters, not inferred from language names or message strings.
  Date: 2026-07-21.

- Decision: use TypeScript/JavaScript and Java as the reference pair, then pressure-test the contract on C# or Rust before broad rollout.
  Rationale: JavaScript supplies the richest existing receiver provider; Java supplies materially different static inference and strong negative fixtures. Two similar dynamic adapters would not validate the neutrality of values, ports, locations, or dispatch closure.
  Date: 2026-07-21.

- Decision: centralize finite emission mechanics in `ProcedureLoweringSession`, but leave syntax interpretation, evaluation order, topology, source-anchor construction, prepasses, and uncertainty in each adapter.
  Rationale: dense IDs, provenance rows, matched call events, budget staging, and cleanup-point registration are representation invariants shared by every adapter. Moving AST interpretation into the same abstraction would erase the exact language distinctions the IR is meant to preserve. An optional separate function-throw boundary is a neutral topology hook, not a C++ policy encoded in the shared layer.
  Date: 2026-07-21.

- Decision: keep FSA definitions, IFDS/IDE facts, WPDS weights, semirings, synchronized-stack state, worklists, and protocol state outside every oracle contract.
  Rationale: the oracles publish finite semantic relations. Clients decide whether those relations become plain set facts, lattice functions, FSA transitions, weights, or pushdown symbols. This preserves the baseline solver and leaves #826 evidence-gated.
  Date: 2026-07-21.

## Outcomes & Retrospective

Issue #816 remains open, but its contract/dispatch checkpoint and shared-lowering milestone are complete on the issue branch. The checkpoint freezes semantic IR schema v5; finite evidence-backed oracle vocabulary; exact query, dispatch-arm, and relation-arena ownership; structured direct/spread/unclassified arguments and one/rest formals; proof-aware grouped call bindings; bounded access paths, contexts, retained arenas, and partial target projection; strong-update proof obligations; explicit dispatch coverage; typed gap impacts; complete artifact-key validation; stable cancellation semantics; and a separate workspace dispatch facade. The lowering milestone removes the repeated emission engine from all language adapters while preserving their syntax and topology ownership.

The next concrete milestone is real TypeScript/Java value emission: procedure ports, lexical values, allocations, assignments, calls, returns, and basic memory/capture facts. Later milestones still need real oracle implementations, receiver compatibility, dispatch refinement, and measurement before #816 itself can be accepted.

## Context and Orientation

`src/analyzer/semantic/ids.rs`, `capabilities.rs`, `provider.rs`, and `ir.rs` own durable artifact validity, scoped dense IDs and handles, total language capabilities, finite semantic work budgets, typed operation outcomes, immutable semantic rows, evidence, and gaps. New oracle contracts build on these types rather than creating parallel source/range identities.

`src/analyzer/semantic/icfg.rs` owns demand-materialized interprocedural control. Public dispatch contracts live in `src/analyzer/semantic/oracle.rs`, and workspace-backed dispatch lives behind `WorkspaceSemanticOracle`. The ICFG delegates semantic call resolution to that facade and retains call-to-entry, matched exit-to-originating-continuation, and bounded snapshot construction.

`src/analyzer/usages/call_relations.rs` remains the authoritative structured, exact-source call resolver and source-level formal-layout algorithm. Oracle code adapts its results to scoped semantic procedures and values; it does not perform FQN-wide or text-search resolution.

`src/analyzer/usages/receiver_analysis.rs` and `js_ts_graph/receiver_analysis.rs` contain the compatibility behavior to preserve: allocation/type/static/module/current-receiver candidates, conditional merges, factory provenance, explicit outcomes, cancellation, and bounds. Their `CodeUnit`, file/range, and recursive DTO identities do not become the neutral oracle API.

`src/analyzer/usages/java_graph/inverted.rs`, `return_type.rs`, and `local_inference.rs` contain the static reference behavior. The semantic adapter should emit enough structured facts that usage graph and query consumers can reuse the oracle rather than copying this resolver again.

`src/analyzer/js_ts/semantic.rs` and `src/analyzer/java/semantic.rs` already emit real procedure and control topology. The next adapter milestone must add value identity and relations without manufacturing expression semantics from the current call placeholders. A shared lowering session may own source/evidence interning and emission mechanics, but language syntax interpretation stays in each structured adapter.

`WorkspaceSemanticOracle` holds a live `WorkspaceAnalyzer` and validates every retained handle against the complete current `SemanticArtifactKey` before projection. Live results use scoped handles. Oracle limits complement `SemanticBudget`: limits bound semantic breadth/depth such as candidates, context, summaries, alias expansion, and access paths, while `SemanticBudget` continues charging actual source bytes and retained/traversal work. Any future complete-result cache must include both the complete artifact key and oracle configuration in its identity; this checkpoint does not add an oracle-result cache.

## Plan of Work

### Milestone 1: freeze the language-neutral oracle contract and dispatch seam

Create `src/analyzer/semantic/oracle.rs` and export it from `semantic/mod.rs`. Move or re-export the existing dispatch types there. Add explicit `CandidateCoverage`, candidate-level evidence containers, `ObjectCardinality`, finite `OracleLimits`, bounded call context, evaluation phase, procedure boundary ports, access-path roots/selectors/tails, point-aware value/access/store queries, abstract objects and locations, value relations, candidate-specific call bindings, alias answers, weak-update reasons, and a validated strong-update certificate. Define `ValueFlowOracle` and `HeapOracle` method shapes over scoped handles and `SemanticOutcome<T>`; do not supply fake default answers.

Add `coverage` to `DispatchResult`. It defaults to `Open`, becomes `Truncated` whenever candidate discovery or materialization is capped, and becomes `Exhaustive` only when the resolver and all applicable gap evidence prove there is no unresolved arm. Candidate count never determines coverage.

Provide `WorkspaceSemanticOracle`, tied to one `WorkspaceAnalyzer` generation and validated `OracleLimits`. Reuse the existing exact call relation implementation. Make `WorkspaceIcfgProvider` delegate `DispatchOracle` calls to this facade and retain only control-transfer/snapshot responsibilities. Preserve public root re-exports so existing `analyzer::semantic::*` consumers continue to compile.

Add typed semantic-gap impacts for at least dispatch coverage, call evaluation, return transfer, value flow, heap read, heap write, and aliasing. Default impact derivation may conservatively follow capability and subject, but adapter-specific extra impacts must be explicit. Tag C++ preprocessing and caller-side evaluation gaps, tag dynamic-dispatch gaps generically, and replace the current C++ checks in generic dispatch. Use the same typed return-transfer impact for existing path-scoped return weakening. Bump the semantic IR schema version because gap rows change, update deterministic rendering, and add validation/tests that prevent unrecognized impact bits or empty impact claims where an exact consumer dependency is required.

Create `tests/semantic_oracle_contract.rs` with synthetic semantic artifacts. Prove at least:

- candidate proof, set coverage, and object cardinality vary independently;
- one candidate with `Open` coverage is not a closed dispatch result;
- an exhaustive multi-candidate set remains exhaustive;
- path truncation produces a `Summary` tail and never a shorter exact path;
- point/phase/context and procedure scopes participate in query identity;
- candidate-specific call bindings cannot mix callees;
- `StrongUpdateCertificate` rejects open/truncated points-to, multiple locations, summary objects, summary paths, incomplete alias/escape evidence, and unproven evidence;
- a complete singleton exact location with complete disjoint/non-escape evidence can receive a strong certificate;
- typed gaps weaken only the downstream facets they declare;
- every limit is positive and finite.

Run existing ICFG tests to prove the extraction is behavior-preserving, including C++ preprocessing/evaluation cases and the Ruby non-regression.

### Milestone 2: extract shared lowering mechanics without changing semantics

Extract a source-anchor-aware procedure lowering session and shared call-site scaffold from the repeated TypeScript/Java and all-language adapter mechanics. It may own deterministic source/evidence/value/call ID allocation, exact point metadata, effect insertion, and common validation. It must not interpret language syntax, parse source text, or force one universal visitor.

Re-run semantic language conformance and ICFG contracts for all languages. This milestone is a mechanical base for widening value emission, not permission to change capability claims or infer new facts.

### Milestone 3: emit real reference-language value facts

Extend TypeScript/JavaScript and Java lowering to emit procedure receiver and parameter rows, expression-specific values, lexical locals, assignments/aliases, allocations, returns, call actuals/results/thrown values, and basic captures. Use tree-sitter fields and existing structured analyzer declarations/inference. Preserve exact source/evidence identity and iterative traversal.

Connect actual expression values to call argument slots and returned expression values to procedure return ports. Do not derive sound-looking bindings from the current invoke-point placeholders. Update capability tables and gaps only for behavior proven by fixtures.

Add shared inline TypeScript/Java fixtures for locals, shadowing, branch ambiguity, object creation, factory return, calls, exceptions, captures, and same-name negatives. The two adapters may differ in evidence and open-world behavior but must publish the same neutral relation kinds where semantics agree.

### Milestone 4: implement value-flow and call bindings

Implement intraprocedural value-relation snapshots and candidate-specific `call_bindings`. Adapt the shared formal-slot selection logic to semantic ports rather than matching by FQN or range. Cover receiver-to-receiver, actual-to-formal, callee-return-to-caller-result, thrown-to-exceptional-result where modeled, and capture source-to-child slot as a separate lexical relation.

Defaults, named arguments, variadics, spreads, receiver conventions, and incomplete callee bodies must retain explicit coverage and proof. A spread actual with no mapped formal cannot produce a complete binding result. Charge every candidate, relation, source read, and summary expansion; honor cancellation between work units.

### Milestone 5: implement bounded heap, alias, and update queries

Emit and query allocation objects, fields, statics, exact/wildcard indexes, lexical cells, and capture slots. Implement point-aware points-to and access-path location queries, preserving candidate coverage and object cardinality. A capped path retains a summary tail; a capped candidate set retains exact discovered candidates plus `Truncated` coverage.

Implement evidence-backed alias answers. Default to `MayAlias` or an incomplete outcome when identity is not proven. Issue a strong-update certificate only when every constructor invariant passes; otherwise return `Weak` with typed reasons. Tests must include loop/recursive allocation-site summaries so one allocation handle is not accidentally treated as one runtime object.

### Milestone 6: refine dispatch and project receiver compatibility

Use value/type facts to refine dispatch only when evidence is sufficient. Add explicit exhaustive-coverage proof for Java static methods, constructors, private methods, and provably final methods/classes. Keep ordinary Java virtual dispatch and JavaScript property/callable dispatch open unless the indexed workspace and language semantics genuinely close them.

Route `ReceiverQueryService` through the oracle facade. Preserve `precise`, `ambiguous`, `unknown`, `unsupported`, and `exceeded_budget`; per-input reasons and limits; allocation/type/static/module/current/factory rendering; prepared-file accounting; and unsupported-language rows. Factory nesting becomes provenance rendering. Add Java receiver support without relabeling CodeQuery `points_to` as whole-program points-to.

### Milestone 7: measurement, review, and rollout decision

Measure cold/warm generation-local oracle construction, invalidation after disk and overlay changes, candidate counts, access-path lengths, alias breadth, retained provenance, and receiver-query compatibility overhead on inline fixtures plus pinned representative TypeScript and Java repositories. Incomplete results never populate a complete cache. Do not add SQLite persistence without a separate measured lifecycle decision.

Run parallel API/identity, soundness, adapter, budget/cancellation, compatibility, and future-consumer reviews. Pressure-test C# or Rust before declaring the contract portable. Update the broader roadmap, this plan, and issue #816 with exact validation and any intentionally deferred language rollout.

## Concrete Steps

Work from the existing issue branch. Do not create or switch branches. At every milestone, inspect `git status --short` and stage only files changed for that milestone.

For the Ultra checkpoint, the expected first edits are:

    .agents/plans/issue-816-value-dispatch-heap-oracles.md
    .agents/plans/language-agnostic-composable-typestate-platform.md
    src/analyzer/semantic/mod.rs
    src/analyzer/semantic/oracle.rs
    src/analyzer/semantic/icfg.rs
    src/analyzer/semantic/ir.rs
    src/analyzer/semantic/ids.rs
    src/analyzer/semantic/render.rs
    src/analyzer/workspace.rs
    src/analyzer/cpp/semantic.rs
    tests/semantic_oracle_contract.rs
    tests/semantic_ir_contract.rs
    tests/icfg_contract.rs

Other semantic adapters and tests may require mechanical `SemanticGap` field initialization after the schema change. Do not mix reference value lowering into this checkpoint.

Format and run the focused contract first:

    cargo fmt
    cargo test --test semantic_oracle_contract --test semantic_ir_contract --test icfg_contract

Then run language conformance because every adapter emits gaps:

    cargo test --test semantic_language_conformance

Run the isolated CI lint gate:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

Before the final issue completion, run the feature-complete suite:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Also run:

    cargo fmt -- --check
    git diff --check

After each completed ExecPlan milestone and its review fixes, commit only that milestone's files with a multiline message explaining the semantic reason for the checkpoint. Record the commit and validation in `Progress` and `Outcomes & Retrospective`.

## Validation and Acceptance

The contract checkpoint is accepted when `semantic_oracle_contract`, `semantic_ir_contract`, `icfg_contract`, and semantic language conformance pass; generic dispatch contains no language/dialect tests; `DispatchResult` carries explicit coverage; every gap used by dispatch/return selection carries typed impact; existing C++ and Ruby behavior remains intact; and specialist review finds no way to obtain a strong-update certificate from open, summary, ambiguous, unproven, or incomplete evidence.

Issue #816 is accepted when both TypeScript/JavaScript and Java can answer the same neutral dispatch/value/heap contracts from real adapter facts; receiver compatibility passes; every requested bound and cancellation path retains partial candidates and exact work; same-name and shadowing negatives do not fabricate relations; closed dispatch is evidence-backed; no text-search or mini-parser fallback was added; and direct-flow/ICFG clients can consume the oracles without importing language-specific graph modules.

The implementation must remain useful to the planned consumers without embedding them. A synthetic test should demonstrate that oracle relations have finite stable identity and can be interned as client facts, and that ports/access selectors can be interpreted as symbolic summary or future pushdown alphabets. No test should instantiate an FSA, IFDS solver, weight algebra, or synchronized pushdown engine inside the oracle module.

## Idempotence and Recovery

All source and plan edits are ordinary version-controlled files. Formatting and tests are repeatable. Semantic artifact caches are generation-local and complete-only; a failed or cancelled oracle query must not mutate a complete cache entry.

If the semantic-gap schema migration breaks an adapter, add the correct typed impact or an explicit empty impact when the gap is purely diagnostic; do not infer impact from detail strings and do not restore language checks in generic consumers. If the dispatch extraction changes behavior, compare the pre-extraction ICFG tests and move existing structured logic intact before attempting precision changes.

If a proposed strong certificate cannot prove one invariant, recover by returning `Weak` with the corresponding reason. If a candidate/path limit is exceeded, retain discovered exact candidates or selectors, mark coverage `Truncated` or the tail `Summary`, and return the appropriate budget/partial outcome. Never recover by dropping candidates, shortening a path as exact, matching by name, or scanning source text.

If TypeScript/Java facts pressure a provisional relation or endpoint shape, revise this living plan and the synthetic contract before broadening to other languages. Backwards compatibility is not required, but every revision must preserve scoped identity, boundedness, explicit uncertainty, and consumer separation.

## Artifacts and Notes

The most important existing behavior to preserve is:

    ReceiverAnalysisOutcome::{Precise, Ambiguous, Unknown, Unsupported, ExceededBudget}
    SemanticOutcome::{Complete, Ambiguous, Unknown, Unsupported, Unproven, ExceededBudget, Cancelled}
    CallRelationService::dispatch_at_bounded
    bind_call_site_arguments / formal_parameter_slots
    WorkspaceIcfgProvider matched call and return stitching

The key soundness distinction is:

    candidate proof != candidate-set coverage != object cardinality

The key ownership distinction is:

    ICFG: control topology
    ValueFlowOracle: caller/callee and intraprocedural value relations
    HeapOracle: objects, locations, access paths, aliases, update eligibility
    client/solver: facts, FSA states, weights, worklists, summaries

## Interfaces and Dependencies

The contract checkpoint should provide these shapes, allowing naming refinements that preserve their semantics:

The bounded call context is retained in each value-flow result and in its query-owned relation-arena identity; it is not transient request metadata. A call-binding query receives a validated `DispatchCandidate`, rather than an independently supplied callee handle, and its result retains the same context. An alias query is one validated observation whose operands share point, phase, and context. `StoreAtPoint` binds one exact `MemoryStore` event to the structured lvalue path and stored value observed before that effect; matching a field or index requires the full base/path relationship, not merely the final selector. Consequently `update_eligibility` takes the validated store subject alone and derives any selected abstract location and certificate evidence from that subject.

    enum CandidateCoverage {
        Exhaustive,
        Open,
        Truncated,
    }

    enum ObjectCardinality {
        Singleton,
        Summary,
        Unknown,
    }

    struct OracleSet<T> { /* private candidates and coverage */ }

    impl<T> OracleSet<T> {
        fn bounded(
            candidates: impl IntoIterator<Item = EvidenceBacked<T>>,
            coverage: CandidateCoverage,
            limits: OracleLimits,
            dimension: OracleSetLimit,
        ) -> Self;
    }

    struct ValueFlowSnapshot {
        procedure: ProcedureHandle,
        context: OracleCallContext,
        relations: Box<[ValueFlowRelation]>,
        coverage: CandidateCoverage,
    }

    struct CallBindings {
        call: CallSiteHandle,
        callee: ProcedureHandle,
        context: OracleCallContext,
        bindings: Box<[CallBinding]>,
        coverage: CandidateCoverage,
    }

    enum ProcedurePortKind {
        Receiver,
        Parameter { ordinal: u32 },
        NormalReturn,
        ExceptionalReturn,
        Capture { slot: MemoryLocationId },
    }

    struct AccessPath {
        root: AccessPathRoot,
        selectors: Box<[AccessSelector]>,
        tail: AccessPathTail,
    }

    struct AliasQuery {
        left: AccessPathAtPoint,
        right: AccessPathAtPoint,
    }

    struct StoreAtPoint {
        store: MemoryStoreHandle,
        target: AccessPathAtPoint,
        value: ValueAtPoint,
        base: Option<ValueAtPoint>,
    }

    enum AliasRelation {
        MustAlias,
        MayAlias,
        Disjoint,
    }

    enum UpdateEligibility {
        Strong(Box<StrongUpdateCertificate>),
        Weak(Box<[WeakUpdateReason]>),
    }

    enum OracleRelationOwner {
        Dispatch(CallSiteHandle),
        ProcedureValueFlow { procedure: ProcedureHandle, context: OracleCallContext },
        CallBinding { call: CallSiteHandle, callee: ProcedureHandle, context: OracleCallContext },
        PointsTo(Box<ValueAtPoint>),
        Locations(Box<AccessPathAtPoint>),
        Alias(Box<AliasQuery>),
        StrongUpdate(Box<StoreAtPoint>),
    }

    trait DispatchOracle {
        fn resolve_call(
            &self,
            call: &CallSiteHandle,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<DispatchResult>, SemanticProviderError>;
    }

    trait ValueFlowOracle {
        fn procedure_relations(
            &self,
            procedure: &ProcedureHandle,
            context: &OracleCallContext,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<ValueFlowSnapshot>, SemanticProviderError>;

        fn call_bindings(
            &self,
            call: &CallSiteHandle,
            candidate: &DispatchCandidate,
            context: &OracleCallContext,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<CallBindings>, SemanticProviderError>;
    }

    trait HeapOracle {
        fn pointees(
            &self,
            value: &ValueAtPoint,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<PointsToResult>, SemanticProviderError>;

        fn locations(
            &self,
            access: &AccessPathAtPoint,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<LocationResult>, SemanticProviderError>;

        fn alias(
            &self,
            query: &AliasQuery,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<AliasResult>, SemanticProviderError>;

        fn update_eligibility(
            &self,
            store: &StoreAtPoint,
            request: &mut SemanticRequest<'_>,
        ) -> Result<SemanticOutcome<UpdateEligibility>, SemanticProviderError>;
    }

The query-bearing `PointsToResult`, `LocationResult`, and `AliasResult` wrappers retain the exact point, phase, and context subject and validate every candidate's provenance against it. `OracleSet::bounded` consumes at most the selected limit plus one candidate and forces `CandidateCoverage::Truncated` when that lookahead proves omission.

`WorkspaceSemanticOracle` currently supplies `DispatchOracle` over a live workspace plus one validated `OracleLimits` value. `ValueFlowOracle` and `HeapOracle` remain contracts until later milestones add real adapter facts and implementations. `WorkspaceIcfgProvider` may forward `DispatchOracle` for compatibility, but its call-transfer implementation consumes the separate facade rather than owning another resolver.

Types whose exact representation should remain provisional until the first TypeScript/Java vertical slice are nominal type summaries, exact index keys, external/module object roots, stable relation-key serialization, escape evidence, and whether intraprocedural relation snapshots are event lists or compact indexed rows. Their required identity, boundedness, proof, and coverage semantics are fixed by this plan even if their Rust layout changes.

Plan revision note (2026-07-21): Initial focused issue plan written after live dependency verification, full roadmap/semantic/ICFG review, and parallel current-surface plus future-consumer audits. It separates proof, coverage, and cardinality; introduces boundary ports and summary-tailed access paths; makes strong updates certificate-based; removes language checks through typed gap impacts; and deliberately ends the Ultra checkpoint before reference-adapter value/heap lowering so that routine implementation can continue under High reasoning.

Plan revision note (2026-07-21): Reconciled the durable contract narrative after specialist review without advancing implementation status. Renamed the generation-bound facade to `WorkspaceSemanticOracle`; made bounded context part of value-flow and call-binding results and relation ownership; made call bindings query a validated dispatch candidate; described aliasing as one same-observation query; and clarified that `StoreAtPoint` binds the exact store event, full structured address path, and stored value so `update_eligibility` does not accept an independently selected location. Added a self-contained glossary for the prospective FSA, IFDS, IDE, WPDS, and SPDS consumers.

Plan revision note (2026-07-21): Reconciled the implemented Ultra checkpoint after adversarial contract and workspace-dispatch review. Query-bearing result wrappers now retain exact observation identity; relation arenas validate full owners, contexts, evidence kinds, and evidence quality; store observations bind the exact base and root; public result construction is bounded and contradiction-checked; raw dispatch exploration is budgeted separately from final unique target caps; and typed gap scope drives ICFG weakening. This checkpoint deliberately stops before shared lowering, real TypeScript/Java value and heap facts, oracle implementations, receiver projection, dispatch refinement, and measurement.

Plan revision note (2026-07-21): Closed the post-commit Ultra audit after schema v5 grouped-call-binding hardening, whole-arena limit validation, exact dispatch target and full boundary subjects, cap-aware partial target retention, and cancellation-precedence fixes at workspace, call-transfer, and snapshot layers. The remaining milestones are implementation-oriented and can proceed under High reasoning.
