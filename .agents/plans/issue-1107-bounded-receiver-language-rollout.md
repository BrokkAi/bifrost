# Expose bounded receiver traversal across every remaining language adapter

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan is maintained in accordance with `.agents/PLANS.md`. It builds on the checked-in architecture and terminology from `.agents/plans/issue-816-value-dispatch-heap-oracles.md`, but it restates the rollout requirements needed to complete this work.

## Purpose / Big Picture

After this work, a `query_code` pipeline can traverse from a C++, C#, Go, PHP, Python, Ruby, Rust, or Scala expression to the receiver values it may denote, the abstract objects those values may point to, and the exact member declarations reached through those receivers. These are the existing `receiver_targets`, `points_to`, and `member_targets` operations. Today those operations work for Java and JavaScript/TypeScript but return `receiver_analysis_language_unsupported` for the eight languages in GitHub issues #1108 through #1115.

The feature must remain conservative. A result is `precise` only when structured syntax, neutral semantic facts, and the language's exact resolver all support a single closed answer. Multiple supported answers remain `ambiguous`. Open or incomplete analysis remains non-precise, even when it has useful candidates. Unsupported syntax and dynamic behavior produce an explicit `unsupported` or `unknown` receiver-analysis row rather than an empty result or a guessed same-name declaration. All work shares the existing finite budget, cancellation token, candidate limits, diagnostics, provenance, and serialized result contract.

Each language remains a separately reviewable implementation and validation milestone, but the user has consolidated publication into one branch and one pull request. The branch will keep issue-aligned checkpoint commits while work is in progress. The final PR will close #1107 and all eight linked child issues together after the cumulative implementation, architectural sweep, documentation, local gates, and CI are green.

## Progress

- [x] (2026-07-23 11:09+02:00) Fetched the live remote, inspected the detached worktree, read epic #1107 and all eight linked issue scopes, and verified that no child already has a pull request.
- [x] (2026-07-23 11:09+02:00) Audited the shared receiver service, semantic source projection, oracle coverage, exact definition/type dispatch, all eight semantic lowerers, the CodeQuery pipeline, executable tutorial harness, schema descriptions, and capability documentation.
- [x] (2026-07-23 11:09+02:00) Completed parallel shared, static-language, and dynamic-language architecture diagnoses. The diagnoses agree that the remaining adapters lack the neutral value and heap facts required for sound receiver queries.
- [x] (2026-07-23 15:42+02:00) Implemented the #1109 C# neutral value-flow lowerer, canonical receiver-site index, bounded/cancellable exact definition and type sessions, conservative semantic coverage gate, structured `dynamic` boundary, and caller-local factory-return identity.
- [x] (2026-07-23 15:42+02:00) Added focused neutral, resolver, receiver-budget, candidate-cap, cancellation, and end-to-end C# tests. Formatting, `cargo check --lib`, and the focused C# pipeline and semantic contracts pass in the detached worktree.
- [x] (2026-07-23 17:31+02:00) Hardened C# precision after adversarial review: partial declarations now project one logical static type, ordinary closed properties remain precise while their downstream exception boundary stays explicit, factory provenance is tied to the resolved call-result handle, named/by-reference arguments and null/default/cast/conversion identities remain open, and derived call indexes are included in semantic-cache weight.
- [x] (2026-07-23 19:24+02:00) Completed bounded-provider hardening: exact limited store/tree-sitter lookups, per-unit metadata/range projection, bounded imports/global usings, hierarchy and attribute ancestry, and generation-coherent per-row `Arc<FileFacts>` input. Cold-cache and unresolved-ancestry adversarial tests pass.
- [x] (2026-07-23 18:05+02:00) Created the user-authorized consolidated branch `dave/1107-bounded-receiver-all-languages`; all remaining milestones will land there as issue-aligned checkpoints.
- [x] (2026-07-23 19:52+02:00) Completed, adversarially reviewed, and validated #1109 for C#, including the shared receiver-site/decorator seam, open-coverage precision fix, conversion-safe identity flow, persisted lookup bounds, and focused property/extension/dispatch/resource tests. This plan update is included in the issue-aligned checkpoint.
- [x] (2026-07-23) Added request-local, budget-charged structural-fact acquisition for receiver steps composed from cross-file reference/call-input rows. The C# cross-file regression proves the already-extracted reference file is reused without a third parse.
- [x] (2026-07-23) Implemented, reviewed, validated, and checkpointed #1110 for Go at `20e62a3c`: neutral named-receiver/parameter/local/allocation/factory facts, bounded exact selectors and method sets, promoted-member traversal, persisted return/type metadata, and explicit interface/generic/multi-result boundaries. The focused receiver pipeline and corrected evaluation-order conformance case pass.
- [x] (2026-07-23) Implemented, reviewed, validated, and checkpointed #1114 for Rust at `453c76cc`: neutral `self`/parameter/local/allocation/call-result/return facts, bounded persisted exact type/member resolution, closed dispatch metadata, and explicit trait/capture/cast/deref/macro gaps. Focused CodeQuery, bounded-definition, and bounded-type tests pass.
- [x] (2026-07-23) Implemented, validated, and checkpointed #1111 for PHP at `6abae27a`: neutral `$this`/parameter/local/allocation/call-result/return facts, exact bounded PHP type/member resolution, factory-return projection, and explicit dynamic/magic boundaries. The semantic contract, bounded current-receiver unit test, and CodeQuery receiver pipeline pass.
- [x] (2026-07-23) Implemented, validated, and checkpointed #1112 for Python at `48848264`: neutral `self`/parameter/local/allocation/call-result/return facts, exact bounded non-module declaration/type/member resolution, factory-return projection, Open dispatch metadata, and value-scoped descriptor/subscript uncertainty. The semantic contract and CodeQuery receiver pipeline pass; the shared conformance topology now records assignment boundaries explicitly.
- [x] (2026-07-23) Implemented, validated, and checkpointed #1113 for Ruby at `47e3a2a1`: neutral receiver/parameter/local/allocation/argument/return facts, request-bounded exact type/member resolution, current/class receivers, local aliases, `.new`, and same-file singleton factory returns. Dynamic send, safe navigation, monkeypatching, refinements, mixins, inheritance, and `method_missing` remain explicit open boundaries. The semantic contract, bounded resolver suite, public receiver pipeline, and library compile pass.
- [x] (2026-07-23) Implemented and boundedness-hardened #1115 for Scala: neutral receiver/value flow, exact bounded type/member resolution, structured package and lexical-scope context, and terminal budget handling for bare-apply shadow scans. The focused AST cutoff suite (2/2), bounded type suite (3/3), receiver pipeline (1/1), and semantic contract (5/5) pass; the final shared conformance rerun remains part of the cumulative gate.
- [x] (2026-07-23) Implemented and focused-validated #1108 for C++: neutral current/parameter/local/allocation/call-result facts, structured pointer/object receiver typing, persisted parser-derived return identities, exact bounded member and hierarchy lookup, and explicit virtual/template/preprocessor/plain-C boundaries. The public C++ receiver suite passes 10/10, including callable-shadow, lexical-namespace, nearest-base, cross-file factory, same-name-negative, and plain-C cases; the checkpoint remains part of the cumulative architecture commit.
- [x] (2026-07-23) Ran an independent cumulative architecture audit before publication. It found boundedness or false-precision escape hatches in cold structural-fact materialization, Go/Rust AST walks, PHP alias/enclosing-type resolution, Python same-file class visibility, Ruby attached-block effect placement, C# extension/hierarchy resolution, and shared Python/Ruby formal-parameter extraction.
- [x] (2026-07-23) Reworked cold cross-file receiver facts into a cancellable, fact-capped materialization API that skips unbounded persisted hydration, stops before allocating past the request limit, and caches only complete snapshots. Added exact early-cap, complete-retry, cache-reuse, and cancellation tests.
- [x] (2026-07-23) Metered shared Python/Ruby formal-parameter and decorator traversal through `ResolutionSession`, corrected Ruby attached blocks to use deferred-effect rather than call-evaluation gaps, and made bounded Python class lookup enforce AST-derived lexical visibility. The wide-parameter cutoff and hidden-nested-class/module-class regressions pass.
- [x] (2026-07-23) Added public uncertainty regressions for Go interface dispatch, PHP union receivers, and Rust trait objects. Together with the C++ virtual/plain-C, C# dynamic/interface, Python/Ruby open dispatch, and Scala overridable-member coverage, every new adapter now has both a supported-form result and an explicit non-precise boundary.
- [x] (2026-07-23) Ran a second independent blocker-only sweep over the cumulative diff. It found absolute C++ paths captured by lexical namespaces, Rust bare types escaping their file module, C# sibling materialization before charging, cold prepared syntax hydrating full analyzer state before cancellable parsing, structured-signature rows without a fixed admission cap, and bounded Ruby/PHP calls into unbounded metadata or parent lookup.
- [x] (2026-07-23) Finished and focused-validated the second-sweep fixes: snapshot-exact prepared syntax, stack-safe and request-metered C#/Go/Rust walks, bounded PHP/Ruby metadata and ancestry projection, fixed structured-signature admission/deserialization limits, exact Rust module and enum-variant ownership, Go pointer/value method sets and addressability, and exact Scala extension/inheritance lookup from source and cold persisted state.
- [x] (2026-07-23) Froze the eight-language implementation and ran the cumulative focused acceptance sweep. Receiver/query, tutorial, uncertainty, C++/Scala semantic-value, hostile structured-metadata, full semantic-language conformance, documentation-contract, and rendered documentation checks pass; the strict isolated CI-equivalent gates remain after the final rebase.
- [x] (2026-07-23) Completed the final independent architecture, Rust-quality, repository-policy, and strict acceptance audits. Fixed Go promoted-path ambiguity, C++ virtual/non-virtual diamond identity, exact Go/C++ data-field precision, role-edge work accounting, structured-type DAG hashing/equality, oversized metadata persistence, bounded-store error completeness, and dirty-state pre-cloning.
- [x] (2026-07-23) Added a seven-language strict public acceptance matrix for exact structured points-to identity/provenance and `call_input -> points_to` composition. C++, Go, PHP, Ruby, Rust, and Scala also hit the public four-of-five `max_targets` cap; Python's five-way structured flow truthfully exhausts `scope_nodes` before reaching that separate cap and remains covered by shared target-cap plus language-specific budget tests.
- [x] (2026-07-23) Ran the post-audit aggregate checkpoint gate: formatting and diff checks, warning-free `cargo check --lib`, 308 focused integration tests, 132-language semantic conformance cases within that set, four bounded-regression tests, three limited-materialization tests, and four hostile resource-bound tests all pass.
- [x] (2026-07-23) Checkpointed the final sweep at `c4bc8f97`, fetched `origin/master` through `5e6e6f08`, and rebased all eight branch commits. The two C# conflicts preserve upstream chained-extension and initializer fixes inside the bounded stack-safe receiver program.
- [x] (2026-07-23) Ran the upstream 73-test C# definition/type slice after the rebase. It exposed one normalized persisted lookup that crossed generic arity; the provider now preserves the requested arity before returning normalized candidates, and all 73 C# tests plus 151 focused receiver/pipeline tests pass.
- [ ] Commit the post-rebase arity fix, run the isolated CI-equivalent gates, open one pull request that closes #1107 and #1108 through #1115, wait for green CI, and squash-merge it.
- [ ] Verify #1107 and #1108 through #1115 are closed, `origin/master` contains the consolidated squash merge, all final validation gates pass, and build artifacts have been cleaned.

## Surprises & Discoveries

- Observation: The public query pipeline is language-neutral, but `ReceiverQueryService::analyze` still contains separate Java and JS/TS implementations and rejects every other language before source projection.
  Evidence: `src/analyzer/usages/receiver_query.rs` routes Java to `analyze_java`, accepts JavaScript/TypeScript through `JsTsReceiverFactProvider`, and otherwise emits `receiver_analysis_language_unsupported`.

- Observation: Removing that language gate would not expose useful, sound receiver analysis. The C++, C#, Go, PHP, Python, Ruby, Rust, and Scala lowerers currently create call-local values of `SemanticValueKind::Receiver`, but do not broadly emit procedure receiver ports, parameter values, lexical locals, assignments, allocations, return flow, or memory facts. A call-site receiver is an expression value; `SemanticValueKind::Receiver` must be reserved for the procedure's current-receiver port.
  Evidence: `HeapOracle::pointees` reports open coverage when Values, Assignments, Allocations, LocalFlow, ParameterFlow, ReceiverFlow, ReturnFlow, or Captures are unavailable. The eight adapters currently declare these components partial or omit the corresponding facts.

- Observation: The semantic gate currently remembers candidate truncation but drops the stronger distinction between exhaustive and open coverage. A nonempty partial `SemanticOutcome` can therefore filter a compatibility-provider result while leaving it `Precise`.
  Evidence: `semantic_receiver_gate` stores only `points_to` and `points_to.coverage().is_truncated()`, while `apply_semantic_gate` preserves a precise compatibility result when all retained values match.

- Observation: Exact definition resolution supports every target language, but public type lookup supports only C#, Go, Java, JavaScript/TypeScript, Rust, and Scala. C++, PHP, Python, and Ruby keep useful structured receiver-type logic private to their definition resolvers.
  Evidence: `src/analyzer/usages/get_type/mod.rs` does not route those four languages; their structured helpers live in `get_definition/cpp.rs`, `get_definition/php.rs`, `get_definition/python.rs`, and `get_definition/ruby.rs`.

- Observation: The generic definition batch API checks cancellation between requests, but a single language resolver invocation does not share the receiver ledger internally. Java has a dedicated `JavaResolutionSession`; the rollout needs a shared bounded seam rather than eight uncharged calls.
  Evidence: `resolve_definition_batch_with_source_and_cancellation` polls between batch entries, while Java's receiver implementation explicitly charges parse preparation, tree walking, hierarchy expansion, and candidate projection.

- Observation: Factory-return provenance cannot be fabricated from a callee name. The heap oracle currently follows intraprocedural assignment, value-flow, and allocation edges; interprocedural call bindings exist separately and are not composed into source points-to.
  Evidence: `ValueFlowOracle::call_bindings` exposes actual/formal and result/return relations, while `HeapOracle::pointees` does not yet cross those bindings.

- Observation: Exporting a callee allocation into a caller points-to result violates the semantic model's procedure-local handle invariants. The honest shared representation is a caller-local call-result root that retains validated dispatch, normal-return binding, and callee return-flow relations as audit material.
  Evidence: `AbstractObject::validate_at` and `OracleRelationOwner::PointsTo` reject callee-local handles/evidence in a caller-owned points-to result; the new `CallResultHandle` keeps those upstream relation arenas private while validating the public root against the caller.

- Observation: Source ranges shared by a call's callee, result, thrown value, and continuation points can make an otherwise exact source query open or polluted if every value is observed at every same-span point.
  Evidence: The first exact C# construction test returned an open aggregate with transient callee/exception observations. Phase-aware source projection now observes call results only at the normal continuation, thrown values only at the exceptional continuation, and callees at invocation.

- Observation: C# `this` and `base` are unnamed tree-sitter keyword nodes. A named-child-only lookup selects the enclosing member access and cannot type the keyword range itself.
  Evidence: The end-to-end current-receiver query initially returned unknown. Bounded C# lookup now descends through all tree-sitter children and focused tests resolve `this` to the enclosing class and `base` to its direct parent.

- Observation: Partial declarations are one logical C# type and therefore cannot exercise a candidate-output cap. A branch with two distinct allocation sites of the same type is the correct behavior-focused cap fixture.
  Evidence: Two partial `Service` declarations deduplicated to one `CodeUnit`; the replacement branch fixture produces two neutral allocation candidates and proves `max_targets = 1` cannot remain precise.

- Observation: Canonical `FileFacts` already provide a cross-language receiver-site contract. Every analyzable language normalizes explicit member calls with `Role::Receiver` and field/member access with `Role::Object`, plus an exact terminal member name.
  Evidence: `src/analyzer/usages/get_definition/call_sites.rs::call_site_syntax_for_reference` already projects call receiver and callee ranges from `FileFacts` without reparsing or language dispatch. C# normalizes both direct and conditional access through these roles.

- Observation: A filename-keyed staging cache is not a safe way to hand normalized facts to receiver analysis. Two rows may refer to different overlay generations of the same `ProjectFile`, and source-text equality alone is weaker than retaining the exact structured-fact snapshot.
  Evidence: `ReceiverSiteIndex` already owns the input `Arc<FileFacts>`. The pipeline can pass that exact Arc from `StructuralMatch`/trace provenance into each receiver expansion and validate cache reuse against the same snapshot.

- Observation: C# access exceptions must be modeled after receiver and index evaluation, not on the expression entry point. Placing the gap first made a fully evaluated local/property receiver appear semantically incomplete even though only downstream exceptional control flow was unsupported.
  Evidence: The indexed-access conformance topology now evaluates `handlers`, `NextIndex()`, and its normal continuation before reaching the element-access exception gap; ordinary property receiver traversal retains exhaustive value evidence.

- Observation: C# object identity cannot flow transparently through every source assignment. Null/default values have no represented object identity, and casts, `as`, explicit typed initializers, and ordinary assignments may invoke user-defined conversions.
  Evidence: Value-scoped `Values` gaps now keep these paths open while still retaining useful structured candidates. A public pipeline regression proves none is promoted to `precise`.

- Observation: Exact bounded resolution must bound provider work before materialization, including one-row lookahead used to prove completeness. Charging a `Vec` after an unbounded supplier returns records work but does not prevent denial-of-service behavior.
  Evidence: Adversarial review found `ResolutionSession::query_rows`, per-unit metadata/range reads, and cold global-using discovery could all perform unbounded work before the receiver ledger observed it.

- Observation: Pre-conversion object candidates are actively misleading in C#. A value constructed as `Source` and assigned through a user-defined conversion to `Target` must not be published as a `Target` allocation.
  Evidence: Explicitly typed initializers, assignments, casts, `as`, null/default, and conditionals without provably identity-preserving branch construction now terminate identity flow with a value-scoped gap. Focused public receiver tests retain no pre-conversion allocation candidate.

- Observation: Large multi-purpose receiver fixtures can exhaust the same finite ledger for reasons unrelated to the behavior under assertion.
  Evidence: A property-chain assertion embedded beside extensions, conditionals, constructors, and factory calls exhausted the default summary/scope budget, while the isolated property project completes with one exact closed member candidate and explicit ambiguous coverage. Resource-bound tests remain separate and intentionally tiny.

- Observation: The connected Bifrost MCP initially could not bind this worktree, and the installed one-shot binary rejected the live cache because the cache schema is newer than the binary. Lazy tool binding later recovered the current worktree and is now the primary symbol navigation path.
  Evidence: Initial MCP calls returned `Bifrost is not bound to a workspace`; the local binary reported cache `user_version 10` exceeds supported version `9`. Later `search_symbols`, `get_symbol_sources`, and `get_summaries` calls resolved the modified C# implementation directly.

- Observation: Rust declarations are not exposed through the generic persisted exact-FQN/member lookup tables used by C#, even though the identifier index contains the exact Rust units.
  Evidence: The first bounded `Service.run` regression returned no definition. A bounded identifier query followed by exact `fq_name` filtering resolves the member without hydration or same-name fallback.

- Observation: Declaring `Captures` globally unsupported opens otherwise exhaustive Rust `self` points-to queries, even when the queried procedure contains no closure capture.
  Evidence: Marking the capability partial and emitting an explicit gap only for closure values preserves an honest open capture boundary while allowing ordinary current-receiver evidence to remain exhaustive.

- Observation: Call-site `Calls` gaps were opening already-evaluated receiver and argument identities even though the shared gap contract says only call-produced values are incomplete unless an adapter adds `CallEvaluation`.
  Evidence: A focused heap-oracle regression now keeps an evaluated argument exhaustive while the same unresolved call's result stays open. Go and Scala then exposed two adapter gaps whose subjects or positions incorrectly crossed receiver evaluation; moving the Go selector exception boundary after its operands and scoping Scala selection gaps to the produced value restored exact receiver evidence.

- Observation: Python path-synthetic module declarations made the generic limited lookup conservatively incomplete even when a receiver query only needed classes, functions, or members.
  Evidence: Every bounded Python identifier lookup exhausted the scope budget regardless of fixture size. A dedicated non-module limited lookup now proves completeness without scanning or silently omitting path-synthetic modules, because its predicate excludes that declaration kind by contract.

- Observation: Structured type arenas removed recursive stack risk but initially admitted arbitrarily large node and string sequences, so a persisted metadata row could still allocate substantial work before a bounded request observed it.
  Evidence: The adversarial model test could construct, serialize, clone, and deserialize 50,000 wrapper nodes. Builder, wire, name-component, edge, string-byte, and persisted-row admission now have fixed caps, while a cap-depth small-stack test retains the stack-safety proof.

- Observation: A source-size cap on prepared syntax is not enough if the preparation path first hydrates or analyzes an entire cold `FileState`.
  Evidence: `prepare_syntax_for_key_cancellable` called `fetch_file_state_for_key_with_source`, whose cold miss runs adapter analysis and store writes before the cancellable tree-sitter parse. The limited path must own the admitted exact source directly and avoid full hydration.

- Observation: Exact qualification and lexical visibility must survive all the way to the bounded resolver.
  Evidence: C++ discarded a leading global `::` before probing lexical namespaces, while Rust retried an unresolved file-module bare type against a crate-global same-name declaration. Collision regressions now require those paths to fail closed or select only the structurally visible owner.

- Observation: Declaration identity alone does not describe an inherited C++ base subobject or a promoted Go path.
  Evidence: A non-virtual C++ diamond reaches two distinct `Base` subobjects while a virtual diamond converges on one, and the same Go declaration reached through two nearest-depth embedding paths remains ambiguous. Parser-derived edge/path identities now preserve both distinctions without recursive or name-only lookup.

- Observation: Work bounds must include normalized role edges and failure paths, not only fact nodes and successful rows.
  Evidence: A single variadic call could produce hundreds of roles after node admission; store failures could become complete empty results; dirty lookups cloned the whole map before charging. Role creation, cached fact admission, bounded fallbacks, and dirty scans now share the same cancellation and work accounting.

- Observation: A flat structured-type arena can still encode a shared-child DAG whose naive recursive equality or hashing repeats exponentially.
  Evidence: Exact equality now interns reachable nodes bottom-up across both arenas and hashing computes one digest per reachable node. A depth-80 shared-child regression compares equivalent differently shared shapes without repeated subtree expansion.

## Decision Log

- Decision: Use #1109 C# as the reference milestone and include the shared coverage and adapter-seam work in the consolidated pull request.
  Rationale: C# already has mature structured member resolution and public type lookup, and its issue explicitly requires open coverage never be promoted to precise. It avoids the additional public type seam needed by C++/PHP/Python/Ruby and the most difficult dynamic or trait semantics.
  Date/Author: 2026-07-23 / Codex

- Decision: A language milestone is complete only after its neutral semantic lowerer emits the facts needed by the fixtures; lifting the receiver service's language gate or wrapping a private type helper is insufficient.
  Rationale: The public `points_to` operation derives identity and provenance from neutral semantic facts. Without those facts, an adapter would either return only unknown rows or would need a prohibited parallel inference engine.
  Date/Author: 2026-07-23 / Codex

- Decision: Derive receiver sites from structured tree-sitter facts and roles, then decorate neutral object identities through existing exact definition and type services.
  Rationale: This keeps syntax ownership in language adapters, semantic identity in the neutral oracle, and declaration identity in the exact resolvers. It avoids source mini-parsers, regex fallbacks, and eight graph-specific query engines.
  Date/Author: 2026-07-23 / Codex

- Decision: Consume the canonical normalized `FileFacts` emitted by the structural adapters instead of reparsing source in `ReceiverQueryService`.
  Rationale: The normalized Call and FieldAccess facts already preserve exact receiver, object, callee, and field spans for all target languages. Reusing them keeps source and ranges generation-coherent and gives later language milestones the same site-selection behavior.
  Date/Author: 2026-07-23 / Codex

- Decision: Treat open, incomplete, or truncated semantic evidence as non-precise even when candidates are retained.
  Rationale: Candidate coverage describes whether unseen valid candidates may exist. A useful partial candidate set can be `ambiguous`, but cannot be `precise`.
  Date/Author: 2026-07-23 / Codex

- Decision: Land languages with existing public type lookup before languages that need type-lookup promotion, with Ruby last among the dynamic adapters.
  Rationale: Go, Rust, and Scala can exercise the shared seam with fewer unrelated API changes. Ruby's dynamic boundaries provide the strongest final adversarial check of the conservative precision policy.
  Date/Author: 2026-07-23 / Codex

- Decision: Keep global schema prose, capability-matrix normalization, cross-language conformance, and Java/JS/TS migration for the final #1107 sweep, while each language checkpoint adds truthful behavior tests.
  Rationale: Repeated edits to the same central files would cause unnecessary merge conflicts. Each child still documents its delivered behavior, and the final sweep makes the global surface coherent.
  Date/Author: 2026-07-23 / Codex

- Decision: Represent supported interprocedural returns with `AccessPathRoot::CallResult`, not a callee allocation or a C#-specific receiver object.
  Rationale: The root is caller-local and valid in points-to results, while its private handle preserves the exact dispatch, binding, and return-flow chain. The receiver layer may decorate that neutral identity as `FactoryReturn` without moving semantic ownership into the adapter.
  Date/Author: 2026-07-23 / Codex

- Decision: Charge flat scans of call rows as scope/nested-entry work and reserve summary-expansion work for actual dispatch, binding, and callee-flow queries.
  Rationale: Counting a source-index scan as an interprocedural expansion doubled call-site work and exhausted the default budget on unrelated local receivers. Both scans remain finite and cancellable, and a 128-unrelated-call regression fixes the accounting contract.
  Date/Author: 2026-07-23 / Codex

- Decision: Reuse prepared C# syntax only when it is derived from the same atomic source snapshot as the exact `Arc<FileFacts>` supplied by the pipeline.
  Rationale: The receiver service must not reparse normalized facts, but it still needs a tree for the authoritative C# resolver. Analyzer-owned prepared syntax preserves the established cache and overlay semantics; a snapshot mismatch terminates conservatively.
  Date/Author: 2026-07-23 / Codex

- Decision: Treat direct compile-time type references as a separate structured precision path, while canonicalizing partial declarations to one representative logical type.
  Rationale: Static receivers do not require runtime points-to evidence, but aliases, predefined types, `global::` qualification, ambiguity, and partial declarations still need exact resolver status. Only a resolved logical singleton can be precise.
  Date/Author: 2026-07-23 / Codex

- Decision: Reserve and charge provider lookahead explicitly, and discard partial exact-resolution rows when completeness cannot be proven within the supplied limit.
  Rationale: Returning the first bounded rows without proving the absence of another candidate could silently turn an overload set into a singleton. Honest inspected-row accounting and a terminal incomplete status preserve the precision contract.
  Date/Author: 2026-07-23 / Codex

- Decision: Stop C# object-identity flow at any assignment or conversion whose identity semantics are not proven structurally.
  Rationale: Retaining a pre-conversion allocation as a useful candidate changes its declared type during public projection and is worse than an honest unknown result. Identity-preserving implicit locals and same-type constructions remain supported; all other conversion-sensitive paths stay open until the exact conversion resolver can prove them.
  Date/Author: 2026-07-23 / Codex

- Decision: Keep exact `Arc<FileFacts>` input mandatory for structural receiver analysis and acquire missing cross-file facts only in the structural executor.
  Rationale: Language adapters must not hide uncharged parse work or combine overlay generations. The executor now loads each missing file once through the normal structural provider/cache, charges source and fact work to the shared query budget, and reuses the request-local Arc for subsequent rows.
  Date/Author: 2026-07-23 / Codex

- Decision: Publish the complete language rollout in one pull request while retaining language-sized checkpoints and reviews.
  Rationale: The user explicitly preferred one large PR. The adapters share the receiver service, neutral oracle contracts, schema, capability documentation, and conformance surface, so one integration branch removes repeated merge/rebase overhead and permits the final architectural cleanup before review.
  Date/Author: 2026-07-23 / User and Codex

- Decision: Enforce a fixed resource invariant at structured-signature construction, deserialization, and persistence boundaries in addition to request-ledger row limits.
  Rationale: Row-count lookahead cannot protect a bounded request if one row can contain an unbounded flat type arena. Fixed node, edge, component, string-byte, and serialized-row caps make every admitted row finite before clone or decode; consumers still charge semantic traversal through the request session.
  Date/Author: 2026-07-23 / Codex

- Decision: Fail oversized structured-signature persistence atomically instead of publishing a complete file state with omitted metadata.
  Rationale: Silent omission makes a cold-cache exact query look complete when required type evidence never reached the store. A non-allocating serialized-size preflight now rejects the write and leaves the authoritative dirty state available for bounded reads.
  Date/Author: 2026-07-23 / Codex

- Decision: Treat one exact Go or C++ data-field declaration as statically bound, while retaining semantic and dispatch closure gates for callables.
  Rationale: Ordinary data fields do not participate in virtual/callable dispatch. Requiring closed runtime receiver evidence turned an exact structured field into an ambiguous result, while applying the exception only after exact singleton field resolution preserves uncertainty for promoted, overloaded, and callable members.
  Date/Author: 2026-07-23 / Codex

- Decision: Preserve C# generic arity when a bounded exact-FQN lookup falls through to the normalized persisted index.
  Rationale: Normalization may reconcile alias and nested-type spelling, but it must not turn an exact `Box` arity-zero miss into `Box<T>`. Filtering the bounded provider batch by the same arity-preserving key used by the live usage index retains upstream #1093 behavior without hydrating the workspace.
  Date/Author: 2026-07-23 / Codex

## Outcomes & Retrospective

All eight child milestones are implemented on the consolidated branch. C++ #1108 supports structured object/pointer receivers, exact lexical namespaces and inheritance, constructors and factory returns while keeping virtual, template, preprocessing, and plain-C boundaries explicit. C# #1109 supports typed locals and parameters, static/current receivers, allocations, closed members, exact extensions, conditional/property sites, and validated call results without relabeling conversion-sensitive objects. Go #1110 models named receivers, addressable value and pointer method sets, embedded promotion, allocations, and factory returns while interfaces and unresolved generic dispatch stay open. PHP #1111 and Python #1112 publish neutral local/call/return identity and reuse exact bounded language resolvers for supported instance, static/class, null-safe, annotated, and factory-return forms. Ruby #1113 supports current, explicit, class/module, local-alias, constructor, ancestor, and singleton-factory receivers with dynamic metaprogramming kept open. Rust #1114 supports exact `self`, rooted lexical module paths, typed values, structs and enum variants, supported factory returns, and closed inherent members while trait-object dispatch stays open. Scala #1115 supports direct, inherited, infix, postfix, right-associative, `super`, factory-return, and exact extension receivers with incomplete hierarchy, implicit-conversion, and dynamic boundaries kept non-precise.

The shared architecture now carries canonical structured receiver sites and parser-derived type identities through one request-local work ledger. Exact definition/type sessions, cold persisted projections, hierarchy expansion, factory-return composition, and structural-fact acquisition all poll cancellation and stop before finite candidate, row, syntax, or metadata limits. Prepared syntax is reused only for the exact source snapshot. Structured type metadata has fixed construction, serialization, and hostile-deserialization admission limits, so a bounded row query cannot materialize an unbounded payload. Open, ambiguous, incomplete, or truncated evidence may retain candidates but cannot become `precise`.

The initial diagnosis prevented an unsound gate-only rollout, and three adversarial architecture sweeps found pre-materialization work, false-precision, lexical-owner, cold-store, addressability, hierarchy, inherited-path identity, role-edge accounting, DAG traversal, and hostile-payload gaps before publication. Cumulative focused validation now covers all three receiver operations, same-name negatives, explicit uncertainty, candidate limits, tiny budgets, cancellation, structural capture and call-input composition, neutral semantic value identity, full semantic-language topology, executable tutorials, documentation contracts, and the rendered documentation site. The final repository-policy audit found no source-text parser fallbacks, unbounded recursive receiver walks, unsafe path handling, or registry-mirroring tests. The isolated strict clippy and all-feature test gates are deliberately deferred until after rebasing the frozen implementation onto current `origin/master`.

## Context and Orientation

The main service is `src/analyzer/usages/receiver_query.rs`. It accepts a receiver operation, source file and byte range, input mode, `ReceiverAnalysisBudget`, and optional cancellation token. It returns a `ReceiverQueryReport` whose `ReceiverAnalysisOutcome` is precise, ambiguous, unknown, unsupported, or exceeded-budget. A `ReceiverWorkLedger` combines setup work, neutral semantic work, and exact compatibility work. Java uses prepared parsed files and `JavaResolutionSession`; JavaScript/TypeScript uses `JsTsReceiverFactProvider`.

The language-neutral semantic layer is under `src/analyzer/semantic/`. Each language lowerer produces a `ProcedureSemantics` artifact containing source-backed values, allocations, assignments, value-flow edges, memory effects, call sites, exits, and explicit gaps. A `WorkspaceSemanticOracle` composes those artifacts. `WorkspaceSemanticOracle::pointees_at_source` maps a source range to `SourcePointsToResult`, whose abstract object candidates carry structured identities and `CandidateCoverage`. Exhaustive coverage proves no additional candidate is hidden by the modeled facts. Open coverage means missing facts or dynamic behavior may hide candidates. Truncated coverage means a finite limit omitted candidates.

The exact definition dispatcher is `src/analyzer/usages/get_definition/mod.rs`. Its language modules already understand language-specific member syntax and ownership. The public type dispatcher is `src/analyzer/usages/get_type/mod.rs`. The query service must reuse these resolvers; it must not select members by spelling alone.

The CodeQuery pipeline is implemented under `src/analyzer/structural/search/`. Stable receiver result DTOs live in `src/analyzer/structural/search/results.rs`, and declarative JSON/RQL vocabulary lives in `src/analyzer/structural/query/schema.rs`. End-to-end tests belong in `tests/code_query_pipelines.rs`, using `tests/common/inline_project.rs::InlineTestProject`. Neutral semantic contracts are covered in `tests/semantic_value_language_contract.rs`. Executable tutorials are checked by `tests/code_query_tutorials.rs`; receiver documentation lives under `docs/src/content/docs/`.

A receiver site is the source expression used as the object of a member access or call. A receiver target is a stable description such as a current receiver, typed parameter, allocation site, static type, module object, or supported factory result. Points-to asks which neutral abstract objects the expression may denote. Member targets asks which exact declarations the member access may resolve to. Provenance explains which supported source relationship produced a public receiver value; ordinary reference or call resolution is not itself receiver provenance.

## Plan of Work

### Milestone 1: establish the shared bounded seam and deliver C# (#1109)

First correct the semantic gate in `src/analyzer/usages/receiver_query.rs` so it retains the `SemanticOutcome` quality and `CandidateCoverage`. Map any open, partial, unproven, unknown, ambiguous, or truncated evidence to a non-precise public result while retaining supported candidates. Exceeded budget and cancellation remain terminal and use the existing ledger.

Replace language-specific receiver-site extraction at the service boundary with a small structured descriptor. The descriptor records the observation range, receiver range, optional member-name range, and whether the normalized site is a call or field access. Build it from the canonical `FileFacts` emitted by the language structural adapter: Call uses `Role::Receiver` and the terminal normalized name, while FieldAccess uses `Role::Object` and `Role::Field`. Static versus instance access remains a semantic decision for the type resolver. Scan and index facts within the receiver setup budget and poll cancellation; cache only a complete site index.

Generalize Java's bounded exact-resolution wrapper enough that C# type and member decoration can use existing `get_type` and `get_definition` services without an unbounded parallel graph. Keep the language-specific resolver authoritative. Generalize neutral-object-to-`ReceiverValue` mapping for allocation, current receiver, parameter, static/type, module, and other supported roots. If an identity lacks sufficient structured decoration, retain an unknown or ambiguous row rather than inventing a label.

In `src/analyzer/csharp/semantic.rs`, emit real procedure current-receiver and parameter ports, source-backed expression values, scope-distinct locals, simple assignment/value-flow edges, object-creation allocations, return flow, and call result/thrown values for the C# constructs selected by the tests. Connect `CallSite.receiver` to the actual source expression value; do not create an unconnected call-local `SemanticValueKind::Receiver`. Claim semantic capabilities only for facts that the adapter now emits, and preserve explicit gaps for dynamic values, unresolved extension applicability, delegates, virtual/interface dispatch, and other incomplete behavior.

Add `InlineTestProject` coverage proving all three operations on member and conditional access, `this`, typed parameters/locals/fields, constructors, properties, a supported factory/call result if interprocedural composition is ready, and extension methods where applicability is exact. Include an unrelated same-name member negative, an open or unsupported dynamic boundary, candidate truncation, tiny-budget exhaustion, cancellation, and structural-capture composition. Add neutral-fact contract tests for the lowerer. Update the C# executable tutorial and capability statement without claiming unsupported forms.

The milestone is accepted when supported C# fixtures no longer return `receiver_analysis_language_unsupported`, all three operations return the stable result shape, no open/truncated result is precise, exact member negatives pass, and focused tests pass. Its checkpoint and review then become part of the consolidated PR that fixes #1109.

### Milestone 2: deliver Go (#1110)

Extend `src/analyzer/go/semantic.rs` with current/named receiver ports, parameters, locals, assignments, allocations, returns, and source-backed selector receiver values. Reuse `get_type/go.rs` and `get_definition/go.rs` through the shared seam. Cover named receivers, selectors, struct/pointer allocation forms, pointer and value method sets, and promoted methods. Preserve open coverage for interface dispatch and unresolved embedding or method-set uncertainty. Add the full behavior, neutral-fact, limit, cancellation, and exact same-name-negative suite, then checkpoint the #1110 implementation on the consolidated branch.

### Milestone 3: deliver Rust (#1114)

Extend `src/analyzer/rust/semantic.rs` with `self` ports, typed parameters/locals, struct and supported constructor allocations, assignments, returns, and source-backed field/method receiver values. Reuse `get_type/rust.rs` and `get_definition/rust.rs`. Cover `self`/`Self`, associated items, struct construction, and the exact autoderef/autoref cases already modeled by the resolver. Preserve ambiguity or open coverage for unresolved trait method sets, generic constraints, and dynamic trait objects. Add the standard conformance and resource-bound tests, then checkpoint the #1114 implementation.

### Milestone 4: deliver Scala (#1115)

Extend `src/analyzer/scala/semantic.rs` with current receiver, typed parameter/local, allocation, assignment, return, and application receiver facts. Reuse `get_type/scala.rs` and `get_definition/scala.rs`. Cover field/application/infix/postfix shapes, constructors, exact inherited members, and exact extensions. Keep `super`, unresolved givens/implicits/conversions, `Dynamic`, incomplete trait conflicts, and unresolved extensions non-precise until real structured support exists. Emit a neutral static/module root before claiming singleton precision. Add the standard tests, then checkpoint the #1115 implementation.

### Milestone 5: deliver C++ (#1108)

Promote the existing structured C++ expression/receiver type helpers from `get_definition/cpp.rs` into the public type dispatcher without copying syntax logic. Extend `src/analyzer/cpp/semantic.rs` with current `this`, typed parameters/locals, object allocations, assignments, returns, and source-backed object/pointer receiver facts. Cover dot and arrow access, constructors, direct return chains where neutral call binding supports them, exact inheritance, and supported virtual cases. Preserve open coverage for templates, dependent names, unresolved preprocessing, pointer alias uncertainty, and open virtual dispatch. Add the standard tests, then checkpoint the #1108 implementation.

### Milestone 6: deliver PHP (#1111)

Promote structured PHP receiver type logic into public type lookup. Extend `src/analyzer/php/semantic.rs` with `$this`, typed parameters/locals/properties, `new` allocations, assignments, returns, and source-backed object/static receiver facts. Reuse exact PHP member resolution for object, null-safe, and static access. Leave late-static binding, dynamic member names, magic members, unresolved traits, and runtime-only behavior explicit. Add the standard tests, then checkpoint the #1111 implementation.

### Milestone 7: deliver Python (#1112)

Promote the batch-aware Python receiver type context into public type lookup without rebuilding it per query. Extend `src/analyzer/python/semantic.rs` with `self`/`cls`, annotated parameters/locals, constructor allocations, assignments, returns, and source-backed attribute/call receiver facts. Cover exact class and instance receivers plus annotated factory returns when neutral call binding can prove them. Keep untyped receivers, monkeypatching, `getattr`/`setattr`, descriptors, metaclasses, and unresolved decorators non-precise. Add the standard tests, then checkpoint the #1112 implementation.

### Milestone 8: deliver Ruby (#1113)

Promote `RubySemanticIndex` and its structured receiver type helper into public type lookup. Extend `src/analyzer/ruby/semantic.rs` with instance/singleton current receivers, supported constructor allocations, local assignment flow, returns, and source-backed explicit/current receiver values. Cover exact current receiver, explicit receiver, class/module receiver, `.new`, ancestors, and supported mixin lookup. Treat safe navigation conservatively and leave untyped parameters, `send`/`public_send`, `method_missing`, monkeypatching, refinements, and incomplete mixins explicit. Add the standard tests, then checkpoint the #1113 implementation.

### Milestone 9: complete the #1107 architecture and documentation sweep

After all language checkpoints, refresh `origin/master` and audit the cumulative implementation for duplicated receiver-site parsing, neutral-object decoration, coverage mapping, resolver charging, diagnostics, and language capability declarations. Migrate Java and JS/TS onto the shared seam where doing so removes duplicate policy without weakening their existing behavior. Compose neutral call bindings into bounded factory-return points-to only if child acceptance still requires it and the operation can preserve candidate-specific evidence, budgets, cancellation, and open coverage.

Update the declarative schema descriptions in `src/analyzer/structural/query/schema.rs`, `docs/src/content/docs/code-querying.md`, `docs/src/content/docs/code-query-json.md`, `docs/src/content/docs/capabilities.md`, and `docs/src/content/docs/code-query-tutorials/receiver-traversal.md`. Ensure `tests/code_query_tutorials.rs` executes receiver examples with `execute_workspace`, because neutral source projection needs a `WorkspaceAnalyzer`. Add cross-language conformance that proves each advertised language has at least one precise supported form and one explicit uncertain/unsupported boundary. Render and inspect the docs, then publish the consolidated PR fixing #1107 and all linked language issues.

## Concrete Steps

Work from `/Users/dave/.codex/worktrees/47c5/bifrost` on `dave/1107-bounded-receiver-all-languages`. Fetch before checkpoints when remote state matters, but do not switch to per-issue branches. Rebase the consolidated branch onto current `origin/master` only at safe, reviewed checkpoints.

For source exploration, prefer the Bifrost code-navigation, code-reading, and codebase-search tools. If the current workspace-binding regression persists, record it and use `rg`, `sed`, and focused Rust tests without pretending the tool succeeded.

Apply edits with the patch tool. After each meaningful ExecPlan checkpoint, update this plan and commit only the files changed for that milestone with a multiline commit message explaining the reason for the checkpoint. Run formatting and focused tests before every checkpoint:

    cargo fmt
    git diff --check
    cargo test --test semantic_value_language_contract <focused-test-name> --features nlp,python
    cargo test --test code_query_pipelines <focused-test-name> --features nlp,python

Before each push, run the repository's isolated strict lint gate:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings

When practical for a language milestone, run the relevant resolver suites and the all-feature test gate:

    scripts/with-isolated-cargo-target.sh cargo test --features nlp,python

Stage only explicit changed paths and create one multiline checkpoint commit after each language milestone and its review. Before publication, run five cumulative review passes covering security, duplication, issue intent and tests, operational/CI risk, and architecture. Fix confirmed findings and rerun proportionate validation. Push the consolidated branch and create one ready-for-review PR whose body contains `Fixes #1107` through `Fixes #1115`, a brief summary, `**Key Changes**`, and `**Touch Points**`.

Wait for GitHub checks. If a check fails, inspect the actual Actions log, fix the root cause on the same branch, validate locally, and push the correction. When every required check is green, squash-merge the PR. Use the key-change list as the squash commit body. Refresh `origin/master`, verify the epic and all children closed, and clean the merged worktree's `target` artifacts.

## Validation and Acceptance

Every child milestone must prove behavior through an inline multi-file project. At minimum, the project contains two unrelated owners with the same member spelling. A receiver query over the intended owner must return only the exact declaration selected by the structured language resolver. A points-to query must return a structured neutral identity with source-backed provenance for a supported receiver, parameter, allocation, or call result. A receiver-target query must expose the same stable DTO used by Java and JS/TS. A language-relevant dynamic or unsupported construct must remain explicit.

The tests must force an open semantic component and show that a retained candidate is not `precise`. They must set a candidate limit below the available candidates and show truncation or ambiguity, not ordinary precision. They must use a tiny work budget and observe `exceeded_budget`. They must cancel before or during work and observe cancellation without unbounded traversal. Setup, semantic projection, and exact resolution work must remain within one `ReceiverAnalysisWork` report.

Cross-language acceptance for #1107 requires that the capability matrix matches executable tests, all three receiver operations are supported for at least one honest form in each of the eight languages, all documented uncertain boundaries stay explicit, Java and JS/TS do not regress, and the complete Rust gates pass. The final all-feature suite must not silently skip the `nlp` integration tests.

## Idempotence and Recovery

Formatting, focused tests, strict linting, full tests, GitHub check reads, and documentation builds are safe to repeat. The isolated cargo-target helper removes its uniquely marked target on success, failure, or interruption. Do not create manually named Bifrost target directories under `/tmp`.

If the consolidated pull request conflicts because `origin/master` changed, first inspect the exact overlap. Rebase only when the conflict does not require an unapproved semantic decision. If the conflict changes the meaning of a language contract, record it in this plan and ask the user for direction.

If a language cannot honestly satisfy a requested form without a shared interprocedural or resolver change, keep the boundary explicit, add the shared principled support, or move that support to the final architecture sweep. Do not use source scanning, same-name fallback, or a graph-specific side engine to make a test green.

After the squash merge, retain the git history and GitHub PR as the durable recovery record. Remove only generated build artifacts from this worktree; never sweep user changes or unrelated worktrees.

## Artifacts and Notes

The live issue set is #1107 with language children #1108 C++, #1109 C#, #1110 Go, #1111 PHP, #1112 Python, #1113 Ruby, #1114 Rust, and #1115 Scala. At the start of this plan all were open and none had a pull request.

The starting remote commit was `08cabc21`, `Docs: document Java receiver query support (#1117)`. The original worktree was clean and detached at `d37e72dc`.

The workspace navigation regression was:

    Bifrost is not bound to a workspace. The MCP client must provide an approved
    filesystem root via roots/list, or configure Bifrost with --root or
    BIFROST_WORKSPACE_ROOT.

The installed one-shot binary also reported:

    DatabaseTooFarAhead: user_version 10 exceeds 9

## Interfaces and Dependencies

`ReceiverQueryService::analyze` remains the one public-internal entry point for all language receiver operations. It continues to accept `ReceiverQueryOperation`, `ProjectFile`, source `Range`, `ReceiverQueryInput`, `ReceiverAnalysisBudget`, and optional `CancellationToken`, and to return `Result<ReceiverQueryReport, ReceiverQueryError>`.

The shared receiver-site descriptor must carry only structured information needed by the neutral service: the query/observation range, receiver range, optional exact member range or name obtained from canonical `FileFacts`, and a normalized Call or FieldAccess shape. It must not carry a language graph, reparse source, or derive semantics from source text.

`WorkspaceSemanticOracle::pointees_at_source` remains the authority for value and heap evidence. Its `SemanticOutcome` proof quality and `SourcePointsToResult::coverage` must survive translation. An exhaustive complete singleton may become precise. Open, partial, unproven, ambiguous, or truncated evidence may retain candidates but cannot become precise.

`get_type` remains the authority for nominal receiver decoration, and `get_definition` remains the authority for exact member identity. The receiver layer may add bounded/cancellable sessions or adapters around those services, but must not copy their language logic or select by name alone.

Each semantic lowerer must connect `CallSite.receiver` to a source-backed expression value. `SemanticValueKind::Receiver` denotes the current receiver at a procedure boundary, not an arbitrary call-site receiver. Adapter capabilities are claims about emitted facts; they must be upgraded only with behavior-focused semantic contract coverage.

Revision note (2026-07-23): Created the plan after the live issue audit and three parallel architecture diagnoses. The initial design makes C# the shared reference milestone because it can establish the required precision and budget contracts with existing structured type/member resolution before the remaining languages proceed.

Revision note (2026-07-23): Replaced the planned parsed-tree receiver-site seam with canonical normalized `FileFacts` after verifying that all target structural adapters already emit the required receiver/object/member roles. This removes query-local syntax duplication and leaves static/type classification with the exact resolver.

Revision note (2026-07-23): Updated milestone 1 after implementation and focused validation. The shared foundation now includes phase-aware source projection and a caller-local call-result identity because #1109's factory-return acceptance could not be satisfied honestly by decorating a callee allocation or by source-name inference.

Revision note (2026-07-23): Recorded the post-implementation architectural review. The C# milestone now keeps conversion/null identity open, orders access gaps after receiver evaluation, distinguishes logical partial types, validates factory provenance against call handles, accounts derived indexes in cache weight, and requires generation-coherent facts plus pre-materialization provider bounds before publication.
