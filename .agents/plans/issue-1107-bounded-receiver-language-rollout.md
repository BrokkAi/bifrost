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
- [ ] Implement, review, validate, and checkpoint #1110 for Go.
- [ ] Implement, review, validate, and checkpoint #1114 for Rust.
- [ ] Implement, review, validate, and checkpoint #1115 for Scala.
- [ ] Implement, review, validate, and checkpoint #1108 for C++.
- [ ] Implement, review, validate, and checkpoint #1111 for PHP.
- [ ] Implement, review, validate, and checkpoint #1112 for Python.
- [ ] Implement, review, validate, and checkpoint #1113 for Ruby.
- [ ] Run the cross-language architecture and documentation sweep, open one pull request that closes #1107 and #1108 through #1115, wait for green CI, and squash-merge it.
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

- Decision: Keep exact `Arc<FileFacts>` input mandatory for C# receiver analysis and treat cross-file rows without coherent facts as unsupported until the final shared pipeline sweep.
  Rationale: Cold materialization inside the language adapter would hide uncharged parse work and could combine different overlay generations. Same-file structural and reference composition is already supported; any cross-file acquisition must happen once in the structural executor with its normal cache profile and shared execution budget.
  Date/Author: 2026-07-23 / Codex

- Decision: Publish the complete language rollout in one pull request while retaining language-sized checkpoints and reviews.
  Rationale: The user explicitly preferred one large PR. The adapters share the receiver service, neutral oracle contracts, schema, capability documentation, and conformance surface, so one integration branch removes repeated merge/rebase overhead and permits the final architectural cleanup before review.
  Date/Author: 2026-07-23 / User and Codex

## Outcomes & Retrospective

C# #1109 is the first completed checkpoint on the consolidated branch. Supported typed locals, parameters, exact static types, current receivers, allocations, constructors, closed members, exact extensions, conditional/property sites, and validated call results now use the stable receiver-analysis result contract. Virtual/interface/delegate/overload/dynamic/unresolved-extension and conversion-sensitive paths remain explicitly non-precise. Provider work is capped before materialization, cancellation and shared work accounting are preserved, and persisted metadata/range lookup does not require full file hydration.

The initial diagnosis prevented an unsound implementation that would merely remove the language gate and accidentally promote open oracle evidence to precise. The adversarial review also prevented pre-conversion objects from being relabeled as a target type. Focused validation passed the C# CodeQuery pipeline suite, neutral semantic contract suite, broader C# unit filter, call-result collision regression, indexed/conditional access topology, formatting, diff checks, and library compilation. The macOS all-feature test binary currently requires the repository's Python-link environment; a direct all-feature invocation failed at link time before executing tests and remains a final-gate environment task rather than a C# behavior failure.

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
