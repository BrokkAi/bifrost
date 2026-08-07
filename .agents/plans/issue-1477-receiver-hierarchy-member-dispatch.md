# Expose receiver evidence, hierarchy paths, and member-dispatch candidates to RQLP (issue #1477)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

Parent context: this is child issue #1477 of epic #1472, which turns 275 mined Bifrost bug-fix commits into typed RQL/RQLP capabilities. This slice owns receiver value/type evidence, member-candidate enumeration and selection, hierarchy paths, canonical method families, and bounded dispatch. Callable signature and overload applicability belongs to sibling #1478; this plan records enough candidate disposition to explain member selection, but does not duplicate #1478's argument-conversion or overload-ranking model. Canonical identity through arbitrary aliases and indirection belongs to #1475; this plan uses exact analyzer `CodeUnit` identity and reports incomplete family identity when the production analyzer cannot canonicalize it.

## Purpose / Big Picture

Today `receiver_targets`, `points_to`, and `member_targets` can answer useful bounded questions, but each source site produces one report containing arrays of values or selected declarations. The public result does not expose every member considered by the resolver, why candidates lost, which hierarchy route found them, which dispatch tier won, or whether several declarations belong to one override/implementation family. RQLP therefore cannot state the invariant that motivated this issue: for this receiver occurrence, these are all candidates, this candidate is the unique language-semantic winner, and no lower-priority or wrong-owner declaration was selected.

After this plan is complete, an RQLP assertion can bind call or member occurrences, expand each binding into receiver-evidence and member-candidate rows, join the rows by stable source-site IDs, group candidates by occurrence, compute minimum hierarchy depth or winning dispatch tier, count distinct canonical candidates, and require exactly zero, one, or many winners. Every source site emits an outcome row even when evidence is unknown, unsupported, ambiguous, open, truncated, cancelled, or over budget, so absence of candidate rows can never masquerade as proof that no candidate exists. Candidate rows retain exact owner, hierarchy route, generic substitutions known to the resolver, dispatch tier, applicability, selection disposition, rejection reason, proof, and completeness. Separate family and bounded-dispatch rows relate overrides and implementations through canonical method-family IDs.

The behavior is visible through `query_code` JSON/RQL result rows and through `run_policy`. End-to-end fixtures demonstrate typed locals, declaration-owner versus runtime-value-type differences, factories, aliases, nested chains, inherited and promoted members, direct-member precedence, extensions, union/intersection receivers, ambiguous traits, and wrong-owner decoys. For a seeded bad resolver result, an invariant policy reports one multi-location finding containing the receiver, selected member, and competing candidates; the corrected fixture is clean; an incomplete language/provider result is `unreliable`, never clean.

## Progress

- [x] (2026-08-04 08:47Z) Read issue #1477 and parent #1472, inspected current receiver queries, semantic oracle evidence, hierarchy APIs, dispatch metadata, RQL pipeline execution, and the 58 motivating commit subjects.
- [x] (2026-08-04 08:47Z) Confirmed that #1473 is concurrently adding occurrence-role rows and stable AST IDs; Milestones 1 and 2 are complete on `dave/github-issue-1473-e95196`, while its RQL exposure and assertion work remain in progress.
- [x] (2026-08-04 08:47Z) Drafted this implementation-ready ExecPlan with the dependency and sibling-issue boundaries made explicit.
- [x] (2026-08-05 10:25Z) Fetched `origin/master` at `aef3d746c`, verified that the reviewed #1473 result was squash-merged as `6d7ea58a0` with all five milestones complete, and attached `dave/issue-1477-receiver-hierarchy-dispatch` directly to that current base. Also verified that #1475 landed as `4eb483db8` and preserves canonical identity through qualified routes and indirection.
- [x] (2026-08-06 09:40Z) Milestone 1: reusable typed row-field and relational assertion foundation. The analyzer-owned row schemas/projections, declarative RQLP parsing/formatting/canonical loading, static type validation, and the bounded iterative join/group/aggregate evaluator landed in PR #1666 (`8f11273e4`). The close-out landed on this branch: `evaluate_relational_assertion_policy` in `crates/bifrost-policy/src/evaluator/assertion.rs` executes every named `bind` query and typed expansion through the production `run_policy` path, violations retain bounded representative rows and become findings anchored at exact source ranges, and `tests/suite_bench_policy/policy_relational_assertions.rs` proves finding/clean/expansion/inconclusive end to end.
- [x] (2026-08-06 11:30Z) Milestone 2: receiver outcome/evidence rows and stable occurrence-to-receiver correlation. The version-1 RQL registry exposes `receiver-outcome` and `receiver-evidence` (the schema lineage was collapsed to a single version 1 by #1683; new vocabulary enters through the version-1 registries, not a version ladder); every analyzed site has a content-scoped `site_id`, an exact fact-backed `site_ast_id` when available, one mandatory outcome projection, and deterministic parent-linked factory evidence rows. Close-out on this branch: row-level fixtures for aliased receivers, ambiguous/open two-type receivers, unknown zero-evidence outcomes, and C# dynamic unsupported outcomes in `search/tests/details.rs`; docs migration adds the typed-row projections to `code-query-json.md` and an executed `Typed Receiver Rows` section to the receiver-traversal tutorial. Per-candidate generic substitutions and semantic provenance handles are explicitly deferred to Milestone 3's resolver-trace seam (see Decision Log) rather than approximated from the compatibility projection.
- [x] Milestone 3: complete member-candidate, selection-summary, and hierarchy-hop rows from the production resolver path. (2026-08-07: closed out; see the dated entries below for the enrichment spine, the Java/Rust/Python/TypeScript rollout, the candidate-hierarchy hop rows, and the recorded TS receiver-path gaps.) (2026-08-06 15:10Z: the selection-summary tranche is complete and `canonical_member_id` landed on candidate rows; `member_targets` is proven equal to the disposition-selected projection behaviorally. Remaining tranche: per-family owner/depth/tier candidate enrichment with parity proofs, and hierarchy-hop rows.) (2026-08-06 13:30Z progress: the language-neutral `member-selection` projection is landed end to end. `(member-selection query)` / `{"op":"member_selection"}` consumes occurrence rows and emits exactly one mandatory summary row per occurrence, projected from the same traced candidate derivation `candidates_of` uses: stable domain-separated `id`, exact `site_ast_id`, decoded member spelling, role, `selected`/`unresolved`/`untraced` outcome, selected/candidate counts, trace completeness, and honest coverage (`exhaustive` for a full trace, `open` for selection-only, `unsupported` when the language records no trace). The row registry, relational-plan expansion (`bind :from site :step member-selection`), REPL/LSP rendering, and the TextMate grammar (which was also missing `receiver-outcome`/`receiver-evidence`) are updated. Remaining: enriched member-candidate rows (owner, hierarchy depth, dispatch tier, applicability, canonical member id) at the resolver seams per semantic family; `candidate-hierarchy` hop rows; `member_targets` re-expressed as the disposition-selected projection; per-family get-definition parity proofs.)
- [ ] Milestone 4: canonical method-family and bounded dispatch relations. (2026-08-06 gap analysis: the neutral dispatch oracle (`oracle/dispatch.rs`, `workspace_oracle/dispatch.rs`) is production-ready per `CallSiteHandle`, with per-candidate proof/completeness/provenance and typed boundaries, but the workspace oracle has no source-position dispatch entry -- only `pointees_at_source` exists -- so `dispatch-outcome`/`dispatch-targets` need a `dispatch_at_source` seam mirroring `workspace_oracle/source.rs` before rows can bridge from CodeQuery call sites. For family edges, no production overrides/implements relation exists anywhere in the analyzer: `TypeHierarchyProvider` supplies type ancestors/descendants only, and `implementation_of` links declaration-only signatures to bodies, not overrides. Building exact per-language override proofs is per-family analyzer work of the same shape as the M3 candidate-enrichment rollout. Neither piece is landable as an honest projection of existing production data.)
- [ ] Milestone 5: RQLP invariants, cross-language conformance fixtures, transports, editor vocabulary, and docs. (2026-08-06 progress: `tests/suite_cross_language/code_query_member_dispatch.rs` is landed with the wrong-owner-decoy conformance for the selection rows, the canonical-identity distinctness proof, the Java mandatory-summary/AST-join test, and an eight-language honesty sweep. The #1477 acceptance trio runs as an RQLP relational policy over `(bind :from site :step member-selection)`: resolving fixture clean, unresolved site one finding with actual 0 at the exact range, truncated binding inconclusive. Measured member-position capability matrix: Rust full trace; TypeScript and Python selection-only traces; Java summarized; Go, C#, C++, PHP, and Ruby state `occurrence_role_unsupported` as an incomplete diagnostic, which makes policies over their rows unreliable rather than clean. Remaining: docs for `member-selection` (code-query-json op table + capability matrix), MCP/CLI/Python-client/VS Code vocabulary checks.)
- [ ] Milestone 6: adversarial review, policy gate, complete validation, and retrospective.
- [x] (2026-08-07) M5 client-vocabulary close-out: the VS Code result union models `receiver_outcome`, `receiver_evidence`, and `member_selection` with rendering in all five result switches and honesty text for non-exhaustive coverage and absent traces (87 extension tests pass); the Python client docstring names the three projections. Docs and MCP already carried the vocabulary from the registries.
- [x] (2026-08-07) M4 prerequisite: `dispatch_at_source` landed on the workspace oracle, mirroring `pointees_at_source` and delegating each located `CallSiteHandle` unchanged to `DispatchOracle::resolve_call`. `SourceDispatchObservation` retains the handle beside each `DispatchResult` so dispatch rows key on semantic identity. Parity with the handle path, typed unknown/unsupported/budget/cancelled outcomes, and conservative aggregate coverage are proven by unit tests (53 dispatch, 133 source). Deliberate divergence recorded: aggregate open coverage is not folded back into outcome quality because `resolve_call` already classifies its own coverage.
- [x] (2026-08-07) M3 remainder complete. Family rollout beyond Java: Rust instruments four member seams (inherent depth 0; trait fallback as `trait_or_interface` at depth 1 with a `trait_impl` hop; both mirrored in the macro token-tree path; a trait-impl member found directly is depth 0 in the trait bucket because depth and bucket are independent axes) and records `wrong_namespace` losers; associated/static calls stay honestly unattributed because that seam holds no receiver type. Python attributes both member seams with true BFS depth and contiguous `extends` routes via a recording-gated re-walk of the same `get_direct_ancestors` edges. TypeScript attributes depth-0 finds (`inherent_or_direct` and `static_or_companion` for `$static` lookups); the provider-resolved receiver path and JS member candidates stay unattributed (the provider returns members without the owner it used). The `candidate-hierarchy` step and `candidate_hop` domain are landed across the registries with the byte-identical `candidate_id` join, the relational-plan expansion, grammar, docs, REPL/LSP rendering, and contiguity/zero-hop/untraced-honesty tests, plus clean and finding policy fixtures. The TypeScript union-annotation collapse is fixed at the get-type seam with AST `union_type`/`intersection_type` walking (two-plus resolving arms now return `ambiguous` with every arm). Validation: cross-language 422, policy 314, analysis crate 1658, plus the four sibling integration suites, all green.
- Discovered gaps recorded as explicit expected-gap tests (follow-up issues needed): the receiver-outcome path has a second copy of the leading-type text scan in `crates/bifrost-js-ts/src/ts_owners.rs:1496` (`ts_leading_type_identifier`), so a union-typed receiver still reports a falsely precise single-candidate outcome through `points_to`/`receiver_outcome`; and TypeScript member resolution performs no superclass/interface walk at all, so an inherited member is `unresolved` with zero candidates.
- [x] (2026-08-07) M4 dispatch tranche: `dispatch-outcome` and `dispatch-targets` are landed end to end over the `dispatch_at_source` seam. Both steps accept structural matches, call sites, reference sites, and occurrence rows; both declare the new `Dispatch` semantic facet, so the pipeline refuses them without workspace oracles instead of answering from structure alone. `dispatch_outcome` is mandatory per input site and states the `SemanticOutcome` variant (`resolved`, `ambiguous`, `unproven`, `unknown`, `unsupported`, `exceeded_budget`, `cancelled`), the oracle's own `CandidateCoverage`, the located call count, the retained target count, truncation, the unsupported capability, and the exceeded budget dimension. `dispatch_target` emits one row per retained candidate plus one per boundary arm that names a target; an unresolved or truncated residual arm names no target and emits no row because the site's coverage already states it. Honesty: `proof` (from `ProofStatus`), `completeness` (from `EvidenceCompleteness`), and `coverage` are published separately, and the derived `dispatch` label is `proven_dispatch` only for a proven, complete arm inside an exhaustive set. Identity: `site_id` is a content-scoped digest under a dispatch-specific domain mirroring the receiver-site recipe, and `site_ast_id` is minted by the exact function the receiver rows use (`receiver::site_ast_id_for_range`), so a dispatch row joins an occurrence row byte-identically. Target identity is a domain-separated digest over the artifact fingerprint and semantic locator -- never an arena id -- and the target declaration is located structurally by span, then rendered through the same `render_unit_declaration` the candidate and hop rows use. The relational expansions `(bind :from site :step dispatch-outcome|dispatch-targets)` execute, which required the assertion evaluator to run binding queries through a workspace-backed executor when the evaluation context carries a workspace (`execute_code_query_detailed_eager_index_workspace`); the analyzer-only path is unchanged. Registry, row-field schema, compact refs, human/REPL/LSP rendering, TextMate grammar, MCP step list, and the code-query-json op table all carry the vocabulary. Validation: cross-language 429, policy 316, analysis crate 1658, policy/mcp/lsp 759, VS Code 87, fmt and workspace clippy clean.
- [x] (2026-08-07) M4 method-family tranche, Java only. The analyzer gained its first production override/implements relation. `MemberFamilyProvider` (`crates/bifrost-analysis/src/analyzer/usages/member_family.rs`) is reached through `IAnalyzer::member_family_provider`, whose default is `None`, so a language that has landed no family is structurally `unsupported` rather than defaulted to supported. The multi-analyzer implements it and passes *itself* as the hierarchy source, mirroring `TypeHierarchyProvider`'s Kotlin-realm delegation, because a Kotlin class can override a Java method and only the composite resolves that ancestor edge. Only forward edges are resolved; `overridden_by`/`implemented_by` come from `java_inverse_member_family`, a bounded inversion over the direct-descendant index that reads the *forward* edges of members below and turns them around, so the two directions cannot disagree. The family id is a `LengthDelimitedDigest` under `bifrost.member_family.v1` over the language label plus each deterministically ordered family root's structured canonical identity (the `canonical_member_digest` recipe), so a root and its overrider carry one id; an unproven family emits no id. Honesty rules landed as typed vocabulary in the core registry: `MethodFamilyRelation` (with an involution round-trip test), `MemberFamilyOutcome` (`proven`, `no_family`, `incomplete`, `unsupported`), `MemberFamilyReason` (proven exclusions separated from missing evidence), and `MemberFamilyCapability`. The `member-family` outcome row is mandatory per member declaration and `family-edges` emits edges only from a proven answer. Registry surface: row-field schema, result value/ref/key, compact refs, human/REPL/LSP rendering, `file_of`, the `member-family`/`family-edges` RQL forms in both spellings, MCP typed-step list, docs op table, TextMate grammar, and the two policy expansion arms (the `RowMemberFamily`/`RowFamilyEdges` atoms already existed unused). Validation: cross-language 436, policy 316, analysis crate 1658, fmt and workspace clippy clean.
- Measured M4 Java member-identity capability, recorded rather than asserted: `parameter_type_spellings`. The Java declaration walk records a structured `CallableArity` and, as of this tranche, each parameter's declared type *spelling* read from the parameter's own AST `type` node, plus `static`/constructor/visibility modifiers from the declaration's `modifiers` node and interface-ness from the class-like node kind. It records no resolved or erased parameter types. The matching rule therefore narrows an ancestor's candidates structurally first (terminal identifier plus recorded arity, inheritable members only) and falls back to the spellings only when that leaves a genuine overload set; that weaker pairing publishes `proof: "unproven"` on the edge, and a spelling that cannot single one candidate out yields `incomplete`/`overload_identity_unproven` with no edge. A member whose modifiers were never recorded is `incomplete`/`modifiers_unrecorded`, never assumed non-static.
- Measured M4 dispatch capability, recorded rather than asserted: Java, Kotlin, C#, Scala, Go, Rust, C/C++, and PHP report `resolved` with `exhaustive` coverage for a closed monomorphic call; TypeScript, JavaScript, Python, and Ruby report `unproven` with `open` coverage for the same shape, so their arms stay `may_dispatch`. A Java interface receiver yields an `unmaterialized` boundary arm at `may_dispatch`. Every analyzed language registers a program semantics provider, so the `unsupported` outcome label is not reachable from an unanalyzed file: such a file yields no input site at all. That boundary is pinned by `a_file_outside_the_analyzed_languages_yields_no_dispatch_site`. Method families (`member-family`, `family-edges`) remain unimplemented; the 2026-08-06 gap analysis about missing production override/implements edges still stands.
- [x] (2026-08-07) M3 enrichment spine and the Java family: `MemberDispatchTier` and `HierarchyRelation` in the core resolution registry (plus `hidden_by_closer_member` and `callable_applicability_deferred` rejection reasons); `MemberEnrichment` (owner, depth, tier, `ApplicabilityVerdict`, hop route) on `TraceCandidate` with a staged member-context mirroring `stage_tier`; the Java member walk records first-discovery parents and per-candidate found-owner/depth and stages attribution at every return, including arity losers as rejected rows; candidate rows project `owner`, `owner_id`, `hierarchy_depth`, `dispatch_tier`, `applicability`. Conformance: depth-2 inherited attribution and depth-0 direct precedence tests pass beside the existing suite.

## Surprises & Discoveries

- Observation: the existing receiver stack already preserves the crucial terminal outcomes. `ReceiverAnalysisOutcome<T>` in `crates/bifrost-analysis/src/analyzer/usages/receiver_analysis.rs` distinguishes `Precise`, `Ambiguous`, `Unknown`, `Unsupported`, and `ExceededBudget`; `ReceiverQueryReport` adds work, candidate truncation, and unsupported semantic capability. The missing work is row-level evidence and candidate-selection detail, not a replacement receiver solver.
  Evidence: `receiver_analysis.rs:16-23`; `receiver_query.rs:94-108`.
- Observation: public `CodeQueryReceiverAnalysis` currently serializes `values: Vec<CodeQueryReceiverValue>` and `member_targets: Vec<CodeQueryDeclaration>` inside one terminal row. `PipelineKey::ReceiverAnalysis` deduplicates by operation, file, and range, so individual receiver facts and member candidates have no independently bindable identity.
  Evidence: `structural/search/results.rs:972-1015`; `structural/search/mod.rs:468-508`.
- Observation: the neutral semantic oracle already has the right proof vocabulary. `OracleCandidate<T>` carries candidate-specific `ProofStatus`, `EvidenceCompleteness`, and bounded provenance; `CandidateCoverage` distinguishes exhaustive, open, and truncated sets; `SemanticOutcome<T>` retains partial values for unknown, unsupported, budget, and cancellation outcomes.
  Evidence: `semantic/oracle/relation.rs:474-545`; `semantic/provider.rs:453-526`.
- Observation: the workspace dispatch oracle already returns candidate-specific dispatch proof and boundaries for exact semantic call sites, but source member resolution does not expose the losing candidates or its precedence trace. Reusing the dispatch oracle is correct for bounded runtime targets; it cannot explain lexical member selection by itself.
  Evidence: `semantic/oracle/dispatch.rs:11-98,230+`; `usages/receiver_query.rs:1265-1325`.
- Observation: the current type hierarchy API exposes direct ancestors and a derived descendant index only. CodeQuery can traverse depth-bounded hierarchy paths internally, but its declaration result discards hop number and complete route. Candidate rows therefore need an explicitly metered path projection rather than reconstructing paths from flattened query results.
  Evidence: `analyzer/capabilities.rs:196-224`; `structural/search/mod.rs:7952-8010`.
- Observation: the 58 commits are not one-language variants of the same bug. They include union/intersection receivers, embedded promotion, traits, extensions, partial types, companion objects, factories, aliases, inherited members, macro/nested chains, direct-member precedence, and inverse-resolution parity across all eleven analyzer families. A language-neutral row contract with explicit per-language capability support is necessary; a single shared winner algorithm would be a second resolver and is prohibited.
- Observation: #1473 intentionally keeps its first occurrence-cardinality assertion specialized and defers generalized named joins, grouping, and set operators to the epic's shared foundation. #1477 is the first child whose own acceptance criteria require joins, minimum/winning aggregation, distinct cardinality, and exact-one/zero/many assertions.
  Evidence: `.agents/plans/issue-1473-semantic-occurrences-ast-role-fidelity.md` on `dave/github-issue-1473-e95196`, Decision Log and Milestone 4.
- Observation: at planning time this worktree was detached at `09eb52b28`, nine commits behind `origin/master`, with pre-existing untracked `.bifrost/` and `src/lsp/` cache artifacts. On 2026-08-05 the user authorized option 1; the worktree is now attached on `dave/issue-1477-receiver-hierarchy-dispatch` at `aef3d746c`, tracking `origin/master`, and the cache artifacts remain untouched.
- Observation: the #1473 feature prerequisite is no longer branch-local. `origin/master` contains its squash merge `6d7ea58a0`, and the checked-in #1473 ExecPlan records occurrence rows, AST-ID correlation, assertion analysis, transports, documentation, and final gates as complete. #1477 can use those contracts rather than recreating them.
- Observation: the merged assertion analysis is broader than the pre-merge plan snapshot: it now has seven specialized families (`occurrence`, `resolution`, `reaching`, `boundary`, `canonical`, `route`, and `round_trip`) sharing one query-completeness gate and finding assembly path. The relational engine must preserve those analyzer-specific proof obligations while consolidating their cardinality mechanics; replacing them wholesale before receiver/member/family rows exist would lose behavior.
  Evidence: `crates/bifrost-policy/src/definition.rs:117-125`; `crates/bifrost-policy/src/evaluator.rs:979-1569`.
- Observation: RQLP's declarative `RecordCursor` currently models a finite number of positional fields and does not admit a variadic sequence of child records. The plan's canonical assertion form places multiple `bind`, `join`, `group`, and `assert` records directly under `analysis`, so parser work must add a bounded variadic positional facility through the central schema rather than special-case raw S-expressions.
  Evidence: `crates/bifrost-policy/src/source.rs:3503-3630`.
- Observation: the TypeScript declared-type lookup collapses union annotations to their first arm. `leading_type_identifier` in `crates/bifrost-analysis/src/analyzer/usages/get_type/js_ts.rs` takes the text before the first non-identifier character, so `caller(service: ServiceA | ServiceB)` resolves the receiver to `ServiceA` alone and the receiver outcome reports `precise`/`exhaustive` with one candidate - a misrepresentation of an open two-arm set. The root cause is text scanning where the tree-sitter `union_type` node carries the structure. Fix this with the union/intersection fixture family in the M3/M5 language rollout (it changes shared get-definition helpers, whose behavior M3 must hold constant while landing the trace, so it must be fixed and proven in that same seam).
  Evidence: `get_type/js_ts.rs:628-634`; a `points_to`/`receiver-outcome` query over that fixture returns `outcome: "precise", candidate_count: 1`.
- Observation: #1473 also landed resolver-owned `TraceCandidate` rows across the language adapters. They already retain selected/rejected outcomes, typed rejection reasons, precedence tiers, boundaries, visibility, and explicit `selection_only` versus fuller trace completeness. #1477 should enrich and correlate this production trace for member selection rather than introduce a second candidate recorder beside it.
  Evidence: `crates/bifrost-analysis/src/analyzer/usages/get_definition/trace.rs`; `crates/bifrost-analysis/src/analyzer/structural/search/environment.rs`; `CodeQueryResolutionCandidate` in `structural/search/results.rs`.

## Decision Log

- Decision: extend the analyzer-owned receiver and resolution paths rather than create a query-only solver.
  Rationale: the production resolver already contains language semantics for aliases, promotion, extensions, traits, partial types, and precedence. RQL rows must be projections of the same decisions used by get-definition and usage analysis, or conformance policies would test a parallel implementation instead of the product.
  Date/Author: 2026-08-04 / Codex.
- Decision: separate one mandatory site outcome row from zero or more evidence/candidate rows.
  Rationale: unknown, unsupported, open, truncated, cancelled, and budget-exceeded states must remain observable even when no candidate exists. A mandatory outcome row prevents an empty candidate relation from being mistaken for a proven zero set.
  Date/Author: 2026-08-04 / Codex.
- Decision: use stable row IDs and foreign keys, not range or spelling equality. Receiver and candidate rows use a `site_id` minted from content identity plus the exact occurrence/call range; when #1473 supplies an AST ID, `site_ast_id` is also retained. Candidate, hierarchy-hop, family-edge, and dispatch rows each have their own domain-separated stable ID and foreign key.
  Rationale: ranges are locations, not identities, and source text cannot distinguish same-name or same-range semantic routes. This agrees with #1473's content-scoped AST identity and the existing semantic oracle handle discipline.
  Date/Author: 2026-08-04 / Codex.
- Decision: add a reusable relational assertion plan to `brokk-bifrost-policy`, while keeping row production and row schemas in `brokk-bifrost-analysis`.
  Rationale: #1477 requires correlation and assertions through RQLP, not a general-purpose database API in `query_code`. Policy evaluation already owns completeness-to-clean/finding/unreliable decisions. Keeping generic bindings and aggregation in policy avoids destabilizing ordinary linear CodeQuery pipelines while still making the operators reusable by sibling conformance policies.
  Date/Author: 2026-08-04 / Codex.
- Decision: the first relational operator set is deliberately finite: named bind, typed field projection, inner join, anti-join, equality filters, grouping, `min`, `count`, `count-distinct`, and cardinality assertions (`exactly`, `at-least`, `at-most`). `exists` is an inner join plus cardinality and `not-exists` is an anti-join. Arbitrary arithmetic, recursive relations, general Datalog, unbounded paths, and user-defined functions are non-goals.
  Rationale: this is the smallest shared algebra that expresses #1477's occurrence-to-receiver-to-candidate joins, winning depth/tier, distinct candidate counts, and zero/one/many invariants. New operators must enter through the same declarative registries in later siblings.
  Date/Author: 2026-08-04 / Codex.
- Decision: member candidates are recorded by resolver-owned selection traces, not rediscovered by enumerating declarations after resolution.
  Rationale: a post-hoc scan cannot know which imports, hierarchy routes, visibility rules, promotions, extensions, or language tiers were considered and rejected. Each language adapter must expose the trace from the same bounded selection path that chooses the production result.
  Date/Author: 2026-08-04 / Codex.
- Decision: #1477 owns member-level applicability and precedence, while #1478 owns callable argument/signature applicability. Candidate rows in this plan distinguish `applicable`, `inapplicable`, and `unknown`; rejection reasons cover receiver ownership, hierarchy depth, visibility, hiding/promotion, member kind, and dispatch tier. When an overload loses only because of call arguments, this plan records `callable_applicability_deferred` unless the production resolver already exposes a structured reason; #1478 later enriches the same row contract.
  Rationale: this preserves a single candidate schema without duplicating sibling #1478's overload model.
  Date/Author: 2026-08-04 / Codex.
- Decision: roll out candidate traces behind an explicit total capability table. Unsupported languages/operations return an outcome row with incomplete capability, never an empty exhaustive set. Milestone 3 lands languages in reviewable semantic families, but the issue is not complete until every claimed language has positive and near-miss fixtures or is explicitly documented unsupported.
  Rationale: eleven independent resolvers cannot honestly inherit a default `supported` answer.
  Date/Author: 2026-08-04 / Codex.
- Decision: no persistence in the first implementation. Rows are demand-derived from the analyzer snapshot, existing persisted facts, semantic artifacts, and resolver indexes under existing request budgets.
  Rationale: correctness and complete bounded accounting must be proven before introducing another cache schema. Persist only after measured latency evidence.
  Date/Author: 2026-08-04 / Codex.
- Decision: retain the seven landed specialized assertion families as authoring sugar during Milestone 1 and route new relational plans through the same assertion policy kind, completeness gate, finding identity, and reporting surface. Consolidate their shared cardinality mechanics incrementally; do not discard canonical-route or round-trip proof behavior merely to claim one evaluator earlier.
  Rationale: #1473-#1475 landed more semantic assertion behavior than the planning snapshot described. Several families call analyzer identity/route producers that cannot yet be expressed as ordinary row bindings. The safe convergence point is the common typed row registry and assertion run assembly, followed by lowering each family when its exact row relation exists.
  Date/Author: 2026-08-05 / Codex.
- Decision: a `receiver-outcome`/`receiver-evidence` row expansion whose source binding is not already a receiver analysis lowers through the production receiver analysis (`receiver_targets`) before the projection step.
  Rationale: the projection steps consume a `ReceiverAnalysis` pipeline value. Lowering through the production analysis keeps expansion rows projections of the same solver run the ordinary receiver queries use, instead of admitting a second row producer. A source binding that is already a receiver analysis appends only the projection.
  Date/Author: 2026-08-06 / Claude.
- Decision: relational runs are inconclusive whenever any contributing relation is non-exhaustive, truncated, or over a plan limit, for every supported cardinality.
  Rationale: `exactly`, `at-most`, and grouped `at-least` can all be falsified by unobserved rows, so the sound uniform rule is simpler and never weaker than a per-cardinality carve-out. Violated groups retain up to eight representative tuples (`MAX_VIOLATION_REPRESENTATIVE_TUPLES`) so findings anchor at exact ranges without enumerating the group; the aggregate value states the complete count.
  Date/Author: 2026-08-06 / Claude.
- Decision: per-candidate generic substitutions and semantic provenance handles do not land as M2 evidence-row fields; they land with M3's resolver-trace seam.
  Rationale: the compatibility projection (`project_receiver_values`) multiplies type-lookup definitions by points-to identity kinds, so a per-row substitution or provenance attribution from that seam would be manufactured rather than recorded where the resolver knows it. The evidence rows already encode value shape (`evidence_kind`), resolved type identity, factory identity, and the parent-linked chain structurally. Adding approximate flat fields now and exact ones in M3 would change the public field vocabulary twice.
  Date/Author: 2026-08-06 / Claude.
- Decision: use #1473's production get-definition candidate trace as Milestone 3's selection spine. Add receiver-site correlation and hierarchy/member-specific fields to those rows at the existing resolver seams; do not create the originally sketched parallel `MemberSelectionProvider` where the production trace already owns candidate admission and rejection.
  Rationale: the landed trace is already emitted by the real language resolvers and distinguishes partial selection-only traces from complete candidate stories. Re-recording candidates in a new provider would violate the plan's single-resolver rule and duplicate eleven adapter integrations.
  Date/Author: 2026-08-05 / Codex.

## Outcomes & Retrospective

Milestone 1 is complete (2026-08-06). Delivered behavior: an RQLP `(analysis :type assertion (bind ...) (join ...) (group ...) (assert ...))` policy now executes end to end through `run_policy`. Each `bind` runs as a full-detail CodeQuery from the resolved selector store; a typed expansion clones its source binding's query and appends the production receiver-analysis and projection steps. Violated groups become findings whose primary and related locations are the exact display ranges and byte spans of the contributing rows, with a stable anchor keyed on the rendered group key. Non-exhaustive or truncated bindings and exceeded plan limits make the run inconclusive with zero findings. Validation evidence: `tests/suite_bench_policy/policy_relational_assertions.rs` (finding with exact range assertions, clean, receiver-outcome expansion coverage, truncation-inconclusive), the crate unit suites, and workspace clippy. Known gaps carried forward: expansion steps beyond `receiver-outcome`/`receiver-evidence` fail with a typed error until their row domains land (M3/M4); the two local test failures observed during validation (`cpp_alias_and_macro_dedup_comparison_count_is_linear`, `cache_db::active_session_can_write_temp_but_not_main`) reproduce on the clean base and are unrelated.

Milestone 2 is complete (2026-08-06). Delivered behavior beyond the #1666 slice: the row-level outcome/evidence contract is now proven for aliased receivers (deterministic typed rows through the alias), ambiguous two-type receivers (`ambiguous`/`open` with one evidence row per candidate and exact candidate accounting), unknown receivers (one `unknown`/`unknown` outcome row, zero evidence), and C# dynamic receivers (one `unsupported` outcome row with the structured reason, zero evidence). Public docs migrated: `code-query-json.md` documents both projections and the corrected step-input domains (occurrence inputs, `file_of` over both row domains), and the receiver-traversal tutorial gained an executed `Typed Receiver Rows` section validated by the tutorial harness. Capability gaps carried forward: per-candidate substitutions/provenance land at the M3 trace seam; the TypeScript union-annotation collapse (Surprises) is fixed in the M3/M5 rollout.

Milestone 3 first tranche and the Milestone 5 core landed 2026-08-06. Delivered behavior: the `member-selection` projection emits the mandatory selection summary per occurrence from the production trace across every language (with `untraced`/`unsupported` honesty where a family records no trace); selected candidate rows carry `canonical_member_id` digests of the #1475 structured identity so same-spelling wrong-owner decoys can never merge in a count-distinct invariant; `member_targets` is proven behaviorally equal to the disposition-selected candidate projection; and the issue's motivating RQLP invariant (bind sites, expand member-selection, join by AST identity, assert exactly-one selected) produces the finding/clean/unreliable trio end to end through `run_policy`. The conformance suite (`code_query_member_dispatch.rs`) covers TypeScript, Java, and an eight-language honesty sweep with wrong-owner decoys. The measured member-position matrix: Rust full trace; TypeScript/Python selection-only; Java summarized; Go/C#/C++/PHP/Ruby stated unsupported.

The 2026-08-06 `bifrost.code-smells` run over the workspace reported findings only in pre-existing code plus one branch-owned sort-in-loop, which was fixed (keys now sorted once per group). The remaining M3 tranche (per-family candidate owner/depth/tier enrichment with get-definition parity proofs) and M4 (a `dispatch_at_source` oracle seam; a production overrides relation for family edges -- see the M4 gap analysis in Progress) are per-family analyzer work that must land family by family, not as projections of existing data.

Update this section after each remaining milestone with behavior delivered, validation evidence, remaining capability gaps, and any changes to the language rollout.

## Context and Orientation

Bifrost is a Rust workspace. `brokk-bifrost-core` contains dependency-bottom model types such as `CodeUnit`, `Range`, structured type identity, signature metadata, and dispatch extensibility. It must not depend on another Bifrost crate. `brokk-bifrost-analysis` owns language analyzers, semantic IR/oracles, get-definition and usage resolution, and CodeQuery/RQL execution. `brokk-bifrost-policy` owns RQLP parsing, evaluation, findings, completeness, human/JSON/SARIF rendering, and policy status. MCP, LSP, the Python client, the VS Code extension, and public docs mirror visible query vocabulary and result variants.

The existing receiver path starts in `crates/bifrost-analysis/src/analyzer/structural/search/mod.rs`. A `receiver_targets`, `points_to`, or `member_targets` pipeline step creates a `ReceiverQueryService` from `crates/bifrost-analysis/src/analyzer/usages/receiver_query.rs`. That service combines structural source/facts, bounded get-type/get-definition adapters, and the neutral semantic workspace oracle. It returns `ReceiverQueryReport`, which becomes `CodeQueryReceiverAnalysis`. The report currently retains only receiver values or selected member declarations.

The neutral semantic oracle under `crates/bifrost-analysis/src/analyzer/semantic/` already defines candidate coverage, candidate proof/completeness/provenance, source points-to observations, call dispatch candidates, and explicit semantic outcomes. These types are the evidence vocabulary to project; do not invent string-valued approximations.

`TypeHierarchyProvider` in `crates/bifrost-analysis/src/analyzer/capabilities.rs` supplies direct ancestor edges per analyzer. Current `supertypes`/`subtypes` CodeQuery execution traverses those edges iteratively under the pipeline budget, but returns only declarations. A hierarchy hop row in this plan means one exact edge on one exact candidate route, with `candidate_id`, zero-based `hop`, `from`, `to`, and relation kind. A candidate's `hierarchy_depth` is the number of hops on that route.

A member selection site is one exact receiver-qualified member occurrence or call. A receiver outcome row states whether its receiver evidence is exhaustive, open, truncated, unknown, unsupported, cancelled, or over budget. A member selection row states the equivalent candidate-set outcome and selected-cardinality. A member candidate row is one declaration considered by the production resolver, not merely one winner. Its disposition is `selected`, `applicable`, or `rejected`; a rejected row carries a constrained rejection reason. A dispatch tier is a language-neutral ordering bucket: `inherent_or_direct`, `inherited_or_promoted`, `trait_or_interface`, `extension`, `static_or_companion`, or `dynamic_or_open`. Each adapter maps its language rules into these buckets while retaining a language-specific constrained detail label when needed.

A canonical method family is the set of declarations that the analyzer proves are the same overridable/implementable member contract. Family edges are typed as `overrides`, `implements`, `overridden_by`, or `implemented_by`; inverse rows are derived from forward exact edges, not resolved independently. A bounded dispatch row is one possible runtime target for an exact call and carries the semantic oracle's proof, completeness, provenance, and overall candidate coverage.

The #1473 work introduces content-scoped occurrence rows and AST IDs. When it is merged, #1477 uses its `ast_id` as the primary correlation key from a member occurrence to the receiver/member site. If #1473 is not merged, implementation must pause rather than recreating its identity scheme.

## Plan of Work

### Milestone 1 - reusable typed bindings and relational assertions

The reviewed #1473 result is integrated on `origin/master` as `6d7ea58a0`, and this worktree is attached at current `origin/master` (`aef3d746c`). Use the checked-in occurrence, AST-ID, and assertion contracts directly; do not copy files from the historical #1473 branch.

In `crates/bifrost-analysis/src/analyzer/structural/search/results.rs`, add a declarative public row-field registry. Every terminal `DetailedCodeQueryDomain` declares its addressable fields and scalar types (`stable_id`, string, integer, boolean, constrained enum, declaration identity). The registry must expose only semantically stable fields; display text and formatted ranges are not join keys. Add `CodeQueryRowRef` as a borrowed, typed projection over a detailed result and methods that reject a field not registered for that result domain. Occurrence rows from #1473 expose `id`, `ast_id`, role/class/namespace, and target identity through this registry.

In `crates/bifrost-policy/src/schema.rs`, register assertion-plan records and constrained values. The canonical RQLP shape is:

    (analysis :type assertion
      (bind :name site :query (rql ...))
      (bind :name receiver :from site :step receiver-evidence)
      (bind :name selection :from site :step member-selection)
      (bind :name candidate :from site :step member-candidates)
      (join :left site :right receiver :on ((id site_id)))
      (join :left site :right candidate :on ((id site_id)))
      (group :name by-site :by (site.id)
        (aggregate :name min-depth :op min :value candidate.hierarchy_depth)
        (aggregate :name winners :op count-distinct :value candidate.canonical_member_id
                   :where ((candidate.disposition eq selected))))
      (assert :group by-site :value winners :cardinality (exactly 1)))

`bind` is either a full CodeQuery selector (`:query`) or one typed expansion from an earlier binding (`:from` plus `:step`). `join` is an inner join by default and accepts `:kind anti` for anti-join. `:on` contains one or more equality pairs; both sides must have the same registered scalar type. `group` owns named aggregates. `aggregate` supports `min`, `count`, and `count-distinct`; an optional typed `:where` predicate is conjunction-only in this milestone. `assert` supports scalar comparison and `(exactly N)`, `(at-least N)`, or `(at-most N)` cardinality. Names are unique, bounded, and resolved before evaluation; cycles and forward references are authoring errors.

Add the decoded definition types in `crates/bifrost-policy/src/definition.rs`, parser/formatter/canonical-hash projections in `source.rs`, `format.rs`, `resolved.rs`, and `canonical_loaded.rs`, and a bounded evaluator in a new `crates/bifrost-policy/src/assertion_policy.rs`. Evaluation is iterative. It caps source rows, expanded rows, join comparisons, retained joined rows, groups, values per group, and related finding locations. It propagates CodeQuery completion and every binding's coverage. A negative or exact-cardinality assertion can be clean only when every contributing relation is exhaustive and untruncated. Existing #1473 assertion syntax must be lowered into this plan or retained as a thin schema sugar over the same evaluator; do not keep two cardinality engines.

Milestone acceptance: policy parser/formatter/canonicalization tests prove the exact form above; invalid fields and mismatched join types fail at the exact RQLP range; an in-memory fixture joins occurrence rows by AST ID and produces clean/finding/unreliable outcomes correctly; tiny limits prove every dimension is bounded.

### Milestone 2 - receiver outcome and evidence rows

Add row contracts under `crates/bifrost-analysis/src/analyzer/usages/receiver_analysis.rs` or a closely related `receiver_rows.rs` module. The end-state types are prescribed in `Interfaces and Dependencies`. `ReceiverSiteOutcome` is mandatory per input site. `ReceiverEvidenceRow` is one independently identified receiver observation/value and carries declared type, inferred value/type, proof source, generic substitution, chain hop, semantic proof/completeness/provenance, and coverage. Preserve allocation and recursive factory provenance by emitting linked rows (`parent_evidence_id`) rather than nesting anonymous values.

Refactor `ReceiverQueryService` so its existing compatibility projection and the new row projection consume one internal report. Do not re-run parsing, get-type, points-to, or factory analysis for each public shape. The old `receiver_targets` and `points_to` results may remain during the milestone as projections, but by milestone completion all documentation and policy examples use typed rows; remove redundant nested public structures if no remaining consumer needs them, since backwards compatibility is not required.

Add CodeQuery step/domain registrations through `query/schema.rs`, `ir.rs`, `decode.rs`, `json.rs`, `sexp.rs`, and `source.rs`. Use `receiver-outcome` and `receiver-evidence` as the public operation labels. Both accept structural matches, occurrence rows that identify receiver/member positions, reference sites, call sites, and expression sites where the existing service supports them. The outcome row exposes `site_id`, optional `site_ast_id`, outcome, coverage, unsupported capability, exceeded limit, and bounded work. Evidence rows expose the stable foreign keys and typed evidence fields. `file_of` accepts both domains.

Milestone acceptance: typed local, factory-return, alias, branch, and nested-chain fixtures return deterministic linked rows; declaration type and runtime value type remain distinct fields; unknown/unsupported/open/truncated/budget outcomes return one outcome row even with no evidence; an occurrence row from #1473 joins to its receiver outcome by `ast_id`/`site_ast_id` without comparing text or range.

### Milestone 3 - production member selection traces and hierarchy paths

Introduce `MemberSelectionReport`, `MemberSelectionOutcome`, `MemberCandidateRow`, `HierarchyHopRow`, and the constrained candidate vocabulary in a new `crates/bifrost-analysis/src/analyzer/usages/member_selection.rs`. Add a `MemberSelectionProvider` capability exposed by `IAnalyzer`, with an explicit total support table per language and no default `supported` implementation. The provider accepts the exact prepared source site, receiver evidence, member name/kind, the shared receiver budget/cancellation, and returns the mandatory selection outcome plus bounded candidate and hop rows.

For each language resolver, factor its current production winner computation so the get-definition result and the trace report share one selection function. Do not add a boolean trace flag. Prefer a small resolver-local selection value that always contains candidates/dispositions and has a `selected_definitions()` projection for the existing API. Record a candidate at the point the production algorithm admits or rejects it, with exact owner, route, depth, tier, member kind, substitutions already known, applicability, disposition, and constrained reason. When a resolver cannot enumerate a complete frontier, set coverage open or truncated; do not manufacture rejected candidates by scanning `all_declarations`.

Roll out in semantic families with focused commits: Java/Kotlin; JavaScript/TypeScript; C#/Scala; Go/Rust; C/C++; PHP/Python/Ruby. Each family lands only when get-definition and usage behavior is unchanged and positive plus wrong-owner/lower-tier near-miss fixtures prove the trace. Direct/inherent candidates must outrank inherited/promoted candidates where the language says so; extensions, traits/interfaces, static/companion members, partial/logical types, union/intersection receivers, and ambiguous traits remain explicit instead of collapsing to name matches.

Add CodeQuery domains and operations `member-selection`, `member-candidates`, and `candidate-hierarchy`. `member-selection` always emits one row. Candidate/hop operations may emit zero rows only alongside an outcome whose exhaustive state justifies it. Register every field for Milestone 1's typed binding layer. Existing `member_targets` becomes the projection of rows with disposition `selected`; delete the separate resolution path.

Milestone acceptance: for every claimed language, exact get-definition targets before and after the refactor are equal; candidate traces show the winner and realistic losing decoys; hierarchy hop sequences are contiguous and terminate at the candidate owner; minimum depth and winning tier in a relational assertion select the production winner; cycles and diamonds are iterative, bounded, and deterministic.

### Milestone 4 - canonical method families and bounded dispatch

Add `MemberFamilyProvider` beside `MemberSelectionProvider`. It returns exact forward edges from a member to members it overrides or implements, keyed by exact canonical `CodeUnit` identity. Derive `overridden_by` and `implemented_by` by bounded inversion over indexed forward edges. Do not infer family membership from FQN or signature string equality. A method-family ID is a domain-separated digest over the deterministically ordered exact family roots plus language/realm identity; if roots cannot be proven canonical, emit an incomplete family outcome and no supposedly exact ID.

Bridge exact call sites to the existing `WorkspaceSemanticOracle` dispatch result. Publish a mandatory dispatch outcome row and zero or more `DispatchTargetRow`s with family ID when proven, target procedure/declaration, proof, completeness, provenance, candidate coverage, and boundary kind. Preserve `may_dispatch` for open/unproven candidates and `proven_dispatch` only for proven-complete candidates in an exhaustive set. Open-world dispatch can never satisfy an exact-set negative assertion.

Add CodeQuery operations `member-family`, `family-edges`, `dispatch-outcome`, and `dispatch-targets`, public result variants, row-field registrations, budgets, diagnostics, and `file_of` where meaningful. Reuse semantic locator and declaration identity; do not serialize internal arena IDs.

Milestone acceptance: Java/C#/Scala overrides, Rust traits, Go embedded/interface methods, PHP interfaces/traits, and C++ virtual members produce exact family edges where supported; inverse edges round-trip; a closed dispatch fixture yields an exhaustive proven set; an open/dynamic fixture yields may-dispatch/open coverage and makes exact-set policy assertions unreliable.

### Milestone 5 - conformance policies, transports, editor vocabulary, and docs

Create `tests/suite_cross_language/code_query_member_dispatch.rs` and add one `mod` line in that suite's `main.rs`. Use `InlineTestProject` for small multi-file fixtures. Cover every acceptance scenario and select representative shapes from the 58 commit inventory. Every positive has a realistic near miss: same-name wrong owner, same member outside the receiver hierarchy, deeper candidate hidden by a direct member, extension shadowed by an inherent member, unrelated trait method, factory returning a sibling type, alias to the wrong logical partial type, and open dispatch that must not be called exact.

Add RQLP policy fixtures under the existing policy test fixture tree. Policies bind occurrence/site, receiver outcome/evidence, selection, candidates, hierarchy hops, family edges, and dispatch rows. They demonstrate inner/anti joins, minimum depth, winning tier, count-distinct canonical members, exactly zero/one/many, and unreliable propagation. Findings retain the subject, winner, and all competing candidate locations with truncation accounting and human/JSON/SARIF parity.

Update the version-1 declarative registries (#1683 collapsed the RQL schema lineage to one version; do not mint a new version for additive vocabulary), live validation, hover, completion, TextMate grammar, MCP help/schema, CLI/REPL, LSP URI enrichment, Python models, VS Code result unions/rendering/navigation, and published docs. Visible vocabulary must come from the registries; do not add editor-only keyword tables. Docs state the language capability matrix and distinguish member selection from sibling #1478's overload applicability.

Milestone acceptance: executable docs and client tests consume exact canonical examples; built-in policy hashes for unrelated policies remain unchanged; the staged binary policy smoke reports finding/clean/unreliable for the three canonical fixtures.

### Milestone 6 - adversarial review and final gates

Review the complete diff for a second resolver, post-hoc candidate scans, source-text parsing, range-based joins, dropped incomplete outcomes, unmetered hierarchy paths, inconsistent forward/inverse families, dynamic dispatch upgraded to proven, and stale public consumer unions. Minimize any recurring mechanically detectable smell into RQL; add it to the built-in pack only if positive and near-miss coverage meets repository policy.

Run the installed `bifrost.code-smells` pack plus every repository policy root in one `run_policy` request, review or fix findings, and rerun the same selection. Run the focused and complete gates below, update all living sections, and checkpoint each completed milestone on the current attached branch. Do not push, tag, publish, or open a PR without explicit user authorization.

## Concrete Steps

All implementation commands run from the active Bifrost worktree on the user-authorized attached branch `dave/issue-1477-receiver-hierarchy-dispatch`. Preserve `.bifrost/` and `src/lsp/` cache artifacts.

Before implementation:

    git fetch origin --prune
    git status --short --branch
    git log --oneline --decorate -12 origin/master

The branch operation is complete: `dave/issue-1477-receiver-hierarchy-dispatch` was created from `origin/master` at `aef3d746c`; #1473 is present through squash merge `6d7ea58a0`, and #1475 through `4eb483db8`.

Focused featureless validation after each coherent edit:

    cargo fmt --all
    cargo nextest run -p brokk-bifrost-core -p brokk-bifrost-analysis -p brokk-bifrost-policy
    cargo test -p brokk-bifrost-analysis --test suite_cross_language code_query_member_dispatch
    cargo test -p brokk-bifrost-policy --test suite_bench_policy
    cargo clippy --workspace --all-targets -- -D warnings

Public surface validation when Milestone 5 changes clients/docs:

    uv run --python 3.12 -- pytest python_tests/test_searchtools_client.py
    npm --prefix editors/vscode test
    cargo test -p brokk-bifrost-analysis --test suite_cross_language code_query_docs
    npm --prefix docs run check
    npm --prefix docs run build

Pre-push/full gate only when requested or at the final milestone. Check disk first and do not run another NLP build concurrently:

    df -h .
    scripts/pre-push-gate.sh
    scripts/check-workspace-packages.sh
    git diff --check

This issue does not touch semantic search/NLP. Do not enable `nlp` during ordinary milestone validation. If the final authorized pre-push gate runs all features, use the repository gate/helper so its isolated target self-cleans.

## Validation and Acceptance

Parsing and static validation must reject duplicate/forward binding names, cycles, unknown row fields, incompatible join field types, aggregates outside a group, unsupported aggregate/value types, and invalid cardinalities at the exact source range. Canonical formatting and semantic hashing must be deterministic.

Every member site returns exactly one receiver outcome and one selection outcome. Candidate/evidence/hop/family/dispatch rows use stable IDs and exact foreign keys. Empty evidence or candidate sets are accompanied by exhaustive/open/truncated/unsupported/budget/cancelled state. No policy may turn an incomplete negative or exact-cardinality result into clean.

Candidate ordering and dispositions must reproduce production get-definition semantics. The selected set projected from candidate rows equals the ordinary get-definition result for each fixture. Wrong-owner and lower-tier candidates remain visible as rejected rows with structured reasons. Hierarchy routes are iterative and bounded, and minimum-depth/winning-tier aggregates reproduce the selected candidate without reimplementing precedence in policy code.

Canonical family relations are exact and reversible within the indexed workspace. Family IDs do not use FQN or signature strings as their identity. Dispatch results distinguish proven exhaustive targets, may-dispatch candidates, and open/unmaterialized boundaries.

The required fixtures cover typed locals, declaration-owner versus value-type differences, factories, aliases, nested chains, promoted/inherited members, direct-method precedence, extensions, union/intersection receivers, ambiguous traits, and wrong-owner decoys. Each claimed language has positive and realistic near-miss coverage. Unsupported language capabilities yield `unreliable` policy results.

The final observable policy trio is:

    seeded bad selection   -> status finding, one multi-location invariant finding
    corrected selection    -> status clean
    incomplete/open input  -> status unreliable

Human, JSON, and SARIF outputs agree on status, stable finding identity, expected/actual counts, subject, winner, competitors, proof, completeness, and related-location truncation.

## Idempotence and Recovery

All fixture projects are temporary and every query/policy operation is read-only. Re-running tests is safe. Schema additions are additive within a milestone and old snapshots remain self-healing through existing version gates. If a language trace cannot be produced from the production resolver, leave that capability unsupported and record the gap; do not add regex, name scanning, or an all-declarations fallback.

If a milestone fails after changing public row unions, keep the worktree and repair every exhaustive consumer before proceeding. Do not reset or delete unrelated files. If #1473 changes its AST ID or assertion schema before merge, update this plan and adapt once at the shared boundary rather than carrying compatibility layers.

## Artifacts and Notes

The 58 motivating commits cluster into these fixture families: receiver/value inference and factories; hierarchy/promotion/inheritance; extensions/traits/interfaces; union/intersection and conditional receivers; partial/logical/canonical owners; nested/macro/member chains; direct-member precedence and wrong-owner decoys; bounded inverse and dispatch proof. The full hash inventory remains in GitHub issue #1477 and is not duplicated here.

Existing implementation paths to reuse:

    crates/bifrost-analysis/src/analyzer/usages/receiver_query.rs
    crates/bifrost-analysis/src/analyzer/usages/receiver_analysis.rs
    crates/bifrost-analysis/src/analyzer/usages/get_definition/
    crates/bifrost-analysis/src/analyzer/usages/get_type/
    crates/bifrost-analysis/src/analyzer/semantic/oracle/
    crates/bifrost-analysis/src/analyzer/semantic/workspace_oracle/
    crates/bifrost-analysis/src/analyzer/capabilities.rs
    crates/bifrost-analysis/src/analyzer/structural/query/
    crates/bifrost-analysis/src/analyzer/structural/search/
    crates/bifrost-policy/src/

Revision note (2026-08-04): Initial implementation-ready plan authored after live issue/parent inspection, receiver/oracle/hierarchy surveys, review of the active #1473 ExecPlan, and classification of all 58 motivating commit subjects. The plan makes #1473 integration, the shared relational assertion layer, production-resolver trace reuse, #1478 applicability boundaries, and honest incomplete-language behavior explicit.

Revision note (2026-08-05): Confirmed the prerequisite against freshly fetched `origin/master`, attached the authorized #1477 branch at `aef3d746c`, and recorded the landed #1473 (`6d7ea58a0`) and #1475 (`4eb483db8`) commits. The dependency gate is cleared.

Revision note (2026-08-05): Began Milestone 1. Added the analyzer-owned typed row-field contract and the policy relational-plan model/validator, recorded the expanded landed assertion surface, and made the remaining parser/evaluator work explicit.

Revision note (2026-08-06): Closed out Milestone 1 on a fresh branch from current master (the #1666 slice merged as `8f11273e4`). Corrected the stale schema v11/v12 references: #1683 collapsed the RQL schema lineage to a single version 1 and all new vocabulary enters through the version-1 registries. Recorded the expansion-lowering and uniform-inconclusive decisions.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/usages/receiver_rows.rs` (final module name may remain beside `receiver_analysis.rs`, but use one location):

    pub struct ReceiverSiteOutcome {
        pub id: String,
        pub site_id: String,
        pub site_ast_id: Option<String>,
        pub file: ProjectFile,
        pub range: Range,
        pub outcome: ReceiverOutcome,
        pub coverage: CandidateCoverage,
        pub unsupported: Option<SemanticCapability>,
        pub exceeded: Option<ReceiverBudgetLimit>,
        pub work: ReceiverAnalysisWork,
    }

    pub struct ReceiverEvidenceRow {
        pub id: String,
        pub site_id: String,
        pub parent_evidence_id: Option<String>,
        pub declared_type: Option<CodeUnit>,
        pub value: Option<ReceiverValueAtom>,
        pub inferred_type: Option<CodeUnit>,
        pub proof_source: ReceiverProofSource,
        pub generic_substitutions: Vec<GenericSubstitution>,
        pub chain_hop: usize,
        pub proof: ProofStatus,
        pub completeness: EvidenceCompleteness,
        pub provenance: Vec<OracleRelationHandle>,
    }

In `crates/bifrost-analysis/src/analyzer/usages/member_selection.rs`:

    pub trait MemberSelectionProvider: CapabilityProvider {
        fn member_selection_support(&self) -> &MemberSelectionSupport;
        fn select_member(
            &self,
            request: &MemberSelectionRequest,
            budget: ReceiverAnalysisBudget,
            cancellation: &CancellationToken,
        ) -> Result<MemberSelectionReport, MemberSelectionError>;
    }

    pub struct MemberSelectionReport {
        pub outcome: MemberSelectionOutcome,
        pub candidates: Vec<MemberCandidateRow>,
        pub hierarchy_hops: Vec<HierarchyHopRow>,
        pub work: ReceiverAnalysisWork,
    }

    pub struct MemberCandidateRow {
        pub id: String,
        pub site_id: String,
        pub canonical_member_id: Option<String>,
        pub member: CodeUnit,
        pub owner: CodeUnit,
        pub hierarchy_depth: usize,
        pub dispatch_tier: MemberDispatchTier,
        pub dispatch_detail: Option<String>,
        pub substitutions: Vec<GenericSubstitution>,
        pub applicability: CandidateApplicability,
        pub disposition: CandidateDisposition,
        pub rejection_reason: Option<MemberRejectionReason>,
        pub proof: ProofStatus,
        pub completeness: EvidenceCompleteness,
    }

    pub struct HierarchyHopRow {
        pub id: String,
        pub candidate_id: String,
        pub hop: usize,
        pub from: CodeUnit,
        pub to: CodeUnit,
        pub relation: HierarchyRelation,
    }

In a sibling family/dispatch module:

    pub struct MethodFamilyEdgeRow {
        pub id: String,
        pub family_id: String,
        pub source: CodeUnit,
        pub target: CodeUnit,
        pub relation: MethodFamilyRelation,
        pub proof: ProofStatus,
        pub completeness: EvidenceCompleteness,
    }

    pub struct DispatchTargetRow {
        pub id: String,
        pub site_id: String,
        pub family_id: Option<String>,
        pub target: ProcedureHandle,
        pub proof: ProofStatus,
        pub completeness: EvidenceCompleteness,
        pub coverage: CandidateCoverage,
        pub boundary: Option<DispatchBoundaryKind>,
    }

In `crates/bifrost-policy/src/definition.rs`, assertion plans conceptually expose:

    pub struct AssertionPlan {
        pub bindings: Vec<RowBinding>,
        pub joins: Vec<RowJoin>,
        pub groups: Vec<RowGroup>,
        pub assertions: Vec<RowAssertion>,
        pub limits: AssertionLimits,
    }

All constrained labels, row domains, row fields, relational operators, aggregate operators, candidate outcomes, dispatch tiers, applicability values, dispositions, rejection reasons, hierarchy relations, and family relations enter through declarative registries with exhaustive parser/decoder/validator/hover/completion/format handling.

Dependency direction remains: core identity/value vocabulary in `brokk-bifrost-core` only when it has no analyzer dependency; receiver/candidate/family/dispatch production and CodeQuery rows in `brokk-bifrost-analysis`; relational assertion parsing/evaluation/findings in `brokk-bifrost-policy`; transports depend outward. No dependency may point from core to analysis or policy, and nothing in this plan depends on `brokk-bifrost-nlp`.
