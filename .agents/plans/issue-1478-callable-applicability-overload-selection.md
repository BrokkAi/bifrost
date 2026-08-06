# Expose callable applicability and overload selection evidence to RQL/RQLP (issue #1478)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

Parent context: this is child issue #1478 of epic #1472, which turns 275 mined Bifrost bug-fix commits into typed RQL/RQLP capabilities. This slice owns structured call shapes, callable signatures, call-site-to-candidate applicability, and overload selection evidence. Sibling #1477 owns receiver evidence, member-candidate enumeration, hierarchy routes, and dispatch tiers; its plan records `callable_applicability_deferred` for a candidate that loses only because of call arguments, and this plan replaces that deferral with a real applicability row. Sibling #1475 owns canonical identity through aliases and indirection; this plan uses exact analyzer `CodeUnit` identity. Sibling #1473 landed content-scoped occurrence rows, stable AST IDs, and resolver-owned `TraceCandidate` rows; this plan correlates through those IDs and enriches that trace instead of recording candidates a second time.

## Purpose / Big Picture

Bifrost's language resolvers already discriminate overloads: Java filters constructor candidates by arity (`java_filter_candidates_by_arity` in `crates/bifrost-analysis/src/analyzer/usages/get_definition/java.rs`), C++ matches call shapes in `crates/bifrost-analysis/src/analyzer/usages/cpp_call_match.rs`, C persists variadic callable arity, Scala matches curried and contextual argument lists, and C# models callable applicability. Every one of those checks computes an answer and throws the evidence away. The public result exposes only the winner, so RQLP cannot state the invariant that motivated the 31 mined bug-fix commits: for this exact ordered call shape, these are all callable candidates, this candidate is applicable and uniquely selected, zero applicable candidates stay unresolved, and several equally applicable candidates stay honestly ambiguous rather than being broken by candidate order.

After this plan is complete, an RQLP assertion can bind call occurrences, expand each into one mandatory call-shape outcome row plus ordered argument-list-group and argument rows, expand candidate callables into signature rows carrying required/total/repeated arity, list kinds, parameter names, generic arity, receiver contract, return type, and declaration role, join call sites to per-candidate applicability rows carrying substitutions, an accepted or structured rejected reason, precedence tier, proof, and completeness, and assert that the selected target sits in the winning applicability tier with exactly zero, one, or many winners. A macro-expanded or configuration-derived argument list that the analyzer cannot see produces an incomplete call-shape outcome, and any exact-cardinality assertion over it is `unreliable`, never clean.

The behavior is visible through `query_code` JSON/RQL result rows and through `run_policy`. For a seeded wrong-overload resolution, an invariant policy reports one multi-location finding containing the call site, the selected callable, and the applicable competitor; the corrected fixture is clean; a macro-derived call shape is `unreliable`.

## Progress

- [x] (2026-08-06 08:55Z) Read issue #1478, parent #1472, and the sibling #1477 ExecPlan; confirmed #1473 (`6d7ea58a0`), #1475 (`4eb483db8`), #1476 (`98dc13b86`), #1479 (`62b1ac760`), and the #1477 relational/receiver foundation slice (`8f11273e4`, PR #1666) are on `master`.
- [x] (2026-08-06 08:55Z) Surveyed the existing machinery: `CallableArity` and `SignatureMetadata` in `crates/bifrost-core/src/analyzer/model.rs`; the `labelled_enum!` constrained vocabularies (`PrecedenceTier`, `RejectionReason`, `BoundaryStatus`, `DeclaredVisibility`) in `crates/bifrost-core/src/analyzer/structural/resolution.rs`; `TraceCandidate`/`CandidateOutcome` in `crates/bifrost-analysis/src/analyzer/usages/get_definition/trace.rs`; per-language arity/shape matchers in `get_definition/{java,cpp,csharp,scala,...}.rs` and `usages/cpp_call_match.rs`; the relational assertion plan (`bind`/`join`/`group`/`aggregate`/`assert`) in `crates/bifrost-policy/src/assertion_policy.rs` and `evaluator/assertion.rs`; the `receiver-outcome`/`receiver-evidence` row registrations in `crates/bifrost-analysis/src/analyzer/structural/query/schema.rs` and `structural/search/results.rs`.
- [x] (2026-08-06 08:55Z) Confirmed the current `RejectionReason` vocabulary has no callable-applicability variants: arity, list shape, named arguments, and generic arity rejections are computed but unlabeled today.
- [x] (2026-08-06 08:55Z) Classified the 31 motivating commit subjects into the fixture families listed under `Artifacts and Notes`.
- [x] (2026-08-06 08:55Z) Authored this implementation-ready ExecPlan.
- [ ] Milestone 1: core call-shape and applicability vocabulary plus structured call-shape extraction rows (2026-08-06 09:20Z progress: `crates/bifrost-core/src/analyzer/structural/callable.rs` lands `CallKind`, `ArgumentListKind`, `CallShapeCoverage`, `ApplicabilityVerdict`, `CallableRejectionReason`, `SelectionResolution`, and `ReceiverContract` with unique round-trip labels, committed as `705e18f6a`. 2026-08-06 10:40Z progress: `crates/bifrost-analysis/src/analyzer/usages/call_shape.rs` derives `CallShapeOutcome`/`ArgumentGroupRow`/`ArgumentRow` rows from the facts arena's `Call` nodes with domain-separated stable IDs mirroring the receiver-site discipline, plus focused Python unit tests for ordered positional groups, named groups, spread flags, empty-versus-missing groups, method/function kinds, deterministic distinct IDs, and the per-file limit. Remaining: CodeQuery `call-shape`/`call-argument-groups`/`call-arguments` registration and execution, row-field registry entries, per-language enrichment for constructor/extractor/infix/method-value kinds and curried/contextual/block/type-argument groups, macro-coverage detection, and the Java/Scala/C++/C# fixtures).
- [ ] Milestone 2: callable-signature rows projected from the persisted semantic signature contract.
- [ ] Milestone 3: per-candidate applicability rows from the production resolvers, rolled out by language family.
- [ ] Milestone 4: ordered-list predicates, uniqueness and winning-tier assertions, registries, editor vocabulary, and docs.
- [ ] Milestone 5: cross-language conformance fixtures and the clean/finding/unreliable policy trio.
- [ ] Milestone 6: adversarial review, policy gate, complete validation, and retrospective.

## Surprises & Discoveries

- Observation: `CallableArity { required, total, repeated }` already exists in `crates/bifrost-core/src/analyzer/model.rs` with an `accepts(arity)` predicate, and `SignatureMetadata` already persists parameter labels with byte ranges, type parameters, and an extension-receiver flag. The persisted semantic signature contract the issue demands largely exists; what is missing is a queryable row projection and per-argument-list structure (one flat arity cannot express curried Scala lists or named C# arguments).
  Evidence: `model.rs:207-330`, `model.rs:1494+`.
- Observation: the resolver-side applicability checks are per-language free functions that return filtered candidate vectors, not evidence. For example `java_filter_candidates_by_arity` drops losers silently, and `cpp_call_match.rs` computes match quality that never leaves the resolver.
  Evidence: `get_definition/java.rs:1186-1213`; `usages/cpp_call_match.rs`.
- Observation: the relational foundation from #1666 already supports named bindings, typed field projection, inner/anti joins, grouping, `min`/`count`/`count-distinct`, and `exactly`/`at-least`/`at-most` cardinality. #1478 needs additive row domains and (in Milestone 4) ordered-list predicates, not a new evaluator.
  Evidence: `crates/bifrost-policy/src/assertion_policy.rs`; `evaluator/assertion.rs`; `8f11273e4` commit message.

## Decision Log

- Decision: reuse the production per-language call matchers as the single applicability source; never build a shared overload-resolution algorithm in the query layer.
  Rationale: the 31 commits show applicability is language semantics (Scala curried/contextual lists, C variadics, C++ template aliases, C# named arguments). A query-side solver would be a second resolver, which the epic prohibits. Each language adapter factors its existing check so the get-definition result and the applicability row come from one function.
  Date/Author: 2026-08-06 / Claude.
- Decision: model a call shape as one mandatory outcome row plus ordered argument-list-group rows plus ordered argument rows, all with stable IDs and foreign keys, rather than one flat arity integer.
  Rationale: the issue's rule contract requires list kinds, arity ranges, generic/type arguments, named/contextual arguments, receiver binding, and call role. Same-total-arity/different-list-shape overloads are a required fixture; a flat count cannot distinguish them.
  Date/Author: 2026-08-06 / Claude.
- Decision: put the constrained call-shape/applicability vocabulary (argument-list kinds, call kinds, applicability verdicts, callable rejection reasons) in `crates/bifrost-core/src/analyzer/structural/` beside `resolution.rs`, using the existing `labelled_enum!` pattern; keep row production and CodeQuery registration in `brokk-bifrost-analysis`; keep relational predicates in `brokk-bifrost-policy`.
  Rationale: the vocabulary is dependency-bottom model data shared by the persisted signature contract and by forward/inverse/cold/warm consumers; core must not depend on other Bifrost crates, and analysis-side code needs `IAnalyzer`.
  Date/Author: 2026-08-06 / Claude.
- Decision: extend candidate rejection with a separate `CallableRejectionReason` constrained enum carried by applicability rows, instead of widening the landed `RejectionReason`.
  Rationale: `RejectionReason` names scope/visibility/namespace checks shared by all reference resolution; callable applicability is a different axis that applies only to call-shaped occurrences, and #1477's member candidate rows already reference the existing enum. A distinct enum keeps both vocabularies exhaustive without a grab-bag variant.
  Date/Author: 2026-08-06 / Claude.
- Decision: candidate order is never a semantic tie breaker. When more than one candidate is applicable in the winning precedence tier, the selection outcome is `ambiguous` with all winners retained; when zero are applicable, the outcome is `unresolved` with all rejected rows retained.
  Rationale: this is the issue's rule contract verbatim, and it is the invariant the seeded-bad fixture must be able to catch.
  Date/Author: 2026-08-06 / Claude.
- Decision: unknown macro- or configuration-derived call shapes produce a mandatory outcome row with incomplete/unknown shape coverage and no fabricated argument rows.
  Rationale: commit `a87b3904f` (macro-expanded C/C++ call arity) shows shapes the analyzer cannot always see. Exact-cardinality assertions over incomplete shapes must be `unreliable`, never clean, matching the epic's fail-unreliable contract.
  Date/Author: 2026-08-06 / Claude.
- Decision: derive the first call-shape slice from the shared facts arena (`NormalizedKind::Call` with `Role::Arg`/`Role::Kwarg`/`Role::Receiver`, spread flags, and keyword spans), not from fresh tree-sitter walks. The arena models one positional group and one named group today, so the slice emits at most `Ordinary` then `Named` groups and classifies only `Function` versus `Method`; a call with zero positional arguments still gets one empty `Ordinary` group, while the `Named` group is omitted when absent. Constructor/extractor/infix/method-value kinds and curried/contextual/block/type-argument groups arrive with per-language enrichment and are never inferred from source text. Two interface deltas from the original sketch: `ArgumentRow` carries a per-argument `spread` flag (the arena records spread per argument, and a whole-group `VariadicPack` kind would erase mixed lists like `f(a, *rest)`), and `CallShapeOutcome` carries a non-optional `site_ast_id` plus an optional `callee_range` (the exact facts node is always known here, unlike receiver sites; a callable-object call has no callee token).
  Rationale: one structured source that get-definition already trusts, no re-parsing, and honest coverage for what the arena cannot express yet.
  Date/Author: 2026-08-06 / Claude.
- Decision: no persistence changes in the first implementation beyond what `SignatureMetadata` already persists. Call-shape and applicability rows are demand-derived under existing request budgets.
  Rationale: same reasoning as #1477 - prove correctness and bounded accounting before adding cache schema. The signature row projection reads the already-persisted contract, which is what the issue's forward/inverse/cold/warm criterion requires.
  Date/Author: 2026-08-06 / Claude.

## Outcomes & Retrospective

Planning is complete. No implementation has started. Update this section after each milestone with behavior delivered, validation evidence, and remaining capability gaps.

## Context and Orientation

Bifrost is a Rust workspace. `brokk-bifrost-core` contains dependency-bottom model types (`CodeUnit`, `Range`, `SignatureMetadata`, `CallableArity`, the `labelled_enum!` constrained vocabularies) and must not depend on another Bifrost crate. `brokk-bifrost-analysis` owns language analyzers, get-definition/usage resolution, and CodeQuery/RQL execution under `src/analyzer/structural/`. `brokk-bifrost-policy` owns RQLP parsing, the relational assertion plan, evaluation, findings, and rendering. MCP, LSP, the Python client, the VS Code extension (`editors/vscode/`), and published docs mirror visible query vocabulary.

A call site here is one exact call-shaped occurrence: a function/method call, constructor invocation, extractor/unapply pattern, infix application, operator application, or method-value/eta-expansion reference. A call shape is the complete ordered structure of that site: its call kind, its ordered argument-list groups (a Scala curried call has several; a Java call has one), each group's list kind (ordinary, type-arguments, named, contextual/implicit, block, receiver-bound, variadic pack), and each group's ordered arguments with optional names. A callable signature is the declaration-side counterpart read from the persisted `SignatureMetadata`/`CallableArity` contract. An applicability row relates one call site to one candidate callable with a verdict (`applicable`, `inapplicable`, `unknown`), a structured rejection reason when inapplicable, the substitutions the resolver used, the candidate's precedence tier, proof, and completeness.

The landed relational assertion plan (PR #1666) gives RQLP `bind`/`join`/`group`/`aggregate`/`assert` records over typed row fields; new row domains registered through `crates/bifrost-analysis/src/analyzer/structural/query/schema.rs` and `structural/search/results.rs` become bindable automatically once their fields enter the row-field registry. The `receiver-outcome`/`receiver-evidence` registrations are the model to follow.

## Plan of Work

### Milestone 1 - call-shape vocabulary and rows

In `crates/bifrost-core/src/analyzer/structural/`, add a `callable.rs` module with `labelled_enum!` vocabularies: `CallKind` (`function`, `method`, `constructor`, `extractor`, `infix`, `operator`, `method_value`), `ArgumentListKind` (`ordinary`, `type_arguments`, `named`, `contextual`, `block`, `receiver_bound`, `variadic_pack`), `CallShapeCoverage` (`exact`, `partial`, `unknown_macro_derived`, `unknown_dynamic`), plus the row structs prescribed under `Interfaces and Dependencies`. Round-trip label tests follow the `ALL_*` pattern in `resolution.rs`.

In `brokk-bifrost-analysis`, add call-shape extraction that reuses the exact per-language call-site parsing the resolvers already perform (`get_definition/call_sites.rs` and the per-language modules). Each analyzed call site yields one mandatory `CallShapeOutcome` row (stable `site_id`, `site_ast_id` when the occurrence layer supplies one, call kind, coverage, work) and zero or more ordered `ArgumentGroupRow`/`ArgumentRow` rows keyed to it. Macro-derived or unreadable shapes yield coverage `unknown_macro_derived`/`partial` with no fabricated arguments. Register `call-shape`, `call-argument-groups`, and `call-arguments` operations through `query/schema.rs`, `ir.rs`, `json.rs`, `sexp.rs`, `source.rs`, and the result/row-field registry in `search/results.rs`.

Acceptance: fixtures across at least Java, Scala, C++, and C# return deterministic ordered rows; a Scala curried call produces multiple groups with correct kinds; a macro-derived C call produces one outcome row with unknown coverage and zero argument rows; occurrence rows join to call-shape rows by AST ID.

### Milestone 2 - callable-signature rows

Project the persisted `SignatureMetadata`/`CallableArity` contract into a `callable-signature` row domain: one row per candidate callable with required/total arity, repeated flag, per-list list kinds and parameter names where the language records them, generic (type-parameter) arity, receiver contract (instance/static/extension/none), return type identity when available, and declaration role. Where `SignatureMetadata` today collapses multiple argument lists into one label, extend the analysis-side extraction (not the persisted schema, unless a field is genuinely absent) so curried/contextual lists are represented; any persisted-schema addition must keep forward/inverse, cold and warm consumers on the same contract and self-heal old snapshots through the existing version gates.

Acceptance: signature rows for overload sets show distinct list shapes at equal total arity; defaults and variadics produce arity ranges (`required < total` or `repeated`); Kotlin/Scala extension receivers and C# static/instance contracts are distinct fields; warm-cache and cold runs return identical rows.

### Milestone 3 - applicability rows from the production resolvers

Add `CallableRejectionReason` (`arity_below_required`, `arity_above_total`, `list_shape_mismatch`, `unknown_named_argument`, `missing_required_argument`, `type_argument_arity_mismatch`, `receiver_contract_mismatch`, `call_kind_mismatch`, `shape_unknown`) to the core vocabulary. Factor each language resolver's existing candidate filtering so the production winner computation and an `ApplicabilityRow` per considered candidate come from one function; do not add a boolean trace flag or a post-hoc rescan. Rows carry verdict, reason, substitutions known to the resolver, precedence tier, proof, and completeness, and correlate to `CallShapeOutcome.site_id` and to the candidate's `CodeUnit`. The selection summary per site states `resolved_unique`, `ambiguous`, `unresolved`, or `unknown_shape`; candidate order must not influence it.

Roll out in families with focused commits: Java/Kotlin; Scala (largest commit cluster); C/C++; C#; Rust/Go; JS/TS/PHP/Python/Ruby as capability allows, with an explicit total support table and no default `supported`. Register `callable-applicability` and `overload-selection` operations and row fields.

Acceptance: for every claimed language, get-definition results before and after the factoring are identical; the selected candidate's applicability row is `applicable`; every filtered-out overload appears as `inapplicable` with the exact structured reason; a two-equal-winners fixture reports `ambiguous` with both rows retained.

### Milestone 4 - relational predicates, registries, editor vocabulary, docs

Add the ordered-list predicates the issue requires to the relational assertion plan in `brokk-bifrost-policy`: position-aware equality over ordered group/argument rows (join on `(site_id, group_index)` and `(group_id, argument_index)` is already expressible; add an `ordered-equal` group assertion for complete list parity), plus a `selected-in-winning-tier` assertion sugar that lowers to existing join/group/cardinality mechanics. All vocabulary enters through the declarative schema registries with parser, decoder, validator, hover, completion, and canonical-format handling; update the TextMate grammar in `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`, MCP help/schema, Python models, VS Code result rendering, and published docs. Do not mint a new RQL schema version: the change is additive.

### Milestone 5 - conformance fixtures and the policy trio

Create `tests/suite_cross_language/code_query_callable_applicability.rs` (one `mod` line in that suite's `main.rs`; use `InlineTestProject`). Fixtures cover: same-total-arity/different-list-shape overloads; defaults and variadics; named arguments; curried and contextual calls; constructors and extractors; generic siblings distinguished by type-argument arity; inherent-versus-trait precedence with applicability; method values/eta-expansion; ambiguous factories; macro-derived parameter lists. Every positive has a realistic near miss. Add RQLP policy fixtures proving: seeded wrong-overload selection yields one multi-location finding (call site, selected callable, applicable competitor); corrected fixture is clean; macro-derived shape yields `unreliable`. Human/JSON/SARIF outputs agree.

### Milestone 6 - adversarial review and final gates

Review the complete diff for a second overload solver, post-hoc candidate scans, string/regex shape parsing, order-dependent tie breaking, fabricated argument rows, or incomplete outcomes upgraded to exact. Run the `bifrost.code-smells` pack plus repository policy roots in one `run_policy` request, fix findings, rerun. Run the focused and pre-push gates. Update all living sections and write the retrospective.

## Concrete Steps

All commands run from the worktree root on branch `dave/github-issue-1478-c18af8`.

Focused featureless validation after each coherent edit:

    cargo fmt --all
    cargo nextest run -p brokk-bifrost-core -p brokk-bifrost-analysis -p brokk-bifrost-policy
    cargo test -p brokk-bifrost-analysis --test suite_cross_language code_query_callable_applicability
    cargo clippy --workspace --all-targets -- -D warnings

Public surface validation when Milestone 4 changes clients/docs:

    uv run --python 3.12 -- pytest python_tests/test_searchtools_client.py
    npm --prefix editors/vscode test
    npm --prefix docs run check && npm --prefix docs run build

Pre-push/full gate only at the final milestone or on request: `scripts/pre-push-gate.sh` (check disk first; no concurrent NLP builds). This issue does not touch NLP; do not enable `nlp` for routine validation.

## Validation and Acceptance

Every call site returns exactly one call-shape outcome row; argument group and argument rows are ordered, stably identified, and foreign-keyed; empty argument sets are distinguishable from unknown shapes by coverage. Signature rows come from the persisted contract and agree between cold and warm runs and between forward and inverse consumers. Applicability rows reproduce production selection exactly: the projected `applicable`-and-selected set equals the get-definition result for each fixture, losers stay visible with structured reasons, zero winners stay `unresolved`, multiple winners stay `ambiguous`. The final observable policy trio is: seeded bad overload -> `finding`; corrected -> `clean`; macro-derived shape -> `unreliable`.

## Idempotence and Recovery

All fixtures are temporary and every query/policy operation is read-only; re-running tests is safe. Schema additions are additive; old snapshots self-heal through existing version gates. If a language's matcher cannot be factored without behavior change, leave that language unsupported with an explicit capability entry and record the gap; do not approximate applicability with name or text matching. If a milestone fails after changing public row unions, repair every exhaustive consumer before proceeding.

## Artifacts and Notes

The 31 motivating commits cluster into these fixture families: Scala call-shape and curried/contextual/companion resolution (12 commits, e.g. `109412ea0`, `5934aecb2`, `9d592013b`, `f55dcc5af`); C/C++ variadic, macro-expanded, template-alias, and direct-temporary call resolution (8, e.g. `8c1b0d45c`, `a87b3904f`, `9335380f8`, `79a0f2c55`); C# applicability, generic method references, and owner arity (4, e.g. `f65b854ae`, `9ece3b65b`, `88e1fad9e`); Rust trait/associated-item routing (3, e.g. `f50fa9853`, `2046433e7`, `9a3f3286f`); Java/overload usage and inverse recovery (4, e.g. `5ad6396ac`, `f0883e092`, `dd63058de`). The full hash inventory remains in GitHub issue #1478.

Existing implementation paths to reuse:

    crates/bifrost-core/src/analyzer/model.rs                     (CallableArity, SignatureMetadata)
    crates/bifrost-core/src/analyzer/structural/resolution.rs     (labelled_enum!, PrecedenceTier, RejectionReason)
    crates/bifrost-analysis/src/analyzer/usages/get_definition/   (per-language matchers, trace.rs, call_sites.rs)
    crates/bifrost-analysis/src/analyzer/usages/cpp_call_match.rs
    crates/bifrost-analysis/src/analyzer/structural/query/        (schema.rs, ir.rs, json.rs, sexp.rs, source.rs)
    crates/bifrost-analysis/src/analyzer/structural/search/       (mod.rs, results.rs row-field registry)
    crates/bifrost-policy/src/                                    (assertion_policy.rs, evaluator/assertion.rs, schema.rs)

## Interfaces and Dependencies

In `crates/bifrost-core/src/analyzer/structural/callable.rs` (labelled enums via `labelled_enum!`; structs plain):

    pub enum CallKind { Function, Method, Constructor, Extractor, Infix, Operator, MethodValue }
    pub enum ArgumentListKind { Ordinary, TypeArguments, Named, Contextual, Block, ReceiverBound, VariadicPack }
    pub enum CallShapeCoverage { Exact, Partial, UnknownMacroDerived, UnknownDynamic }
    pub enum ApplicabilityVerdict { Applicable, Inapplicable, Unknown }
    pub enum CallableRejectionReason {
        ArityBelowRequired, ArityAboveTotal, ListShapeMismatch, UnknownNamedArgument,
        MissingRequiredArgument, TypeArgumentArityMismatch, ReceiverContractMismatch,
        CallKindMismatch, ShapeUnknown,
    }
    pub enum SelectionResolution { ResolvedUnique, Ambiguous, Unresolved, UnknownShape }

In `brokk-bifrost-analysis` (module beside the receiver rows):

    pub struct CallShapeOutcome {
        pub id: String, pub site_id: String, pub site_ast_id: Option<String>,
        pub file: ProjectFile, pub range: Range,
        pub call_kind: CallKind, pub coverage: CallShapeCoverage,
    }
    pub struct ArgumentGroupRow {
        pub id: String, pub site_id: String, pub group_index: usize,
        pub kind: ArgumentListKind, pub argument_count: usize,
    }
    pub struct ArgumentRow {
        pub id: String, pub group_id: String, pub argument_index: usize,
        pub name: Option<String>, pub range: Range,
    }
    pub struct CallableSignatureRow {
        pub id: String, pub callable: CodeUnit, pub arity: CallableArity,
        pub group_kinds: Vec<ArgumentListKind>, pub parameter_names: Vec<Option<String>>,
        pub generic_arity: usize, pub receiver_contract: ReceiverContract,
        pub return_type: Option<CodeUnit>, pub declaration_role: /* existing role vocabulary */,
    }
    pub struct ApplicabilityRow {
        pub id: String, pub site_id: String, pub candidate: CodeUnit,
        pub verdict: ApplicabilityVerdict, pub reason: Option<CallableRejectionReason>,
        pub substitutions: Vec<GenericSubstitution>, pub tier: PrecedenceTier,
        pub proof: ProofStatus, pub completeness: EvidenceCompleteness,
    }

Exact field types must follow the landed receiver-row precedent where this sketch and the code disagree; update this plan when they do. Dependency direction remains: vocabulary in `brokk-bifrost-core`; row production and CodeQuery registration in `brokk-bifrost-analysis`; relational predicates and findings in `brokk-bifrost-policy`; transports depend outward; nothing depends on `brokk-bifrost-nlp`.

Revision note (2026-08-06): Initial implementation-ready plan authored after inspection of issue #1478, epic #1472, the sibling #1477 plan and its landed foundation slice (`8f11273e4`), the persisted signature contract, the resolver-side arity/shape matchers, and classification of the 31 motivating commits.
