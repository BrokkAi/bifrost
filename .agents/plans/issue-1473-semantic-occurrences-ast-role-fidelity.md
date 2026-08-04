# Expose semantic occurrences as a typed RQL domain and assert AST-role fidelity (issue #1473)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

Parent context: this is child issue #1473 of epic #1472 (turning 275 mined bug-fix commits into RQL/RQLP capabilities). This slice owns "semantic occurrence and AST-role fidelity" (46 commits, inventoried in the GitHub issue body). Sibling slices own lexical precedence (#1474), canonical identity (#1475), and so on; capabilities that belong thematically to a sibling slice (for example generalized named joins across arbitrary RQL sub-results, or import-precedence modeling) must be filed as follow-ups against those issues rather than built here.

## Purpose / Big Picture

Today Bifrost can tell you *where a declaration is* and *where its references are*, but it cannot answer the question that 46 of our own regressions hinged on: "at this exact identifier position, what does the parser say this token *is* — a declaration name, a resolved reference, a local binder, a map key, a type operand — and does the semantic layer agree?" Bugs like a shorthand-destructuring binder being reported as a reference, a static qualifier resolving to a shadowing local, or a quoted annotation being treated as a string all share one shape: an identifier occurrence whose semantic classification silently diverged from its syntactic role.

After this change, three things work that do not work today:

1. RQL can enumerate typed occurrence rows. A query such as `(occurrences (language "java") (role declaration_name))` returns every declaration-name occurrence in scope, each with a content-scoped stable ID, exact range, enclosing declaration, normalized role, namespace (type/value/module/macro/label), raw and decoded spelling, occurrence class (declaration, reference, binding, or explicit non-reference), and — for reference-class rows — the resolved semantic target. The same rows appear in canonical CodeQuery JSON.
2. Structural captures correlate with occurrences by AST identity. A structural pattern that captures a node can be joined against occurrence rows through the captured node's AST ID (content hash of the file plus the facts-arena node index), never through source text or range coincidence.
3. A new diagnostic-neutral RQLP `assertion` analysis kind can require or forbid an occurrence at a captured AST role with exact cardinality: "every node captured here must have exactly one binding-class occurrence and no reference-class occurrence." When the language adapter has not declared support for the role being asserted, the run reports `unreliable` (incomplete), never a clean pass over an empty result. Violations render as one multi-location invariant finding carrying the source role, the expected occurrence, the actual rows, and the capability evidence, with human/JSON/SARIF parity.

Observability: after the final milestone, running the new conformance fixtures via `cargo nextest run` shows occurrence queries returning classified rows in at least four languages, and `bifrost policy` (or the `run_policy` MCP tool) executing an `assertion` policy that fails on a seeded fixture bug and passes after the fixture is corrected.

## Progress

- [x] (2026-08-04 10:20Z) Explored the three subsystems (typed-domain architecture, occurrence data sources, RQLP assertion machinery) and recorded findings in Context and Orientation.
- [x] (2026-08-04 10:40Z) ExecPlan drafted and committed.
- [x] (2026-08-04 14:05Z) Milestone 1: occurrence-role registry, namespace type, explicit per-adapter role-support tables, facts extension. Landed as four commits: core registry + `RoleSink` channel; facts arena + snapshot v2 + capability spine; the seven all-`Unsupported` adapter tables; Java/Rust/Python/JS-TS classification with per-adapter tests. `cargo test -p brokk-bifrost-analysis --lib` 1632 passed, `--test suite_cross_language` 315 passed, `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] Milestone 2: per-file occurrence derivation layer with classification, spelling, and semantic targets.
- [ ] Milestone 3: RQL/JSON typed domain exposure (schema version bump, forms, rows, capture AST IDs, transports, grammar, docs).
- [ ] Milestone 4: RQLP `assertion` analysis kind with correlated existence/absence/cardinality and multi-location findings.
- [ ] Milestone 5: cross-language conformance fixtures derived from the mined commit inventory; final gates.

## Surprises & Discoveries

- Observation: the repo already contains a persisted content-scoped AST identity. `FileFacts` in `crates/bifrost-analysis/src/analyzer/structural/facts.rs` stores a SHA-256 `ContentIdentity` of the source plus a dense pre-order `u32` node arena (`NormalizedNode { kind, range, parent, name, subtree_end }`), snapshot-persisted under `STRUCTURAL_FACTS_SNAPSHOT_VERSION`. Structural match roots already carry the fact id (`FactMatch { node: u32, .. }` in `matcher.rs`); only captures drop it.
  Evidence: `matcher.rs:18` `CaptureBinding { name, span, kind }` has no node id; `results.rs:1216` `CodeQueryCapture { name, text, start_line, range, kind }` has no id.
- Observation: the whole-file occurrence pass already exists twice in embryonic form: LSP semantic tokens (`crates/bifrost-lsp/src/lsp/handlers/semantic_tokens.rs` — declarations + candidate identifier enumeration + batch definition resolution, then throwing everything away but a token type) and `crates/bifrost-analysis/src/analyzer/reference_candidates.rs` (candidate frontier with per-language boolean exclusion predicates such as `is_go_declaration_name`, `is_js_ts_export_alias` — which are exactly non-reference role classifications expressed as exclusions).
- Observation: `CodeQueryFlowSymbolSite` (`structural/search/results.rs:570`) plus the `LengthDelimitedDigest` recipe in `structural/search/value_flow.rs::public_symbol_site` is essentially the occurrence-row shape already shipped once: `id / path / language / declaration chain / role / byte span / occurrence ordinal / range`, minted with a domain-separated digest and no mount or dense IDs.
- Observation: unreliable propagation is already end-to-end. Adapter capability gaps become `CodeQueryDiagnosticCode` with `Incomplete` impact, `CodeQueryResult::completion()` derives `Incomplete` purely from typed diagnostic impact, and `crates/bifrost-policy/src/evaluator.rs:3608` maps capability codes to `PolicyIncompleteReason::CapabilityIncomplete`; `coordinator.rs::report_exit_status` turns any non-exhaustive run into `POLICY_EXIT_UNRELIABLE` unless a finding already fired. Nothing new is needed for the propagation spine, only for the new codes to enter it.
- Observation: `StructuralSpec::supports_role` defaults to `true` (spec.rs:48), so "explicitly declared support" is currently false advertising for structural roles. The semantic side's `SemanticCapabilities` (a total table sized by variant count so nothing can be silently omitted, `analyzer/semantic/capabilities.rs`) is the model to copy.
- Observation (M1): the four deep adapters needed **no** kind-table extensions. Every occurrence-bearing position the milestone's acceptance names is already a fact node: Java maps `identifier`/`type_identifier`/`scoped_identifier`/`scoped_type_identifier`, Rust adds `field_identifier`, JS/TS already map `shorthand_property_identifier` *and* `shorthand_property_identifier_pattern` separately, and Python's single `identifier` covers everything because `dotted_name` and `type` are containers whose identifier children are facts. The plan's contingency ("extend kind tables where identifier-bearing positions are not fact nodes") did not fire.
  Consequence for M2: the grammars *do* distinguish the shapes the issue's regressions confuse — JS shorthand-binder vs shorthand-read is two node kinds, Python annotation vs parameter is the `type` wrapper — so no occurrence classification in this milestone needed source text, and none should later.
- Observation (M1): three identifier positions are deliberately left unclassified rather than guessed. JS/TS statement labels are `statement_identifier`, which is not in the kind table (adding it would make every label a fact for one `LabelOrKey` row); Rust loop labels are `label`, not an identifier node; Java `this`/`super` and Rust `self`/`super`/`crate` are their own node kinds. `GeneratedSource` and `PatternPosition` have no emitter outside Rust patterns yet. All are honest gaps: the roles are declared unsupported where no adapter emits them, so nothing silently reports a clean empty result.
- Observation (M1): the compound-versus-token question is real and had to be settled. `scoped_identifier` is itself a fact of kind `Identifier`, so classifying it as well as its tail would have produced two rows for one name at overlapping ranges. Adapters therefore classify only terminal identifier tokens; a qualified name contributes `PathSegment` rows for its scope and one contextual row for its tail.
- Observation: RQL has no exists/count/cardinality and no named sub-results; set branches are anonymous and positional, and captures are cleared once a non-structural step runs (`ir.rs:705`). Match policies are strictly one-row-one-finding (`adapt_match_candidates`), and match findings never populate `related` even though the multi-location shape exists.

## Decision Log

- Decision: occurrence identity is structural, not semantic. An occurrence's AST ID is `(file ContentIdentity, facts-arena node u32)`, published as a domain-separated digest; correlation with captures is an equijoin on that pair. The alternative — semantic-IR `SourceAnchor`/`SemanticLocator` — was rejected because occurrences are by definition parser-backed and must exist for every supported file even where semantic lowering is partial or absent, and because captures live in the facts world already.
  Rationale: the issue requires "correlate structural captures with occurrences by AST ID, never source text"; facts ids are the identity captures can actually carry with a one-field change, and `ContentIdentity` scoping makes them content-stable exactly as required ("content-scoped IDs").
  Date/Author: 2026-08-04, Fable 5.
- Decision: one `QueryValueKind::Occurrence` row kind with an `class` field (`declaration | reference | binding | non_reference`), not three separate kinds. The issue names `declaration_occurrence` / `reference_occurrence` / `binding_occurrence` as capabilities, not necessarily as distinct row types; a single kind with constrained-value filters keeps the step algebra small and lets one row carry an explicit non-reference outcome, which a three-kind split would have to encode as a fourth kind anyway.
  Rationale: parsimony; every consumer (policy assertions, JSON, transports) wants the class as data, and filters (`:class`, `:role`, `:namespace`) compose with the existing pattern-field machinery.
  Date/Author: 2026-08-04, Fable 5.
- Decision: occurrence roles are a new registry axis (`occurrence_roles!` in `crates/bifrost-core/src/analyzer/structural/kinds.rs`), not new entries in the existing `roles!` registry. The existing `Role` enum describes child positions of Call/Assignment/Import facts (callee, receiver, args, ...); occurrence roles describe what an identifier token *is* (declaration name, binder, label key, ...). Conflating the axes would break `Role::valid_for(kind)` and the target-role partitions.
  Rationale: the two vocabularies have different carriers (parent-scoped role targets vs per-identifier-node classification) and different support semantics.
  Date/Author: 2026-08-04, Fable 5.
- Decision: correlated existence/absence and exact-cardinality assertions live in the policy layer (new `PolicyAnalysis::Assertion` kind that runs a subject selector, joins captures to occurrence rows by AST ID, and aggregates), not as general RQL exists/count/named-join forms. Generalized relational operators (named bindings, equijoins, grouping, set equality) are the epic's shared foundation and thematically belong to #1472's cross-slice work; if a sibling slice needs them first, file a follow-up issue there rather than growing them ad hoc here.
  Rationale: the policy layer already computes exactly the completeness inputs a sound cardinality verdict needs (`query_completion`, truncation, limits), and a policy-side join on stable AST IDs satisfies every acceptance criterion of this issue without inventing a second relational algebra.
  Date/Author: 2026-08-04, Fable 5.
- Decision: initial deep role coverage targets four adapters — Java, Rust, Python, JS/TS — with every other adapter (Go, Ruby, PHP, Scala, Kotlin, C++, C#) shipping an explicit total support table that marks the new roles `Unsupported`. Unsupported roles make dependent queries and assertions incomplete/unreliable, which is the designed-for behavior, so partial rollout is sound rather than wrong. Remaining adapters are follow-on work inside this plan's Milestone 5 or subsequent sessions.
  Rationale: eleven adapters times eleven roles at once is an unreviewable change; the capability system exists precisely so partial support is honest.
  Date/Author: 2026-08-04, Fable 5.
- Decision: occurrence rows are derived on demand per query request (a derived layer over `FileFacts` plus batch definition resolution) and are not persisted in the cache DB in this plan. The facts snapshot itself (with the new occurrence-role rows) remains persisted as today.
  Rationale: YAGNI; resolution batches are already the latency-bearing path for semantic tokens and references, and a premature occurrence table would duplicate the cache-liveness machinery. If latency evidence demands persistence later, that is a measured follow-up.
  Date/Author: 2026-08-04, Fable 5.

- Decision (M1): `OccurrenceRoleSupport` is built by `const` chaining off `OccurrenceRoleSupport::NONE` rather than by a runtime `SemanticCapabilitiesBuilder`-style type. `StructuralSpec::occurrence_role_support` hands the table out by reference, so a runtime builder would force a `LazyLock` (or an equivalent) into all eleven adapters purely to express a constant. The table is still total and still defaults to `Unsupported`; only the construction syntax differs from the prior art.
  Rationale: the property the plan cares about is totality and explicitness, both preserved; the borrow shape is what dictated the constructor.
  Date/Author: 2026-08-04, Fable 5.
- Decision (M1): per-adapter occurrence-role tests extract facts directly (`extract_file_facts` in a `#[cfg(test)]` module beside each spec) instead of using `InlineTestProject`. An occurrence role is a pure function of `(source, spec)`; the analyzer, project and cache layers an inline project stands up cannot change the answer, so the inline form would add setup without adding coverage, while the direct form asserts exact byte offsets and prints every classified token on failure. Milestone 3's end-to-end query tests are where `InlineTestProject` earns its keep, because there the analyzer *is* under test.
  Rationale: behavior-focused coverage of the adapter contract, per the repo's test guidance against tests that duplicate construction logic.
  Date/Author: 2026-08-04, Fable 5.
- Decision (M1): occurrence roles do not count against `max_roles` and are not added to `work_item_count`. An adapter classifies nodes it was handed and never synthesizes them, so the node arena already bounds the work; folding them into `work_item_count` would silently move every existing CodeQuery budget threshold for identifier-dense files.
  Rationale: the budget exists to bound unbounded growth, and this collection cannot grow independently of one that is already bounded.
  Date/Author: 2026-08-04, Fable 5.
- Decision (M1): Python assignment targets (`x = 1`) classify as `ValueReference`, not `Binder`; only `for` targets, `as`-pattern targets, parameters and pattern positions are binders. Python has no declaration form for a local, so calling every assignment target a binding introduction would make `Binder` mean "appears on a left-hand side" in Python and "is declared here" everywhere else, and the class partition would stop meaning the same thing across languages.
  Rationale: a role must mean the same thing in every adapter or the assertion kind in Milestone 4 cannot be written once.
  Date/Author: 2026-08-04, Fable 5.
- Decision (M1): the `occurrences` name in `brokk-bifrost-analysis`'s structural module is currently a re-export of the core vocabulary module (`analyzer::structural::occurrences`). Milestone 2's derivation layer must therefore pick a different module name (`occurrence_rows` or similar) or re-home the re-export, rather than shadowing it.
  Rationale: recorded here because the collision is invisible until M2's first file is created.
  Date/Author: 2026-08-04, Fable 5.

## Outcomes & Retrospective

To be written at milestone completions.

## Context and Orientation

Bifrost is a Rust workspace. The crates that matter here:

- `crates/bifrost-core` — the model layer at the bottom of the dependency graph (no Bifrost dependencies). Holds `CodeUnit`, `Range`, the structural spec trait (`src/analyzer/structural/spec.rs`) and the declarative kind/role registries (`src/analyzer/structural/kinds.rs`).
- `crates/bifrost-analysis` — the analyzer. Tree-sitter parsing, per-language modules (`src/analyzer/{java,rust,python,js_ts,go,ruby,php,scala,kotlin,cpp,csharp}/`), the structural query engine (`src/analyzer/structural/`), usage graphs (`src/analyzer/usages/`), and definition resolution (`src/analyzer/usages/get_definition/`).
- `crates/bifrost-policy` — RQLP policies: `.rqlp` documents, evaluation, findings, rendering (human/JSON/SARIF).
- `crates/bifrost-mcp`, `crates/bifrost-lsp`, `bifrost_searchtools` (Python client), `editors/vscode` — transports that surface query results and policies.

Terms used below:

- "Facts" / "facts arena": `FileFacts` in `crates/bifrost-analysis/src/analyzer/structural/facts.rs`. Per file, a normalized pre-order array of `NormalizedNode { kind: NormalizedKind, range, parent: Option<u32>, name: Option<Span>, subtree_end: u32 }` plus `roles: CompactRows<RoleTarget>` and `source_identity: ContentIdentity` (SHA-256 of the source bytes). Only nodes whose tree-sitter kind appears in the language's `kind_table` become facts. Facts are snapshot-persisted (`encode_snapshot`/`decode_snapshot`, `STRUCTURAL_FACTS_SNAPSHOT_VERSION`, currently 1) in the cache DB via `structural/provider.rs`.
- "Structural spec": per-language `StructuralSpec` impl in `crates/bifrost-analysis/src/analyzer/<lang>/structural.rs`, declaring a `kind_table` (tree-sitter kind string -> `NormalizedKind`), `should_extract`, `supports_role` (currently defaulting to `true`), and `extract(node, kind, sink: &mut RoleSink)` which emits role targets.
- "CodeQuery" / "RQL": the structural query language. Typed IR in `crates/bifrost-analysis/src/analyzer/structural/query/ir.rs` (`QueryValueKind`, `QueryStep`, `CodeQuery`, `SCHEMA_VERSION` currently 7); declarative surface registries in `query/schema.rs` (`query_step_ops!`, `rql_forms!`, `rql_properties!`, `json_fields!`, `QueryStepOption` tables, and the `RQL_*_SCHEMA_VERSION` lineage, head currently `7`); RQL s-expression lowering in `query/sexp.rs`; JSON decode in `query/decode.rs`; canonical JSON render in `query/json.rs`; validation/hover/completion in `query/source.rs`. Execution: `structural/execution/plan.rs` lowers to a DAG; row execution and the giant step-dispatch `match` live in `structural/search/mod.rs`; public row types in `structural/search/results.rs`.
- "RQLP": the policy document format in `crates/bifrost-policy/src/schema.rs` (`policy_records!` etc., `POLICY_SCHEMA_VERSION = 1`), decoded in `source.rs`, defined in `definition.rs` (`PolicyAnalysis::{Match, Taint, Typestate}`), evaluated in `evaluator.rs` (dispatch at ~line 542), aggregated into `PolicyFinding`s (`finding.rs`) with anchors (`finding_identity.rs`) and rendered in `render/{human,sarif}.rs`. Result states: `PolicyRunCompletion::{Complete, ProvenSubset, Inconclusive, Unsupported, Failed}`; batch exit `POLICY_EXIT_{CLEAN,FINDING,UNRELIABLE}` from `coordinator.rs::report_exit_status`.
- "Definition resolution": `crates/bifrost-analysis/src/analyzer/usages/get_definition/mod.rs` — `resolve_definition_batch_with_source_and_cancellation` maps identifier positions to `DefinitionLookupOutcome { status: DefinitionLookupStatus, definitions: Vec<CodeUnit>, lexical_definition, .. }` where `DefinitionLookupStatus` distinguishes `Resolved | NoDefinition | UnresolvableImportBoundary | Ambiguous | UnsupportedLanguage | InvalidLocation | NotFound`.
- "Candidate frontier": `crates/bifrost-analysis/src/analyzer/reference_candidates.rs` — enumerates identifier-ish terminal ranges per file (`semantic_token_candidate_ranges`, `reference_candidate_ranges`), with per-language exclusion predicates (`is_excluded_reference_candidate`) that currently encode non-reference knowledge as booleans for Go, C#, Rust, JS/TS.
- "Capability propagation": adapter `supports_role`/`supports_kind` -> `structural/capabilities.rs` (`QueryFeature`, `QueryFeatures::for_query`, `unsupported_by`) -> `CodeQueryDiagnosticCode::UnsupportedStructuralFeature` with `CodeQueryDiagnosticImpact::Incomplete` -> `CodeQueryResult::completion()` -> policy `evaluator.rs:3608` code map -> `PolicyIncompleteReason::CapabilityIncomplete` -> `PolicyRunCompletion` -> exit status.

What does NOT exist today (verified 2026-08-04): no unified occurrence row or per-file occurrence index anywhere (the only uses of the word are the semantic-IR span-collision disambiguator and prose); no shared namespace type (Rust has a private `RustSymbolNamespace` in `rust/usage_index.rs:70`; other languages use ad-hoc `*_is_type_position` predicates); no occurrence-role vocabulary (the nearest enums are `UsageHitKind` (6 variants), `ReferenceKind` (8), `DeclarationKind` (8 binder kinds, query-local), structural `Role` (10 child-position roles)); no AST ID on captures; no assertion/invariant policy kind; no exists/count/cardinality in RQL; no decoded-spelling handling (raw identifiers, quoted/backticked names) anywhere.

The mined 46-commit inventory in the issue body is the fixture source: each commit is a real regression where an occurrence's syntactic role and semantic classification diverged. Milestone 5 samples them for positive and near-miss fixtures; the inventory must remain in the issue and is not duplicated here.

## Plan of Work

### Milestone 1 — occurrence-role registry, namespace, explicit adapter support, facts extension

Scope: the vocabulary and the truth about who supports it, plus making the facts arena carry it. Nothing user-visible yet beyond unit tests, but this milestone is the foundation every later one builds on and it changes the persisted facts snapshot.

In `crates/bifrost-core/src/analyzer/structural/kinds.rs` (or a sibling module `occurrences.rs` in the same directory if kinds.rs grows unwieldy — keep the registry style identical), add a declarative `occurrence_roles!` macro registry generating `OccurrenceRole`, `ALL_OCCURRENCE_ROLES`, `label`, `from_label`, `description`, serde snake_case — same shape as `normalized_kinds!`. Initial vocabulary (one variant per issue-named position):

    DeclarationName      "declaration_name"   the name token of a declaration head
    Binder               "binder"             a pure binding introduction (parameter, local, pattern binder, loop variable, catch variable)
    LabelOrKey           "label_or_key"       a label, keyword-argument name, or keyed-field/map-key position
    TypeOperand          "type_operand"       an identifier consumed as a type (annotations, ascriptions, generic arguments, extends/implements operands)
    PathSegment          "path_segment"       a non-terminal segment of a qualified path or scoped name
    ImportAlias          "import_alias"       the locally introduced alias name in an import/export
    ImportTarget         "import_target"      the imported/exported source name
    ReceiverPosition     "receiver_position"  the receiver of a member access or call
    MemberPosition       "member_position"    the member name in a member access or call
    PatternPosition      "pattern_position"   a non-binding identifier inside a pattern (e.g. matched constant, struct-pattern field name)
    GeneratedSource      "generated_source"   a token whose presence generates declarations elsewhere (e.g. property macros, accessor-generating fields)
    ValueReference       "value_reference"    a plain read/write of a value in expression position

Add a shared `Namespace` enum in the same module: `Type | Value | Module | Macro | Label`, with labels and serde, promoted from the semantics of `RustSymbolNamespace` (`crates/bifrost-analysis/src/analyzer/rust/usage_index.rs:70`); leave the Rust-internal type in place for now and do not rewire the Rust resolver in this plan (that is #1474/#1475 territory) — the shared type is for occurrence rows.

Add an `OccurrenceClass` enum: `Declaration | Reference | Binding | NonReference`. The role-to-class mapping is a total function `OccurrenceRole::class()` (DeclarationName -> Declaration; Binder, PatternPosition-binding -> Binding; ValueReference, TypeOperand, PathSegment, ImportTarget, ReceiverPosition, MemberPosition -> Reference; LabelOrKey, ImportAlias, GeneratedSource -> NonReference), with the documented caveat that adapters classify the role and the class follows — a role never straddles classes; where a syntax position can be either (e.g. shorthand destructuring is binder in patterns, reference in expressions), the adapter must emit the correct role for the concrete node.

Extend the facts layer (`crates/bifrost-analysis/src/analyzer/structural/facts.rs`): store per-node occurrence roles as a new compact rows table (`occurrence_roles: CompactRows<OccurrenceRole>` keyed by node id, mirroring how `roles` stores `RoleTarget`), add wire codes (`occurrence_role_code`/`decode_occurrence_role`), and bump `STRUCTURAL_FACTS_SNAPSHOT_VERSION` to 2 so stale snapshots re-extract rather than misdecode. Extend `RoleSink` (`crates/bifrost-core/src/analyzer/structural/spec.rs`) with `occurrence_role(node, role: OccurrenceRole)` so specs can emit them during the existing `extract` walk.

Replace the boolean `supports_role` pattern for the new axis with an explicit total table: add `OccurrenceRoleSupport` (array sized by `OccurrenceRole::COUNT`, entries `Supported | Unsupported`, defaulting to `Unsupported`, builder-style like `SemanticCapabilitiesBuilder` in `crates/bifrost-analysis/src/analyzer/semantic/capabilities.rs`) and a required `fn occurrence_role_support(&self) -> &OccurrenceRoleSupport` on `StructuralSpec` with no default implementation, so every one of the eleven adapters is forced to state its table explicitly (acceptance criterion: every adapter declares supported and unsupported roles explicitly). Wire the table into `structural/provider.rs` and `structural/capabilities.rs` alongside `QueryFeature::Role` — add `QueryFeature::OccurrenceRole(OccurrenceRole)` so queries and assertions that mention an unsupported occurrence role produce `UnsupportedStructuralFeature` diagnostics with `Incomplete` impact through the existing spine.

Implement emission for the four deep adapters (Java, Rust, Python, JS/TS) in their `structural.rs` files: extend kind tables where identifier-ish terminals are not yet facts (verify per adapter that every occurrence-bearing position is a fact node; Java already maps `identifier`, `type_identifier`, `scoped_identifier`, `scoped_type_identifier` to `NormalizedKind::Identifier`), and emit occurrence roles in `extract` from tree-sitter fields (`child_by_field_name("name")` etc.), reusing the classification knowledge currently trapped in `reference_candidates.rs::is_excluded_reference_candidate` and the per-language `declarations.rs` name-node logic. The seven other adapters implement `occurrence_role_support` returning all-`Unsupported` and emit nothing.

Also regenerate the Rune IR TextMate vocabulary if the registries the grammar test reads change (`kinds.rs` test `rune_ir_textmate_vocabulary_matches_canonical_registries` reads `editors/vscode/syntaxes/bifrost-rune-ir.tmLanguage.json`); if the new registry is a separate axis not covered by that regex, add an equivalent self-consistency test for the new vocabulary instead.

As built (2026-08-04): the occurrence-role registry is a separate axis and the Rune IR grammar regexes read only `ALL_KINDS` and `ALL_ROLES`, so `rune_ir_textmate_vocabulary_matches_canonical_registries` is untouched. The equivalent self-consistency tests live in `crates/bifrost-core/src/analyzer/structural/occurrences.rs`: unique labels with serde round-trip for roles, classes and namespaces; a total role-to-class partition with every class inhabited; dense indices that size the support table; and a totality/default test for `OccurrenceRoleSupport`. Wire-code round-trip (including rejection of an out-of-range code) lives with the codec in `structural/facts.rs`.

Tests: registry self-consistency (unique labels, total partitions, wire-code round trip); snapshot version round trip with occurrence rows; per-adapter behavior tests using `InlineTestProject` (from `tests/common/inline_project.rs`) asserting that, for a small file, specific byte ranges carry specific occurrence roles — e.g. in Java, the class name token is `declaration_name`, a parameter is `binder`, an annotation name is `type_operand`, an import tail is `import_target`; and that an adapter with all-Unsupported support emits nothing while its table says so.

Acceptance for M1: `cargo nextest run` green on the new unit and inline-project tests; `cargo clippy --workspace --all-targets -- -D warnings` clean; the facts snapshot version bump forces re-extraction (verified by a decode-mismatch test).

### Milestone 2 — the occurrence derivation layer

Scope: a per-file, request-scoped producer that turns facts plus resolution into full occurrence rows. Internal API only.

New module `crates/bifrost-analysis/src/analyzer/structural/occurrences.rs`. Define the internal row:

    pub struct OccurrenceRow {
        pub file: ProjectFile,
        pub content_identity: ContentIdentity,
        pub node: u32,                       // facts-arena id; the AST ID pair is (content_identity, node)
        pub range: Range,
        pub role: OccurrenceRole,
        pub class: OccurrenceClass,
        pub namespace: Namespace,
        pub enclosing: Option<CodeUnit>,
        pub raw_spelling: String,            // exact source slice of the node
        pub decoded_spelling: Option<String>,// only when decoding changes it (r#ident, `quoted`, escaped)
        pub target: OccurrenceTarget,
    }

    pub enum OccurrenceTarget {
        None,                                 // non-reference classes
        Resolved(Vec<CodeUnit>),              // reference class, resolved (possibly ambiguous: >1)
        Lexical(LexicalDefinition),           // binding/reference resolved to a query-local binder
        Unresolved(DefinitionLookupStatus),   // reference class, resolution failed or boundary
    }

Producer: `fn occurrences_for_file(analyzer, file, source, cancellation) -> OccurrenceFileResult` where the result carries rows plus a completeness marker (`Complete | Incomplete { unsupported_roles, reasons }`). The pass walks the facts arena selecting nodes that carry occurrence roles (Milestone 1), fills range/spelling from `NormalizedNode` (never byte-scanning — the existing `ResolvedReferenceSite` token-bounds scanner in `usages/reference_site.rs` must not be used here), computes `enclosing` via `analyzer.enclosing_code_unit`, and resolves reference-class rows through `resolve_definition_batch_with_source_and_cancellation` (one batch per file, the same way `semantic_tokens.rs` does). Namespace comes from the role plus adapter classification (TypeOperand -> Type, PathSegment -> Module-or-Type per adapter, LabelOrKey -> Label, default Value); where the adapter cannot say, the row is omitted and the file result is marked incomplete for that role — never guessed.

Decoded spelling: a per-adapter hook on the structural spec (`fn decode_spelling(&self, raw: &str) -> Option<String>` default `None`), implemented for Rust (`r#ident` -> `ident`) and any deep adapter with quoting (JS/TS string-keyed members stay out of scope — they are not identifier occurrences).

Stable ID minting: `occurrence_id(content_identity, node, role)` via `LengthDelimitedDigest::new(b"bifrost.code_query.occurrence.v1")`, following `search/value_flow.rs::public_symbol_site` — no mount, no dense workspace IDs, content-scoped by construction.

Tests: inline-project tests per deep language covering the issue's fixture list at the unit level — renamed and shorthand destructuring (JS/TS: `const { a, b: c } = x` gives `a` binder+? — `a` is binder in the pattern; near-miss: `{ a }` in an expression is a reference), type operands vs binders (Python annotations vs parameters), keyed fields vs map keys, static qualifiers vs shadowing values (Java), raw identifiers (Rust `r#type`), declaration heads vs genuine reads. Also: cancellation propagates; an unsupported-role language yields `Incomplete`, not empty-complete.

### Milestone 3 — RQL/JSON typed domain exposure

Scope: occurrences become queryable, captures become correlatable, transports learn the new rows. This follows the established add-a-typed-domain recipe (the value-flow #1297 and CFG #824 precedents); the file list below is the recipe instantiated.

Schema lineage: add `RQL_OCCURRENCE_SCHEMA_VERSION = 8` in `query/schema.rs`, chain a `SchemaVersionDescriptor` to the current head, raise `SCHEMA_VERSION` in `query/ir.rs` to 8, update the lineage test (`schema.rs:~1275`), and bump the compatible-head fixtures under `tests/fixtures/policies/**/*.normalized.json` (leave explicitly pinned older fixtures alone).

IR (`query/ir.rs`): `QueryValueKind::Occurrence` + label; steps and their typing arrows in `output_kind()`:

    occurrences-of   : declaration -> occurrence        (all occurrences whose target resolves to the declaration, plus its declaration-name occurrence)
    occurrences-in   : structural_match | file -> occurrence   (occurrences lexically inside the node/file)
    occurrence-target: occurrence -> declaration        (resolved targets of reference-class rows)
    file-of          : occurrence -> file               (existing fan-in gains an arm)

Seed form: an `occurrence` seed (`CodeQuerySeed` variant) with filter options `:class`, `:role`, `:namespace`, plus the standard `language`/`inside`/`where` machinery. Constrained-value label tables for `OccurrenceClass`, `OccurrenceRole`, `Namespace` following `ALL_REFERENCE_KINDS` style at the bottom of `schema.rs`.

Registry entries (`query/schema.rs`): `query_step_ops!` entries with `signature`, `description`, `since: 8`; matching 1:1 `rql_forms!` wrappers and `RqlForm::property()` arms; `json_fields!` step fields; `QueryStepOption` tables; `ValueShape` additions for the constrained values. Frontends: `query/sexp.rs` lowering, `query/decode.rs` decode + option allowlist, `query/json.rs` canonical render, `query/source.rs` validation/hover/completion.

Capture AST IDs: add the facts node id to `CaptureBinding` (`matcher.rs`) and surface it on `CodeQueryCapture` (`results.rs`) as `ast_id: Option<String>` minted with `LengthDelimitedDigest::new(b"bifrost.code_query.ast_node.v1")` over `(content_identity, node)` — the same pair occurrence IDs embed, so equality of the digest is the equijoin. Also expose the same `ast_id` on `CodeQueryMatch` for the root node. This is additive to the wire shape; the schema-version bump covers it.

Row types (`structural/search/results.rs`): `CodeQueryResultValue::Occurrence(Box<CodeQueryOccurrence>)` with

    pub struct CodeQueryOccurrence {
        pub id: String,            // occurrence digest
        pub ast_id: String,        // node digest shared with captures
        pub path: String,
        pub language: String,
        pub class: ..., pub role: ..., pub namespace: ...,
        pub range: CodeQueryRange, pub start_byte: usize, pub end_byte: usize,
        pub enclosing_symbol: Option<String>,
        pub raw_spelling: String, pub decoded_spelling: Option<String>,
        pub target: CodeQueryOccurrenceTarget,   // none | resolved{units} | lexical{...} | unresolved{status}
    }

plus `CodeQueryResultRef::Occurrence`, diagnostic codes (`OccurrenceRoleUnsupported`, `OccurrenceResolutionIncomplete`, `OccurrenceRowBudgetExhausted`) with `as_str()` and impacts, limits/work counters, `DetailedCodeQueryDomain/Key::Occurrence` and every exhaustive-match arm the compiler surfaces.

Execution (`structural/search/`): new dispatch arms in the step `match` in `mod.rs`, a small adapter module calling Milestone 2's producer, `SemanticPipelineValue`-equivalent plumbing (occurrences are not semantic-artifact-backed, so follow the `ReferenceSite`/`CallSite` pipeline-value pattern rather than the semantic one), dedup keys, `public_result`/`public_ref`/`detailed_projection` arms. Unsupported occurrence roles referenced by a query emit the capability diagnostics from Milestone 1 through `QueryFeatures`.

Policy plumbing for the new rows (not yet the assertion kind): `evaluator.rs` terminal-domain decision (Occurrence IS a valid match-policy terminal domain — a match policy listing suspicious occurrences is legitimate), evidence arms, ref label/path arms, diagnostic-code -> `PolicyIncompleteReason` map entries, `MatchResultDomain::Occurrence` + anchor support in `finding_identity.rs`, `selector_compiler.rs` terminal list.

Transports: `mcp_common.rs`/`mcp_extended.rs` vocabulary prose, `searchtools_service.rs`, LSP URI enrichment (`server.rs` ~1342), REPL rendering (`code_query_repl.rs`), Python client (`bifrost_searchtools/models.py`, `__init__.py`, README), VS Code (`rql_query.ts`/`rql_results.ts`, all switch sites). TextMate grammar `editors/vscode/syntaxes/bifrost-rql.tmLanguage.json`: form alternation gains `occurrences[-_]of|occurrences[-_]in|occurrence[-_]target|occurrence`, keyword options gain `class|role|namespace` conservatively; update `editors/vscode/test/rql-grammar.test.ts`.

Tests: new `tests/suite_cross_language/code_query_occurrences.rs` (add `mod` line in that harness's `main.rs` per `.agents/docs/test-harness-consolidation-2026-07.md`) with behavior-focused coverage: seed + filters returns classified rows in the four deep languages; `occurrences-of` on a declaration returns its declaration-name row plus references; capture `ast_id` equals the occurrence `ast_id` for the same node (the correlation contract, asserted end to end); unsupported language yields Incomplete; round-trip RQL <-> JSON; hover/validation cases in `query/tests.rs` and `source.rs` tests; docs examples in `code_query_docs.rs`; Python/VS Code client tests.

### Milestone 4 — the RQLP `assertion` analysis kind

Scope: `(analysis :type assertion ...)` with correlated require/forbid/cardinality over occurrences at captured roles, one multi-location finding per violated assertion, full unreliable propagation, renderer parity.

Vocabulary (`crates/bifrost-policy/src/schema.rs`): `PolicyAnalysisKind::Assertion`, `AnalysisOwners` assertion bit (audit every `POLICY_ALL` record's applicability rather than blanket-granting), and new records:

    (analysis :type assertion
      (subject (rql ... (capture NAME) ...))            ; subject selector; must produce captures
      (assert :at NAME                                   ; capture name to correlate on
              :role declaration_name|binder|...          ; expected occurrence role
              :expect declaration|reference|binding|none ; expected class ("none" = forbid)
              :cardinality (exactly N)|(at-least N)|(at-most N)   ; default (exactly 1); (exactly 0) == :expect none
              [:namespace type|value|module|macro|label]
              [:require-target]                          ; reference-class rows must have Resolved target
      ))

Multiple `assert` records per analysis are allowed; each is an independent invariant. Fan-out (mechanical, per the fourth-kind checklist): `definition.rs` (`PolicyAnalysis::Assertion { spec }`, `PolicyAnalysisType::Assertion`), `source.rs` decode, `format.rs`, `resolved.rs`, `canonical_loaded.rs` (canonical JSON projection — required for `PolicySemanticHash`; note any change to canonical projection of existing kinds would invalidate every built-in hash, so make the projection purely additive), `classification.rs`, renderer analysis-type labels.

Evaluation (`evaluator.rs`): new `evaluate_assertion_policy` alongside match/taint/typestate. It runs the subject selector with `result_detail = Full` (captures required), collects per-capture `(path, ast_id)` pairs, runs an occurrence query scoped to the subject files, joins by `ast_id` equality (never range or text), and evaluates each assert record per subject node. Soundness rules, in order:

1. If the subject query completion is not `Complete`/`ProvenSubset`, or the occurrence query is incomplete, or any adapter involved marks the asserted role `Unsupported`, or truncation/limits fired: the run is `Inconclusive`/`Unsupported` with the capability recorded — a `forbid`/`exactly` verdict over incomplete rows is never a pass or a clean.
2. A subject with no captured node for `:at` is an authoring error (`InvalidExecutionPlan`-style diagnostic), not an empty pass.
3. Cardinality is evaluated over the joined complete row set; violations produce findings, satisfied asserts produce nothing.

Findings: new `assemble_assertion_run` (one finding per violated assert per subject node, aggregating all actual rows), `AssertionFindingEvidence { asserted_role, expected_class, expected_cardinality, actual_count, capability: Vec<PolicyCapability> }` + `PolicyFindingEvidence::Assertion`, new `PolicyLocationRelationship::{Subject, ExpectedOccurrence, ActualOccurrence}` with matching arms in `render/human.rs::location_relationship` and `render/sarif.rs::relationship_label`, and a new `AssertionFindingAnchor` keyed on the subject node (`ast_id` digest + assert record id) so absence violations — which have no offending occurrence to anchor on — still get a strong stable anchor. Populate `related` with the subject location plus every actual occurrence row (respecting `related_truncated` accounting).

Manifest: adding the analysis kind must not change existing built-in policy semantic hashes; assert this with the existing `print_computed_semantic_hashes` test comparing before/after. `run_policy` MCP needs no schema change (kind selection is via document content), but `searchtools_service.rs` status mapping and the policy CLI tests gain assertion cases.

Tests: `tests/suite_bench_policy/` (or the suite the manifest lists for policy CLI) end-to-end: an assertion policy over a fixture with a seeded role-fidelity bug exits `finding` with one multi-location finding whose related locations include subject and actual rows in all three renderers; the corrected fixture exits `clean`; the same policy against a language whose adapter marks the role `Unsupported` exits `unreliable`; truncated occurrence results exit `unreliable`; JSON/SARIF/human parity snapshots.

### Milestone 5 — conformance fixtures from the mined inventory, rollout, gates

Scope: prove the capability against the class of bugs that motivated it, and leave the surface release-ready.

From the 46-commit inventory in the issue, select at least six representative regressions spanning the four deep languages and write fixture pairs (buggy shape as positive, corrected/nearby shape as near-miss) under the existing fixture conventions, exercised through both the RQL surface (occurrence queries in `code_query_occurrences.rs`) and the assertion surface (policies in test fixtures). Mandatory scenario coverage (issue acceptance): renamed/shorthand destructuring, type operands versus binders, keyed fields versus map keys, static qualifiers versus shadowing values, quoted annotations versus strings, declaration heads versus genuine reads. Add a near-miss for every positive.

Audit that no new code path uses regex, source text, or range coincidence where AST identity is available (the correlation joins, the spelling extraction, the fixture assertions). Consider minimizing one recurring smell into a candidate `.rqlp` rule per the repo's "Review findings as RQL regressions" policy only if it meets the shippable-rule bar; otherwise leave the built-in pack untouched.

Decide and record (Decision Log) whether any additional adapters graduate from `Unsupported` in this plan or in follow-up sessions. Update docs (`docs/src/content/docs/{code-query-json,code-querying,rune-query-language,rql-vscode,python-client,static-analysis-policies}.md`) with executable examples harvested by the docs tests. Run the full pre-push gate.

## Concrete Steps

All commands from the repository root (`/Users/dave/Workspace/BrokkAi/bifrost` or the active worktree). Commit checkpoints on the current branch after each coherent unit of work, with multiline messages explaining the why.

Focused validation during a milestone (featureless, task-scoped):

    cargo nextest run -p brokk-bifrost-core -p brokk-bifrost-analysis
    cargo nextest run -p brokk-bifrost-policy        # Milestones 4-5
    cargo clippy --workspace --all-targets -- -D warnings

Note the clippy PATH caveat on this machine: bare `cargo clippy` may pick a Homebrew driver; ensure the rustup toolchain is first on PATH. Inside nested worktrees do not use the `clippy-no-cuda` alias (duplicate alias-array merge breaks it) — use the expanded command.

Pre-push gate at milestone boundaries:

    scripts/pre-push-gate.sh

VS Code grammar/client tests (Milestone 3):

    cd editors/vscode && npm test

Python client tests (Milestone 3):

    uv run --python 3.12 -- pytest python_tests/test_searchtools_client.py

Do not enable `nlp` for any of this work; it is unrelated to semantic search.

## Validation and Acceptance

Behavioral acceptance, per milestone:

- M1: a new unit test in `bifrost-core` fails if any adapter omits its `occurrence_role_support` table (compile error by design — the trait method has no default); inline-project tests show specific ranges carrying specific roles in Java/Rust/Python/JS-TS; a facts snapshot encoded at version 1 is rejected/re-extracted at version 2.
- M2: `occurrences_for_file` on a Java fixture returns rows where the class-name token is `{class: declaration, role: declaration_name, namespace: type}` and a shadowed static qualifier resolves to the static target, not the local; a Scala file (undeep adapter) yields `Incomplete`, not `Complete` with zero rows.
- M3: in the REPL or via MCP `query_code`, `(occurrences (language "rust") (role binder))` returns binder rows with stable IDs; a structural query capturing a node yields a capture whose `ast_id` string-equals the `ast_id` of the occurrence at that node; RQL <-> canonical JSON round-trips; schema version 7 documents still validate, version 8 forms are rejected under an explicit `:schema-version 7` pin.
- M4: `run_policy` on an assertion policy over a seeded-bug fixture reports status `finding` with one finding whose related locations list the subject and every actual occurrence, in human, JSON, and SARIF output; the corrected fixture reports `clean`; an unsupported-role language reports `unreliable`. Exit codes 1/0/2 respectively from the policy CLI.
- M5: the six mandatory scenario fixture pairs pass; `scripts/pre-push-gate.sh` green; `scripts/check-workspace-packages.sh` unaffected (no new published files).

## Idempotence and Recovery

Every milestone is additive until its final wiring step; re-running builds and tests is always safe. The facts snapshot version bump is self-healing (old snapshots are discarded and re-extracted). If Milestone 3's schema bump must be rolled back mid-work, revert the `SCHEMA_VERSION` constant and the descriptor; fixtures pinning the compatible head are updated in the same commit as the bump so a revert is one `git revert`. The `canonical_loaded.rs` change in Milestone 4 must be verified hash-neutral for existing kinds before commit (run the built-in catalog load test); if hashes moved, the projection change was not additive — fix the projection, never regenerate the manifest to paper over it.

## Artifacts and Notes

Key prior art to imitate, by path:

    crates/bifrost-analysis/src/analyzer/structural/search/value_flow.rs   public_symbol_site: digest-minting recipe
    crates/bifrost-analysis/src/analyzer/semantic/capabilities.rs          total capability table pattern
    crates/bifrost-analysis/src/analyzer/structural/query/schema.rs        registry macros + schema lineage
    crates/bifrost-lsp/src/lsp/handlers/semantic_tokens.rs                 whole-file classify-and-resolve pass shape
    crates/bifrost-analysis/src/analyzer/reference_candidates.rs           existing non-reference exclusion knowledge
    .agents/plans/issue-1297-codequery-value-flow-endpoints.md             the last typed-domain rollout, end to end

The 46-commit inventory lives in the GitHub issue body for #1473 and is the source for Milestone 5 fixture selection.

## Interfaces and Dependencies

End-state signatures that must exist (paths relative to repo root):

In `crates/bifrost-core/src/analyzer/structural/kinds.rs` (or sibling `occurrences.rs`):

    pub enum OccurrenceRole { DeclarationName, Binder, LabelOrKey, TypeOperand, PathSegment,
                              ImportAlias, ImportTarget, ReceiverPosition, MemberPosition,
                              PatternPosition, GeneratedSource, ValueReference }
    pub enum OccurrenceClass { Declaration, Reference, Binding, NonReference }
    pub enum Namespace { Type, Value, Module, Macro, Label }
    impl OccurrenceRole { pub fn class(self) -> OccurrenceClass; pub fn label(self) -> &'static str; }
    pub struct OccurrenceRoleSupport { /* total table, Supported|Unsupported per role */ }

In `crates/bifrost-core/src/analyzer/structural/spec.rs`:

    fn occurrence_role_support(&self) -> &OccurrenceRoleSupport;   // no default: every adapter declares
    // RoleSink gains: fn occurrence_role(&mut self, node: Node, role: OccurrenceRole);

In `crates/bifrost-analysis/src/analyzer/structural/occurrences.rs`:

    pub struct OccurrenceRow { /* as specified in Milestone 2 */ }
    pub enum OccurrenceTarget { None, Resolved(Vec<CodeUnit>), Lexical(LexicalDefinition), Unresolved(DefinitionLookupStatus) }
    pub fn occurrences_for_file(...) -> OccurrenceFileResult;

In `crates/bifrost-analysis/src/analyzer/structural/query/ir.rs`:

    QueryValueKind::Occurrence
    QueryStep::{OccurrencesOf, OccurrencesIn, OccurrenceTarget}
    // schema.rs: RQL_OCCURRENCE_SCHEMA_VERSION = 8

In `crates/bifrost-analysis/src/analyzer/structural/search/results.rs`:

    CodeQueryResultValue::Occurrence(Box<CodeQueryOccurrence>)
    pub struct CodeQueryOccurrence { /* as specified in Milestone 3, incl. id + ast_id */ }
    // CodeQueryCapture gains ast_id: Option<String>; CodeQueryMatch gains ast_id

In `crates/bifrost-policy/src/definition.rs`:

    PolicyAnalysis::Assertion { spec: AssertionPolicySpec }
    pub struct AssertionPolicySpec { pub subject: PolicySelector, pub asserts: Vec<OccurrenceAssert> }
    pub struct OccurrenceAssert { pub at: String, pub role: OccurrenceRole, pub expect: ExpectedOccurrence,
                                  pub cardinality: AssertCardinality, pub namespace: Option<Namespace>,
                                  pub require_target: bool }

Dependency direction constraints (enforced by `scripts/check-workspace-dependencies.mjs`): the new core types live in `brokk-bifrost-core` with no Bifrost dependencies; the derivation layer and query surface live in `brokk-bifrost-analysis`; the assertion kind lives in `brokk-bifrost-policy`. Nothing here touches `nlp` crates.

Revision note (2026-08-04): initial version, authored from three targeted codebase surveys (typed-domain recipe, occurrence data inventory, RQLP assertion machinery) recorded in Surprises & Discoveries and Context and Orientation.
