# Expose lexical resolution context and precedence as typed RQL rows (issue #1474)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

Parent context: this is child issue #1474 of epic #1472 (turning 275 mined bug-fix commits into RQL/RQLP capabilities). This slice owns "lexical scope, imports, namespaces, and precedence" (53 commits, inventoried in the GitHub issue body). It builds directly on the completed sibling #1473 (semantic occurrences and AST-role fidelity, merged as PR #1571, ExecPlan `.agents/plans/issue-1473-semantic-occurrences-ast-role-fidelity.md`), which established the occurrence-row substrate, the AST-identity join contract, and the RQLP `assertion` analysis kind that this plan extends. Capabilities that belong thematically to a sibling slice (canonical identity through qualified routes is #1475; receiver/member dispatch is #1477; overload selection is #1478) must be filed as follow-ups against those issues rather than built here.

## Purpose / Big Picture

Today Bifrost can tell you *what* an identifier occurrence resolved to (the #1473 occurrence row carries `OccurrenceTarget`), but it cannot tell you *why* — or why not. The resolver considers candidates in a precedence order (local binding beats member, member beats import, import beats package), rejects losers by shadowing, namespace, visibility, or position, and then throws all of that away: precedence is statement order inside fourteen per-language resolver files, a rejected candidate is a `continue`, and the only surviving trace is a free-text diagnostic string on the whole outcome. The 53 mined regressions in the issue inventory share one shape: the resolver picked the wrong candidate, or rejected the right one, and nothing queryable could have expressed the invariant "the selected target is the unique highest-precedence applicable candidate here."

There is a second, concrete motivation recorded in the issue comments: running the built-in `bifrost.code-smells` pack against this repository produced 284 findings with a 100% false-positive rate, and roughly 250 of them reduce to one missing predicate — *is the value operated on inside this loop declared inside or outside the loop body?* That is a reaching-binding question: join the receiver occurrence to the binding that is actually in effect at that position, then ask whether that binding's declaring scope is contained in the loop. Neither "the reaching binding of an occurrence" nor "the declaring scope of a binding" exists as data today.

After this change, four things work that do not work today:

1. RQL can enumerate the lexical environment as typed rows. A query can list the lexical scopes of a file (each with a stable AST identity and a parent), the bindings each scope introduces (locals, parameters, pattern binders, imports — each with the byte interval in which it is in effect and its hoisting behavior), and the package/module clause a file belongs to. The same rows appear in canonical CodeQuery JSON.
2. An identifier occurrence can be joined to its *reaching binding*: the specific binding of that name that is in effect at that exact source position, computed from activation intervals and scope ancestry rather than from source-order co-presence. From the binding, one more step reaches its declaring scope, so "receiver declared outside the enclosing loop" becomes a two-step structural query.
3. Reference-class occurrences expose *resolution candidate rows*: for a supported occurrence, the set of candidates the resolver considered, each with a precedence tier (a small language-neutral vocabulary: lexical binding, own member, inherited member, explicit import, wildcard import, same package/module, external, and so on), an outcome (selected, or rejected with a typed reason such as shadowed, wrong namespace, not visible, not in scope at this position), and a boundary status (whether resolution crossed an authoritative boundary such as an unindexed external root). Where a language's resolver has not been instrumented, the candidate query reports incomplete — never an empty complete answer.
4. The RQLP `assertion` analysis kind (from #1473) gains resolution asserts: a policy can require that the selected target of an occurrence sits at (or above) a given precedence tier, forbid selection from a given tier (the "no name-only fallback past an authoritative boundary" contract), and require or forbid reaching-binding containment relative to the subject capture (the loop-invariance predicate). Incomplete inputs yield `unreliable`/`Inconclusive`, never a clean pass.

Observability: after the final milestone, `cargo nextest run` shows environment and candidate queries returning classified rows in the four deep languages (Java, Rust, Python, JS/TS); the policy CLI runs a resolution assertion that fails on a seeded shadowing fixture and passes on its near-miss; and a fixture-level prototype of the "sort in loop over a loop-invariant binding" rule separates the true-positive shape (`crates/bifrost-policy/src/composition/precedence.rs`-style: binding declared outside the `while`, sorted each iteration) from the dominant false-positive shape (loop-local binding sorted once per iteration).

## Progress

- [x] (2026-08-04) Branch merged with `origin/master` at `a97b50c0d` so the #1473 foundation (schema v8, occurrence rows, assertion kind) is present.
- [x] (2026-08-04) Two codebase surveys completed (resolver/scope machinery; import/namespace/external machinery); findings recorded in Context and Orientation below.
- [x] (2026-08-04) ExecPlan drafted.
- [ ] Milestone 1 — core vocabulary, scope facts, capability tables.
- [ ] Milestone 2 — lexical environment derivation layer (scopes, bindings, imports, reaching bindings).
- [ ] Milestone 3 — resolution trace (candidate/outcome rows) out of `get_definition`.
- [ ] Milestone 4 — RQL/JSON typed domain exposure, schema version 9.
- [ ] Milestone 5 — RQLP resolution asserts.
- [ ] Milestone 6 — conformance fixtures from the mined inventory, loop-invariance prototype, audit, docs, gates.

## Surprises & Discoveries

Findings from the pre-plan surveys (2026-08-04). Update this section as implementation proceeds.

- Observation: precedence is nowhere a value. The Java bare-identifier path (`crates/bifrost-analysis/src/analyzer/usages/get_definition/java.rs:1282-1349`) encodes "file-local type > local binding gate > member > static import > boundary" purely as statement order with early returns. The same is true across all fourteen `get_definition/*.rs` files (~54k lines total). Rejection sites (`LocalInferenceEngine::is_shadowed`, `rust::lexical_scope::name_shadowed_in_tree`, `python_name_shadowed_at`, Go's `shadowed: bool`) discard the losing candidate; the only surviving record is the untyped `DefinitionLookupDiagnostic { kind: String, message: String }` (`get_definition/mod.rs:447`), and navigation post-processing rewrites even that (`mod.rs:1455, 1512, 1528, 1548`).
- Observation: the exact join point for candidate rows already exists. `occurrence_rows.rs:379` zips reference-class occurrence rows with `DefinitionLookupOutcome`s and collapses each outcome to `OccurrenceTarget`, dropping `diagnostics` and everything the resolver knew. Candidate rows hang off this same zip.
- Observation: activation intervals exist as data in exactly two languages, in different shapes, both private and boolean-query-only. Rust: `RustLexicalScopeIndex` (`rust/lexical_scope.rs:474`) with `BindingVisibility { start, end, function }` — `let` bindings run from declaration end to scope end (`:514`), `match` arm bindings from pattern end to arm end (`:532`), items get the whole scope (hoisted, `:668`). Ruby: `LocalBindingTimeline` (`ruby/semantic.rs:239`) with per-name activation offsets. JS/TS deliberately drops order (`JsTsLexicalBindingIndex`, `js_ts/syntax.rs:120-131` — `var` hoists, lexical declarations are treated scope-wide). Python is function-scope categorical (`PythonLexicalScopeInventory::name_resolution_at`, `python/bindings.rs:329`) except comprehension targets, which are range-scoped.
- Observation: no language builds a parent-linked lexical scope tree. Rust and JS/TS build flat name-to-interval maps; everyone else re-walks tree-sitter ancestors per query through the shared grammar tables in `analyzer/lexical_definitions.rs` (`is_lexical_scope` at `:1147`, `is_parameter_owner` at `:886`, etc., all eleven languages covered). The only parent-linked scopes in the repo are CFG completion frames (`semantic/cfg.rs:715-780`), which are control-flow targets, not binding environments.
- Observation: the reaching-binding answer is computed and immediately discarded today. `resolve_lexical_binding` (`lexical_definitions.rs:259`) walks ancestors outward and, when a plain local wins, returns `LexicalBindingResolution::OtherLocal` — deliberately opaque, "a nearer local wins" without saying which. `get_definition/mod.rs:1147-1155` turns that into `no_definition("local_binding")`. This is also the root cause of follow-up issue #1569 (Java bare local reads resolve `NoDefinition`): the winner's identity exists at the moment of the walk and is thrown away.
- Observation: `StructuredImportPath` (`bifrost-core/src/analyzer/model.rs:2560`) already carries `lexical_prefixes`, `lexical_scopes` (byte ranges), and `declaration_start_byte` — import activation intervals exist as parsed data. Only Scala consumes them positionally (`scala_import_visible_at`, `scala/wildcard_imports.rs:202`). Python's `PythonImportBinding` (`python/imports.rs:124`) carries `start_byte, scope_start_byte, scope_end_byte` explicitly.
- Observation: Scala has a working precedence/ambiguity prototype, confined to Scala and `pub(crate)`: `ScalaWildcardImportEnvironment { owners, ambiguous: bool }` with ordered owners, and `ScalaExplicitImportTier { candidate, declaration, package }` (`scala/wildcard_imports.rs:45, :57`). It is the design template for the tier vocabulary, but Scala's occurrence adapter is all-`Unsupported` (the #1473 rollout stopped at four deep adapters), so Scala cannot be a claimed language here without first graduating its occurrence support.
- Observation: wildcard-import ambiguity is a first-class value only in Scala. Java silently returns `None` when two wildcard packages collide on a simple name (`java/imports.rs:637-646`); Python skips `from x import *` entirely when building binding rows (`python/imports.rs:186`); Rust and JS/TS track nothing. "Unresolved wildcard ambiguity as incomplete evidence" (an issue requirement) has exactly one precedent to generalize.
- Observation: `DefinitionLookupStatus::UnresolvableImportBoundary` is one undifferentiated bucket, and `semantic/workspace_oracle/dispatch.rs:678` classifies it as `DispatchQuality::Complete`. It cannot distinguish "external root exists, declared in the build, but unindexed" from "nothing known". The JVM external index tracks its own truncation (`MAX_INDEX_ARTIFACTS` etc., `jvm/external.rs:42-50`) but its `production_diagnostics` are `#[cfg(test)]`-only. Semantic-pack inventory evidence (`semantic_model/authoring.rs:761-895`, commit `81f536ba3`) is the closest existing "external root identity plus availability" row.
- Observation: no normalized visibility model exists for workspace source. `CodeUnit` has no visibility field; the typed `Visibility` enum (`semantic_model/model.rs:350`) covers external artifact facts only; Rust's `RustVisibility`/`Domain` (`rust/imports.rs:12`, `rust/usage_index.rs:230`) is the most developed model and is really name-resolution reachability; Java and PHP do string modifier matching.
- Observation: loop containment is ready-made. `NormalizedKind::{Loop, ForLoop, WhileLoop}` with subsumption exist and are mapped in all deep adapters; the facts arena is pre-order with `subtree_end`, so ancestor checks are O(1) (`FileFacts::is_ancestor`, `structural/facts.rs:587`). The missing half of the loop-invariance rule is binding identity, not loop structure.
- Observation: `Namespace` was already promoted to `bifrost-core` by #1473 with a recorded note that the Rust-internal `RustSymbolNamespace` "stays where it is until the resolver work in #1474/#1475". Java and Rust classify `PathSegment` occurrences but drop every row for lack of a namespace (`NamespaceUnknown(path_segment)`), because module-vs-type is undecidable at the token in those grammars.

## Decision Log

- Decision: the claimed languages for this plan are Java, Rust, Python, and JS/TS — the four adapters with deep occurrence-role support from #1473. Scala is *not* graduated here, despite carrying the largest share (~20) of the 53 mined commits. Graduating Scala means occurrence-role classification plus environment derivation plus resolver tracing in one slice, which would double this plan; the #1473 retrospective already names Scala as the tractable next occurrence slice, and its wildcard-import machinery is used here as the vocabulary template so the eventual graduation drops in. A follow-up issue for "Scala occurrence + resolution-context graduation" must be filed when Milestone 6 closes. The Scala-heavy fixtures from the inventory are represented by same-shape fixtures in claimed languages where the shape exists there (import-vs-lexical precedence, wildcard ambiguity, package-relative resolution), and by lexical Scala positives only where #1473's precedent applies (an explicitly tested boundary, not a silent gap).
  Rationale: partial rollout is sound by construction under the capability spine; an honest `unreliable` in Scala beats a rushed classifier, exactly as in #1473's M5 decision.
  Date/Author: 2026-08-04, Fable 5.
- Decision: environment rows (scopes, bindings, import binders, package clause) are derived per file on demand, like occurrence rows — not persisted in the cache DB. The facts snapshot gains only what identity requires: scope-forming block nodes as facts (a new `NormalizedKind::Block`), because a scope ID must be an arena-node AST identity to join with captures and occurrences. Snapshot version bumps 2 -> 3.
  Rationale: same YAGNI argument as #1473's persistence decision; scope identity is the only thing that must live in the arena because identity is the join currency.
  Date/Author: 2026-08-04, Fable 5.
- Decision: reaching-binding resolution is a general algorithm over derived environment rows (name equality, activation-interval containment, scope-ancestry walk, nearest-scope-wins, with per-binding hoisting class controlling the interval), implemented once in the derivation layer — not per language. Languages contribute only their binding rows and hoisting classes through spec hooks. Where a language cannot state an interval or hoisting class for a binder, the environment result is incomplete for that axis (the `covers()` pattern from #1473), and reaching-binding answers over it are incomplete — never guessed.
  Rationale: the per-language machinery that exists (Rust intervals, JS/TS scope-wide, Python categorical) disagrees in shape but agrees in semantics once "hoisting class" is data; one algorithm with declared inputs is the design-philosophy answer, and it is what makes the RQLP asserts language-neutral.
  Date/Author: 2026-08-04, Fable 5.
- Decision: candidate rows come from an opt-in `ResolutionTrace` sink threaded through `resolve_definition_batch` — not from re-implementing resolution. The shared outcome constructors (`candidates_outcome`, the lexical fast path, `gated_boundary`) are instrumented first, which yields a coarse baseline trace (selected candidates, ambiguity sets, boundary status) for every language at once; *deep* tracing (rejected candidates with typed reasons at each tier) is implemented inside the per-language resolvers for Java and Rust in this plan, with Python and JS/TS following in a later session unless Milestone 3 finds them cheap. A language without deep tracing reports candidate queries as incomplete for the rejection axis, complete for the selection axis.
  Rationale: the issue's acceptance is "queryable without exposing unstable resolver internals"; a typed sink at the seams keeps resolver control flow the source of truth and the trace an emission, so resolver refactors cannot silently diverge from a parallel model. Java and Rust are chosen because Java's tier order is the canonical worked example (`java.rs:1282-1349`) and Rust already has interval and namespace machinery to report against.
  Date/Author: 2026-08-04, Fable 5.
- Decision: the precedence-tier vocabulary is a single language-neutral enum in `bifrost-core`, ordered, with per-language applicability declared in the capability table — not per-language tier enums. Initial vocabulary (ordered from strongest): `LexicalBinding`, `OwnMember`, `InheritedMember`, `ExplicitImport`, `PackageOrModule`, `WildcardImport`, `ExternalRoot`, `NameOnlyFallback`. `NameOnlyFallback` exists so the "forbidden fallback" assert has a tier to forbid; a resolver that selects by bare-name index scan after a structured prefix was available emits its selection at that tier.
  Rationale: the RQLP asserts compare tiers, so tiers must be one ordered vocabulary; Scala's `ScalaExplicitImportTier { candidate, declaration, package }` and the Java statement order both project onto this set, which was checked against the mined-commit shapes before drafting.
  Date/Author: 2026-08-04, Fable 5.
- Decision: resolution asserts extend the existing `assertion` analysis kind from #1473 (`(analysis :type assertion :subject ... :asserts [...])`) with new assert record types, rather than introducing a new analysis kind. The kind's machinery — subject selector, capture-to-row join by `ast_id`, soundness rules (incomplete inputs yield `Inconclusive` with zero findings), multi-location findings, renderer parity — is exactly what resolution asserts need; only the row source (candidate/binding rows instead of occurrence rows) and the predicates differ.
  Rationale: a second kind would duplicate the evaluator's completeness accounting, which #1473's M4 decision log explicitly warns is the thing to keep single.
  Date/Author: 2026-08-04, Fable 5.
- Decision: this plan fixes the `OtherLocal` discard as part of Milestone 2. `resolve_lexical_binding` will return the identified winning local (a `LexicalDefinition`) instead of the opaque `OtherLocal`, which resolves shape 1 of follow-up issue #1569 (Java bare local reads) at its root. Shape 2 of #1569 (Java static field members) is a member-resolution gap owned by #1477's territory and stays open; Milestone 6 fixtures must not assert Java member targets.
  Rationale: the reaching-binding layer computes the winner anyway; keeping the discard would mean deriving the answer and still reporting `NoDefinition` one line away.
  Date/Author: 2026-08-04, Fable 5.
- Decision: visibility is exposed only as far as an adapter can state it honestly: a `DeclaredVisibility` enum in core (`Public | Protected | Internal | PackagePrivate | Private | CrateOrModule { path } | Unknown`) carried on binding and candidate rows, populated from existing per-language sources (Rust `RustVisibility`, Java/PHP modifier nodes), with `Unknown` never silently equal to `Public`. No new visibility inference is built; wiring visibility into rejection *reasons* (a candidate rejected because not visible) comes only from tiers where the resolver already checks it.
  Rationale: the issue asks to expose the context used to resolve, not to build a new visibility checker; YAGNI plus honesty.
  Date/Author: 2026-08-04, Fable 5.
- Decision: external-root availability is exposed as a typed `BoundaryStatus` on candidate rows and trace completeness — `WorkspaceLocal | ExternalIndexed | ExternalDeclaredUnindexed | ExternalUnknown` — fed from `DefinitionLookupStatus::UnresolvableImportBoundary` refined by the JVM external index and semantic-pack dependency evidence where available. The `workspace_oracle` classification of boundary outcomes as `Complete` is left untouched in this plan; only the trace reports the refinement.
  Rationale: refining the dispatch oracle's quality classification changes taint/dispatch behavior and belongs to a measured follow-up; the trace can report honestly without changing resolution behavior.
  Date/Author: 2026-08-04, Fable 5.

## Context and Orientation

Bifrost is a Rust workspace. The crates that matter here:

- `crates/bifrost-core` — the model layer at the bottom of the dependency graph (must depend on no Bifrost crate; enforced by `scripts/check-workspace-dependencies.mjs`). Holds `CodeUnit`, `FqName`, `ImportInfo`/`StructuredImportPath` (`src/analyzer/model.rs:2560-2648`), the structural spec trait (`src/analyzer/structural/spec.rs`), the kind/role registries (`src/analyzer/structural/kinds.rs`), and the #1473 occurrence vocabulary (`src/analyzer/structural/occurrences.rs`: 12 `OccurrenceRole`s, `OccurrenceClass`, `Namespace`, `OccurrenceRoleSupport`).
- `crates/bifrost-analysis` — the analyzer. Per-language modules, the structural query engine (`src/analyzer/structural/`), the occurrence derivation layer (`structural/occurrence_rows.rs`), definition resolution (`src/analyzer/usages/get_definition/`), and the shared lexical grammar tables (`src/analyzer/lexical_definitions.rs`).
- `crates/bifrost-policy` — RQLP policies; the `assertion` analysis kind from #1473 lives in `definition.rs`/`evaluator.rs` with findings in `finding.rs` and anchors in `finding_identity.rs`.
- Transports: `crates/bifrost-mcp`, `crates/bifrost-lsp`, `bifrost_searchtools` (Python client), `editors/vscode`, the REPL in `src/bin/bifrost/code_query_repl.rs`.

Terms used below:

- "Facts" / "facts arena": `FileFacts` (`structural/facts.rs`) — per file, a pre-order array of `NormalizedNode { kind, range, parent, name, subtree_end }` plus role tables and a SHA-256 `ContentIdentity`. Descendants of node `n` are exactly `(n+1)..subtree_end(n)`; `is_ancestor` is O(1). Persisted under `STRUCTURAL_FACTS_SNAPSHOT_VERSION` (currently 2 after #1473).
- "AST identity": the pair `(ContentIdentity, arena node u32)`, published as a domain-separated digest (`occurrence_rows.rs::ast_id`). Structural captures, match roots, and occurrence rows all carry it; digest equality is the equijoin. Every new row family in this plan carries the same identity for its anchor node.
- "Occurrence row": `OccurrenceRow` (`occurrence_rows.rs:71-86`) — file, AST identity, range, role, class, namespace, enclosing declaration, spelling, and `OccurrenceTarget::{None, Resolved(Vec<CodeUnit>), Lexical(Box<LexicalDefinition>), Unresolved(DefinitionLookupStatus)}`. Reference-class rows are resolved in one batch per file at `occurrence_rows.rs:333-389`; line 379 zips rows with outcomes.
- "Definition resolution": `resolve_definition_batch_with_source_and_cancellation` (`get_definition/mod.rs:619`) — per request: lexical fast path (`resolve_lexical_binding`), then per-language dispatch (`mod.rs:1160-1324`), then outcome constructors `candidates_outcome` (`:1406`, sorts/dedups/keys candidates; one is `Resolved`, more is `Ambiguous`), `lexical_definition_outcome` (`:1627`), and the boundary gate `gated_boundary` (`:1680`). `DefinitionLookupStatus` is `Resolved | NoDefinition | UnresolvableImportBoundary | Ambiguous | UnsupportedLanguage | InvalidLocation | NotFound`.
- "Lexical grammar tables": `analyzer/lexical_definitions.rs` — per-language node-kind predicates (`is_lexical_scope`, `is_parameter_owner`, `is_binding_leaf`, `binding_container`, `is_local_declaration`, ...) covering all eleven languages. These are the seed vocabulary for scope and binder classification.
- "Capability spine": adapter support tables -> `QueryFeature` -> `CodeQueryDiagnosticCode` with `Incomplete` impact -> `CodeQueryResult::completion()` -> policy `PolicyIncompleteReason::CapabilityIncomplete` -> `PolicyRunCompletion` -> exit status. #1473 added per-axis honesty (`OccurrenceCompleteness::covers(role)`); this plan follows the same pattern for environment axes.
- "Assertion kind": `(analysis :type assertion :subject (rql ... :capture "N" ...) :asserts [(assert :id ... :at "N" ...)])` (`bifrost-policy`). Subject captures join to rows strictly by `ast_id`; any incomplete input makes the run `Inconclusive` with zero findings; violations render as one multi-location finding.

What exists that this plan builds on, and what does not exist (verified 2026-08-04 by survey; details in Surprises & Discoveries): no scope IDs or scope tree in any language; activation intervals only in Rust (`rust/lexical_scope.rs`) and Ruby, in incompatible private shapes; no reaching-binding computation anywhere (`OtherLocal` discards the winner); no precedence value, no rejected-candidate record, no typed rejection reason; imports modeled as `ImportInfo` rows with `StructuredImportPath` carrying unused positional data; wildcard ambiguity tracked only in Scala; no normalized source visibility; `NormalizedKind` has no `Block` and no `Module`/`Package` kind; RQL exposes imports only as file-to-file edges (`imports-of`/`importers-of`).

The 53-commit inventory in the issue body is the fixture source. By language it is roughly: Scala ~20 (import visibility, wildcard member namespaces, active packages, for-comprehension bindings, lexical/namespace precedence), Rust ~10 (scoped owners, module routes, local-module visibility, shadowing scope-awareness, lexical vs Cargo-root precedence, import namespaces), JS/TS ~5 (lexical roles falling into indexed lookup, module variable inverse usages, constructor-assigned fields, lexical/local-property identity), C# ~4, Java (try-resource binding scope), Python (private module-level visibility, reference parity), Go, C++, PHP, Ruby one to three each, plus the cross-language `585b8a7c5` (lexical parameter definitions) and `ff08191ac` (structural boundary-claim gate). Milestone 6 samples the shapes, not the languages, per the Decision Log.

## Plan of Work

### Milestone 1 — core vocabulary, scope facts, capability tables

Scope: the typed vocabulary every later milestone consumes, the arena change that gives scopes an AST identity, and the honesty tables. Nothing user-visible beyond unit tests. This milestone changes the persisted facts snapshot (version 2 -> 3).

In `crates/bifrost-core/src/analyzer/structural/kinds.rs`, add `NormalizedKind::Block` ("a braced or indented statement list that forms a lexical scope and is not already a callable, class, loop, or conditional body node") to `normalized_kinds!`, with per-adapter kind-table entries in Milestone 1's adapter work mapping the block node kinds the shared `is_lexical_scope` table already names (`block`, `statement_block`, `compound_statement`, and language equivalents). Loops, callables, classes, and conditionals are already facts; `Block` closes the gap so every scope-forming node is an arena node with an AST identity. Do not add a `Module`/`Package` normalized kind in this plan (recorded as coarse, not wrong, in #1473; the package clause gets its own row family instead).

In a new sibling module `crates/bifrost-core/src/analyzer/structural/resolution.rs` (registry style identical to `occurrences.rs`), add:

    pub enum HoistingClass { SourceOrder, ScopeWide, DeclaredHead }
        // SourceOrder: in effect from the end of its declarator to the end of its scope (Rust let, Java local).
        // ScopeWide: in effect for the whole scope regardless of position (JS var/function, Python function locals, Rust items).
        // DeclaredHead: in effect exactly within a declared sub-interval the adapter states (match arms, comprehensions, for-headers).
    pub enum BindingKind { Local, Parameter, PatternBinder, LoopVariable, CatchOrResource, ImportBinder, TypeParameter }
    pub enum PrecedenceTier { LexicalBinding, OwnMember, InheritedMember, ExplicitImport, PackageOrModule, WildcardImport, ExternalRoot, NameOnlyFallback }   // ordered, strongest first; Ord derived
    pub enum CandidateOutcome { Selected, Rejected(RejectionReason) }
    pub enum RejectionReason { ShadowedByNearer, NotInScopeAtPosition, WrongNamespace, NotVisible, WrongDeclarationSpace, AmbiguousPeer, BoundaryBlocked }
    pub enum BoundaryStatus { WorkspaceLocal, ExternalIndexed, ExternalDeclaredUnindexed, ExternalUnknown }
    pub enum DeclaredVisibility { Public, Protected, Internal, PackagePrivate, Private, CrateOrModule, Unknown }
    pub struct LexicalEnvironmentSupport { /* total table over EnvironmentAxis, Supported|Unsupported, default Unsupported */ }
    pub enum EnvironmentAxis { Scopes, BindingIntervals, ImportBinders, PackageClause, CandidateSelection, CandidateRejection }

Each enum gets labels, serde snake_case, `ALL_*` arrays, and self-consistency tests (unique labels, round-trip), exactly as `occurrences.rs` does. `StructuralSpec` gains a required `fn lexical_environment_support(&self) -> &LexicalEnvironmentSupport` with no default, so all eleven adapters must state their table (compile error on omission — the #1473 pattern). The four deep adapters declare `Scopes`, `BindingIntervals`, `ImportBinders`, `PackageClause`, and `CandidateSelection` supported (Java/Rust additionally `CandidateRejection` after Milestone 3); the seven others declare all-Unsupported. Wire `QueryFeature::EnvironmentAxis(...)` into `structural/capabilities.rs` alongside `QueryFeature::OccurrenceRole` so unsupported axes produce `UnsupportedStructuralFeature` diagnostics with `Incomplete` impact through the existing spine.

Facts: bump `STRUCTURAL_FACTS_SNAPSHOT_VERSION` to 3 (the `Block` kind changes extraction; stale snapshots must re-extract, and the version bump is the established self-healing mechanism). Add `Block` mappings to the four deep adapters' kind tables and verify with per-adapter tests that block nodes become facts with correct `subtree_end` intervals.

Tests: registry self-consistency; snapshot version-mismatch re-extraction; per-adapter block-fact tests asserting specific byte ranges; a compile-covered totality test for `LexicalEnvironmentSupport`.

Acceptance for M1: `cargo nextest run -p brokk-bifrost-core -p brokk-bifrost-analysis` green; `cargo clippy --workspace --all-targets -- -D warnings` clean; a facts snapshot encoded at version 2 is rejected and re-extracted at version 3.

### Milestone 2 — the lexical environment derivation layer

Scope: a per-file, request-scoped producer that turns facts plus per-language hooks into scope rows, binding rows, import-binder rows, and a package-clause row, plus the reaching-binding function over them. Internal API only. This milestone also fixes the `OtherLocal` discard (Decision Log).

New module `crates/bifrost-analysis/src/analyzer/structural/lexical_environment.rs`. Rows:

    pub struct ScopeRow { file, content_identity, node: u32, range: Range, kind: NormalizedKind, parent_scope: Option<u32> }
        // identity = ast_id(content_identity, node); parent_scope is the nearest enclosing scope-forming fact, so ancestry is a chain walk.
    pub struct BindingRow { file, content_identity, node: u32,             // the binder token's arena node (join key with binder-class occurrence rows)
                            name: String, kind: BindingKind, hoisting: HoistingClass,
                            declaring_scope: u32,                          // arena node of the ScopeRow that owns it
                            activation: Range,                             // byte interval in which the binding is in effect
                            source_order: u32,                             // ordinal of the binder among the scope's binders in source order
                            visibility: DeclaredVisibility,
                            import: Option<ImportBinderDetail> }           // Some iff kind == ImportBinder
    pub struct ImportBinderDetail { local_name, alias: Option<String>, target_segments: Vec<String>, wildcard: bool,
                                    wildcard_ambiguous: Option<bool>,      // None = not computed for this language; Some(true) = collision detected
                                    boundary: BoundaryStatus }
    pub struct PackageClauseRow { file, package_fq: Option<FqName>, syntactic: bool }   // syntactic=false when path-derived (Python, Rust fallback)
    pub struct EnvironmentFileResult { scopes, bindings, package, completeness: EnvironmentCompleteness }   // per-axis covers(), #1473 pattern

Derivation: one arena walk selects scope-forming facts (Callable, Class, Loop variants, Conditional bodies where the grammar scopes them, and the new Block) and builds `ScopeRow`s with parent links. Binder-class occurrence rows (already emitted by the deep adapters) seed `BindingRow`s; the activation interval and hoisting class come from a new spec hook `fn binding_activation(&self, node, kind, scope_range) -> Option<(HoistingClass, Range)>`, whose four deep implementations port the existing knowledge: Rust generalizes `rust/lexical_scope.rs` (let: declarator end to scope end; match arm: pattern end to arm end; items: scope-wide), JS/TS returns scope-wide per `js_ts/syntax.rs:127`'s documented semantics, Python returns scope-wide for function locals and `DeclaredHead` for comprehension targets (port `PythonComprehensionBinding`), Java returns source-order from declarator end (matching `check_preceding_local_variables`). A `None` from the hook marks the `BindingIntervals` axis incomplete for the file — never guessed. Import binders come from `TreeSitterAnalyzer::import_info_of` rows: `local_name()` desugar, `StructuredImportPath.declaration_start_byte` and `lexical_scopes` give the activation interval (file- or scope-scoped per language), wildcard flag verbatim; `wildcard_ambiguous` is computed only where the language can (initially: collision detection over same-file wildcard sets for Java, mirroring `resolve_external_imports`'s silent `None` case, and left `None` elsewhere). The package row reads `package_name_of`/`path_derived_package_fq`.

Reaching binding: `fn reaching_binding(env: &EnvironmentFileResult, name: &str, position_byte: usize, namespace: Option<Namespace>) -> ReachingBindingOutcome` with `ReachingBindingOutcome::{Reached(binding node), Shadowed { winner, shadowed: Vec<..> }, NoBinding, Incomplete(axis) }`. Algorithm, once, general: candidates are bindings with equal name whose activation interval contains the position and whose declaring scope is an ancestor of (or equal to) the position's innermost scope; the winner is the one with the nearest declaring scope, ties broken by latest activation start (rebinding); the entire computation refuses (returns `Incomplete`) when the file's `BindingIntervals` axis does not cover the involved binding kinds.

Fix the `OtherLocal` discard: extend `resolve_lexical_binding` (or layer above it in `mod.rs:1147`) so a winning plain local produces `lexical_definition_outcome` with the identified `LexicalDefinition` instead of `no_definition("local_binding")`. Add regression tests reproducing #1569 shape 1 (`int local = 1; return local;` resolves to the binder as a lexical definition) in Java, plus the equivalent in the other three deep languages. This changes observable resolver behavior; run the affected usage/get-definition suites and record any fixture churn in Surprises.

Tests: lib unit tests over a real `WorkspaceAnalyzer` per the #1473 M2 pattern. Mandatory scenarios (each is a mined-inventory shape): rebinding within one block (two `let x` in Rust — the reaching binding of a read between them is the first, after the second is the second); shadowing across nested scopes (Java `22bb0cb3b` try-resource: the resource binding's activation is the try block); before/after-use (Java local read before declaration reaches nothing; JS `var` read before declaration reaches the hoisted binding); import vs local precedence data (both rows exist with correct intervals so Milestone 3 can trace the choice); for-comprehension/loop-header binders (`DeclaredHead`); wildcard import row with `wildcard_ambiguous: Some(true)` when two same-file wildcards collide on a fixture name; an unsupported language (Scala) yields per-axis `Incomplete`, not empty-complete.

Acceptance for M2: on a Java fixture, `reaching_binding` at a read position inside a loop returns the outer binding with its declaring scope outside the loop fact's interval, and the same call for a loop-local read returns the inner binding — the two halves of the motivating discriminator, asserted at the unit level.

### Milestone 3 — the resolution trace

Scope: typed candidate/outcome rows out of `get_definition`, joined to occurrence rows. Internal API plus the occurrence-row extension; RQL exposure is Milestone 4.

In `get_definition/mod.rs`, add a `ResolutionTrace` sink: an optional per-request collector on `DefinitionBatchContext` with

    pub struct TraceCandidate { candidate: TraceCandidateRef, tier: PrecedenceTier, outcome: CandidateOutcome,
                                boundary: BoundaryStatus, visibility: DeclaredVisibility }
    pub enum TraceCandidateRef { Unit(CodeUnit), Lexical(LexicalDefinition), ImportBinder { file, node: u32 } }
    pub struct ResolutionTraceResult { candidates: Vec<TraceCandidate>, completeness: TraceCompleteness }
        // TraceCompleteness distinguishes SelectionOnly (shared-path instrumentation) from Full (deep per-tier tracing)

Instrument the shared seams first, which covers every language at the selection axis: `lexical_definition_outcome` emits a `Selected` at `LexicalBinding`; `candidates_outcome` emits one `Selected` (or, for the ambiguous case, all members as `Selected`-tier peers with `RejectionReason::AmbiguousPeer` on none — ambiguity stays explicit as multiple selected rows plus the outcome status); `gated_boundary` emits the boundary status. Then deep-trace Java and Rust: at each early-return tier in the Java bare-identifier path and its qualified siblings, emit the candidates the tier considered with typed rejections (`ShadowedByNearer` from the `locally_bound` gate, `NotVisible` where modifier checks reject, `WrongNamespace` from Rust's `RustSymbolNamespace::accepts`, `NotInScopeAtPosition` from interval checks, `BoundaryBlocked` at the gate). The sink is append-only and must not alter control flow; a debug assertion checks that when the trace records a `Selected` candidate, the outcome's `definitions`/`lexical_definition` agree with it (fail at the construction point, per the repo's assertion convention).

`BoundaryStatus` refinement: when the outcome is `UnresolvableImportBoundary`, consult (a) the JVM external declaration index — hit means `ExternalIndexed` (and the candidate row carries the resolved external type), build-declared-but-truncated means `ExternalDeclaredUnindexed` (surface the currently-test-only `production_diagnostics` counts through a small accessor), (b) semantic-pack dependency evidence (`prepare_dependency_semantic_packs` outcomes) for the same distinction in Python/JS-TS, defaulting to `ExternalUnknown`.

Join to occurrences: extend the derivation at `occurrence_rows.rs:379` — when the caller requests candidates (a new flag on the derivation entry point so existing consumers pay nothing), run the batch with the trace sink attached and attach `Vec<TraceCandidate>` plus `TraceCompleteness` to each reference-class row. The existing `OccurrenceTarget` collapse is untouched; candidates are additive.

Tests: per-language trace tests asserting, for fixture shapes from the inventory: a shadowing local produces a `Rejected(ShadowedByNearer)` row for the outer candidate and a `Selected` at `LexicalBinding` for the local (Rust `61c223586` shape); an explicit import beating a wildcard produces `Selected` at `ExplicitImport` and `Rejected` peers at `WildcardImport`; a boundary produces `BoundaryStatus != WorkspaceLocal` and no `NameOnlyFallback` selection; the debug assertion fires on a deliberately inconsistent fake sink in a `#[should_panic]` test; Python/JS-TS report `SelectionOnly` completeness.

Acceptance for M3: for the Java shadowing fixture, the trace lists both candidates with tiers and the typed rejection; for a Scala file, requesting candidates yields the `CandidateSelection` axis incomplete through the capability spine, not an empty trace.

### Milestone 4 — RQL/JSON typed domain exposure, schema version 9

Scope: environment and candidate rows become queryable; the #1297/#1473 typed-domain recipe instantiated. Follow `.agents/plans/issue-1473-semantic-occurrences-ast-role-fidelity.md` Milestone 3 as the worked example; that plan's file list is the checklist (schema lineage, IR, frontends, execution, results, policy plumbing, transports, TextMate, docs).

Schema lineage: `RQL_RESOLUTION_SCHEMA_VERSION = 9` in `query/schema.rs`, chained descriptor, `SCHEMA_VERSION = 9` in `ir.rs`, lineage test update, compatible-head fixture bumps.

New row kinds and steps (typing arrows):

    QueryValueKind::{LexicalScope, Binding, ResolutionCandidate}
    scopes            : seed, filters :kind                          -> lexical_scope
    bindings          : seed, filters :kind :name :hoisting          -> binding
    scope-of          : binding | occurrence | structural_match      -> lexical_scope      (innermost owning scope)
    scope-ancestors   : lexical_scope                                -> lexical_scope      (transitive parents, self excluded)
    bindings-in       : lexical_scope | structural_match             -> binding            (declared in that scope/subtree)
    reaching-binding  : occurrence                                   -> binding            (Milestone 2 semantics; empty+diagnostic when Incomplete/NoBinding, explicit multi-row when Shadowed is queried with :include-shadowed)
    binding-occurrence: binding                                      -> occurrence         (the binder token's occurrence row)
    candidates-of     : occurrence                                   -> resolution_candidate, filters :tier :outcome :boundary
    candidate-target  : resolution_candidate                         -> declaration        (unit-backed candidates)
    package-of        : file                                         -> declaration? — no: expose the package clause as fields on the existing file row (package_fq, syntactic) rather than a new kind; a fourth kind for one row per file is not warranted.

All rows carry `ast_id` where they anchor to an arena node (scopes, bindings, candidates via their occurrence), so capture-to-row correlation stays the #1473 equijoin. Registry entries with `since: 9`, constrained-value tables for the new enums, sexp/decode/json/source wiring, execution dispatch arms calling the Milestone 2/3 producers, dedup keys, diagnostic codes (`EnvironmentAxisUnsupported`, `ResolutionTraceIncomplete`, budget codes), policy terminal-domain decisions (binding and candidate rows ARE valid match-policy terminals, per the #1473 occurrence precedent), transports (MCP prose, LSP URI enrichment, REPL rendering, Python client models, VS Code result rendering), TextMate grammar additions (conservative, form names and new keyword options only), and the three pre-existing exhaustiveness assertions in `results.rs` that #1473's M3 recorded (`grep assert_detailed_terminal_identities` before running the suite).

Tests: `tests/suite_cross_language/code_query_lexical_environment.rs` (add the `mod` line per the harness manifest): the loop-invariance discriminator end to end as a query — capture the receiver of a `sort` call inside a loop, `reaching-binding`, `scope-of`, and assert containment against the loop match for both fixture halves; scope ancestry chains; `candidates-of` tier/outcome filtering; schema-9 rejection under a `:schema-version 8` pin; RQL/JSON round-trips; hover/validation; docs examples; Python client round-trip.

### Milestone 5 — RQLP resolution asserts

Scope: extend the `assertion` analysis kind with three assert record families, keeping the #1473 evaluator's soundness accounting single (Decision Log).

Authored forms (exact spellings settled at decode-design time, same `KeywordPairs` conventions as `(assert ...)`):

    (assert-resolution :id ID :at "CAPTURE"
        :expect-tier TIER            ; selected candidate's tier must be exactly/at-least this tier (`:at-least true`)
        [:forbid-tier TIER]          ; no Selected row at this tier (the anti-fallback contract: :forbid-tier name_only_fallback)
        [:require-unique true])      ; exactly one Selected row (ambiguity is a violation, not a silent pick)
    (assert-reaching :id ID :at "CAPTURE" :name-of "CAPTURE2"?   ; reaching binding of the captured occurrence
        :declared (inside|outside) "CAPTURE3")                   ; containment of the binding's declaring scope vs another captured node
    (assert-boundary :id ID :at "CAPTURE" :forbid-fallback-past (external_declared_unindexed|external_unknown))
                                     ; once boundary status is at or past the named strength, forbid NameOnlyFallback selection

Evaluation joins subject captures to candidate/binding rows by `ast_id` exactly as the occurrence asserts do; every soundness rule carries over verbatim — incomplete subject or row query, unsupported axis, `SelectionOnly` completeness where a rejection-dependent assert needs `Full`, truncation, or budget exhaustion yields `Inconclusive` with zero findings. Violations render one multi-location finding: subject, selected candidate (with tier), expected tier or containment, and every considered candidate as related locations, with human/JSON/SARIF parity. Fan-out is the mechanical fourth-kind checklist from #1473 M4, including the three `(analysis, taint, typestate)` agreement triples in `resolved.rs` and the `AnalysisOwners` audit; adding the records must leave every built-in policy semantic hash unmoved (verify with the catalog consistency test).

Tests: end-to-end policy suites — a shadowing fixture where `:expect-tier lexical_binding` passes and the seeded bug (outer selected) exits `finding` with the trace in related locations; `:forbid-tier name_only_fallback` firing on a seeded fallback fixture; the reaching/declared-outside assert reproducing the loop-invariance verdict on both fixture halves; unsupported language exits `unreliable`; renderer parity snapshots.

### Milestone 6 — conformance fixtures, loop-invariance prototype, audit, docs, gates

Scope: prove the capability against the mined class and the FP corpus, and leave the surface release-ready.

From the 53-commit inventory, select at least eight representative shapes across the four claimed languages, each as a positive/near-miss pair on both surfaces (query and assertion), covering the issue's mandated scenario families: sibling imports vs true targets; before/after-use declarations; local/private/global namesakes; type/value namespace collisions; multiple namespaces in one file; unindexed declared dependencies (boundary fixtures using a declared-but-absent artifact); wildcard ambiguity kept explicit; authoritative-boundary anti-fallback. The deferred-body rule from the repository policy applies: where containment cannot distinguish a closure body inside a loop, the fixture pins the boundary explicitly rather than claiming it.

Build the loop-invariance rule as a tested fixture-level `.rqlp` (subject: sort/parse/read call occurrence inside a loop; assert: reaching binding of the receiver declared outside the loop body), with the true-positive shape modeled on `composition/precedence.rs:135` and near-misses for each dominant FP family from the 284-finding corpus: loop-local declaration, iterator-adapter fresh binding, field projection of the loop variable (expected: the projection case stays a finding candidate or an explicit boundary — decide from the trace evidence and record it), rebinding of an outer name inside the loop, and a closure body. Do NOT add it to the built-in `policy-packs/` pack in this plan: it claims four languages at most and the pack bar requires proven near-misses per claimed language plus re-verification on every adapter graduation; the parked tuning of the in-loop rules (issue comment) resumes only after this rule's fixtures are green and is its own follow-up.

Audit: sweep every new code path for regex/source-text/range-coincidence standing in for structure (the #1473 audit found two real defects this way — run it, do not assert it); verify no `split("::")`-style path parsing entered the import-binder derivation. Docs updates across the six content pages with executable examples. File the follow-up issues the Decision Log promises (Scala graduation; in-loop rule pack tuning; workspace-oracle boundary-quality refinement). Full pre-push gate.

## Concrete Steps

All commands from the repository root or active worktree. Commit checkpoints on the current branch after each coherent unit, multiline messages explaining the why.

Focused validation during a milestone (featureless, task-scoped):

    cargo nextest run -p brokk-bifrost-core -p brokk-bifrost-analysis
    cargo nextest run -p brokk-bifrost-policy        # Milestones 5-6
    cargo clippy --workspace --all-targets -- -D warnings

PATH caveat on this machine: ensure the rustup toolchain precedes Homebrew or clippy/rustdoc pick a mismatched driver. In nested worktrees do not use the `clippy-no-cuda` alias; use the expanded command. Known pre-existing failures to not chase: `cache_db streaming_reader` and `suite_mcp_cli interactive_session_prewarm`.

Pre-push gate at milestone boundaries: `scripts/pre-push-gate.sh`. VS Code tests (`cd editors/vscode && npm test`) and Python client tests (`uv run --python 3.12 -- pytest python_tests/test_searchtools_client.py`) at Milestone 4. Do not enable `nlp` for any of this work.

## Validation and Acceptance

Behavioral acceptance, per milestone, is stated inline above. Overall, against the issue's acceptance criteria: candidate and rejection traces are queryable through `candidates-of` without exposing resolver internals (the trace is typed emission at stable seams, not resolver state); RQLP asserts selected-candidate precedence (`:expect-tier`), forbids out-of-scope fallback (`:forbid-tier`, `assert-boundary`); fixtures combine true targets with sibling imports, before/after-use declarations, namesakes, namespace collisions, unindexed dependencies, and authoritative boundaries; and ambiguity or incompleteness always surfaces as explicit multi-row answers, `Incomplete` diagnostics, or `Inconclusive` runs — the tests assert completeness before reading findings (the #1473 lesson).

## Idempotence and Recovery

Every milestone is additive until its final wiring step. The facts snapshot bump (M1) is self-healing. The schema bump (M4) reverts as one commit with its fixture updates. The `resolve_lexical_binding` behavior change (M2) is the one non-additive step: it is gated behind its own commit with the full usage-suite run recorded, so a revert is surgical. The M5 canonical-projection change must be verified hash-neutral before commit (catalog consistency test); if hashes move, fix the projection, never regenerate the manifest.

## Interfaces and Dependencies

End-state signatures that must exist are listed inline in Milestones 1-3 (vocabulary in `bifrost-core/src/analyzer/structural/resolution.rs`; derivation in `bifrost-analysis/src/analyzer/structural/lexical_environment.rs`; trace types in `usages/get_definition/mod.rs`; row kinds and steps in `structural/query/ir.rs` at schema 9; assert records in `bifrost-policy`). Dependency direction: new core types in `brokk-bifrost-core` (no Bifrost deps; the vocabulary must not reference `IAnalyzer` or stores), derivation/trace/query in `brokk-bifrost-analysis`, asserts in `brokk-bifrost-policy`. Nothing touches `nlp` crates. Prior art to imitate, by path:

    .agents/plans/issue-1473-semantic-occurrences-ast-role-fidelity.md      the foundation plan; its M3/M4 are the recipes for M4/M5 here
    crates/bifrost-analysis/src/analyzer/structural/occurrence_rows.rs      derivation-layer shape, per-axis completeness, id minting
    crates/bifrost-analysis/src/analyzer/rust/lexical_scope.rs              interval semantics to generalize
    crates/bifrost-analysis/src/analyzer/scala/wildcard_imports.rs          tier/ambiguity prototype (vocabulary source, not code reuse)
    crates/bifrost-analysis/src/analyzer/lexical_definitions.rs             shared scope/binder grammar tables
    crates/bifrost-analysis/src/analyzer/usages/get_definition/java.rs      the canonical tier order to instrument (1282-1349)

## Outcomes & Retrospective

(To be written at completion.)

Revision note (2026-08-04): initial version, authored from two targeted codebase surveys (resolver/scope machinery; import/namespace/external machinery) recorded in Surprises & Discoveries, plus the #1473 ExecPlan and retrospective, the issue body and its 284-finding false-positive corpus comment, and the epic #1472 shared-foundation contract.
