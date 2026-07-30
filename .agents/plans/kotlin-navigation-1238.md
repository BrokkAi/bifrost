# Kotlin definition, type, hierarchy, and source navigation (issue #1238)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and
`Outcomes & Retrospective` must be kept up to date as work proceeds.

The canonical rules for writing and maintaining ExecPlans live in `.agents/PLANS.md` at the repository root. This
document must be maintained in accordance with that file.

## Purpose / Big Picture

Bifrost already parses Kotlin, indexes Kotlin declarations, and resolves Kotlin type names against the shared JVM
dependency realm. What it cannot do is answer "where is this defined?" for a Kotlin reference. Today every Kotlin
`get_definitions_by_location`, `get_declarations_by_location`, and `get_type_by_location` request returns the
placeholder diagnostic `kotlin_navigation_unsupported`, and the LSP hover, go-to-definition, go-to-type-definition,
and signature-help handlers that are built on top of those calls return nothing for `.kt` and `.kts` files.

After this change, a user editing Kotlin can put the cursor on a type name, a constructor call, a function call, a
property access, a member of a companion object, an extension function call, a named argument, or an import, and
Bifrost answers with the physical declaration it refers to. The same answers flow into the MCP tools
(`get_definitions_by_location`, `get_declarations_by_location`, `get_type_by_location`, `get_symbol_sources`) and the
LSP surfaces (hover, definition, declaration, type definition, signature help, prepare-rename).

You can see it working from a shell without any editor. With a two-file Kotlin workspace:

    // src/lib/Base.kt
    package lib

    open class Base {
        fun greet(name: String): String = "hello $name"
    }

    // src/app/App.kt
    package app

    import lib.Base

    fun main() {
        val base = Base()
        base.greet("world")
    }

running the MCP `get_definitions_by_location` tool against the `greet` token in `App.kt` returns a single definition
whose `fqn` is `lib.Base.greet`, instead of today's `kotlin_navigation_unsupported` diagnostic. Section
`Validation and Acceptance` gives the exact command.

The bar for this work is *proven identity*. Where Bifrost cannot prove which declaration a reference means, it must
say so with a specific diagnostic (ambiguous, not indexed, unsupported shape, local binding) rather than guessing a
same-named declaration from somewhere else in the workspace. There is no regex, string-splitting mini-parser, or
text-search fallback anywhere in this work: every fact comes from the Kotlin tree-sitter syntax tree or from the
analyzer's indexed declarations.

## Progress

- [x] (2026-07-29 09:00Z) Researched the existing Kotlin analyzer surface (`crates/bifrost-analysis/src/analyzer/kotlin/`),
      the Java and Scala definition resolvers, the definition/type lookup dispatch, and the Kotlin tree-sitter grammar's
      actual node shapes (dumped s-expressions from the vendored grammar).
- [x] (2026-07-29 09:20Z) Wrote this ExecPlan.
- [x] (2026-07-29 10:30Z) Milestone 1: reference-site classification, declaration-site and import handling, type
      references. Kotlin arm added to the `get_definition` dispatch. 11 new `kotlin_*` tests in
      `tests/suite_symbols/get_definition_test.rs`, all green; `cargo clippy --all-targets` clean.
- [x] (2026-07-29 11:40Z) Milestone 2: calls, constructors, arity-steered overload selection, named arguments,
      callable references, bare value references. 24 `kotlin_*` tests green; clippy clean.
- [x] (2026-07-29 12:40Z) Milestone 3: navigation expressions, receiver typing, inherited/companion/extension
      members, safe calls, `!!`, call-result chains, enum entries, `this`/`super`. 42 `kotlin_*` tests green;
      clippy clean.
- [x] (2026-07-29 13:20Z) Milestone 4: `get_type` Kotlin arm, Kotlin arms for the shared call-site callee/argument
      lookup so signature help finds a Kotlin call, and LSP tests for hover, definition, type definition, signature
      help, and prepare-rename.
- [x] (2026-07-29 14:00Z) Milestone 5: abstention-matrix test, the Kotlin local-binding fix it exposed, and
      capability notes. Full validation: `suite_symbols` 1110 passed, `suite_analyzers` 671 passed,
      `bifrost_lsp_server` 196 passed, `cargo clippy --all-targets --all-features -- -D warnings` clean.
- [x] (2026-07-30) Find-references and reference-rewriting rename for Kotlin landed with #1239 — both usage paths now
      answer for Kotlin, so `textDocument/references` and `rename_symbol` no longer abstain. See
      `.agents/plans/kotlin-usage-graph-1239.md`. That work also replaced this issue's `KotlinCtx::is_companion_object`
      syntax re-read with the published `SignatureMetadata` marker, so navigation and the usage graphs answer
      "is this object a companion?" from one fact.
- [ ] Remaining, owned by sibling issues: structural RQL (#1240), CFG/semantic lowering including smart casts (#1241).

## Surprises & Discoveries

- Observation: a Kotlin local `val`/`var` never resolved as a local binding, even though the lexical resolver's
  Kotlin arms name every part involved. `is_local_declaration` matches `property_declaration`, but the binding-leaf
  walk stops there and never descends to the nested `variable_declaration` that actually holds the name, so every
  local fell through to the language resolver and came back as "not indexed".
  Evidence: `kotlin_unresolvable_references_abstain_with_specific_diagnostics` expected `local_binding` for
  `println(shadowed)` and got `no_indexed_definition`. Fixed at the source in
  `crates/bifrost-analysis/src/analyzer/lexical_definitions.rs` by descending into the
  `variable_declaration`/`multi_variable_declaration` children only — a general descent would collect the
  identifiers inside the *initializer* as bound names, making `val x = someName` declare `someName`.

- Observation: the shared call-site machinery could not find any part of a Kotlin call. The argument list is
  `value_arguments` nested inside `call_suffix`, which neither the `arguments` field lookup nor the shared
  child-kind list reaches, and the callee is simply "the child that is not the suffix", which no field names.
  Signature help therefore returned `null` for Kotlin even after definition resolution worked.
  Evidence: `bifrost_lsp_server_signature_help_returns_kotlin_function_signature` failed with
  `expected signatureHelp result object, got {"result":null}` until `callee_node_for_call` and
  `argument_nodes_for_call` grew Kotlin arms.

- Observation: a declaration's syntax node is not always the *smallest* node covering its recorded range. An
  `enum_entry` spans exactly its own name, so its `simple_identifier` child covers the same bytes and wins the
  smallest-covering walk. Declaration lookup has to climb back out to the outermost node with that span.
  Evidence: `kotlin_enum_entry_and_its_member_resolve` failed with `receiver_type_unknown` for `Color.RED.label()`
  until `kotlin_declaration_node` was introduced.

- Observation: Kotlin overloads collapse into one indexed identity. Two functions with the same fully-qualified name
  become a single `CodeUnit` carrying several signatures, so "pick the right overload" is only expressible across
  *owners*, never within one name.
  Evidence: the first draft of `kotlin_overloaded_call_selects_by_arity` asserted one `CodeUnit` per overload and
  failed with a single `app.render` definition carrying the first declaration's signature. The test was rewritten as
  `kotlin_call_arity_reaches_an_inherited_overload_past_a_nearer_one`, which is the behaviour that actually matters.

- Observation: the vendored Kotlin grammar exposes almost no tree-sitter *fields*. Only `function_declaration` and
  `property_declaration` carry a field (`receiver`), and `if_expression` carries `condition`/`consequence`. Everything
  else — the callee of a call, the receiver of a navigation, the name of a named argument — must be read positionally
  from named children.
  Evidence: `crates/bifrost-analysis/vendor/tree-sitter-kotlin/src/node-types.json`; only `receiver`, `condition`,
  `consequence` and a handful of others appear under `"fields"`.

- Observation: `String::length` does *not* parse as `callable_reference`. It parses as
  `(navigation_expression (simple_identifier) (navigation_suffix (simple_identifier)))`, identical to a property
  access. Only the receiver-less form `::topLevel` produces a `callable_reference` node.
  Evidence: s-expression dump of `val mref = String::length` against the vendored grammar.

- Observation: a Kotlin declaration written on a single line (`class D { fun f() {} }`) makes the grammar emit
  `MISSING _automatic_semicolon` error nodes, and `object O { val p = 1 }` immediately followed by another
  declaration on the next line can degrade into `infix_expression`/`object_literal` recovery. Fixtures in tests must
  therefore be written multi-line, with declarations separated by blank lines, exactly as real Kotlin is written.
  Evidence: s-expression dump; `class C : Base(), Marker { fun f(...) ... }` produced `(MISSING _automatic_semicolon)`.

- Observation: local bindings already work for Kotlin without any change in this issue. `resolve_lexical_binding` in
  `crates/bifrost-analysis/src/analyzer/lexical_definitions.rs` runs *before* the per-language dispatch in
  `get_definition`, and it already has Kotlin arms (added by issue #1236). A Kotlin parameter reference resolves to a
  `LexicalDefinition`; a reference to a local `val`/`var` returns the explicit `local_binding` diagnostic.
  Evidence: `lexical_definitions.rs:422` and the `Language::Kotlin` arms at lines 920-1271; the pre-dispatch call in
  `usages/get_definition/mod.rs`.

- Observation: a dotted type name such as `lib.Base` is a *single* `user_type` node with two `type_identifier`
  children, not a nested/scoped node. The Kotlin resolution ladder in
  `crates/bifrost-analysis/src/analyzer/kotlin/types.rs` already accepts the dotted spelling as one string, so the
  resolver hands it the joined text of the `user_type`'s `type_identifier` children (a structured join of AST node
  texts, not a string parse of the source).
  Evidence: `fun h(): lib.Base? = null` dumps as `(nullable_type (user_type (type_identifier) (type_identifier)) (quest))`.

- Observation: Kotlin primary constructors are indexed as *synthetic* `CodeUnit`s named `Owner.Owner`, and only when
  the constructor has at least one parameter. A no-argument class such as `class Base` has no constructor unit at
  all, so `Base()` must resolve to the class declaration itself.
  Evidence: `crates/bifrost-analysis/src/analyzer/kotlin/declarations.rs`, `visit_primary_constructor` (the
  `if !parameters.is_empty()` guard and `.with_synthetic(true)`).

- Observation: `KotlinAnalyzer::direct_children` filters out synthetic units, so constructor units are invisible to
  the generic child walk but *are* reachable by fully-qualified lookup (`support.fqn("lib.Base.Base")`). Constructor
  resolution therefore goes through the fqn lookup, not through `direct_children`.
  Evidence: `crates/bifrost-analysis/src/analyzer/kotlin/mod.rs`, `fn direct_children`.

- Observation: `MultiAnalyzer` widens Kotlin import resolution and Kotlin ancestor resolution across the JVM realm,
  but only through `ImportAnalysisProvider::imported_code_units_of` and `TypeHierarchyProvider::get_direct_ancestors`.
  Calling `KotlinAnalyzer::resolve_type_name_in_file` directly (as a resolver naturally would) bypasses the realm and
  silently loses cross-language answers. The Kotlin resolver therefore resolves *names* through the analyzer-level
  `BoundedDefinitionLookup` (`fqn`, `fqn_in_any_language`) and *hierarchy* through
  `analyzer.type_hierarchy_provider()`, both of which are realm-aware when the workspace is multi-language.
  Evidence: `crates/bifrost-analysis/src/analyzer/multi_analyzer.rs`, `fn kotlin_realm` and its two call sites.

## Decision Log

- Decision: fix the Kotlin local-binding gap in `lexical_definitions.rs` rather than handling locals inside the new
  Kotlin resolver.
  Rationale: "a reference to a local is a local binding, not a workspace declaration" is a language-agnostic rule
  that runs before the per-language dispatch for every other language. Duplicating it in the Kotlin resolver would
  have left the shared path still broken for any future caller, and would have made Kotlin the one language whose
  locals are decided somewhere else.
  Date/Author: 2026-07-29, David Baker Effendi (agent).

- Decision: named-argument labels resolve to the *callable* that declares the parameter, not to the parameter itself.
  Rationale: Kotlin parameters are not indexed as `CodeUnit`s, and the alternative channel — `LexicalDefinition` — is
  rendered by `crates/bifrost-analysis/src/searchtools/selectors.rs::lexical_definition_candidate` against the
  *request's* file, so it cannot address a parameter declared in another file. Answering with the callable is the
  finest identity that stays correct across files. Proving the parameter exists (by reading its name from the
  declaring file's syntax at the byte range the indexer recorded) is what keeps the answer honest: an unknown label
  abstains with `unknown_named_argument`.
  Date/Author: 2026-07-29, David Baker Effendi (agent).

- Decision: call arity participates in the name-resolution ladder's existence predicate rather than filtering the
  ladder's result, with a second arity-blind pass behind it.
  Rationale: Kotlin picks the overload that can accept the call even when a nearer scope declares the same name with
  a different shape. Post-filtering cannot express that, because the ladder would already have stopped at the nearer
  scope and returned its non-matching declaration.
  Date/Author: 2026-07-29, David Baker Effendi (agent).

- Decision: whether a nested class is a companion object is answered by re-reading the declaration's own syntax
  through a per-request file-syntax cache, not by a persisted flag or by inspecting the rendered signature string.
  Rationale: the index cannot distinguish `companion object` from a nested `object` — both are nested classes — and
  adding a persisted flag means a store schema column and migration for one language's navigation. Parsing the
  declaring file (cached per request) is an AST check, mirroring how the Java resolver inspects a declaration's
  annotations for Lombok, and the same cache also answers parameter-name and declared-type questions.
  Date/Author: 2026-07-29, David Baker Effendi (agent).

- Decision: model the Kotlin resolver on `usages/get_definition/java.rs` rather than on `scala.rs`.
  Rationale: Kotlin and Java share the JVM identity model (packages, classes, dotted fully-qualified names,
  arity-distinguished overloads, an ancestor chain for inherited members), and `java.rs` is 3.1k lines against
  `scala.rs`'s 10.7k. Scala's extra size is spent on `given`/`using`, implicit conversions, `apply`/`unapply`
  extractors, export clauses, and union types — none of which Kotlin has. Copying Scala would import machinery Kotlin
  cannot use.
  Date/Author: 2026-07-29, David Baker Effendi (agent).

- Decision: use the shared `ResolutionSession` from
  `crates/bifrost-analysis/src/analyzer/usages/get_definition/resolution_session.rs` rather than defining a
  Kotlin-private session type the way `java.rs` does with `JavaResolutionSession`.
  Rationale: `JavaResolutionSession` predates the shared type and duplicates it. A new language should not add a
  third copy. The shared session already provides the budget charging, cancellation observation, and
  `BoundedResolution` terminal states the acceptance criteria require for "budget-exhausted cases remain explicit".
  Date/Author: 2026-07-29, David Baker Effendi (agent).

- Decision: resolve names through the analyzer-level lookup (`BoundedDefinitionLookup::fqn` and friends) plus the
  Kotlin ladder's *precedence rules*, instead of calling `KotlinAnalyzer::resolve_type_name_in_file`.
  Rationale: see the `MultiAnalyzer` observation above. `resolve_kotlin_type_name` in
  `crates/bifrost-analysis/src/analyzer/kotlin/types.rs` is already parameterised over an `exists` predicate exactly
  so that different callers can supply a different notion of "this name is real". Passing a realm-aware predicate
  reuses the precedence rules without duplicating them and without losing cross-language answers.
  Date/Author: 2026-07-29, David Baker Effendi (agent).

- Decision: a reference to a *local* `val`/`var` keeps returning the pre-existing `local_binding` diagnostic rather
  than being taught to resolve to the local declaration.
  Rationale: that behaviour is language-agnostic, is produced before the Kotlin dispatch is ever reached, and is what
  every other language does. Changing it is out of scope for a Kotlin issue and would change nine other languages'
  observable output.
  Date/Author: 2026-07-29, David Baker Effendi (agent).

- Decision: Kotlin rename gets prepare-rename and declaration-site rename support, but a rename whose reference
  rewriting depends on the usage graph continues to surface the usage-graph failure from issue #1239 rather than
  emitting partial edits.
  Rationale: `crates/bifrost-analysis/src/symbol_rename.rs` rewrites references by asking the usage finder for them,
  and `crates/bifrost-analysis/src/analyzer/usages/finder.rs` returns a terminal failure for Kotlin because the
  Kotlin edge builder is issue #1239's deliverable. Emitting a declaration-only edit would silently produce
  non-compiling code. Abstaining is the correct behaviour under "safe rename where identity is proven".
  Date/Author: 2026-07-29, David Baker Effendi (agent).

- Decision: `.kts` scripts are resolved by the same code path as `.kt`, with no script-specific special casing.
  Rationale: issue #1236 already indexes `.kts` declarations through the same walk and deliberately does not index
  top-level script statements. Navigation therefore works for declarations in a script and abstains for statement-only
  constructs, which is the honest boundary. Gradle DSL accessors that exist only after the build script's own
  compilation (`implementation(...)`, `plugins { }`) are not workspace declarations and stay unresolved with the
  ordinary "not indexed" diagnostic.
  Date/Author: 2026-07-29, David Baker Effendi (agent).

## Outcomes & Retrospective

The goal was met. A Kotlin reference now resolves to its physical declaration across imports and aliases, type
annotations and supertypes, constructor and function calls, member accesses through typed receivers, inherited and
companion and extension members, enum entries, named arguments, and `this`/`super`. Those answers reach every
surface built on them: the MCP definition/declaration/type tools and the LSP hover, definition, declaration, type
definition, signature help, and prepare-rename handlers, none of which needed a change of their own.

What the work actually cost, against the original plan: roughly two thirds of it was the resolver, and the
remaining third was three structural facts the plan did not anticipate — that Kotlin overloads share one indexed
identity (so arity has to steer the name-resolution ladder rather than filter its result), that a declaration's
syntax node is not always the smallest node covering its recorded range, and that the shared call-site helpers were
blind to Kotlin's grammar. Each is recorded above with the failing test that exposed it.

Two limits are deliberate and tested rather than hidden. Smart casts (`if (v is Base) v.greet()`) abstain, because
narrowing needs the flow analysis that belongs to #1241; and a named-argument label answers with the callable that
declares the parameter rather than the parameter itself, because parameters are not indexed and the
lexical-definition channel cannot address another file. Find-references and reference-rewriting rename still abstain
until #1239 builds the Kotlin usage graph.

What remains for a follow-up: Kotlin's `SignatureMetadata` still records no return type or extension receiver, so
both are recovered by re-reading the declaring file's syntax through a per-request cache. That is correct and cheap
at this scale, but publishing them at index time would let #1239 and #1240 reuse the facts without reparsing.

## Context and Orientation

This section assumes no prior knowledge of this repository.

### What Bifrost is, and the two entry points this work changes

Bifrost is a code-intelligence engine. It parses a workspace with tree-sitter, indexes every declaration as a
`CodeUnit` (a declaration identity: a file, a kind, and a fully-qualified name), and answers structured questions
about it over three transports: a CLI, an MCP server, and an LSP server.

Two of those questions matter here.

*Definition lookup* answers "the token at this file/line/column refers to which declaration?". Its implementation is
`crates/bifrost-analysis/src/analyzer/usages/get_definition/mod.rs`. The function `resolve_one` reads the file,
locates the token (a `ResolvedReferenceSite`, carrying `focus_start_byte`/`focus_end_byte` and the token `text`),
parses the file, tries a language-agnostic lexical-binding resolution, and then dispatches on
`crate::analyzer::Language` to a per-language module: `java.rs`, `scala.rs`, `rust.rs`, and so on. Each returns a
`DefinitionLookupOutcome`, which is a status (`Resolved`, `Ambiguous`, `NoDefinition`, …), a list of `CodeUnit`
definitions, an optional `LexicalDefinition` (for locals and parameters, which are not `CodeUnit`s), and a list of
`DefinitionLookupDiagnostic { kind, message }` values. Helper constructors live at the bottom of that module:
`candidates_outcome(Vec<CodeUnit>)` for success, `no_definition(kind, message)` for an explicit abstention.

*Type lookup* answers "what is the type of the expression at this location?" and is implemented in
`crates/bifrost-analysis/src/analyzer/usages/get_type/mod.rs`, with the same per-language module shape and a
`TypeLookupOutcome`.

Today, `get_definition/mod.rs` has this arm (around line 1172):

        // Kotlin definition navigation is issue #1238.
        Language::Kotlin => no_definition(
            "kotlin_navigation_unsupported",
            "Kotlin definition navigation is not supported yet",
        ),

and `get_type/mod.rs` omits `Language::Kotlin` from its supported-language `matches!` list, so Kotlin falls into the
`unsupported_language` branch. Removing those two placeholders and making them work is this issue.

### What already exists for Kotlin

Issues #1235, #1236, and #1237 are complete. Concretely, that means:

- `crates/bifrost-analysis/vendor/tree-sitter-kotlin/` holds the pinned grammar, and
  `crates/bifrost-analysis/src/analyzer/kotlin/language.rs` exposes it as `LANGUAGE`.
- `crates/bifrost-analysis/src/analyzer/kotlin/declarations.rs` walks a parsed Kotlin file and produces the
  language-neutral declaration model: packages, classes (including `object`, `companion object`, `enum class`,
  `interface`), functions, properties, primary/secondary constructors, enum entries, and type aliases. Identities are
  *source-level*: `lib.Base.greet`, never a JVM-mangled `LibKt` or `Base$Companion`.
- `crates/bifrost-analysis/src/analyzer/kotlin/imports.rs` records structured imports (`ImportInfo`, with
  `is_wildcard` and an alias) and `KOTLIN_DEFAULT_IMPORT_PACKAGES` (the packages Kotlin imports implicitly, such as
  `kotlin` and `java.lang`).
- `crates/bifrost-analysis/src/analyzer/kotlin/types.rs` implements Kotlin's name-resolution ladder as
  `resolve_kotlin_type_name(name, &KotlinNameScope, exists)`. `KotlinNameScope` is `{ package_name, imports,
  scope_owners }`. The ladder is: enclosing scopes (and what they inherit) → explicit import (terminal: an explicit
  import that names an unknown target does *not* fall through) → same package → star imports (two different star
  matches are `Ambiguous`, which Kotlin rejects) → default imports. It returns
  `KotlinTypeName::{Resolved(String), Ambiguous, Unresolved}`.
- `crates/bifrost-analysis/src/analyzer/kotlin/hierarchy.rs` and `supertypes.rs` implement ancestors and descendants;
  `KotlinAnalyzer` implements `TypeHierarchyProvider`.
- `crates/bifrost-analysis/src/analyzer/multi_analyzer.rs` widens Kotlin's import and hierarchy resolution across the
  shared JVM source realm, so a Kotlin class can extend a Java class declared in the same workspace.
- `crates/bifrost-analysis/src/analyzer/lexical_definitions.rs` has Kotlin arms for scopes, parameter containers, and
  identifier kinds, so parameters and locals already resolve.

### The Kotlin grammar shapes this work reads

These were confirmed by parsing real Kotlin with the vendored grammar and dumping the s-expressions. Every shape
below is what the resolver matches on. Node kinds are quoted exactly.

A call is `call_expression` with two named children: the callee expression, then `call_suffix`. `call_suffix` holds
`value_arguments` (with `value_argument` children) and/or `annotated_lambda` (a trailing lambda).

        Base()                  (call_expression (simple_identifier) (call_suffix (value_arguments)))
        base.greet("x")         (call_expression
                                  (navigation_expression (simple_identifier) (navigation_suffix (simple_identifier)))
                                  (call_suffix (value_arguments (value_argument (string_literal ...)))))

A member access is `navigation_expression` with a receiver expression followed by `navigation_suffix`, whose named
child is the member `simple_identifier`. `?.` and `.` produce the same shape; `!!` wraps the receiver in
`postfix_expression`. Chains nest left-deep:

        a.b().c().d             (navigation_expression
                                  (call_expression
                                    (navigation_expression
                                      (call_expression
                                        (navigation_expression (simple_identifier) (navigation_suffix (simple_identifier)))
                                        (call_suffix (value_arguments)))
                                      (navigation_suffix (simple_identifier)))
                                    (call_suffix (value_arguments)))
                                  (navigation_suffix (simple_identifier)))

A named argument is a `value_argument` whose *first* named child is a `simple_identifier` followed by the value
expression: `foo(name = 1)` is `(value_argument (simple_identifier) (integer_literal))`. A positional argument has a
single child.

A type reference is `user_type`, whose named children are `type_identifier`s (one per dotted segment) and an optional
`type_arguments`. `nullable_type` wraps it and adds `quest`. A supertype list entry is `delegation_specifier`, holding
either `user_type` (interface) or `constructor_invocation` (superclass constructor call:
`(constructor_invocation (user_type (type_identifier)) (value_arguments))`).

An extension declaration carries the tree-sitter field `receiver`, holding a `receiver_type`:
`fun String.ext(): Int` is `(function_declaration receiver: (receiver_type (user_type (type_identifier)))
(simple_identifier) …)`.

An import is `(import_header (identifier (simple_identifier)+) [(import_alias (type_identifier))] [(wildcard_import)])`.

`this` is `this_expression`; `super` is `super_expression`; `x is T` is
`(check_expression (simple_identifier) (user_type ...))`; `x as T` is `(as_expression (simple_identifier) (user_type ...))`.

The important consequence of the field-poor grammar: "the callee of this call" is *the first named child that is not
`call_suffix`*, and "the member of this navigation" is *the `simple_identifier` inside the `navigation_suffix`*. Both
are structural AST reads. At no point does this work split source text on `.` or `::` to recover structure.

### Where tests go

Behaviour-focused, end-to-end tests for definition and type lookup live in
`tests/suite_symbols/get_definition_test.rs`, which drives the real MCP tool surface with
`call_search_tool_json(root, "get_definitions_by_location", args)` against a workspace built by
`InlineTestProject` (see `tests/common/inline_project.rs`). That is the harness this work uses: it proves the whole
stack, not just an internal function. Kotlin analyzer-level unit tests live in
`tests/suite_analyzers/kotlin_analyzer_test.rs` and `tests/suite_analyzers/kotlin_imports_and_hierarchy.rs`.

Per the repository's `CLAUDE.md`, new integration tests are added as a module of an existing suite, never as a new
top-level `tests/*.rs` binary.

## Plan of Work

The work is one new module, `crates/bifrost-analysis/src/analyzer/usages/get_definition/kotlin.rs`, one new module
`crates/bifrost-analysis/src/analyzer/usages/get_type/kotlin.rs`, and small edits at the dispatch sites. It is
delivered in five milestones, each independently verifiable.

The resolver's overall shape, mirroring `java.rs`:

1. `resolve_kotlin(analyzer, support, file, source, tree, site) -> DefinitionLookupOutcome` is the entry point called
   from the dispatch in `get_definition/mod.rs`. It creates an unbounded `ResolutionSession`, finds the smallest
   named node covering the focus, and classifies it.
2. Classification rejects declaration sites (the name of the thing being declared) with
   `declaration_site`, and routes everything else to a shape-specific resolver.
3. Every shape-specific resolver ends in either `candidates_outcome(units)` or `no_definition(kind, message)`.

### The Kotlin name scope at a reference site

Several resolvers need "what names are visible here?". That is one helper:

    fn kotlin_scope_at(analyzer, session, file, byte) -> KotlinNameScope

It reads the file's package via the analyzer's parsed model, the file's `ImportInfo`s via
`ImportAnalysisProvider::import_info_of`, and the scope owners by taking `analyzer.enclosing_code_unit(file, range)`
at `byte` and walking `parent_of` outward, collecting each owner's fully-qualified name, then extending that with
what those owners inherit via `analyzer.type_hierarchy_provider()`. The inherited extension is depth-capped (four
levels, matching `MAX_INHERITED_SCOPE_DEPTH` in `kotlin/types.rs`) so a cyclic hierarchy cannot make one lookup
unbounded.

Resolving a spelled name to a fully-qualified name is then:

    fn kotlin_resolve_type_name(session, support, scope, spelled) -> KotlinTypeName

which is `resolve_kotlin_type_name(spelled, scope, |candidate| support.fqn_in_any_language(candidate) has a class)`.
Using `fqn_in_any_language` is what makes a Kotlin file resolve a Java or Scala type declared in the same workspace.

### Milestone 1 — reference-site classification, imports, and type references

Scope: the resolver exists, is wired into the dispatch, correctly refuses declaration sites, and resolves type
references and imports. Calls and member accesses still return an explicit unsupported-shape diagnostic; that is
honest and testable.

At the end of this milestone, putting the cursor on `Base` in `import lib.Base`, on `Base` in `val b: Base`, on
`Base` in `class Derived : Base()`, or on `Inner` in `val v: Outer.Inner` resolves to the declaration. Putting it on
`Derived` in `class Derived` returns `declaration_site`.

Edits:

- New file `crates/bifrost-analysis/src/analyzer/usages/get_definition/kotlin.rs` containing:
  `resolve_kotlin`, `parse_kotlin_tree`, the scope helper, the name resolver, `kotlin_is_declaration_name`,
  `kotlin_import_reference_outcome`, and `kotlin_type_reference_outcome`.
- `crates/bifrost-analysis/src/analyzer/usages/get_definition/mod.rs`: add `mod kotlin;`, re-export what the type
  lookup needs, replace the `Language::Kotlin` placeholder arm with a call to `kotlin::resolve_kotlin`, and route
  `parse_tree_for_language`'s Kotlin arm through `kotlin::parse_kotlin_tree` so the parser construction lives with
  the rest of the Kotlin code.

`kotlin_is_declaration_name` returns true when the focused node is the name child of a `class_declaration`,
`object_declaration`, `function_declaration`, `variable_declaration`, `parameter`, `class_parameter`, `type_alias`,
`enum_entry`, or `type_parameter`. This mirrors `is_java_declaration_or_import_name`, minus the import part, because
Kotlin *does* resolve imports.

`kotlin_import_reference_outcome` handles a focus inside an `import_header`. The import's dotted path is the sequence
of `simple_identifier` children of the header's `identifier` node. The focused segment's index determines the prefix:
focusing segment *k* means the candidate fully-qualified name is segments `0..=k` joined with `.`. That candidate is
looked up with `support.fqn_in_any_language`; a wildcard import or a prefix that is only a package returns
`import_package_reference`. Focusing the `import_alias`'s `type_identifier` resolves to the same target as the full
path, which is what makes aliases navigable.

`kotlin_type_reference_outcome` handles a focus on a `type_identifier`. It walks up to the enclosing `user_type`,
joins that `user_type`'s `type_identifier` children *up to and including the focused one* with `.` (so focusing
`Outer` in `Outer.Inner` resolves to `Outer`, and focusing `Inner` resolves to `Outer.Inner`), resolves that spelling
through the ladder, and returns the class declaration. If the enclosing `user_type` is the type of a
`constructor_invocation` inside a `delegation_specifier`, the type reference still resolves to the class — the
constructor case is milestone 2.

`KotlinTypeName::Ambiguous` becomes `no_definition("ambiguous_kotlin_type", …)`; `Unresolved` becomes
`no_definition("no_indexed_definition", …)`.

Tests (new module `tests/suite_symbols/get_definition_test.rs` functions, all `kotlin_*`-prefixed):

- `kotlin_import_resolves_to_imported_class`
- `kotlin_import_alias_resolves_to_the_aliased_class`
- `kotlin_type_annotation_resolves_to_class`
- `kotlin_nested_type_annotation_resolves_each_segment_exactly`
- `kotlin_supertype_reference_resolves_to_base_class`
- `kotlin_class_declaration_name_is_not_a_reference_site` (negative)
- `kotlin_star_import_collision_reports_ambiguous` (negative)
- `kotlin_explicit_import_of_unknown_type_does_not_fall_through_to_same_package` (negative; this is the terminal-tier
  rule from `kotlin/types.rs` and is the subtle one)

### Milestone 2 — calls, constructors, overloads, named arguments

Scope: `call_expression` with a bare `simple_identifier` callee, `constructor_invocation`, overload selection by
arity, and named arguments.

A bare callee `f` in `f(args)` is resolved in this order, and the first tier that produces candidates wins:

1. A type name in scope (via the ladder). Then the reference is a *constructor call*. The target is
   `support.fqn("{type_fqn}.{simple_name}")` filtered to functions — the synthetic constructor unit — and if that is
   empty (a class with no primary-constructor parameters, which is not indexed as a constructor), the class
   declaration itself.
2. A member of an enclosing declaration or one of its ancestors, found by walking the scope owners and asking
   `support.fqn("{owner}.{f}")` filtered to functions.
3. A member of the companion object of an enclosing class (`{owner}.Companion.{f}`, and the declared companion name
   when it is not the default).
4. A top-level function in the file's package: `support.fqn("{package}.{f}")`.
5. An explicitly imported function, then a star-imported one, then a default-imported one — all through the ladder,
   which already encodes that precedence.

Overload selection: when more than one candidate survives, filter by call arity. The argument count is the number of
`value_argument` children of the `value_arguments` node, plus one when the `call_suffix` has an `annotated_lambda`
(a trailing lambda is an argument). A candidate accepts an arity when its `SignatureMetadata`'s `CallableArity`
admits it — Kotlin's arity metadata already records default-parameter and `vararg` facts (see
`kotlin_callable_arity` handling in `kotlin/declarations.rs`), so a function with defaults accepts a range. If
filtering leaves exactly one candidate the outcome is `Resolved`; if it leaves several the outcome is `Ambiguous`
with `ambiguous_definition`; if it leaves none the unfiltered set is returned rather than claiming nothing exists,
matching `java_member_candidates`.

Named arguments: a focus on the leading `simple_identifier` of a `value_argument` resolves the enclosing call's
callee first, then looks for a parameter of that name. Kotlin does not index parameters as `CodeUnit`s, so the answer
is a `LexicalDefinition` produced by locating the matching `parameter`/`class_parameter` node inside the resolved
callable's declaration range. If the callee is unresolved or ambiguous, the named argument abstains with
`no_named_argument_owner`.

Tests:

- `kotlin_constructor_call_resolves_to_primary_constructor`
- `kotlin_constructor_call_of_parameterless_class_resolves_to_the_class`
- `kotlin_top_level_function_call_resolves_in_same_package`
- `kotlin_imported_function_call_resolves_to_declaration`
- `kotlin_overloaded_call_selects_by_arity`
- `kotlin_default_parameter_overload_accepts_shorter_call`
- `kotlin_trailing_lambda_counts_as_an_argument`
- `kotlin_named_argument_resolves_to_the_parameter`
- `kotlin_call_to_unknown_function_reports_no_indexed_definition` (negative)
- `kotlin_ambiguous_overload_reports_ambiguous` (negative)

### Milestone 3 — navigation expressions and receiver typing

Scope: `base.greet()`, `Companion.make()`, `Color.RED`, `this.g()`, `super.f()`, `a?.b`, `a!!.b`, chains, extension
functions, and property accessors.

A focus on the member `simple_identifier` inside a `navigation_suffix` resolves in two steps: type the receiver, then
find the member on that type.

Receiver typing handles exactly these structured cases, and abstains explicitly on anything else:

- `this_expression` → the nearest enclosing class-like `CodeUnit`. A labelled `this@Outer` uses the label to pick the
  named enclosing owner.
- `super_expression` → the first direct ancestor of the enclosing class; `super<Base>` uses the named ancestor.
- `simple_identifier` that resolves through the ladder to a class → a *static-like* receiver (an `object`, a
  companion, or an enum class). Members are looked up on that class directly, and on its companion.
- `simple_identifier` that is a local binding or parameter → its declared type when written
  (`(variable_declaration (simple_identifier) (user_type …))` or `(parameter (simple_identifier) (user_type …))`), or
  the constructed type when the initializer is a constructor call, or the return type of the initializer's callee
  when the initializer is a call. Anything else (a lambda, an `if`, an unannotated delegate) abstains with
  `receiver_type_unknown`.
- `call_expression` receiver → the declared return type of the resolved callee. This is what makes `a.b().c()` work,
  and it composes recursively with a depth cap.
- `navigation_expression` receiver → the declared type of the resolved property.
- `postfix_expression` wrapping any of the above (the `!!` operator) → unwrapped to the inner receiver.
- `as_expression` receiver → the asserted type.
- A receiver whose smart cast would be needed (`if (v is Base) v.greet()`) is *not* inferred; it abstains with
  `receiver_type_unknown`. Kotlin's smart casts require flow analysis that belongs to issue #1241.

Member lookup on a resolved owner type walks: the owner's own members, then its companion, then its ancestors
breadth-first (through `analyzer.type_hierarchy_provider()`, which is realm-aware), then visible extension functions
whose `receiver` type resolves to the owner or one of its ancestors. Extension candidates are found by asking the
ladder for each enclosing/imported/same-package scope and filtering the resulting functions to those whose
declaration carries a `receiver` field — a structured check on the declaration's syntax, not a name heuristic.

Property accessors: a Kotlin property is indexed as a single `Field` unit even when it has a custom `get()`/`set()`.
Navigating to `obj.value` therefore resolves to the property unit. A focus on `field` inside an accessor body
resolves to the enclosing property.

Tests:

- `kotlin_member_call_on_typed_local_resolves_exactly`
- `kotlin_member_call_on_parameter_resolves_exactly`
- `kotlin_inherited_member_resolves_to_base_declaration`
- `kotlin_companion_member_call_resolves_through_the_class_name`
- `kotlin_companion_member_call_resolves_through_the_companion_name`
- `kotlin_object_member_resolves_to_object_declaration_member`
- `kotlin_enum_entry_resolves_to_entry_declaration`
- `kotlin_safe_call_resolves_like_a_plain_call`
- `kotlin_not_null_assertion_receiver_resolves_like_a_plain_call`
- `kotlin_call_result_chain_resolves_second_member`
- `kotlin_extension_function_call_resolves_to_extension_declaration`
- `kotlin_this_receiver_resolves_to_enclosing_class_member`
- `kotlin_super_receiver_resolves_to_base_member`
- `kotlin_property_access_resolves_to_property_declaration`
- `kotlin_member_on_untyped_lambda_receiver_abstains` (negative)
- `kotlin_smart_cast_receiver_abstains` (negative)
- `kotlin_member_not_on_receiver_type_reports_no_indexed_definition` (negative)
- `kotlin_same_name_member_on_a_different_class_is_not_returned` (negative; the "exactness" criterion)

### Milestone 4 — type lookup, signature help, hover, declaration, rename

Scope: everything downstream of definition resolution.

- New `crates/bifrost-analysis/src/analyzer/usages/get_type/kotlin.rs` with `resolve_kotlin_type`, modelled on
  `get_type/java.rs`: it asks a `kotlin_type_lookup_resolution` function (exported from the definition module) for
  the fully-qualified type name of the focused expression, then turns that into indexed definitions. Declaration
  names of callables return `InappropriateSymbolContext`.
- `get_type/mod.rs`: add `mod kotlin;`, add `Language::Kotlin` to the supported-language `matches!`, and add the
  dispatch arm.
- `get_definition/call_sites.rs`: replace `Language::Kotlin => false` in `is_call_reference_candidate` with a
  `kotlin_call_reference_candidate` that accepts a `simple_identifier` that is a call's callee or a
  `navigation_suffix` member of a callee, and a `type_identifier` inside a `constructor_invocation`. This is what
  makes signature help find the callee token for a Kotlin call.
- Verify hover: `crates/bifrost-lsp/src/lsp/handlers/hover.rs` already tags Kotlin code fences as `kotlin` and works
  off the resolved candidate, so it needs no change; a test proves it now returns a skeleton.
- Verify `textDocument/declaration` and `textDocument/typeDefinition`: both go through the same resolution with a
  `NavigationOperation`, so they need no change; tests prove them.
- Rename: add a Kotlin case to the rename tests proving prepare-rename offers the right identifier span, and that a
  rename which would need reference rewriting surfaces the usage-graph failure rather than a partial edit.

Tests: LSP-level tests belong in the `tests/suite_lsp_parity` suite; type-lookup tests join the `kotlin_*` group in
`tests/suite_symbols/get_definition_test.rs` (that file already holds `*_type_lookup_*` tests for Java and Scala).

- `kotlin_type_lookup_resolves_explicit_local_type`
- `kotlin_type_lookup_resolves_constructor_initialized_local`
- `kotlin_type_lookup_reports_no_type_for_inferred_lambda_local` (negative)
- `kotlin_type_lookup_reports_inappropriate_context_for_function_declaration_name` (negative)
- `kotlin_hover_returns_declaration_skeleton`
- `kotlin_signature_help_reports_the_called_function`
- `kotlin_prepare_rename_offers_the_declaration_identifier`

### Milestone 5 — abstention matrix and documentation

Scope: prove the "explicit abstention" acceptance criterion as a single readable matrix, and update the capability
documentation so it describes real support.

- One table-driven test, `kotlin_unresolvable_references_abstain_with_specific_diagnostics`, asserting the exact
  diagnostic `kind` for each abstention: `declaration_site`, `local_binding`, `ambiguous_kotlin_type`,
  `ambiguous_definition`, `receiver_type_unknown`, `no_indexed_definition`, `unsupported_kotlin_reference_shape`.
  The point of collecting them in one place is that a future change which silently converts an abstention into a
  guess fails one obvious test.
- Update the Kotlin capability notes: the module doc-comment in `crates/bifrost-analysis/src/analyzer/kotlin/mod.rs`
  currently lists "definition navigation (#1238)" as an unsupported boundary; that line moves to the supported list,
  leaving #1239/#1240/#1241 as the remaining boundaries. Any editor or docs capability table that lists Kotlin
  navigation as unsupported is updated in the same commit; search with
  `grep -rn "1238" docs editors crates` to find them.

## Concrete Steps

All commands run from the repository root, which for this work is
`/Users/dave/Workspace/BrokkAi/bifrost/.claude/worktrees/cargo-dist-cleanup-972b88`.

Build and run the Kotlin analyzer unit tests:

    cargo test -p brokk-bifrost-analysis --lib kotlin

Run the definition/type integration tests for Kotlin only:

    cargo test --test suite_symbols -- kotlin

Run the whole symbols suite (the regression guard for the nine existing languages):

    cargo test --test suite_symbols

Before committing Rust changes, run the checks CI enforces:

    cargo fmt
    PATH="/Users/dave/.cargo/bin:$PATH" cargo clippy --all-targets --all-features -- -D warnings

The `PATH` prefix is required in this checkout: two rustc installations exist and a bare `cargo clippy` picks a
`clippy-driver` that cannot read the other's build artifacts, failing with
`error[E0514]: found crate 'cc' compiled by an incompatible version of rustc`.

Expected output shape from a passing Kotlin run:

    running 28 tests
    test kotlin_import_resolves_to_imported_class ... ok
    ...
    test result: ok. 28 passed; 0 failed; 0 ignored

## Validation and Acceptance

Acceptance is behavioural. The following must be true after the work, and each is covered by a named test that fails
before the change and passes after.

1. With the two-file workspace from `Purpose / Big Picture`, requesting definitions at the `greet` token of
   `base.greet("world")` returns exactly one definition with fqn `lib.Base.greet` and status `resolved`. Before the
   change the same request returns status `no_definition` with diagnostic kind `kotlin_navigation_unsupported`.

2. Requesting definitions at `Base` in `val base = Base()` returns the primary constructor when the class has
   constructor parameters, and the class itself when it does not.

3. Requesting definitions at a name that two star imports both bind returns status `no_definition` with diagnostic
   kind `ambiguous_kotlin_type`, and returns *no* definitions. It must not pick one.

4. Requesting definitions at a member of a receiver whose type cannot be proven returns
   `receiver_type_unknown` and no definitions.

5. Requesting the type at `val base: Base = Base()`'s `base` token returns the type `lib.Base` with its declaration.

6. Every test in `cargo test --test suite_symbols` still passes, proving no other language regressed.

7. `cargo clippy --all-targets --all-features -- -D warnings` is clean.

## Idempotence and Recovery

Every step is an ordinary source edit; re-running the test commands is safe and has no side effects. The work adds
new modules and replaces two placeholder match arms, so an incomplete milestone leaves Kotlin returning explicit
diagnostics rather than wrong answers — the placeholder and the real resolver both abstain, they differ only in how
precisely. If a milestone must be abandoned, reverting its commit restores the previous behaviour with no migration
or data change, because nothing here is persisted: definition lookup is computed per request from the parse tree and
the declaration index.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/usages/get_definition/kotlin.rs`, define:

    pub(crate) fn resolve_kotlin(
        analyzer: &dyn IAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        file: &ProjectFile,
        source: &str,
        tree: Option<&Tree>,
        site: &ResolvedReferenceSite,
    ) -> DefinitionLookupOutcome;

    pub(super) fn parse_kotlin_tree(source: &str) -> Option<Tree>;

    pub(crate) enum KotlinTypeLookupResolution {
        Type { fqn: String, target_kind: TypeLookupTargetKind },
        InappropriateSymbolContext,
    }

    pub(crate) fn kotlin_type_lookup_resolution(
        analyzer: &dyn IAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        file: &ProjectFile,
        source: &str,
        root: Node<'_>,
        site: &ResolvedReferenceSite,
    ) -> Option<KotlinTypeLookupResolution>;

In `crates/bifrost-analysis/src/analyzer/usages/get_type/kotlin.rs`, define:

    pub(crate) fn resolve_kotlin_type(
        analyzer: &dyn IAnalyzer,
        support: &dyn BoundedDefinitionLookup,
        file: &ProjectFile,
        source: &str,
        tree: Option<&Tree>,
        site: &ResolvedReferenceSite,
    ) -> TypeLookupOutcome;

Dependencies used, and why:

- `crate::analyzer::kotlin::types::{KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name}` — the existing
  Kotlin precedence ladder. Reused rather than reimplemented so navigation and hierarchy can never disagree about
  what a name means.
- `crate::analyzer::kotlin::imports::{KOTLIN_DEFAULT_IMPORT_PACKAGES, kotlin_import_path}` — the structured import
  facts.
- `crate::analyzer::BoundedDefinitionLookup` — the realm-aware "does this fqn exist / give me its units" interface.
- `crate::analyzer::TypeHierarchyProvider` via `IAnalyzer::type_hierarchy_provider()` — realm-aware ancestors.
- `crate::analyzer::usages::get_definition::resolution_session::ResolutionSession` — budget and cancellation.
- `crate::analyzer::tree_walk::{first_named_child_of_kind, named_children}` — the shared structured AST helpers, so
  this module adds no new traversal idiom.

## Artifacts and Notes

The grammar shapes in `Context and Orientation` were produced by temporarily adding a test to
`crates/bifrost-analysis/src/analyzer/kotlin/language.rs` that parses a fixture and prints
`tree.root_node().to_sexp()`, then running:

    cargo test -p brokk-bifrost-analysis --lib kotlin::language -- --nocapture

The test was removed afterwards; the recorded s-expressions above are the durable artifact. Re-create it the same way
if a future shape question arises rather than guessing from the grammar source.
