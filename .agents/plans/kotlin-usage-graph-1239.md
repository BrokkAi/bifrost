# Kotlin structured reference, usage, and call graphs (issue #1239)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and
`Outcomes & Retrospective` must be kept up to date as work proceeds.

The canonical rules for writing and maintaining ExecPlans live in `.agents/PLANS.md` at the repository root. This
document must be maintained in accordance with that file.

## Purpose / Big Picture

Bifrost can already answer "where is this Kotlin symbol defined?" (issue #1238). It cannot answer the inverse: "who
uses it?". Every Kotlin find-references request, every Kotlin rename that must rewrite call sites, every
`usage_graph`/`callers`/`callees` query over Kotlin code, and every dead-code or relevance judgement about a Kotlin
declaration currently abstains with the structured failure `unsupported_target_language` from
`crates/bifrost-analysis/src/analyzer/usages/finder.rs`. That abstention is deliberate and honest — a partial answer
would silently produce broken renames — but it means a Kotlin user gets a hard "no" from six tools that work for the
other nine languages.

After this change, a user can point at a Kotlin declaration and get its real callers. Concretely, with this two-file
workspace:

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

running the MCP `scan_usages` tool for `lib.Base.greet` returns one hit at the `greet` token in `App.kt`, attributed to
the caller `app.main`, instead of today's `unsupported_target_language` diagnostic. Running `usage_graph` returns an
edge `app.main -> lib.Base.greet`. Running `rename_symbol` on `lib.Base.greet` rewrites both the declaration and the
call site rather than abstaining. Section `Validation and Acceptance` gives the exact commands and the expected JSON.

The bar for this work is the same one #1238 set: **proven identity**. A reference is reported only when the analyzer
can prove which declaration it names, from the Kotlin tree-sitter syntax tree and the analyzer's indexed declarations.
Where identity cannot be proven, the reference is recorded as an *unproven* hit (a separate, explicitly-labelled
channel that already exists in `FuzzyResult`) rather than being guessed into the proven set or dropped on the floor.
There is no regex, no source-text scanning in place of the AST, and no text-search fallback anywhere in this work.

There is a second, less obvious gain. Java, Scala, and Kotlin already share one usage *candidate space* — the `Jvm`
ecosystem in `crates/bifrost-analysis/src/analyzer/usages/workspace_graph.rs`, so that a reference resolved in any of
the three can land on a declaration from any of them. Today Kotlin is a passive member of that space: Java and Scala
references can resolve *onto* Kotlin declarations, but Kotlin source contributes no edges of its own. After this work
the realm is symmetric, so a mixed Java/Kotlin workspace — which is what almost every real Kotlin/JVM codebase is —
reports call relationships in both directions.

## Progress

- [x] (2026-07-30 09:10Z) Researched the two usage paths (query and inverted-edge), the `java_graph` and `scala_graph`
      precedents, the shared edge driver in `usages/inverted_edges.rs`, the `Jvm` realm wiring in
      `usages/workspace_graph.rs` and `searchtools/scan_usages.rs`, the #1238 Kotlin definition resolver in
      `usages/get_definition/kotlin.rs`, and the dead-code candidate routing in `code_quality/dead_code_smells.rs`.
- [x] (2026-07-30 09:35Z) Wrote this ExecPlan.
- [x] (2026-07-30 10:20Z) Milestone 1a: extracted the Kotlin grammar shape readers from
      `usages/get_definition/kotlin.rs` into a shared `analyzer/kotlin/syntax.rs`, fixing the latent
      `kotlin_call_arity` bug for `constructor_invocation` on the way. `suite_symbols -- kotlin` still 49 passed.
- [x] (2026-07-30 11:05Z) Milestone 1b: `usages/kotlin_graph/` with `TargetSpec`, `KotlinNameResolver`, the forward
      scan, and hit recording; `KotlinUsageGraphStrategy` wired into the `finder.rs` dispatch. Kotlin type references
      resolve; callable and property targets abstain with `unsupported_target_shape` instead of the blanket
      `unsupported_target_language`. 11 new tests in `tests/suite_usages/usages_kotlin_graph_test.rs`.
      Full validation: `suite_usages` 1340 passed, `suite_symbols` 1110 passed, `suite_cross_language` 246 passed,
      `cargo clippy --all-targets -- -D warnings` clean.
- [x] (2026-07-30 12:15Z) Milestone 1c: audited Kotlin's coverage against `usages_java_graph_test.rs` and
      `usages_scala_graph_test.rs` and closed every gap milestone 1 claims (see `Coverage parity with Java and Scala`).
      28 tests. Found and fixed three real defects on the way — duplicate-fqn fail-closed, `typealias` misclassified as
      a property, and generic parameters not shadowing a same-named class — all recorded in
      `Surprises & Discoveries`.
- [ ] Milestone 2: query path for constructors, functions, and properties. Per the revised decision below, this now
      starts by promoting #1238's `KotlinCtx` into a shared `analyzer/kotlin/semantics.rs` and calling it, rather than
      reimplementing receiver typing and member lookup. Remaining: receiver typing, companions, objects, inheritance,
      extensions, overload arity, callable references, override declarations, and the unproven/same-owner hit channels
      (both trimmed out of milestone 1 because a written type reference is never uncertain).
- [ ] Milestone 3: inverted edge builder; `usage_graph`, `callers`, `callees`, relevance, and dead code light up.
- [ ] Milestone 4: cross-language JVM symmetry — Kotlin call sites for Java/Scala targets and vice versa.
- [ ] Milestone 5: rename reference rewriting, the abstention matrix, dead-code bulk eligibility, capability notes.

## Surprises & Discoveries

- Observation: `kotlin_call_arity` as written by #1238 read its argument list by walking into `call_suffix` itself,
  so it returned `0` for a `constructor_invocation` — which holds `value_arguments` *directly* rather than nesting it
  inside a suffix. No #1238 caller passes a `constructor_invocation`, so the bug was latent; the graph's constructor
  arm would have been the first caller to hit it, and would have silently failed to match any superclass constructor
  call's arity.
  Evidence: `kotlin_value_arguments` already handled both shapes and `kotlin_call_arity` did not use it. Fixed while
  moving the helper by routing it through `kotlin_value_arguments`; the trailing-lambda term still reads `call_suffix`
  directly, because only an ordinary call can carry a trailing lambda.

- Observation: Kotlin failed closed on a duplicated fully-qualified name where Java reports both copies. The first
  Kotlin name resolver returned a single `CodeUnit` and required the lookup to be unambiguous, so two source files
  declaring `lib.Base` — a vendored copy, or one package built by two modules — made every reference to `Base` resolve
  to nothing, reporting zero usages for a type that is used everywhere.
  Evidence: `kotlin_duplicate_source_copies_of_one_fqn_are_both_reported`, written against Java's
  `java_graph_strategy_uses_java_fqn_identity_across_duplicate_source_copies`, failed before the fix.
  Fixed at the root by resolving to the *fully-qualified name* rather than to a declaration: in the JVM realm the name
  is the identity, which is exactly what `usages/workspace_graph.rs` already says ("two declarations in the same
  ecosystem with the same fully-qualified name are the same node"). The uniqueness requirement was borrowed from
  #1238's `resolve_type_unit`, where it is right — a *definition* query must not pick one of two candidates — and
  wrong here, because a usage query asks whether the reference names the target, and it names both.

- Observation: a Kotlin `typealias` is indexed as a `CodeUnitType::Field` with the alias-ness recorded separately
  (`declarations.rs`, `visit_type_alias` calls `mark_type_alias`), so `is_class()` is false for one. That silently put
  alias targets in the property arm, where a query for `typealias Parent = Base` abstained as an unimplemented
  property, and it also kept the name ladder from resolving any spelling that names an alias.
  Evidence: `kotlin_type_usage_reports_a_typealias_target_and_the_alias_itself` failed with `expected a hit on line 7,
  got []`.
  Fixed by consulting `IAnalyzer::type_alias_provider()` in both places: a type-alias unit classifies as
  `TargetKind::Type`, and `type_exists` counts one. An alias is referenced in type positions and has no receiver, so
  answering it with receiver typing would have been meaningless once milestone 2 filled the property arm in.

- Observation: Kotlin has *separate namespaces for types and values*, which makes the single shadow map every other
  graph language uses wrong for it. `val Base = 1` shadows the class `Base` where a value is expected (`Base.length`
  reads the local string's property) but not where a type is expected (`val x: Base` is still the class); a generic
  parameter `class Box<Base>` does exactly the reverse. Java's `maybe_record_type_hit` can use one
  `LocalInferenceEngine` shadow space for both because Java has one namespace.
  Evidence: `kotlin_generic_parameter_shadows_a_class_of_the_same_name`, which reported the type parameter as a
  reference to the imported class before the walk grew a separate type-parameter scope stack.

- Observation: `GlobalUsageDefinitionIndex` implements `BoundedDefinitionLookup`, which is the *only* thing #1238's
  `KotlinCtx` needs from its caller besides `&dyn IAnalyzer`. That makes the entire #1238 semantic layer — receiver
  typing, member lookup order, companion detection, cross-file declared-type and extension-receiver reading —
  constructible from what the usage graph already holds, at the cost of one line
  (`analyzer.global_usage_definition_index()`).
  Evidence: `crates/bifrost-analysis/src/analyzer/global_usage_definition_index.rs:212`, and `KotlinCtx`'s two fields
  `analyzer: &dyn IAnalyzer` / `support: &dyn BoundedDefinitionLookup`.
  Consequence: the Decision Log entry "the graph module does not call `resolve_kotlin`" is still right about
  `resolve_kotlin` itself, but wrong about the layer beneath it. See the revised decision below; milestone 2's plan
  changes from "reimplement receiver typing" to "promote the semantic layer and call it".

## Coverage parity with Java and Scala

This section is the checklist that keeps Kotlin's tests honest against its JVM siblings. It exists because a new
language's suite tends to test what the implementation happens to do, while the sibling suites encode years of
adversarial cases — `usages_java_graph_test.rs` has 68 tests over 4601 lines and `usages_scala_graph_test.rs` has
roughly 190 over 12794, against Kotlin's 28. Raw counts are the wrong comparison (Scala's bulk is `given`/`using`,
implicits, `apply`/`unapply`, and export clauses, none of which Kotlin has), so what matters is whether every *shape
Kotlin can express* has a case, and whether every language-agnostic *guarantee* is asserted for Kotlin too.

Reviewed as of milestone 1, and every gap that milestone 1 claims to cover is now closed. The type-position shapes
have Kotlin cases: generic arguments, annotation uses, `is`/`as` operands, enums, `data class`, interface supertypes,
`typealias`, nested-segment resolution, and the same-package/star-import/enclosing-scope tiers of the ladder. The
adversarial same-name cases have Kotlin cases: a same-named type in another package, colliding star imports, a
shadowing local binding, a shadowing generic parameter, and the terminal-explicit-import rule. The language-agnostic
result contracts have Kotlin cases: import hits visible to the editor surface but absent from the external usage
surface, candidate-file restriction, the `max_usages` truncation report, and stack safety under deep nesting.

Two Kotlin-specific cases have no Java or Scala counterpart at all and were added because the language forces them.
Colliding star imports are a *compile error* in Kotlin, so the reference is a usage of neither candidate and reporting
it for one would be picking a winner the language refuses to pick. An explicit import claims a name whether or not its
target exists, so a file importing a nonexistent `other.Base` does not reference its own package's `Base` — Java has
no equivalent tier rule, which is the concrete reason the Kotlin ladder is reused rather than reimplemented.

One divergence from Java is deliberate and one was a bug. Deliberate: Kotlin has separate namespaces for types and
values, so shadowing needs two tests rather than one — `val Base = 1` shadows the class where a value is expected but
not where a type is, and a generic parameter does the reverse. Java's single shadow map is wrong for Kotlin, which is
why the walk tracks value bindings and type parameters separately. The bug is recorded in `Surprises & Discoveries`:
Kotlin was failing closed on a duplicated fully-qualified name where Java reports both copies.

Inherited by later milestones. The following sibling cases have no Kotlin counterpart *yet* because the behaviour they
test does not exist yet; each milestone must close its own row before it is done, and the Kotlin-specific shape is
named so the case is not merely transliterated from Java.

Milestone 2 (callables and properties) owes: arity matching including defaults, `vararg`, and a trailing lambda
(Java's `accepts_varargs_expanded_and_array_calls_but_rejects_wrong_arity`, Scala's
`callable_arity_accepts_defaults_and_repeated_parameters`); an override declaration reported as an override hit
(Java's `method_declaration_hits_validate_the_visited_overload_signature`); inherited members resolved to the
declaring ancestor and *not* to a sibling that redeclares them (Java's
`keeps_concrete_override_receiver_proof_narrow` and `separates_interface_calls_from_concrete_overrides`, Scala's
`trait_member_conflict_does_not_guess_inherited_receiver`); a receiver whose type cannot be proven landing in the
unproven channel rather than the proven one (Java's `push_unproven_hit` paths, exercised through
`excludes_incompatible_anonymous_return_receivers`); same-owner classification excluding implicit-`this` calls from the
external surface while `super` stays external (Java's `filters_same_file_self_calls` and
`counts_this_field_and_method_usages`); receiver-chain budget exhaustion reported rather than silently truncated
(Java's `budgets_deep_return_receiver_chains`); a bare property read shadowed by a local at or below the class scope
(Java's `finds_bare_inherited_field_read_and_excludes_local_shadows`); and the Kotlin-only shapes with no sibling at
all — companion-object members reached through both the class name and the companion name, extension functions whose
declared `receiver` type must conform, safe-call and `!!` receivers, and a smart cast staying unproven.

Milestone 3 (the inverted edge builder) owes the whole edge-path suite: `usage_graph_java_test.rs`'s
`resolves_instance_static_and_constructor_calls`, `receiver_typing_is_type_based_not_name_based`, and
`every_edge_endpoint_is_a_node`, plus Scala's `scala_usage_graph_bulk_fetch_bypasses_lru_and_preserves_point_entry`,
which exists because hydrating each file through the per-file LRU during a whole-workspace build evicts the cache a
user's interactive queries depend on.

Milestone 4 (cross-language JVM) owes the symmetric counterparts of Java's existing one-directional set:
`java_type_usage_lookup_merges_java_and_scala_source_hits`,
`java_nested_type_usage_lookup_requires_import_or_qualification_in_scala`,
`java_type_usage_lookup_handles_same_package_and_wildcard_scala_imports`,
`java_type_usage_lookup_ignores_scala_local_type_shadowing`, and
`java_type_usage_lookup_respects_usage_finder_file_filter_for_scala_hits` — each of which needs a Kotlin-source
version, *and* a Kotlin-target version reading Java and Scala source, which Java's suite has no precedent for because
its cross-language support only runs one way.

Milestone 5 owes the abstention matrix and the rename cases, which have no direct sibling equivalent because Kotlin is
the first language where rename was gated on the usage graph landing.

## Decision Log

- Decision: build a new `crates/bifrost-analysis/src/analyzer/usages/kotlin_graph/` module modelled on `java_graph`,
  rather than extending `java_graph` to accept Kotlin or copying `scala_graph`.
  Rationale: the three JVM languages share a candidate space, not a grammar. `java_graph` reads `method_invocation`,
  `field_access`, and `object_creation_expression`; none of those node kinds exist in the Kotlin grammar, so
  "extending" it would mean a `match language` inside every scan function — a flag parameter in the shape
  `CLAUDE.md` names as a design smell. `scala_graph` is 19.5k lines because Scala has `given`/`using`, implicit
  conversions, `apply`/`unapply` extractors, export clauses, and union types, none of which Kotlin has; copying it
  would import machinery Kotlin cannot use. `java_graph` (4.0k lines) is the right size and the right identity model:
  dotted package-qualified fqns, arity-distinguished overloads, an ancestor chain for inherited members. This mirrors
  the #1238 decision to model the Kotlin definition resolver on `java.rs` rather than `scala.rs`.
  Date/Author: 2026-07-30, David Baker Effendi (agent).

- Decision: promote the Kotlin AST shape readers that #1238 left private inside
  `usages/get_definition/kotlin.rs` into a shared `crates/bifrost-analysis/src/analyzer/kotlin/syntax.rs`, and have
  both the definition resolver and the new graph module import them.
  Rationale: "the callee of a call is the first named child that is not `call_suffix`" and "the member of a navigation
  is the `simple_identifier` inside the `navigation_suffix`" are facts about the grammar, not about one consumer. The
  vendored grammar is field-poor (only `receiver`, `condition`, `consequence` carry tree-sitter fields), so every one
  of these reads is positional and therefore easy to get subtly wrong in a second copy. `CLAUDE.md` requires looking
  for a shared helper before adding a local one and adding to the shared location when it is needed in more than one
  place. `scala_graph/syntax.rs` is the precedent for a per-language syntax module that several usage consumers share
  (`java_graph/hits.rs` already imports from it).
  Date/Author: 2026-07-30, David Baker Effendi (agent).

- Decision: the graph module does not call `resolve_kotlin` from `usages/get_definition/kotlin.rs` to resolve
  reference sites, even though that function already answers "what does this token name?".
  Rationale: `resolve_kotlin` is built for one cursor position per request. It owns a `KotlinCtx` holding `Rc` and
  `RefCell` per-request caches, so it is neither `Send` nor `Sync`, while the inverted edge builder runs
  `build_edge_output` across files in parallel through rayon. More fundamentally the two have different shapes: the
  definition path asks one question and may parse other files to answer it; the graph path walks one file once, top to
  bottom, seeding a `LocalInferenceEngine` as it descends so that a receiver's type is already known by the time a
  call is reached. Reusing the per-request resolver would mean re-deriving the whole scope for every token in the
  workspace. What *is* shared is the layer below both: the syntax helpers (see the previous decision) and the Kotlin
  name-resolution ladder `resolve_kotlin_type_name` in `crates/bifrost-analysis/src/analyzer/kotlin/types.rs`, so
  navigation and usages can never disagree about what a name means.
  Date/Author: 2026-07-30, David Baker Effendi (agent).

- Decision (revised 2026-07-30, supersedes the second half of the previous entry): promote #1238's `KotlinCtx` and its
  semantic helpers out of `usages/get_definition/kotlin.rs` into a shared `crate::analyzer::kotlin::semantics`, and
  have the query path *call* that layer instead of reimplementing receiver typing.
  Rationale: `KotlinCtx` needs exactly two things from its caller — a `&dyn IAnalyzer` and a
  `&dyn BoundedDefinitionLookup` — and `GlobalUsageDefinitionIndex` implements the latter, so the usage graph can
  construct it from what it already holds. What that layer answers is not "definition navigation": it is "Kotlin facts
  the index does not publish" — what type a declaration declares, whether a nested object is a companion, what an
  extension extends, which members a receiver type reaches and in what order. Writing a second copy of the member
  lookup order would guarantee that find-references and go-to-definition eventually disagree about which declaration a
  call means, which is precisely the failure this issue exists to avoid. The original entry's reasoning still holds for
  `resolve_kotlin` (the per-cursor entry point) and for the *inverted* builder, which is parallel and cannot hold `Rc`;
  milestone 3 therefore keeps its own file-local walk and consults the shared layer only for the per-declaration facts,
  behind the `Mutex`-guarded caches milestone 2 introduces.
  Date/Author: 2026-07-30, David Baker Effendi (agent).

- Decision: resolve names in the graph builders through a realm-aware predicate rather than through
  `KotlinAnalyzer::resolve_type_name_in_file`.
  Rationale: #1238 recorded (and this plan re-verifies) that `MultiAnalyzer` widens Kotlin resolution across the
  shared JVM source realm only through `ImportAnalysisProvider::imported_code_units_of` and
  `TypeHierarchyProvider::get_direct_ancestors`. Calling `resolve_type_name_in_file` directly bypasses the realm and
  silently loses cross-language answers — exactly the answers Milestone 4 exists to provide. The graph builders
  therefore resolve names through `IAnalyzer::global_usage_definition_index` and
  `IAnalyzer::type_hierarchy_provider`, both realm-aware under `MultiAnalyzer`.
  Date/Author: 2026-07-30, David Baker Effendi (agent).

- Decision: Kotlin properties are one `TargetKind`, not two.
  Rationale: `crates/bifrost-analysis/src/analyzer/kotlin/declarations.rs` indexes a Kotlin property as a single
  `Field` `CodeUnit` even when it declares a custom `get()`/`set()`. A reference `obj.value` and a reference
  `obj.value = 1` therefore name the same declaration, and modelling accessors separately would invent identities the
  index does not have. Java's `TargetKind::Field` covers this without change.
  Date/Author: 2026-07-30, David Baker Effendi (agent).

- Decision: same-owner call sites (implicit `this`, explicit `this`, own-type static/companion receiver) are recorded
  as same-owner hits and excluded from the external usage surface, matching Java, Rust, C++, and JS/TS (#1014 facet
  B).
  Rationale: this is an existing cross-language contract enforced by `reclassify_self_receiver_hit_at` in
  `usages/common.rs` and `route_same_owner` in `usages/same_owner.rs`. A new language that opted out would make
  "is this declaration dead?" mean something different for Kotlin than for its own Java neighbours in the same
  workspace.
  Date/Author: 2026-07-30, David Baker Effendi (agent).

- Decision: smart casts stay unresolved in this issue, as they do in #1238.
  Rationale: narrowing `if (v is Base) v.greet()` needs the flow analysis that #1241 owns. A receiver whose type is
  only knowable through narrowing produces an *unproven* hit, not a proven one and not silence — so the call site is
  visible to a human reviewing references, and no consumer can mistake it for a proven edge. When #1241 lands, the
  same site becomes proven with no change to this module's contract.
  Date/Author: 2026-07-30, David Baker Effendi (agent).

## Outcomes & Retrospective

To be written at completion. Compare against the acceptance list in `Validation and Acceptance` and record what the
work actually cost against the milestone estimates, in the style of `.agents/plans/kotlin-navigation-1238.md`.

## Context and Orientation

This section assumes no prior knowledge of this repository.

### What Bifrost is

Bifrost is a code-intelligence engine. It parses a workspace with tree-sitter, indexes every declaration as a
`CodeUnit` (a declaration identity: a source file, a kind such as class/function/field, and a fully-qualified name such
as `lib.Base.greet`), and answers structured questions about the workspace over three transports: a CLI, an MCP server,
and an LSP server. Everything in this plan lives in the `brokk-bifrost-analysis` crate at
`crates/bifrost-analysis/`.

The term *fqn* below always means "fully-qualified name" in the *source-level* spelling that Bifrost indexes: Kotlin's
`lib.Base.greet`, never the JVM-mangled `lib/BaseKt.greet` or `Base$Companion`.

### The two usage paths, and why there are two

"Who uses this?" is asked in two shapes, and Bifrost answers them with two different code paths. Every graph language
implements both, and the trait pair in `crates/bifrost-analysis/src/analyzer/usages/traits.rs` exists to make that a
contract rather than a convention.

The **query path** answers "who uses *this one* declaration?". It is what the MCP tool `scan_usages`, the LSP
`textDocument/references` request, the `references_of` and `used_by` CodeQuery relations, and `rename_symbol` all use.
Its entry point is `UsageFinder::query` in `crates/bifrost-analysis/src/analyzer/usages/finder.rs`, which does three
things: discovers a set of *candidate files* that might contain a reference (via `usages/candidates.rs`), truncates
that set to the caller's file and byte budgets, and then dispatches on the target's language to a per-language
*strategy*. The strategy scans each candidate file's syntax tree looking for references to the target, and returns a
`FuzzyResult` — either a success carrying a set of `UsageHit`s, a "too many call sites" truncation, or a structured
`Failure`. The per-language contract is `UsageQueryResolver` in `usages/traits.rs`.

The **edge path** answers "give me the whole caller-to-callee graph". It is what the MCP tool `usage_graph`, the
`callers`/`callees` CodeQuery relations, the dead-code smell detector in
`crates/bifrost-analysis/src/code_quality/dead_code_smells.rs`, and the relevance ranking behind
`most_relevant_files` all use. Doing this by running the query path once per declaration would be quadratic, so
instead it runs *inverted*: one pass over every file in the workspace, resolving every reference it finds to the fqn it
names, and attributing it to the smallest declaration enclosing it. The language-agnostic half of that — attributing a
reference to its caller, deduplicating, applying the per-callee call-site cap — lives in
`crates/bifrost-analysis/src/analyzer/usages/inverted_edges.rs`. A language provides only a function that walks its
AST and calls `EdgeCollector::record_kind(callee_fqn, kind, start_byte, end_byte)`. The per-language contract is
`UsageEdgeResolver` in `usages/traits.rs`.

Both paths must agree. `usages/traits.rs` says so in a doc comment: "One impl per graph language, so 'both usage paths
share one resolver' is a contract, not convention." In practice they share the target model and the receiver-typing
logic, and differ only in whether they are looking for one target or recording all of them.

### What a hit can be: proven, unproven, and same-owner

`UsageHit` (in `crates/bifrost-analysis/src/analyzer/usages/model.rs`) carries a kind. Three of those kinds matter
here, and getting them right is most of what "explicit" means in the acceptance criteria.

A **proven** hit is a reference the analyzer proved names the target. It is the default kind, pushed by
`hits::push_hit`.

An **unproven** hit is a reference that *might* name the target but could not be proven — most often because the
receiver's type could not be established. It is pushed by `hits::push_unproven_hit` into a separate `unproven_hits`
set, surfaced separately in the result, and excluded from proven-edge consumers. This is the channel that keeps
"we don't know" from collapsing into either "yes" or "no". A declaration reachable only through unproven references is
reported as *inconclusive* by the dead-code detector, never as confidently dead.

A **same-owner** hit is a proven reference whose receiver is the current instance or the declaring type itself:
implicit `this`, explicit `this`, or `Owner.member` from inside `Owner`. It is recorded and then reclassified by
`hits::push_self_receiver_hit`, and is excluded from the *external* usage surface. This is cross-language contract
#1014 facet B, already enforced for Java, Rust, C++, and JS/TS. Without it, every private helper called only from its
own class would look used.

### What already exists for Kotlin

Issues #1235, #1236, #1237, and #1238 are complete. Concretely:

- `crates/bifrost-analysis/vendor/tree-sitter-kotlin/` holds the pinned grammar;
  `crates/bifrost-analysis/src/analyzer/kotlin/language.rs` exposes it as `LANGUAGE`.
- `crates/bifrost-analysis/src/analyzer/kotlin/declarations.rs` indexes packages, classes (including `object`,
  `companion object`, `enum class`, `interface`), functions, properties, primary and secondary constructors, enum
  entries, and type aliases. Two facts from that file matter repeatedly below: a primary constructor is indexed as a
  *synthetic* `CodeUnit` named `Owner.Owner` and **only when it has at least one parameter** (so `class Base` has no
  constructor unit at all, and `Base()` names the class); and a property is one `Field` unit even with custom
  accessors.
- `crates/bifrost-analysis/src/analyzer/kotlin/imports.rs` records structured imports (`ImportInfo`, carrying
  `is_wildcard` and an optional alias) and `KOTLIN_DEFAULT_IMPORT_PACKAGES` (the packages Kotlin imports implicitly).
  `kotlin_import_path(&ImportInfo)` gives the dotted path.
- `crates/bifrost-analysis/src/analyzer/kotlin/types.rs` implements Kotlin's name-resolution ladder as
  `resolve_kotlin_type_name(name, &KotlinNameScope, exists)`, where `KotlinNameScope` is
  `{ package_name, imports, scope_owners }`. The ladder is: enclosing scopes and what they inherit → an explicit
  import (*terminal*: an explicit import naming an unknown target does **not** fall through to the next tier) → the
  same package → star imports (two different star matches are `Ambiguous`, which Kotlin rejects) → default imports. It
  returns `KotlinTypeName::{Resolved(String), Ambiguous, Unresolved}`. The `exists` predicate is a caller-supplied
  closure, which is the seam this plan uses to make resolution realm-aware.
- `crates/bifrost-analysis/src/analyzer/kotlin/hierarchy.rs` and `supertypes.rs` implement ancestors and descendants;
  `KotlinAnalyzer` implements `TypeHierarchyProvider`.
- `crates/bifrost-analysis/src/analyzer/multi_analyzer.rs` widens Kotlin's import and hierarchy resolution across the
  shared JVM source realm (`crate::analyzer::jvm::realm`), so a Kotlin class can extend a Java class in the same
  workspace.
- `crates/bifrost-analysis/src/analyzer/usages/get_definition/kotlin.rs` (1668 lines, issue #1238) resolves a Kotlin
  reference site to its declaration. Its private helpers include the AST shape readers this plan promotes to a shared
  module, and its `KotlinCtx` methods encode the member-lookup order (own members, then companion, then ancestors
  breadth-first, then visible extensions) that Milestone 2 mirrors.
- Kotlin is already a member of the `Jvm` ecosystem in `usages/workspace_graph.rs` (see `UsageEcosystem::of`), and
  `WorkspaceUsageNode::language_label` already reports `"kotlin"`, so a Kotlin declaration is already a graph *node*.
  What is missing is any edge originating in Kotlin source.

### The exact places that abstain today

Four sites carry an explicit `#1239` marker and are the checklist for "is this issue done":

1. `crates/bifrost-analysis/src/analyzer/usages/finder.rs:711` — the `graph_find_usages` dispatch, where
   `Language::Kotlin` shares the `Language::None` arm and returns
   `GraphUsageOutcome::terminal_failure(..., UnsupportedTargetLanguage, "UsageFinder")`. This is what makes
   find-references and rename abstain.
2. `crates/bifrost-analysis/src/analyzer/usages/workspace_graph.rs:390-407` — the `Jvm` realm runs
   `build_java_usage_edge_weights` and `build_scala_usage_edge_weights` over the shared candidate set, with a comment
   stating Kotlin's builder arrives with #1239.
3. `crates/bifrost-analysis/src/searchtools/scan_usages.rs:2344` — the same two-builder `Jvm` block for the
   `usage_graph` tool, with the same comment.
4. `crates/bifrost-analysis/src/analyzer/kotlin/mod.rs:29-34` — the module doc comment listing usage graphs as an
   unsupported boundary owned by #1239.

### The Kotlin grammar shapes this work reads

These were confirmed by #1238 against the vendored grammar and re-verified for this plan. Node kinds are quoted
exactly. The consequence of the field-poor grammar is stated after each shape: the read is *positional over named
children*, which is a structured AST read, not a text parse.

A call is `call_expression` with two named children — the callee expression, then `call_suffix`. `call_suffix` holds
`value_arguments` (with `value_argument` children) and/or `annotated_lambda` (a trailing lambda, which *is* an
argument for arity purposes):

    Base()                  (call_expression (simple_identifier) (call_suffix (value_arguments)))
    base.greet("x")         (call_expression
                              (navigation_expression (simple_identifier) (navigation_suffix (simple_identifier)))
                              (call_suffix (value_arguments (value_argument (string_literal ...)))))

So "the callee of this call" is *the first named child that is not `call_suffix`*.

A member access is `navigation_expression`: a receiver expression followed by `navigation_suffix`, whose named child is
the member `simple_identifier`. `?.` and `.` produce the same shape. `!!` wraps the receiver in `postfix_expression`.
Chains nest left-deep:

    a.b().c().d             (navigation_expression
                              (call_expression
                                (navigation_expression
                                  (call_expression
                                    (navigation_expression (simple_identifier) (navigation_suffix (simple_identifier)))
                                    (call_suffix (value_arguments)))
                                  (navigation_suffix (simple_identifier)))
                                (call_suffix (value_arguments)))
                              (navigation_suffix (simple_identifier)))

So "the member of this navigation" is *the `simple_identifier` inside the `navigation_suffix`*, and "the receiver" is
*the named child before it*.

A named argument is a `value_argument` whose first named child is a `simple_identifier` followed by the value
expression: `foo(name = 1)` is `(value_argument (simple_identifier) (integer_literal))`. A positional argument has one
child.

A type reference is `user_type`, whose named children are one `type_identifier` per dotted segment plus an optional
`type_arguments`. A dotted type name such as `lib.Base` is a **single** `user_type` with two `type_identifier`
children, not a nested node. `nullable_type` wraps it and adds `quest`. A supertype list entry is
`delegation_specifier`, holding either `user_type` (an interface) or `constructor_invocation` (a superclass
constructor call: `(constructor_invocation (user_type (type_identifier)) (value_arguments))`).

An extension declaration carries the tree-sitter field `receiver`, holding a `receiver_type`, so
`fun String.ext(): Int` is `(function_declaration receiver: (receiver_type (user_type (type_identifier)))
(simple_identifier) ...)`. This is one of the very few real fields in the grammar, and it is the structured check that
distinguishes an extension function from an ordinary one — never a name heuristic.

An import is `(import_header (identifier (simple_identifier)+) [(import_alias (type_identifier))]
[(wildcard_import)])`.

`this` is `this_expression`; `super` is `super_expression`; `x is T` is
`(check_expression (simple_identifier) (user_type ...))`; `x as T` is `(as_expression (simple_identifier)
(user_type ...))`. A receiver-less callable reference `::topLevel` is `callable_reference`; note that `String::length`
does **not** parse as `callable_reference` — it parses identically to a property access,
`(navigation_expression (simple_identifier) (navigation_suffix (simple_identifier)))`.

One practical warning from #1238, which will otherwise waste an afternoon: a Kotlin declaration written on a single
line (`class D { fun f() {} }`) makes the grammar emit `MISSING _automatic_semicolon` error nodes, and
`object O { val p = 1 }` immediately followed by another declaration can degrade into `infix_expression`/
`object_literal` recovery. **Fixtures in tests must be written multi-line, with declarations separated by blank lines,
exactly as real Kotlin is written.**

### Where tests go

Per `CLAUDE.md`, a new integration test is a module of an existing suite plus one `mod` line in that suite's
`main.rs`; never a new top-level `tests/*.rs` binary. The suites and their members are listed in
`.agents/docs/test-harness-consolidation-2026-07.md`.

- Query-path tests: `tests/suite_usages/usages_kotlin_graph_test.rs`, registered in `tests/suite_usages/main.rs`.
  Model on `tests/suite_usages/usages_java_graph_test.rs`, which builds a workspace with `InlineTestProject` (see
  `tests/common/inline_project.rs`), constructs the analyzer directly, and drives `UsageFinder` with an
  `ExplicitCandidateProvider`.
- Edge-path tests: `tests/suite_usages/usage_graph_kotlin_test.rs`, registered the same way, with a checked-in fixture
  workspace at `tests/fixtures/usage-graph-kotlin/`. Model on `tests/suite_usages/usage_graph_java_test.rs`, which
  calls the real MCP tool through `crate::common::usage_graph::usage_graph_at` and asserts on edges.
- Cross-language tests: `tests/suite_cross_language/`, alongside `cross_language_import_hits.rs` and
  `cross_language_receiver_definition.rs`.
- Rename tests: wherever the existing `rename_symbol` tests live for Java; find them with
  `grep -rln "rename_symbol" tests/`.

`CLAUDE.md` also forbids low-value tests that mirror implementation-shaped lists. Every test named below asserts a
behaviour a user can observe: a hit at a specific token attributed to a specific caller, an edge between two specific
fqns, or a specific diagnostic kind for a case that must abstain.

## Plan of Work

The work is one new module tree plus small edits at four wiring sites. The module tree mirrors `java_graph`:

    crates/bifrost-analysis/src/analyzer/kotlin/syntax.rs          (new; shared grammar shape readers)
    crates/bifrost-analysis/src/analyzer/usages/kotlin_graph.rs    (new; strategy + public builders)
    crates/bifrost-analysis/src/analyzer/usages/kotlin_graph/
        resolver.rs                                                (TargetSpec, receiver matching, name resolution)
        extractor.rs                                               (forward per-file scan for the query path)
        hits.rs                                                    (hit pushing and caller attribution)
        shared.rs                                                  (KotlinQueryResolver, KotlinEdgeResolver)
        inverted.rs                                                (whole-workspace edge build)
        jvm_cross.rs                                               (Milestone 4; cross-language JVM scanning)

### Milestone 1 — shared syntax helpers, the module skeleton, and type targets

Scope: at the end of this milestone, asking for usages of a Kotlin *class* returns real hits, and asking for usages of
a Kotlin function returns an explicit `unsupported_target_shape` diagnostic rather than the blanket
`unsupported_target_language`. That intermediate state is honest and testable, which is why type targets come first;
they are also the highest-value single case, because a class is what a user most often asks "who uses this?" about.

What exists at the end that did not exist before: a Kotlin arm in the usage dispatch, and a `kotlin_graph` module that
can find every proven reference to a Kotlin type.

First, the shared syntax module. Create `crates/bifrost-analysis/src/analyzer/kotlin/syntax.rs` and **move** (not
copy) these helpers out of `crates/bifrost-analysis/src/analyzer/usages/get_definition/kotlin.rs`, changing their
visibility to `pub(crate)` and leaving `get_definition/kotlin.rs` importing them:

- `kotlin_callee(call) -> Option<Node>` — the first named child that is not `call_suffix`.
- `kotlin_value_arguments(call) -> Option<Node>` — the `value_arguments` inside the `call_suffix`.
- `kotlin_call_arity(call) -> usize` — the `value_argument` count plus one for a trailing `annotated_lambda`.
- `kotlin_named_argument_label(argument, node) -> bool` — whether `node` is the label of a named `value_argument`.
- `kotlin_enclosing_import_header(node) -> Option<Node>`.
- `kotlin_is_declaration_name(node) -> bool`.
- `kotlin_declaration_node(root, range) -> Option<Node>` — the *outermost* node with the declaration's recorded span.
  #1238 discovered this is needed because an `enum_entry` spans exactly its own name, so the smallest-covering walk
  returns the `simple_identifier` child instead of the entry.
- `kotlin_is_expression_kind(kind) -> bool`.
- `kotlin_call_with_callee(node) -> Option<Node>`.

Then add these, new in this milestone, to the same module:

- `kotlin_navigation_member(navigation) -> Option<Node>` — the `simple_identifier` inside the `navigation_suffix`.
- `kotlin_navigation_receiver(navigation) -> Option<Node>` — the named child before the `navigation_suffix`.
- `kotlin_unwrap_receiver(node) -> Node` — strips `postfix_expression` (`!!`) and `parenthesized_expression` to the
  inner receiver, iteratively with a depth cap.
- `kotlin_user_type_segments(user_type) -> Vec<Node>` — the `type_identifier` children in order.
- `kotlin_nominal_type_node(node) -> Option<Node>` — unwraps `nullable_type` and `type_arguments` wrappers to the
  `user_type`.

Verify the move is behaviour-preserving before continuing: `cargo test --test suite_symbols -- kotlin` must still
report the same count it reported before the move (see `Concrete Steps` for how to capture that baseline).

Second, `kotlin_graph.rs`, modelled directly on `java_graph.rs`. It declares the submodules, defines
`KotlinUsageGraphStrategy` with `new`, `can_handle`, and `find_graph_usages`, implements `UsageAnalyzer` for it, and
exposes `build_kotlin_usage_edges` / `build_kotlin_usage_edge_weights` (which Milestone 3 fills in; in this milestone
they may construct the resolver and return empty edges, because an empty edge set is what Kotlin contributes today and
so introduces no regression). `find_graph_usages` refuses a non-Kotlin target with
`GraphFailureReason::UnsupportedTargetLanguage("target is not Kotlin")` and a missing analyzer with
`MissingAnalyzerCapability("analyzer does not expose KotlinAnalyzer")`, both `fallback_safe`, exactly as
`JavaUsageGraphStrategy` does.

Third, `kotlin_graph/resolver.rs` with the target model:

    pub(super) enum TargetKind { Type, Constructor, Function, Property }

    pub(super) struct TargetSpec {
        pub(super) target: CodeUnit,
        pub(super) targets: HashSet<CodeUnit>,
        pub(super) kind: TargetKind,
        pub(super) owner: CodeUnit,
        pub(super) receiver_owner_fq_names: HashSet<String>,
        pub(super) declaration_owner_fq_names: HashSet<String>,
        pub(super) member_name: String,
        pub(super) callable_arities: Option<HashSet<CallableArity>>,
    }

The field meanings, which are the same as Java's: `receiver_owner_fq_names` is the set of types a receiver may have
for a reference to name this target; `declaration_owner_fq_names` is the set of types whose *declaration* of the same
member name counts as an override of this target (used to report override declarations as references); `targets` holds
every overload passed in, because the caller may pass several; `callable_arities` is `None` for a type and a set of
`CallableArity` for a callable.

`TargetSpec::from_target` classifies: `is_class()` gives `Type` with the target as its own owner. Otherwise the owner
is `analyzer.parent_of(target)`, and the kind is `Property` for `is_field()`, `Constructor` when
`target.identifier() == owner.identifier()` (which is how the synthetic `Owner.Owner` constructor unit is spelled),
and `Function` otherwise. For `Function`, extend `declaration_owner_fq_names` with every ancestor and descendant that
declares a matching member, through `analyzer.type_hierarchy_provider()` — realm-aware, so a Java subclass overriding
a Kotlin `open fun` is included.

Kotlin arity comes from `analyzer.signature_metadata(unit).first().and_then(|m| m.callable_arity())`, which already
records default-parameter and `vararg` facts from `declarations.rs`, so a function with defaults accepts a *range*.
Note the #1238 discovery that Kotlin overloads collapse into one indexed identity: two functions with the same fqn
become one `CodeUnit` carrying several signatures. Arity is therefore collected over all of
`analyzer.signature_metadata(unit)`, not just the first, and "pick the right overload" is only expressible across
*owners*.

Fourth, `kotlin_graph/hits.rs` — a near-transcription of `java_graph/hits.rs`, which is already language-agnostic in
substance: `push_hit`, `push_import_hit`, `push_override_declaration_hit`, `push_self_receiver_hit`,
`push_unproven_hit`, and `enclosing_context` with its per-node cache. It attributes a hit to
`analyzer.enclosing_code_unit(file, &range)` and walks out to the owning class through `analyzer.parent_of`.

Fifth, `kotlin_graph/extractor.rs` with `scan_file` and the type-target arm. `scan_file` reads the file, parses it with
the Kotlin `LANGUAGE`, builds a `LocalInferenceEngine` (from `usages/local_inference.rs` — the shared
scope-aware symbol-to-type map every graph language uses), and walks the tree. The walk must be **iterative**, not
recursive: `CLAUDE.md` requires stack-safe traversal for analyzer tree walks, and `usages/inverted_edges.rs`'s Java
builder already uses the shared `walk_tree_iterative` from `crate::analyzer::tree_walk` with
`TreeWalkAction::DescendWithExit` to pair scope entry and exit. Use that helper here rather than the recursive
`scan_node` that `java_graph/extractor.rs` still uses.

Kotlin scope-entering nodes, for the local inference engine: `class_body`, `function_body`, `function_declaration`,
`anonymous_initializer`, `lambda_literal`, `control_structure_body`, `when_entry`, `for_statement`, `catch_block`.
Declarations to seed: `property_declaration` and `variable_declaration` (a local `val`/`var`), `parameter`,
`class_parameter` (a primary-constructor `val`/`var`), and `for_statement`'s binding. A binding's type comes from its
declared `user_type` when written, or from the constructed type when the initializer is a constructor call; anything
else declares a *shadow* (the engine's marker for "this name is a value of unknown type", which prevents the name from
later being misread as a type reference).

The type-target arm records a hit when a resolved type reference equals the target's fqn. The cases:

- `user_type` — resolve each dotted segment prefix, and record the segment whose resolution equals the target. This is
  the same "resolve each semantic segment, pair it with the exact token that named it" shape as Java's
  `resolve_type_segments`, and it is what makes focusing `Inner` in `Outer.Inner` report `Outer.Inner` while focusing
  `Outer` reports `Outer`. Skip a `user_type` whose parent is also a `user_type` so a segment is not recorded twice.
- `constructor_invocation` inside a `delegation_specifier` — a superclass constructor call also references the type.
- `import_header` — record an import hit (a distinct kind, via `push_import_hit`) when the dotted path resolves to the
  target. An `import_alias`'s `type_identifier` records at the alias token.
- A `simple_identifier` that is the receiver of a `navigation_expression` and resolves to the target type — this is the
  static/companion/`object` qualifier case, `Base.helper()`.
- `check_expression` (`is T`) and `as_expression` (`as T`) type operands, which are ordinary `user_type` children and
  so are covered by the first case.

Skip declaration-site names (`kotlin_is_declaration_name`) and package declarations.

Resolving a spelled name in the graph builders is one function in `resolver.rs`:

    pub(super) fn resolve_kotlin_name(
        analyzer: &dyn IAnalyzer,
        kotlin: &KotlinAnalyzer,
        file: &ProjectFile,
        spelled: &str,
    ) -> Option<CodeUnit>

It builds a `KotlinNameScope` from the file's package and `ImportAnalysisProvider::import_info_of(file)` plus the scope
owners at the reference byte, calls `resolve_kotlin_type_name` with an `exists` predicate backed by
`analyzer.global_usage_definition_index()` (realm-aware — see the Decision Log), and maps `Resolved` to the class unit,
`Ambiguous` and `Unresolved` to `None`. Per-file scope construction is cached for the duration of one file scan.

Sixth, wire the dispatch. In `usages/finder.rs`: add the `use` for `KotlinUsageGraphStrategy`, add
`impl_graph_usage_analyzer!(KotlinUsageGraphStrategy);`, add a `Language::Kotlin` arm to `graph_find_usages` routing to
it, and remove `Language::Kotlin` from the `Language::None` catch-all along with the `#1239` comment. Update the
strategy list in the `UsageFinder` doc comment to include Kotlin.

Tests in `tests/suite_usages/usages_kotlin_graph_test.rs`:

- `kotlin_type_usage_reports_type_annotation_and_constructor_call`
- `kotlin_type_usage_reports_supertype_reference`
- `kotlin_type_usage_reports_import_as_an_import_hit`
- `kotlin_type_usage_reports_each_nested_segment_at_its_own_token`
- `kotlin_type_usage_reports_aliased_import_at_the_alias_token`
- `kotlin_type_usage_excludes_the_declaration_site` (negative)
- `kotlin_type_usage_excludes_a_same_named_type_in_another_package` (negative; the exactness criterion)
- `kotlin_type_usage_excludes_a_shadowing_local_binding` (negative)
- `kotlin_function_target_reports_unsupported_shape_until_milestone_2` (a temporary test; Milestone 2 deletes it and
  replaces it with the real behaviour. Its purpose is to prove the milestone boundary is an *explicit* abstention
  rather than an empty success, which is the acceptance criterion "unsupported constructs preserve their normal
  contracts".)

Acceptance for this milestone: `cargo test --test suite_usages -- kotlin` passes with the tests above, and
`cargo test --test suite_symbols -- kotlin` still passes at its pre-move count, proving the syntax-helper move
regressed nothing.

### Milestone 2 — constructors, functions, and properties

Scope: the query path becomes complete for every target kind. At the end, `scan_usages` and
`textDocument/references` work for a Kotlin function, constructor, or property, including through inheritance,
companions, objects, and extensions.

This is the largest milestone and the one where Kotlin differs most from Java, so the receiver-typing rules are
enumerated exhaustively. Each maps to a `ReceiverTargetMatch` of `Matched`, `Incompatible`, or `Unresolved`, with the
same meaning as Java's: `Matched` pushes a proven hit, `Unresolved` pushes an unproven hit, and `Incompatible` pushes
nothing (the analyzer proved this reference names something *else*).

Receiver typing, in `resolver.rs`, mirroring the order the #1238 resolver established in `kotlin_receiver`:

- `this_expression` → the nearest enclosing class-like unit; `this@Outer` uses the label to select the named enclosing
  owner. A matched `this` receiver is a *same-owner* hit.
- `super_expression` → the first direct ancestor of the enclosing class; `super<Base>` names its ancestor. A `super`
  receiver is **not** same-owner (matching Java).
- `simple_identifier` resolving through the ladder to a class → a static-like receiver: an `object`, a companion, or an
  enum class. Look up members on that class and on its companion. If the enclosing declaration is owned by that same
  class, this is a same-owner hit.
- `simple_identifier` bound as a local or parameter → its declared type when written; the constructed type when the
  initializer is a constructor call; the declared return type of the initializer's callee when the initializer is a
  call. Anything else is `Unresolved`.
- `call_expression` receiver → the declared return type of the resolved callee, recursively, with a depth cap. This is
  what makes `a.b().c()` work. Reuse `METHOD_RECEIVER_CHAIN_LIMIT` from `java_graph/return_type.rs` rather than
  inventing a second limit, so the two JVM languages report the same budget name when they exhaust it.
- `navigation_expression` receiver → the declared type of the resolved property.
- `postfix_expression` (`!!`) and `parenthesized_expression` → unwrapped via `kotlin_unwrap_receiver`.
- `as_expression` → the asserted type.
- A receiver that would need a smart cast → `Unresolved`, producing an unproven hit (see the Decision Log).

Member lookup on a resolved owner type walks, in order: the owner's own members; its companion; its ancestors
breadth-first through the realm-aware `type_hierarchy_provider`; then visible extension functions whose `receiver`
field resolves to the owner or one of its ancestors. Extension candidates are identified by the presence of the
`receiver` tree-sitter field on the declaration — a structured check, never a name heuristic.

Kotlin's `SignatureMetadata` records no return type and no extension receiver (a gap #1238 flagged as a follow-up), so
both are currently recovered by re-reading the declaring file's syntax. In the graph builders that read must go through
a shared per-scan cache keyed by `ProjectFile`, because the inverted builder runs in parallel across files and would
otherwise reparse the same declaring file once per reference. Use a `Mutex<HashMap<..>>` cache passed into the scan,
exactly as `java_graph` does with `MethodReturnCache` / `FileReturnCache`.

Reference shapes to record, per target kind:

For `Constructor`: a `call_expression` whose callee resolves to the owner type, with an arity the target accepts.
Remember that a parameterless class has no constructor unit, so a `Constructor` target always has at least one
parameter; and a `constructor_invocation` in a `delegation_specifier` is a constructor reference as well as a type
reference.

For `Function`: a `call_expression` whose callee is a bare `simple_identifier` (resolved against the enclosing scope,
the enclosing class and its ancestors, the companion, the file's package top level, then imports — the ladder order);
a `call_expression` whose callee is a `navigation_expression` (receiver-typed as above); a `callable_reference`
(`::topLevel`); a `navigation_expression` used as a function reference (`String::length` parses this way — see the
grammar section); and an *override declaration* in a subclass, recorded via `push_override_declaration_hit` when the
declaring owner is in `declaration_owner_fq_names` and the signature matches. Arity gates every call: a call whose
argument count no candidate arity accepts is not a reference to this target.

For `Property`: a `navigation_expression` member access, receiver-typed as above; a bare `simple_identifier` naming
the property from inside the owner or a subclass, gated on not being shadowed by a local binding at or below the
enclosing class scope (Java's `class_scope_depths` logic, which exists precisely because a field reference and a local
of the same name are spelled identically); an enum entry reference; and a `field` reference inside a custom accessor
body, which names the enclosing property.

Named arguments do not produce usage hits: a label names a parameter, and Kotlin parameters are not indexed as
`CodeUnit`s, so there is no target for the hit to be *of*. #1238 answered a named-argument *definition* query with the
declaring callable, which is the finest identity that stays correct across files; the usage path has no equivalent
need, because a query for the callable already reports the call site. Assert this in a test so the choice is not
mistaken for an oversight.

Same-owner classification, per the Decision Log: implicit-`this` bare calls, explicit `this` receivers, and own-type
static/companion receivers are matched and then reclassified with `push_self_receiver_hit`. `super` stays external.

Delete `kotlin_function_target_reports_unsupported_shape_until_milestone_2` and add:

- `kotlin_member_call_on_typed_local_reports_the_call_site`
- `kotlin_member_call_on_parameter_reports_the_call_site`
- `kotlin_constructor_call_reports_the_primary_constructor`
- `kotlin_top_level_function_call_reports_in_same_package`
- `kotlin_imported_function_call_reports_the_call_site`
- `kotlin_inherited_member_call_reports_against_the_base_declaration`
- `kotlin_override_declaration_is_reported_as_an_override_hit`
- `kotlin_companion_member_call_reports_through_class_and_companion_names`
- `kotlin_object_member_call_reports_the_call_site`
- `kotlin_extension_function_call_reports_the_extension_declaration`
- `kotlin_safe_call_and_not_null_assertion_report_like_a_plain_call`
- `kotlin_call_result_chain_reports_the_second_member`
- `kotlin_property_access_reports_the_property`
- `kotlin_enum_entry_reference_reports_the_entry`
- `kotlin_callable_reference_reports_the_function`
- `kotlin_implicit_this_call_is_a_same_owner_hit_not_an_external_usage`
- `kotlin_super_call_is_an_external_usage`
- `kotlin_default_parameter_call_with_fewer_arguments_is_reported`
- `kotlin_trailing_lambda_counts_toward_arity`
- `kotlin_wrong_arity_call_is_not_reported` (negative)
- `kotlin_same_name_member_on_an_unrelated_class_is_not_reported` (negative; exactness)
- `kotlin_shadowing_local_is_not_reported_as_a_property_reference` (negative)
- `kotlin_smart_cast_receiver_is_reported_as_unproven_not_proven` (negative-ish; asserts the unproven channel)
- `kotlin_named_argument_label_is_not_a_usage_of_the_callable_twice` (negative)

Acceptance: the MCP-level scenario from `Purpose / Big Picture` returns one hit attributed to `app.main`.

### Milestone 3 — the inverted edge builder

Scope: `usage_graph`, `callers`, `callees`, relevance ranking, and dead-code detection all light up for Kotlin.

What exists at the end: `kotlin_graph/inverted.rs` walking every Kotlin file once and recording every resolvable
reference as an edge.

`build_kotlin_edges` follows `java_graph/inverted.rs::build_java_edges` exactly: generic over
`Output: UsageEdgeBuildOutput<String>` so one function serves both `build_edges` and `build_edge_weights`, driven by
`build_edge_output(files, keep_file, ...)` and `parse_and_collect_with_declarations`, with a `ClassRangeIndex` per file
for attributing a reference to its enclosing class and a `Mutex`-guarded return-type cache shared across files.

The scan reuses Milestone 2's receiver typing, restated in the recording direction: instead of asking "does this
receiver's type match the target?", it asks "what fqn does this reference name?" and calls
`EdgeCollector::record_kind(fqn, classify_reference_node(node), start, end)`. Where the type cannot be established it
calls `record_unproven_name`, which feeds the `unproven_inbound` count that makes a declaration *inconclusive* rather
than dead. Same-owner calls route through `route_same_owner` from `usages/same_owner.rs`, which records them as
unproven inbound — matching Java and Rust, so a method reachable only through same-owner calls is never reported as
confidently dead.

`KotlinEdgeResolver::try_new` collects `analyzer.project().analyzable_files(Language::Kotlin)` and prefetches
`bulk_file_states` with `BulkFileStateSource::Omit`, mirroring `JavaEdgeResolver`. The bulk prefetch matters for a
reason worth stating: `scala_graph`'s test
`scala_usage_graph_bulk_fetch_bypasses_lru_and_preserves_point_entry` exists because hydrating each file through the
per-file LRU during a whole-workspace build evicts the cache a user's interactive queries depend on. Add the
equivalent Kotlin test.

Wire three sites:

- `usages/kotlin_graph.rs`: fill in `build_kotlin_usage_edges` and `build_kotlin_usage_edge_weights`.
- `usages/workspace_graph.rs`: add a third `record_package_edges!` invocation for the `Jvm` ecosystem,
  `"workspace_usage_graph::resolve_jvm_kotlin"` → `super::kotlin_graph::build_kotlin_usage_edge_weights`. Update the
  block comment: the three passes cover disjoint call sites because each resolver scans only files of its own
  language, so there is still no double counting. Remove the `#1239` sentence.
- `searchtools/scan_usages.rs`: add the matching third builder to the `Jvm` block and remove the `#1239` sentence.

Also confirm — with a test, not by reading — that `#[cfg(test)] resolved_ecosystems.dedup()` in `workspace_graph.rs`
still reports `Jvm` once now that three passes run over it.

Tests in `tests/suite_usages/usage_graph_kotlin_test.rs`, against a new fixture workspace
`tests/fixtures/usage-graph-kotlin/` (multi-line Kotlin, per the grammar warning):

- `resolves_instance_companion_and_constructor_calls`
- `receiver_typing_is_type_based_not_name_based`
- `resolves_inherited_and_overridden_members_to_their_declarations`
- `resolves_extension_function_calls_to_the_extension_declaration`
- `resolves_property_reads_and_writes_to_one_property_node`
- `same_owner_calls_do_not_create_proven_inbound_edges`
- `unresolvable_receivers_are_counted_as_unproven_inbound`
- `every_edge_endpoint_is_a_node` (via the shared `assert_every_edge_endpoint_is_a_node` helper)
- `kotlin_usage_graph_bulk_fetch_bypasses_lru_and_preserves_point_entry`

Acceptance: `usage_graph` on the `Purpose / Big Picture` workspace contains the edge `app.main -> lib.Base.greet`, and
a Kotlin declaration used only from Kotlin is no longer reported as dead by the dead-code smell.

### Milestone 4 — cross-language JVM symmetry

Scope: a Java or Scala reference to a Kotlin declaration, and a Kotlin reference to a Java or Scala declaration, are
both reported.

The edge path largely handles this already, because all three languages resolve into one `Jvm` fqn space and each
builder resolves through the realm-aware `global_usage_definition_index`. Milestone 3's tests should be extended to a
mixed workspace to confirm it rather than assume it; where an edge is missing, the fix belongs in whichever builder
failed to resolve the name, not in a special case.

The query path needs explicit work, because it scans only files whose language matches the target's.
`java_graph/shared.rs` already calls `scan_scala_files_for_java_type` for exactly this reason: a Java *type* target
also collects hits from Scala files, through the dedicated scanner in `java_graph/jvm_scala.rs`. Two symmetric gaps
must close:

1. A Java or Scala type target must also collect hits from Kotlin files. `java_graph/jvm_scala.rs` is 333 lines of
   "scan files of another JVM language for references to this type", parameterised over almost nothing — it hardcodes
   Scala's node kinds and Scala's import shape. Rather than add a `language` flag parameter to it (the smell
   `CLAUDE.md` names), factor the language-independent part — the visibility model (is the target visible in this file
   by package or by import?), the shadowing scopes, and the hit push — into a shared
   `usages/jvm_cross_language.rs`, and give each language a small descriptor supplying its identifier node kinds,
   scope-entering node kinds, and import path reader. Then `jvm_scala.rs` and the new Kotlin scanner are two
   descriptors over one engine.
2. A Kotlin target must collect hits from Java and Scala files, which is new capability in both directions and has no
   precedent to copy — Java's existing cross-language support is one-directional. Implement it as
   `kotlin_graph/jvm_cross.rs` using the shared engine from (1).

Candidate discovery must also widen, or the cross-language files never reach the strategy.
`usages/candidates.rs::add_scala_candidates_for_java_type` is the existing precedent, and
`ExplicitCandidateProvider::find_candidates` has a `keep_scala_for_java` special case. Generalise both to "for a JVM
type target, keep files of every JVM language", which is simpler than the current pairwise special-casing and removes
a special case rather than adding one.

Tests in `tests/suite_cross_language/`:

- `java_reference_to_a_kotlin_class_is_reported`
- `kotlin_reference_to_a_java_class_is_reported`
- `kotlin_call_to_a_java_method_is_reported`
- `java_call_to_a_kotlin_function_is_reported`
- `kotlin_class_extending_a_java_class_reports_the_supertype_reference`
- `java_subclass_overriding_a_kotlin_open_function_is_reported_as_an_override`
- `mixed_jvm_usage_graph_has_edges_in_both_directions`
- `scala_reference_to_a_kotlin_class_is_reported`

Acceptance: in a three-language JVM workspace, `scan_usages` for a Kotlin class returns hits from `.java`, `.scala`,
and `.kt` files, and `usage_graph` contains edges whose two endpoints were declared in different languages.

### Milestone 5 — rename, the abstention matrix, dead-code bulk eligibility, and capability notes

Scope: close the consumer surfaces named in the issue and its comment, and prove the abstentions are explicit.

Rename needs no new code — `crates/bifrost-analysis/src/symbol_rename.rs` rewrites references by asking the usage
finder, and the finder now answers for Kotlin. It needs *tests*, because "rename produces non-compiling code" is the
failure mode #1238 explicitly refused to risk:

- `kotlin_rename_rewrites_the_declaration_and_every_call_site`
- `kotlin_rename_rewrites_an_imported_reference_and_its_import`
- `kotlin_rename_across_java_and_kotlin_rewrites_both_languages`
- `kotlin_rename_abstains_when_a_reference_is_unproven` (the safety property: an unproven reference must block the
  rename rather than be silently left behind)

The abstention matrix is one table-driven test, `kotlin_unresolvable_usages_abstain_with_specific_diagnostics`,
asserting the exact diagnostic kind or hit channel for each case that cannot be proven: an unresolved receiver, an
ambiguous star-import name, a budget-exhausted receiver chain, a cancelled scan, a truncated result. Its purpose is
that a future change which silently converts an abstention into a guess fails one obvious test.

Dead-code bulk eligibility is an optimisation, and this is the milestone to decide it deliberately rather than by
omission. With Milestone 2 done, a Kotlin candidate already falls through
`code_quality/dead_code_smells.rs`'s language match into `analyze_candidate`, the per-candidate *precise* scan, which
is correct but O(candidates x files). Java and Scala avoid that with a `dead_code_bulk_eligibility` function
classifying a candidate as `BulkSafe` or `NeedsPrecise`. Add `kotlin_graph::dead_code_bulk_eligibility` with the
conservative classification — `Type` is bulk-safe; `Function` is bulk-safe unless the fqn is overloaded or a
star-import could expose it; `Constructor` and `Property` always need a precise scan — and a `Language::Kotlin` arm in
the candidate match. If measurement shows the precise path is fast enough on a real Kotlin corpus, record that in
`Surprises & Discoveries` and leave the bulk path out with the evidence; do not add it speculatively.

Capability notes, all in the same commit:

- `crates/bifrost-analysis/src/analyzer/kotlin/mod.rs` — move usage graphs from the unsupported-boundaries paragraph
  to the supported list, leaving #1240 and #1241, and delete the sentence about find-references and rename abstaining.
- Any editor or docs capability table listing Kotlin usages as unsupported. Find them with
  `grep -rn "1239" crates editors docs .agents --include='*.rs' --include='*.md' --include='*.json'` and confirm the
  only remaining hits are in `vendor/tree-sitter-kotlin/src/parser.c`, which are unrelated parser state numbers.
- `.agents/plans/kotlin-navigation-1238.md` — its `Progress` section lists find-references and rename as "remaining,
  owned by #1239". Mark that entry done and point at this plan.

Acceptance: `grep -rn "1239"` over `crates`, `editors`, `docs`, and `.agents` returns only the vendored-parser hits and
this plan; the full validation command set in `Concrete Steps` is green.

## Concrete Steps

All commands run from the repository root, which for this work is
`/Users/dave/Workspace/BrokkAi/bifrost/.claude/worktrees/cargo-dist-cleanup-972b88`.

Before touching anything, capture the baseline test counts that the Milestone 1 syntax-helper move must preserve:

    cargo test --test suite_symbols -- kotlin 2>&1 | tail -3

Expect a line of the form `test result: ok. N passed; 0 failed; ...`. As of 2026-07-30, before any work in this plan,
that number is **49**. After the Milestone 1 syntax-helper move it must still be 49.

Kotlin analyzer unit tests:

    cargo test -p brokk-bifrost-analysis --lib kotlin

Query-path tests for this work:

    cargo test --test suite_usages -- kotlin

Edge-path and cross-language tests:

    cargo test --test suite_usages -- usage_graph_kotlin
    cargo test --test suite_cross_language -- kotlin

The regression guard for the nine existing languages — this is the command that catches a shared-helper move or a
`candidates.rs` generalisation that broke someone else:

    cargo test --test suite_usages
    cargo test --test suite_symbols
    cargo test --test suite_cross_language

Before committing Rust changes, run the checks CI enforces. Note the `PATH` prefix: this checkout has two rustc
installations, and a bare `cargo clippy` picks a `clippy-driver` that cannot read the other's build artifacts, failing
with `error[E0514]: found crate 'cc' compiled by an incompatible version of rustc`.

    cargo fmt
    PATH="/Users/dave/.cargo/bin:$PATH" cargo clippy --all-targets --all-features -- -D warnings

`--all-features` here means `nlp,python`, which is a large build. Per `CLAUDE.md`, this work does not touch
semantic search, so routine per-milestone validation should use the focused featureless form, and the all-features
clippy is reserved for the pre-push gate:

    PATH="/Users/dave/.cargo/bin:$PATH" cargo clippy --all-targets -- -D warnings

If an isolated target directory is needed, route it through the helper rather than a hand-named temp directory:

    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets -- -D warnings

Expected output shape from a passing Kotlin query-path run at the end of Milestone 2:

    running 24 tests
    test kotlin_member_call_on_typed_local_reports_the_call_site ... ok
    ...
    test result: ok. 24 passed; 0 failed; 0 ignored

## Validation and Acceptance

Acceptance is behavioural. Each item below is covered by a named test that fails before the change and passes after.

1. With the two-file workspace from `Purpose / Big Picture`, `scan_usages` for `lib.Base.greet` returns exactly one
   hit, at the `greet` token of `base.greet("world")` in `src/app/App.kt`, with the enclosing caller reported as
   `app.main`. Before the change the same request returns a failure with reason kind
   `unsupported_target_language`.

2. `usage_graph` on the same workspace contains an edge from `app.main` to `lib.Base.greet`, and every edge endpoint is
   also a node in the returned node list.

3. `scan_usages` for `lib.Base` returns hits at the `Base` token of the import, the `Base` token of the constructor
   call, and nothing at the `Base` token of `open class Base` itself.

4. A call whose receiver type cannot be proven appears in the *unproven* channel of the result, not the proven one,
   and not nowhere. Specifically, `if (v is Base) v.greet()` reports an unproven hit.

5. A private Kotlin function called only from within its own class is **not** reported as an external usage, and the
   dead-code smell reports it as inconclusive rather than confidently dead.

6. `rename_symbol` on `lib.Base.greet` produces edits for both the declaration in `Base.kt` and the call site in
   `App.kt`. Before the change it produces no edits and surfaces the usage-graph failure.

7. In a mixed Java/Kotlin workspace, `scan_usages` for a Kotlin class returns hits from `.java` files, and
   `scan_usages` for a Java class returns hits from `.kt` files.

8. Every test in `cargo test --test suite_usages`, `cargo test --test suite_symbols`, and
   `cargo test --test suite_cross_language` still passes, proving no other language regressed.

9. `PATH="/Users/dave/.cargo/bin:$PATH" cargo clippy --all-targets --all-features -- -D warnings` is clean.

10. `grep -rn "1239" crates editors docs .agents` returns only hits inside
    `crates/bifrost-analysis/vendor/tree-sitter-kotlin/src/parser.c` (unrelated parser state numbers) and this plan.

## Idempotence and Recovery

Every step is an ordinary source edit; re-running any test command is safe and has no side effects. Nothing here is
persisted: both usage paths are computed per request from parse trees and the declaration index, so there is no
migration, no schema change, and no cache to invalidate. The one exception is the fixture workspace added in Milestone
3 under `tests/fixtures/usage-graph-kotlin/`, which is checked-in source with no build side effects; the shared
`usage_graph_at` helper deliberately constructs a transient service so a fixture suite never writes to the parent
repository's `.bifrost/cache`.

The work is additive except for two subtractions, and both are recoverable by reverting one commit. Milestone 1 moves
helpers out of `usages/get_definition/kotlin.rs` into `kotlin/syntax.rs`; if that move goes wrong, the baseline
`suite_symbols` count captured in `Concrete Steps` detects it immediately. Milestone 4 generalises
`java_graph/jvm_scala.rs` into a shared engine; if that refactor destabilises Java-to-Scala usages, the
`suite_cross_language` and `suite_usages` regression runs detect it, and the Kotlin scanner can be landed as a
separate module alongside the untouched Scala one at the cost of duplication, with the refactor deferred to a
follow-up.

An incomplete milestone leaves Kotlin abstaining more coarsely rather than answering wrongly: the dispatch arm either
routes to a strategy that reports an explicit unsupported-shape diagnostic, or it does not exist and the previous
blanket language failure stands. At no point does a half-finished milestone produce a wrong edge or a partial rename.

## Interfaces and Dependencies

In `crates/bifrost-analysis/src/analyzer/kotlin/syntax.rs`, define (all `pub(crate)`):

    pub(crate) fn kotlin_callee(call: Node<'_>) -> Option<Node<'_>>;
    pub(crate) fn kotlin_value_arguments(call: Node<'_>) -> Option<Node<'_>>;
    pub(crate) fn kotlin_call_arity(call: Node<'_>) -> usize;
    pub(crate) fn kotlin_navigation_member(navigation: Node<'_>) -> Option<Node<'_>>;
    pub(crate) fn kotlin_navigation_receiver(navigation: Node<'_>) -> Option<Node<'_>>;
    pub(crate) fn kotlin_unwrap_receiver(node: Node<'_>) -> Node<'_>;
    pub(crate) fn kotlin_user_type_segments(user_type: Node<'_>) -> Vec<Node<'_>>;
    pub(crate) fn kotlin_nominal_type_node(node: Node<'_>) -> Option<Node<'_>>;
    pub(crate) fn kotlin_is_declaration_name(node: Node<'_>) -> bool;
    pub(crate) fn kotlin_enclosing_import_header(node: Node<'_>) -> Option<Node<'_>>;
    pub(crate) fn kotlin_declaration_node<'tree>(root: Node<'tree>, range: &Range) -> Option<Node<'tree>>;

In `crates/bifrost-analysis/src/analyzer/usages/kotlin_graph.rs`, define:

    pub struct KotlinUsageGraphStrategy;

    impl KotlinUsageGraphStrategy {
        pub fn new() -> Self;
        pub fn can_handle(target: &CodeUnit) -> bool;
        pub(crate) fn find_graph_usages(
            &self,
            analyzer: &dyn IAnalyzer,
            overloads: &[CodeUnit],
            scan_scope: &UsageScanScope<'_>,
            max_usages: usize,
        ) -> GraphUsageOutcome;
    }

    impl UsageAnalyzer for KotlinUsageGraphStrategy { /* ... */ }

    pub(crate) fn build_kotlin_usage_edges<F>(
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> Option<UsageEdges>
    where
        F: Fn(&ProjectFile) -> bool + Sync;

    pub(crate) fn build_kotlin_usage_edge_weights<F>(
        analyzer: &dyn IAnalyzer,
        nodes: &HashSet<String>,
        keep_file: F,
    ) -> Option<UsageEdgeWeights>
    where
        F: Fn(&ProjectFile) -> bool + Sync;

In `crates/bifrost-analysis/src/analyzer/usages/kotlin_graph/shared.rs`, define the two resolvers that make "both
usage paths share one target model" a contract:

    pub(crate) struct KotlinQueryResolver<'a> { kotlin: &'a KotlinAnalyzer }
    impl<'a> UsageQueryResolver<'a> for KotlinQueryResolver<'a> { /* ... */ }

    pub(crate) struct KotlinEdgeResolver<'a> {
        kotlin: &'a KotlinAnalyzer,
        files: Vec<ProjectFile>,
        file_states: HashMap<ProjectFile, FileState>,
    }
    impl<'a> UsageEdgeResolver<'a> for KotlinEdgeResolver<'a> { /* ... */ }

Dependencies used, and why each rather than an alternative:

- `crate::analyzer::kotlin::types::{KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name}` — Kotlin's existing
  precedence ladder, reused rather than reimplemented so navigation, hierarchy, and usages can never disagree about
  what a name means. Its `exists` predicate parameter is the seam that makes resolution realm-aware.
- `crate::analyzer::kotlin::imports::{ImportInfo, kotlin_import_path, KOTLIN_DEFAULT_IMPORT_PACKAGES}` — structured
  import facts, so import visibility is never recovered by scanning source text.
- `crate::analyzer::IAnalyzer::global_usage_definition_index` and `::type_hierarchy_provider` — the realm-aware
  lookups. Chosen over `KotlinAnalyzer::resolve_type_name_in_file` for the reason in the Decision Log.
- `crate::analyzer::usages::inverted_edges::{EdgeCollector, build_edge_output, parse_and_collect_with_declarations,
  classify_reference_node, ClassRangeIndex, UsageEdgeBuildOutput}` — the shared edge driver, so every accounting rule
  (self-reference dropping, call-site capping, weight dedup) has exactly one implementation.
- `crate::analyzer::usages::local_inference::{LocalInferenceEngine, LocalInferenceConfig}` — the shared scope-aware
  binding map, so Kotlin's shadowing behaves like every other language's.
- `crate::analyzer::usages::same_owner::route_same_owner` and
  `crate::analyzer::usages::common::reclassify_self_receiver_hit_at` — the #1014 facet B contract, shared rather than
  restated.
- `crate::analyzer::tree_walk::{walk_tree_iterative, TreeWalkAction}` — stack-safe iterative traversal, required by
  `CLAUDE.md` for analyzer tree walks.
- `crate::analyzer::usages::java_graph::return_type::METHOD_RECEIVER_CHAIN_LIMIT` — the receiver-chain budget, shared
  with Java so the two JVM languages report the same limit name when a chain exhausts it.
