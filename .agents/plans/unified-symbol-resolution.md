# Unify usage-graph symbol resolution on the analyzer's keyed index

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agent/PLANS.md` at the repository root.

This plan builds on and supersedes the remaining work of `.agents/plans/shared-usage-index-refactor.md` (checked in; read it for the Scala-specific history). That plan added `src/analyzer/usages/symbol_index.rs` and migrated Scala onto it. This plan dissolves that module into the analyzer-owned index layer, generalizes the pattern to the other languages that need it, and removes the remaining linear declaration scans across the usage-graph code.

## Purpose / Big Picture

Bifrost's `usage_graph` and `scan_usages` tools resolve names in source files to declared symbols. Today each of the eleven supported languages resolves names its own way, and four of them (C#, Go, Python, C++) do it partly by linearly scanning every declaration in the workspace — per reference site, per hit, or per query. On large repositories this is the same O(all-declarations) pathology that was just fixed for Scala (commit a18d726). After this plan, there is exactly one workspace-wide keyed symbol index, owned and cached by the analyzer; one small derived index for callable facts (return types, arity); and one shared per-file "visible name" resolver algorithm that package/namespace-addressed languages instantiate instead of hand-rolling their own. The linear scans are gone, and the per-language code that remains is genuinely language-specific semantics (C++ overload matching, Go struct-embedding promotion, Scala extension methods, Rust trait resolution).

Observable outcomes: all existing usage-graph and get-definition test suites keep passing; new regression tests demonstrate keyed lookups where scans used to be; `src/analyzer/usages/symbol_index.rs` and `src/analyzer/usages/receiver_facts.rs` no longer exist; and grepping the usage-graph code for `get_all_declarations()` finds no resolution-path callers.

## Progress

- [x] (2026-07-07) ExecPlan drafted from a four-agent survey of all eleven language graph builders.
- [x] (2026-07-07 09:11 CDT) Milestone 1 complete: `DefinitionLookupIndex` now uses adapter-supplied normalization and simple-type naming, stores normalized FQN/type/member keyed maps, and `src/analyzer/usages/receiver_facts.rs` plus its module declaration are deleted.
- [x] (2026-07-07 09:11 CDT) Milestone 2 complete: `UsageFactsIndex` is built from analyzer state, exposed through `IAnalyzer`, Scala `ProjectTypes` consumes `DefinitionLookupIndex` plus `UsageFactsIndex`, and `src/analyzer/usages/symbol_index.rs` plus its module declaration are deleted.
- [x] (2026-07-07 10:11 CDT) Milestone 3 complete: added the shared `visible_names` resolver, migrated C# visible type resolution plus forward and inverted usage graph paths to `DefinitionLookupIndex`/`UsageFactsIndex`, replaced C# enclosing-class scans with `ClassRangeIndex`, removed the private C# inverted method/class/return indexes, added the noisy receiver-return regression, and passed the Milestone 3 quality gates.
- [x] (2026-07-07 10:24 CDT) Milestone 4 complete: Go query graph construction now builds the same keyed `GoEdgeIndex` facts from its already parsed files, `collect_promoted_receiver_types` uses keyed direct-member and embedded-field maps, constructor-name seeding uses the multi-candidate constructor-return map, the `graph_declarations` helper family is deleted, and the Milestone 4 quality gates passed.
- [x] (2026-07-07 10:36 CDT) Milestone 5 complete: Python `resolve_receiver_type` now replaces its all-declarations fallback with keyed current-module/exact/normalized type probes, classmethod detection uses owner/member keyed lookup, imported class method factory-return enumeration uses keyed direct children while preserving Python's existing decorator and body-return inference, and the Milestone 5 quality gates passed.
- [x] (2026-07-07 10:51 CDT) Milestone 6 complete: C++ `VisibilityIndex` now routes qualified lookups through `DefinitionLookupIndex` and unqualified tail lookups through a per-closure identifier map built once from the include closure, `precise_parent_of` resolves owner FQNs through the keyed index, C++ static/member return binding uses keyed owner/member lookup with exact include-closure membership, and the duplicate `split_top_level_commas` copy in `cpp_graph/resolver.rs` is deleted.
- [ ] Milestone 7: replace Java's and PHP's lazy return-type caches with `UsageFactsIndex`.

## Surprises & Discoveries

- Observation: The `definitions` map in `AnalyzerState` is already keyed by `adapter.normalize_full_name(...)` (`src/analyzer/tree_sitter_analyzer.rs`, `index_state`), while `DefinitionLookupIndex::insert` hardcodes the Scala-flavored normalization `fqn.replace("$.", ".").trim_end_matches('$')` (`src/analyzer/definition_lookup_index.rs`, in `insert`). The generic index duplicates by copy-paste what the adapter hook already abstracts.
  Evidence: compare `definition_lookup_index.rs` `insert` with `tree_sitter_analyzer.rs` `LanguageAdapter::normalize_full_name` and `scala_graph/resolver.rs::scala_normalized_fq_name` — identical string transform in two places.
- Observation: C#'s inverted-edge builder independently reinvented the symbol index (`class_units` fqn map, `MethodDeclarationIndex` keyed `(owner, name, arity)`, `MethodReturnCache`) while its forward resolver in the same language does eight full linear scans over `get_all_declarations()` for the same lookup shapes.
  Evidence: `src/analyzer/usages/csharp_graph/inverted.rs` (index construction near the top of `build_csharp_edges`) vs. `csharp_graph/resolver.rs` (`receiver_type_units`, `member_declared_type_fq_name`, `method_return_type_fq_name_for_arity`, `resolve_member_type_fq_name`, `resolve_type_fq_name` fallback) and `csharp_graph/extractor.rs` (`extension_receiver_type_matches`).
- Observation: Go solved the keyed-index problem once (`GoEdgeIndex` in `go_graph/resolver.rs`) for the edge path but the query path rebuilds the same facts with repeated linear collection (`graph_declarations` and five callers), approaching O(n²) in `collect_promoted_receiver_types`.
  Evidence: doc comment above `GoEdgeIndex` in `go_graph/resolver.rs` acknowledging the mirror structure.
- Observation: Scala's existing `(package, simple)` key and `CodeUnit::identifier()` differ for companion objects. `scala_display_name(unit)` trims a trailing `$` from the last segment, while `identifier()` deliberately returns `Foo$` when the last segment ends in `$`.
  Evidence: `src/analyzer/scala/declarations.rs` creates object type short names with `format!("{raw_name}$")`; `src/analyzer/model.rs::CodeUnit::identifier` returns the `$`-suffixed member name when the last segment ends in `$`; `src/analyzer/usages/scala_graph/resolver.rs::scala_display_name` trims the trailing `$`. Milestone 1 therefore added `LanguageAdapter::simple_type_name`, with Scala overriding it to preserve `scala_display_name` behavior.
- Observation: `SignatureMetadata` does not carry structured return-type information. It stores a signature label and parameter metadata only, so return-type extraction still has to come from language signature text.
  Evidence: `src/analyzer/model.rs::SignatureMetadata` has fields `label: String` and `parameters: Vec<ParameterMetadata>` and exposes `label()`/`parameters()` only. Milestone 2 moved Scala's existing signature arity/return helpers into `src/analyzer/scala/mod.rs` and reused them through `ScalaAdapter` rather than adding new ad hoc parsers.
- Observation: After merging type and member normalized FQN lookups into `DefinitionLookupIndex::by_normalized_fqn`, Scala's `type_by_normalized_fqn` must filter to class units before direct-member import resolution.
  Evidence: the initial Milestone 2 rebase made `import app.ConsoleRenderer.{default => renderer}` seed neither a member nor a type receiver for `renderer.render`; the normalized key `app.ConsoleRenderer.default` correctly contained `app.ConsoleRenderer$.default`, but the type probe consumed the function before the member probe. Filtering `type_by_normalized_fqn` to `is_class()` restored `scala_renamed_member_import_resolves_to_member_definition` and `scala_imported_factory_return_type_uses_factory_scope`.
- Observation: The Milestone 3 C# scan diagnosis was accurate. The forward path had the listed `get_all_declarations()` scans in `receiver_type_units`, `member_declared_type_fq_name`, `method_return_type_fq_name_for_arity`, `resolve_member_type_fq_name`, `resolve_type_fq_name`, and `extension_receiver_type_matches`, and `enclosing_declared_type` manually scanned `get_declarations(file)` ranges. The inverted path independently built `class_units`, `MethodDeclarationIndex`, and `MethodReturnCache`.
  Evidence: pre-edit `rg -n "get_all_declarations\\(\\)|MethodDeclarationIndex|MethodReturnCache|class_units" src/analyzer/usages/csharp_graph` showed those anchors in `resolver.rs`, `extractor.rs`, and `inverted.rs`; post-edit `rg -n "get_all_declarations\\(\\)" src/analyzer/usages/csharp_graph` returns no matches.
- Observation: C# `CodeUnit::signature()` for methods is the parameter key, while the rendered signatures stored in `signatures_of` carry the declared return type. Building `UsageFactsIndex` from the parameter key first would leave C# return facts empty.
  Evidence: `src/analyzer/csharp/declarations.rs::visit_method` creates the function with `CodeUnit::with_signature(..., Some(csharp_parameter_key(...)))` and separately stores `csharp_method_skeleton(...)` through `add_signature_with_metadata`.
- Observation: The shared `UsageFactsIndex` can resolve ordinary C# same-namespace/import-visible return types, but not every owner-relative nested type because the generic facts builder has package and declaration FQN context, not the declaring owner type context.
  Evidence: C# still needs `resolve_member_type_fq_name(owner, type_text)` to interpret nested owner names such as `Outer.Inner`/`Outer$Inner`; the C# resolver now probes `UsageFactsIndex` first and keeps the existing signature-derived owner-relative resolution as a fallback.
- Observation: The Milestone 4 Go scan diagnosis was accurate. `graph_declarations` was called by `collect_promoted_receiver_types`, `graph_direct_member_fqns`, `graph_direct_children`, `graph_embedded_field_type_fqns`, and `graph_fqn_exists`; the promoted-receiver walk passed closures that re-entered those helpers per candidate type and embedded edge.
  Evidence: pre-edit `rg -n "graph_declarations|graph_direct_member_fqns|graph_direct_children|graph_embedded_field_type_fqns|graph_fqn_exists" src/analyzer/usages/go_graph/resolver.rs` showed all five helpers and their promotion call sites; post-edit `grep -rn "graph_declarations" src/analyzer/usages/go_graph/` returns no matches.
- Observation: No keyed-lookup semantic discrepancy was found in Milestone 4. The direct member, embedded field, package-directory, and constructor-return facts already used by the inverted Go edge path matched the query path's required behavior when scoped to the query graph's parsed files.
  Evidence: after the migration, the required Go/get-definition suite passed unchanged: `get_definition_test` 376, `go_dead_code_smells` 11, `gopls_goto_definition` 5, `usage_graph_go_test` 11, and `usages_go_graph_test` 39.
- Observation: The Milestone 5 Python scan diagnosis was accurate. `resolve_receiver_type` had a `target_self_file`-gated `get_all_declarations().find(...)` fallback for bare class annotations, `target_class_method_named` scanned every declaration per attribute candidate to find decorated class methods on the target class, and `collect_imported_class_method_return_types` scanned every declaration per imported class to enumerate methods.
  Evidence: pre-edit `rg -n "get_all_declarations\\(\\)|resolve_receiver_type|target_class_method_named|collect_imported_class_method_return_types" src/analyzer/usages/python_graph` showed exactly those three Python graph call sites; post-edit `grep -R -n "get_all_declarations()" src/analyzer/usages/python_graph/` returns no matches.
- Observation: Python's keyed FQN/member shapes match the scan sites migrated in Milestone 5, with no observed semantic discrepancy. Python class declarations use the module FQN as `package_name`, nested classes use `$` inside `short_name`, and `CodeUnit::identifier()` returns the source-spelled simple class name for both top-level and nested classes. Direct method children are indexed by owner FQN because Python method short names use `Class.method`.
  Evidence: `src/analyzer/python/declarations.rs` constructs classes with `CodeUnit::new(file, Class, module_fq, short_name)` where nested classes are `Parent$Child`, and methods with `short_name` `Class.method`; the required Python/get-definition suite passed unchanged after replacing the scans (`get_definition_test` 376, `usages_python_graph_test` 68 passed/3 ignored, `intellij_python_definition` 18, `intellij_python_find_usages` 15 passed/5 ignored, `basedpyright_goto_definition` 2, `python_js_ts_dead_code_smells` 17, `usages_python_test` 4).
- Observation: Python's existing workspace method-return helper is body-aware, while `UsageFactsIndex` only builds from signatures and metadata. For Python factories this matters because `callable_return_type_name` can infer `return Service()` when no `-> Service` annotation exists.
  Evidence: `src/analyzer/usages/python_graph/extractor.rs::factory_return_type` first reads the `return_type` AST field and then scans return statements for constructed/returned receiver names; `UsageFactsIndex::build_from_declarations` only receives analyzer signatures/metadata. The existing tests `imported_factory_return_receiver_resolves_member_usage` and `python_imported_factory_return_receiver_method_resolves_to_definition` exercise the unannotated `def build_service(): return Service()` case and passed after keeping `callable_return_type_name`.
- Observation: The Milestone 6 C++ scan diagnosis was accurate. `VisibilityIndex` stored a `visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>` include-closure declaration bag and the listed resolver methods filtered that bag per lookup; `precise_parent_of` called `get_all_declarations().find(...)` from the per-hit `hits.rs::enclosing_context` path; and the comma splitter existed both as `cpp_call_match.rs::cpp_split_top_level_commas` and `cpp_graph/resolver.rs::split_top_level_commas`.
  Evidence: pre-edit `rg -n "visible_by_file|get_all_declarations\\(\\)|split_top_level_commas" src/analyzer/usages/cpp_graph src/analyzer/usages/cpp_call_match.rs` showed the resolver scan sites, the parent scan, and both splitter definitions. Post-edit `rg -n "get_all_declarations\\(\\)" src/analyzer/usages/cpp_graph src/analyzer/usages/cpp_graph.rs` returns no matches, and `rg -n "fn .*split_top_level_commas" src/analyzer/usages/cpp_graph src/analyzer/usages/cpp_call_match.rs src/analyzer/usages/cpp_graph.rs` reports only `cpp_call_match.rs::cpp_split_top_level_commas`.
- Observation: C++ declaration shape is not Java-like: `package_name` stores namespace text such as `lib` or `outer::inner`, while `short_name` stores nested classes with `$` and members with `.`, so a type `namespace lib { class Factory { class Inner; }; }` keys as package `lib`, short `Factory$Inner`, and FQN `lib.Factory$Inner`. `types_in_package` is populated for C++ classes and aliases by that namespace/simple shape, but namespace-qualified source names such as `lib::Factory::Inner` do not map to a single Java-style `(package, simple)` probe.
  Evidence: `src/analyzer/cpp/declarations.rs::visit_namespace` appends namespaces with `::`; `visit_named_class_like` uses `format!("{}${name}", parent.short_name())` for nested classes; `visit_variable_declaration` and function extraction use dotted member short names; and `CodeUnit::fq_name` joins package and short name with `.`. The C++ resolver's `cpp_name_for` reverses this by rendering package plus short name with `::`.
- Observation: C++ keyed lookup must distinguish exact include-closure membership from logical target visibility. During the first Milestone 6 test run, using `same_visible_symbol` as the keyed candidate membership predicate admitted both an included header declaration and a same-FQN source definition for `Service::create`; the two signatures produced different parsed return texts and made static factory receiver inference ambiguous.
  Evidence: the first `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_cpp_test` run failed `object_sensitive_factory_receiver_resolves_only_constructed_type` and `static_factory_return_resolves_in_method_namespace`; after changing keyed candidate filtering to exact closure membership while leaving `is_visible`'s logical matching for target comparisons, `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_cpp_test` passed 13 tests.

## Decision Log

- Decision: Merge the raw keyed lookups of `WorkspaceSymbolIndex` into `DefinitionLookupIndex` rather than keeping two workspace indexes.
  Rationale: `DefinitionLookupIndex` is already an `IAnalyzer` trait method backed by analyzer state with a working rebuild lifecycle, and it already half-duplicates the normalization logic. Two indexes with overlapping keys invite drift; the repo's design philosophy says fix the root cause.
  Date/Author: 2026-07-07 / Claude (approved by Jonathan)
- Decision: Keep callable facts (return-type FQN, arity, is_function) in a separate derived index (`UsageFactsIndex`) built lazily from the raw index, not folded into `DefinitionLookupIndex` inserts.
  Rationale: Resolving a return-type text to an FQN requires the completed type index (Scala's build does an explicit two-pass for this). Per-declaration facts can be maintained at insert time; cross-declaration derived facts cannot, without a reverse-dependency invalidation scheme that is not worth building. Lazy build inside `AnalyzerState` inherits the existing wholesale-rebuild invalidation for free.
  Date/Author: 2026-07-07 / Claude (approved by Jonathan)
- Decision: The `(package, simple)` type map stores `Vec<CodeUnit>` per key and lets callers pick, instead of baking in the current `symbol_index.rs` policy of preferring non-`$`-suffixed FQNs.
  Rationale: The `$` preference is Scala companion-object policy and does not belong in generic code; Go needs multiple candidates preserved (interface-compatible receivers). Scala's caller applies its preference at the call site.
  Date/Author: 2026-07-07 / Claude
- Decision: The shared visible-name resolver driver targets package/namespace-addressed languages (Java, C#, PHP, Scala, C++, Go, Python-partially). JS/TS and the module axis of Rust resolve through file-scoped export/import edges (`ImportBinder`/`ExportIndex`/`reexport_seeds.rs`), which is a different, already-shared layer; they are explicitly out of scope.
  Rationale: Module-graph resolution answers "which file's export does this local name bind to"; package resolution answers "which FQN does this name denote given imports and package context". Forcing one through the other is the overstraining this refactor must avoid.
  Date/Author: 2026-07-07 / Claude (approved by Jonathan)
- Decision: Rust and Ruby are out of scope for this plan.
  Rationale: Rust already resolves through analyzer-level keyed structures (`RustReferenceContext`, `DefinitionLookupIndex`) and its return-type facts need wrapper metadata (`Box`/`Arc`/`Rc`/`Option`/`Result` unwrapping) that would contort the shared struct for one consumer. Ruby's problems are structural (single 1959-line file, no inverted-edge path, per-candidate re-parsing, mixin/MRO ordering) and get their own follow-up plan.
  Date/Author: 2026-07-07 / Claude (approved by Jonathan)
- Decision: Store `definition_lookup_index` and `usage_facts_index` as `Arc` inside `AnalyzerState`, with inherent `_shared()` accessors on `TreeSitterAnalyzer` (forwarded by `ScalaAnalyzer`) returning owned handles; `ProjectTypes` holds `Arc`s instead of cloned snapshots.
  Rationale: The Milestone 2 rebase cloned both workspace indexes per `ProjectTypes::build` to satisfy the `Arc<ScalaProjectTypes>` caches — O(workspace) string-key copies per build, at every call site including `scala/hierarchy.rs`. An `Arc` handle is a refcount bump. Deliberately inherent methods, not `IAnalyzer` methods with defaults: a trait default returning an empty index would silently mask a missing forward in wrapper analyzers. Languages migrating in Milestones 3-6 add the same inherent forward when they first need ownership. This is the intentional-refcounting case the repo conventions allow: one large immutable snapshot shared across readers.
  Date/Author: 2026-07-07 / Claude (prompted by Jonathan flagging the clone cost)
- Decision: Migration order after the foundation: C# first, then Go, Python, C++, then the Java/PHP return-cache swap.
  Rationale: C# has the largest win (eight forward-path linear scans plus three reinvented indexes) and is the best generality test for the shared API. Java and PHP already resolve names correctly through analyzer-level import-aware lookups; only their lazily-memoized return-type caches are worth replacing, so they go last and smallest.
  Date/Author: 2026-07-07 / Claude
- Decision: Build `UsageFactsIndex` eagerly in `AnalyzerState::index_state` using `LanguageAdapter` hooks, rather than storing a `OnceLock` that has to be parameterized by a per-language extractor later.
  Rationale: The index depends on the completed `DefinitionLookupIndex` and language-specific signature extraction. Eager construction keeps wholesale-rebuild invalidation, avoids trait-object lifetime plumbing through `IAnalyzer::usage_facts_index`, and still exposes the same cached immutable index to callers. This supersedes the earlier preference for lazy construction while preserving the same observable cache lifecycle.
  Date/Author: 2026-07-07 / Codex
- Decision: Keep Scala companion-object preference in Scala hooks/call sites, not in the generic index.
  Rationale: `DefinitionLookupIndex` stores every candidate for `(package, simple)` and normalized FQN keys. Scala's `simple_type_name` hook and `ProjectTypes` candidate selection prefer non-`$` type declarations where Scala source spelling requires it; generic consumers can preserve multiple candidates for their own semantics.
  Date/Author: 2026-07-07 / Codex
- Decision: Let `ProjectTypes` own cloned snapshots of `DefinitionLookupIndex` and `UsageFactsIndex` instead of borrowing them.
  Rationale: existing get-definition/get-type code caches `Arc<ScalaProjectTypes>` without a lifetime parameter. Cloning the immutable analyzer-owned indexes once per resolver construction preserves compatibility and keeps hot-path lookup borrowed inside `ProjectTypes`.
  Date/Author: 2026-07-07 / Codex
- Decision: Shape `FileImportContext` around imported candidate FQN strings plus a `select_unique` hook instead of the sketch's single `imported_type(simple) -> Option<String>`.
  Rationale: C# imports include using-namespace expansion, aliases, global usings, partial classes, and same-FQN generic arity distinctions. The shared driver owns the probe order, while `select_unique` lets C# preserve its existing logical-dedup rule for partial declarations and generic arity without cloning in the common path.
  Date/Author: 2026-07-07 / Codex
- Decision: Make C# adapter normalization replace nested-type `$` separators with source-spelled `.` for the shared normalized FQN map.
  Rationale: Existing C# resolution treated `Example.Outer.Inner` and analyzer FQN `Example.Outer$Inner` as the same type. Adapter-level normalization moves that behavior into `DefinitionLookupIndex::by_normalized_fqn` instead of retaining scan-time string matching.
  Date/Author: 2026-07-07 / Codex
- Decision: Prefer rendered analyzer signatures over `CodeUnit::signature()` when building `UsageFactsIndex`, with `CodeUnit::signature()` as fallback.
  Rationale: C# method `CodeUnit::signature()` stores only a parameter key such as `(int)`, so return-type extraction must read the rendered method skeleton stored in `signatures_of`. Scala function units already rely on rendered signatures, so this preserves Scala behavior while enabling C# facts.
  Date/Author: 2026-07-07 / Codex
- Decision: Keep C# owner-relative return-type derivation as a fallback behind `UsageFactsIndex` probes.
  Rationale: The shared facts index does not know the declaring owner when resolving a return type text, so nested owner-relative C# type names still need the existing structured owner-aware resolver. This fallback is behind keyed member/method lookup and does not reintroduce workspace declaration scans.
  Date/Author: 2026-07-07 / Codex
- Decision: Share `GoEdgeIndex` with the Go query graph instead of adding Go-specific `UsageFactsIndex` hooks or a third query-only structure.
  Rationale: `GoEdgeIndex` already contains the Go-specific keyed facts needed by both paths: direct members, embedded-field promotion links, package-directory import resolution, and constructor returns with every distinct candidate preserved. Building it from `GoProjectGraph`'s already parsed files avoids reparsing during queries and keeps Go's first-result constructor interpretation in one place. Generic Go `UsageFactsIndex` hooks would not replace the embedding maps or directory resolver, so they would add another structure without removing meaningful code.
  Date/Author: 2026-07-07 / Codex
- Decision: For Python imported class method factory-return facts, use `DefinitionLookupIndex::fqn_direct_children` for method enumeration and keep Python's existing `callable_return_type_name` return helper, instead of adding Python `UsageFactsIndex` hooks in Milestone 5.
  Rationale: The expensive part was declaration enumeration, not Python's return classification. `UsageFactsIndex` would only cover signature-derived annotations unless expanded with Python body inference, while the current helper already preserves both annotation and body-return behavior. Keyed direct-child enumeration deletes the workspace scan and keeps Python's decorator/body-sensitive logic in Python code, matching the milestone's "only the declaration enumeration goes through the index" rule.
  Date/Author: 2026-07-07 / Codex
- Decision: Do not use the shared `visible_names::resolve_visible_type` driver for C++ in Milestone 6; use C++-specific keyed probes over `DefinitionLookupIndex` plus a per-closure identifier map.
  Rationale: The shared driver has Java/C# package semantics: qualified exact FQN, imports, same package, and unique global fallback. C++ name lookup in this resolver needs an enclosing-namespace walk (`lib::Factory` then `lib` for a return type `Service`), `::` source spelling mapped onto analyzer FQNs that mix namespace packages with `$` nested-class separators and `.` member separators, and include-closure membership as an exact candidate filter. Forcing that through `FileImportContext` would hide C++ semantics in an import-shaped abstraction.
  Date/Author: 2026-07-07 / Codex
- Decision: Keep the include-closure declaration set in `VisibilityIndex`, and add `visible_by_identifier` as a per-root-file keyed map for unqualified C++ tail lookups.
  Rationale: The generic `DefinitionLookupIndex` has exact FQN, normalized FQN, package/simple type, and owner/member maps, but the old C++ unqualified lookup deliberately matched the terminal identifier among declarations visible through includes, regardless of namespace, before call-site logic proved target/non-target status. A per-closure identifier map preserves that behavior without rescanning the closure bag per lookup. Qualified references and owner/member lookups now go through `DefinitionLookupIndex`.
  Date/Author: 2026-07-07 / Codex
- Decision: Filter keyed C++ lookup candidates by exact include-closure membership, not by `same_visible_symbol`; reserve logical same-FQN matching for comparing a resolved candidate to the requested target.
  Rationale: The old lookup structure only iterated declarations physically present in the caller file's include closure. Logical matching is necessary when comparing a header declaration to a target definition, but using it as the candidate membership predicate admitted source definitions that were not included and changed overload/return-type ambiguity. Exact closure membership restored the old candidate set.
  Date/Author: 2026-07-07 / Codex

## Outcomes & Retrospective

Milestones 1 and 2 are complete in the working tree, with no commits made. `DefinitionLookupIndex` is now the raw analyzer-owned index for exact FQNs, normalized FQNs, package/simple type lookup, and owner/member lookup. `UsageFactsIndex` is the derived callable-facts index and preserves overload entries while collapsing conflicting single-return lookups to ambiguity. Scala now uses those analyzer-owned indexes while keeping its extension-method side table and AST-local `factory_returns` precedence; the guard test `overloaded_factory_receiver_emits_no_partial_edge` passed in the focused suite.

Validation on 2026-07-07: `cargo fmt` completed; `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_scala_test --test usages_scala_graph_test --test intellij_scala_goto_definition --test metals_goto_definition --test get_definition_test --test searchtools_fuzzy_symbol_lookup --test usages_rust_graph_test --test usages_ruby_test` passed (`get_definition_test` 376, `intellij_scala_goto_definition` 2, `metals_goto_definition` 5, `searchtools_fuzzy_symbol_lookup` 21, `usage_graph_scala_test` 13, `usages_ruby_test` 40, `usages_rust_graph_test` 92, `usages_scala_graph_test` 38); `BIFROST_SEMANTIC_INDEX=off cargo test definition_lookup_index` ran the three new `DefinitionLookupIndex` unit tests and passed; `BIFROST_SEMANTIC_INDEX=off cargo test usage_facts` ran the new `UsageFactsIndex` ambiguity test and passed; `cargo clippy --all-targets --all-features -- -D warnings` completed cleanly. `rg -n "symbol_index|receiver_facts" src` returns no matches.

Milestone 3 is complete in the working tree, with no commits made. The new `src/analyzer/usages/visible_names.rs` resolver implements the Java-style probe order for package/namespace languages: qualified exact FQN, import context, same package, then exact-name global fallback with uniqueness enforced by the context. C# `resolve_visible_type` now enters that driver, while `visible_type_candidates` remains a keyed candidate collector for import analysis. C# forward usage resolution now uses `DefinitionLookupIndex` for receiver type units, fields/properties, owner/member methods, nested type probes, and extension receiver hierarchy roots; `UsageFactsIndex` supplies C# callable and field return facts with the existing owner-aware signature fallback where needed. C# inverted edge building no longer owns `class_units`, `MethodDeclarationIndex`, or `MethodReturnCache`; it uses the same shared indexes as the forward path. `enclosing_declared_type` now uses `ClassRangeIndex`.

Validation on 2026-07-07 for Milestone 3: `cargo fmt` completed; `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_csharp_test --test usages_csharp_graph_test --test roslyn_goto_definition --test usage_graph_scala_test --test usages_scala_graph_test --test get_definition_test` passed (`get_definition_test` 376, `roslyn_goto_definition` 9, `usage_graph_csharp_test` 14, `usage_graph_scala_test` 13, `usages_csharp_graph_test` 38, `usages_scala_graph_test` 38); `cargo clippy --all-targets --all-features -- -D warnings` completed cleanly; `rg -n "get_all_declarations\\(\\)" src/analyzer/usages/csharp_graph` returns no matches.

Milestone 4 is complete in the working tree, with no commits made. `GoProjectGraph` now owns a `GoEdgeIndex` built from the same parsed files used by the query graph, so the query path and inverted edge path consume the same keyed direct-member, embedded-field, package-directory, and constructor-return facts. `collect_promoted_receiver_types` now iterates the scoped type units once and uses keyed promotion lookups through `go_unique_indexed_member_candidate_at_nearest_depth`; owner-constructor seeding now probes `constructor_names_by_return_type`, preserving the multi-candidate constructor-return semantics already present in `GoEdgeIndex`. The `graph_declarations` helper family and its FQN/direct-child scan helpers are deleted.

Validation on 2026-07-07 for Milestone 4: `cargo fmt` completed; `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_go_test --test usages_go_graph_test --test gopls_goto_definition --test go_dead_code_smells --test get_definition_test` passed (`get_definition_test` 376, `go_dead_code_smells` 11, `gopls_goto_definition` 5, `usage_graph_go_test` 11, `usages_go_graph_test` 39); `cargo clippy --all-targets --all-features -- -D warnings` completed cleanly; `grep -rn "graph_declarations" src/analyzer/usages/go_graph/` returns no matches.

Milestone 5 is complete in the working tree, with no commits made. Python's `resolve_receiver_type` no longer performs a workspace-wide fallback scan; after import and file-local declaration checks, the target-file-only fallback probes `DefinitionLookupIndex::types_in_package` using the current module FQN, then exact FQN and normalized FQN maps. `target_class_method_named` now uses `DefinitionLookupIndex::members_for_owner_name` for the target class and attribute name before applying Python's existing classmethod decorator check. `collect_imported_class_method_return_types` now enumerates `DefinitionLookupIndex::fqn_direct_children` for the imported class and keeps the existing `callable_return_type_name` helper so annotation and body-inferred factory returns behave as before. Python's file-local `collect_factory_return_types_from_root` was not changed.

Validation on 2026-07-07 for Milestone 5: `cargo fmt` completed; `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_python_test --test usages_python_graph_test --test intellij_python_find_usages --test intellij_python_definition --test basedpyright_goto_definition --test python_js_ts_dead_code_smells --test get_definition_test` passed (`basedpyright_goto_definition` 2, `get_definition_test` 376, `intellij_python_definition` 18, `intellij_python_find_usages` 15 passed/5 ignored, `python_js_ts_dead_code_smells` 17, `usages_python_graph_test` 68 passed/3 ignored, `usages_python_test` 4); `cargo clippy --all-targets --all-features -- -D warnings` completed cleanly; `grep -R -n "get_all_declarations()" src/analyzer/usages/python_graph/` returns no matches.

Milestone 6 is complete in the working tree, with no commits made. C++ `VisibilityIndex` still computes the include closure per root file, but it now uses that closure as a membership filter instead of the lookup structure for qualified and owner/member lookups. It holds the analyzer-owned `DefinitionLookupIndex` through a shared handle forwarded by `CppAnalyzer`, avoiding a workspace-index clone when visibility indexes are cached. Qualified C++ references are converted into possible analyzer FQN shapes and probed through `DefinitionLookupIndex::by_fqn`; owner/member method and field lookups use `DefinitionLookupIndex::members_for_owner_name`; unqualified tail-name lookup uses `visible_by_identifier`, a per-closure identifier map built once from the include closure to preserve the old terminal-name behavior without per-lookup bag scans. `precise_parent_of` now derives the parent FQN from the unit's `package_name` and owner short name and probes `definition_lookup_index().by_fqn(...)`. The duplicate comma splitter in `cpp_graph/resolver.rs` was deleted; `signature_arity` now uses `cpp_call_match.rs::cpp_split_top_level_commas`.

Validation on 2026-07-07 for Milestone 6: `cargo fmt` completed; `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_cpp_test --test usages_cpp_graph_test --test clangd_goto_definition --test cpp_dead_code_smells --test get_definition_test` passed (`clangd_goto_definition` 9, `cpp_dead_code_smells` 15, `get_definition_test` 376, `usage_graph_cpp_test` 13, `usages_cpp_graph_test` 47); `cargo clippy --all-targets --all-features -- -D warnings` completed cleanly; `rg -n "get_all_declarations\\(\\)" src/analyzer/usages/cpp_graph src/analyzer/usages/cpp_graph.rs` returns no matches; `rg -n "fn .*split_top_level_commas" src/analyzer/usages/cpp_graph src/analyzer/usages/cpp_call_match.rs src/analyzer/usages/cpp_graph.rs` reports only `src/analyzer/usages/cpp_call_match.rs:152:pub(in crate::analyzer::usages) fn cpp_split_top_level_commas(`.

## Context and Orientation

All paths are relative to the repository root, which is the git worktree at `/mnt/optane/bifrost-shared-usage-index` on branch `shared-usage-index-refactor`.

Bifrost analyzes source code with tree-sitter parsers. An "analyzer" is a per-language object implementing the `IAnalyzer` trait (`src/analyzer/i_analyzer.rs`). Most languages wrap a generic `TreeSitterAnalyzer<A: LanguageAdapter>` (`src/analyzer/tree_sitter_analyzer.rs`). A `LanguageAdapter` supplies language-specific hooks; the relevant one here is `normalize_full_name(&self, fq_name: &str) -> String` (default: identity; Java overrides it in `src/analyzer/java/adapter.rs`). A "CodeUnit" (`src/analyzer/model.rs`) is one declaration — a class, function, field, or module — carrying `fq_name()`, `identifier()`, `package_name()`, `signature()`, `source()` (its file), and kind predicates like `is_class()`/`is_function()`/`is_field()`.

"FQN" means fully qualified name, e.g. `example.Service.run`. "Normalized FQN" means the adapter-normalized form; for Scala that strips companion-object markers (`Foo$` becomes `Foo`, `Foo$.bar` becomes `Foo.bar`).

The analyzer builds an immutable `AnalyzerState` in `AnalyzerState::index_state(files, project, adapter)` (`src/analyzer/tree_sitter_analyzer.rs`, around line 905). State is rebuilt wholesale, never patched in place, so anything stored inside it is invalidated correctly for free. State already contains `definition_lookup_index: DefinitionLookupIndex`, exposed through `IAnalyzer::definition_lookup_index()`.

`DefinitionLookupIndex` (`src/analyzer/definition_lookup_index.rs`) is the existing workspace-wide keyed index over CodeUnits: `by_fqn`, `direct_children_by_fqn`, `by_file_identifier`, `packages`, `files_by_package`, `normalized_fqns` (a `HashSet<String>` of existence only, built with the hardcoded `$` normalization noted in Surprises).

The usage subsystem lives in `src/analyzer/usages/`. Each language has a `<lang>_graph.rs` facade plus a `<lang>_graph/` directory with (typically) `extractor.rs` (the forward per-target scan for `scan_usages`), `resolver.rs` (target classification and name resolution), `inverted.rs` (the whole-workspace edge builder for `usage_graph`), and `hits.rs`. `src/analyzer/usages/inverted_edges.rs` is the already-shared edge-collection engine; do not touch it. `src/analyzer/usages/symbol_index.rs` is the module this plan dissolves: it defines `TypeDecl`, `MemberDecl`, `WorkspaceSymbolIndexBuilder`, and `WorkspaceSymbolIndex` with keyed maps for types (by FQN, normalized FQN, `(package, simple)`) and members (by normalized FQN, by `(owner, name)`), plus `callable_return_types: HashMap<String, Option<String>>` where an ambiguous return collapses to `None`. Its only consumer is `src/analyzer/usages/scala_graph/inverted.rs` (`ProjectTypes`).

`src/analyzer/usages/receiver_facts.rs` is dead code: its only reference in the crate is the `pub(crate) mod receiver_facts;` line in `src/analyzer/usages/mod.rs`. Verified by grep on 2026-07-07.

The linear scans this plan eliminates, by language (function names are the stable anchors; line numbers drift):

C# forward path, all scanning `csharp.get_all_declarations()` (which clones a Vec of every declaration in the workspace) per reference site: `receiver_type_units` (two scans), `member_declared_type_fq_name`, `method_return_type_fq_name_for_arity`, `resolve_member_type_fq_name` (scan branch), `resolve_type_fq_name` (scan fallback) in `csharp_graph/resolver.rs`; `extension_receiver_type_matches` in `csharp_graph/extractor.rs`; plus `enclosing_declared_type` in `resolver.rs` which scans `get_declarations(file)` with manual range containment instead of using the shared `ClassRangeIndex` from `inverted_edges.rs`.

Go query path: `graph_declarations` in `go_graph/resolver.rs` collects every declaration of every candidate file into a Vec, and is called by `collect_promoted_receiver_types`, `graph_direct_member_fqns`, `graph_direct_children`, `graph_embedded_field_type_fqns`, and `graph_fqn_exists` — several of them repeatedly within one query. The keyed equivalent already exists in the same file as `GoEdgeIndex` (`package_names`, `constructor_return_types`, `direct_member_fqns`, `embedded_field_type_fqns`), used only by the edge path.

Python: `resolve_receiver_type` in `python_graph/resolver.rs` falls back to a linear `get_all_declarations().find(...)`; `target_class_method_named` in `python_graph/extractor.rs` runs a full workspace scan per candidate attribute node; `collect_imported_class_method_return_types` in `python_graph/extractor.rs` scans all declarations per imported class.

C++: every lookup on `VisibilityIndex` (`cpp_graph/resolver.rs`) — `resolve_type`, `resolve_named`, `named_candidates`, `contains_named_symbol`, `resolve_known_non_target`, `resolve_call_return_binding` — linearly filters the per-file `visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>` bag; and `precise_parent_of` does `get_all_declarations().find(...)` per recorded hit (called from `hits.rs::enclosing_context`).

Java and PHP have no resolution-path linear scans. Java resolves through `JavaAnalyzer::resolve_type_name_in_file` (`src/analyzer/java/imports.rs::resolve_type_name`), which composes keyed lookups: exact FQN via `definitions()`, then the file's cached imports map, then a same-package probe `definitions("{package}.{name}")`, then a global fallback. PHP resolves through analyzer-level `resolve_php_type`/`resolve_php_function`/`resolve_php_constant`. What Java and PHP do hand-roll is lazy return-type memoization: Java's `MethodReturnCache`/`FileReturnCache` in `java_graph/inverted.rs` re-parse method bodies; PHP's `CallableReturnCache`/`FileReturnCache` in `php_graph/inverted.rs` plus `declared_field_type_fq_name`/`declared_callable_return_type_fq_name` in `php_graph/syntax.rs` re-parse the declaring file per lookup.

Scala's current shape after commit a18d726, which Milestone 2 rebases: `ProjectTypes` in `scala_graph/inverted.rs` builds a `WorkspaceSymbolIndexBuilder` from `scala.all_declarations()`, first types, then members (using a throwaway types-only index to resolve each member's return-type text via `return_type_fqn`, the keyed three-way probe: `(package, simple)`, exact FQN, normalized FQN). Scala keeps two things outside the shared index, and both must survive the rebase unchanged: the `extension_methods_by_name` side table (Scala-3 extension methods), and the per-file AST-local `factory_returns` map built by `collect_factory_return_types`, which takes precedence over the workspace index whenever it has an entry — even an ambiguous one — because analyzer declarations can collapse same-FQN overloads that the AST-local map still distinguishes (see the prior plan's Decision Log; the guarding test is `overloaded_factory_receiver_emits_no_partial_edge`).

Test environment for every milestone: run suites as `BIFROST_SEMANTIC_INDEX=off cargo test --test <suite>` from the repository root so no semantic-index threads or model downloads start. New tests that need small ad hoc projects must use `InlineTestProject` from `tests/common/inline_project.rs` (see `tests/usage_graph_scala_test.rs` for the style). The lint gate is `cargo fmt` then `cargo clippy --all-targets --all-features -- -D warnings`; the repository denies all warnings.

## Plan of Work

### Milestone 1 — extend DefinitionLookupIndex; delete dead module

Goal: `DefinitionLookupIndex` becomes the single raw keyed index, with adapter-driven normalization instead of the hardcoded `$` transform, and gains the two key shapes `symbol_index.rs` has that it lacks.

In `src/analyzer/definition_lookup_index.rs`: change `insert` to `insert(&mut self, unit: &CodeUnit, normalize: &dyn Fn(&str) -> String)` (or an equivalent generic parameter) and use it for the normalized entries; change `from_declarations` accordingly. Replace the `normalized_fqns: HashSet<String>` existence set with `by_normalized_fqn: HashMap<String, Vec<CodeUnit>>` and keep `normalized_fqn_exists` as a thin wrapper so existing callers compile. Add `types_by_package_simple: HashMap<(String, String), Vec<CodeUnit>>` populated for `is_class()` units keyed by `(package_name, identifier)` with accessor `types_in_package(&self, package: &str, simple: &str) -> &[CodeUnit]`. Add `direct_children_by_normalized_fqn: HashMap<String, Vec<CodeUnit>>` (parent key normalized) and an accessor `members_for_owner_name(&self, owner_fqn: &str, normalized_owner_fqn: &str, name: &str) -> Vec<&CodeUnit>` that probes the exact-owner children first, then the normalized-owner children, filtering by `identifier() == name` — mirroring the exact-then-normalized fallback contract of `WorkspaceSymbolIndex::members_for_owner_name`.

In `src/analyzer/tree_sitter_analyzer.rs::index_state`, pass `|s| adapter.normalize_full_name(s)` to the insert calls. Audit all other `DefinitionLookupIndex::insert`/`from_declarations` callers (grep; there is at least the unit test in the module itself) and thread a normalizer through — identity where no adapter exists.

One subtlety to verify rather than assume: Scala's `(package, simple)` key currently uses `scala_display_name(unit)` (the last `.`-segment of `short_name()`), not `identifier()`. Check whether they differ for the units Scala indexes (companion objects, nested types). If they differ, add a `LanguageAdapter` hook `fn simple_type_name(&self, unit: &CodeUnit) -> String { unit.identifier().to_string() }` and override it for Scala; record what you found in Surprises & Discoveries.

Also in this milestone: delete `src/analyzer/usages/receiver_facts.rs` and its `mod` line in `src/analyzer/usages/mod.rs` (re-verify zero other references first).

Acceptance: full existing suites pass unchanged — at minimum `get_definition_test`, `searchtools_fuzzy_symbol_lookup`, `usages_rust_graph_test`, `usages_ruby_test`, `usage_graph_scala_test`, `usages_scala_graph_test` (Rust and Ruby consume `fqn_direct_children`/`file_identifier`; get_definition consumes the index broadly). Add unit tests in `definition_lookup_index.rs` for the new keys, including a normalization-sensitive case (a `Foo$`-style FQN resolvable through the normalized map when the normalizer strips `$`).

### Milestone 2 — derived UsageFactsIndex; rebase Scala; delete symbol_index.rs

Goal: callable facts get one home, built lazily from analyzer state; Scala consumes the merged layers; `symbol_index.rs` is gone.

Create `src/analyzer/usage_facts.rs` defining:

    pub(crate) struct CallableFacts {
        pub(crate) arity: Option<usize>,
        pub(crate) return_type_fqn: Option<String>,
        pub(crate) is_function: bool,
    }

    pub(crate) struct UsageFactsIndex {
        by_fqn: HashMap<String, Vec<CallableFactsEntry>>, // every overload declaration preserved
        unambiguous_return_by_fqn: HashMap<String, Option<String>>, // collapse rule below
    }

with accessors `callable_return_type(&self, fqn: &str) -> Option<&str>` (returns `None` when absent or ambiguous — the same collapse rule as `symbol_index.rs::insert_callable_return_type`: two declarations sharing an FQN with different return types yield `None`), `callable_return_candidates(&self, fqn: &str) -> impl Iterator<Item = &str>` (all distinct candidates, for Go's multi-candidate needs in Milestone 4), and `facts(&self, fqn: &str) -> &[CallableFactsEntry]`. Exact field/entry shapes may be adjusted for ergonomics; the accessors and collapse semantics are the contract. Preserve the prior plan's invariant that overload declarations sharing a displayed FQN are all retained (the Scala override-target builder iterates every member declaration).

Build: a free function `UsageFactsIndex::build(analyzer: &dyn IAnalyzer, extract: &dyn SignatureFactsExtractor) -> UsageFactsIndex` where `SignatureFactsExtractor` is a small trait supplying `arity_of(signature: &str) -> Option<usize>` and `return_type_text(signature: &str) -> Option<&str>`. Before writing string helpers, inspect `SignatureMetadata` in `AnalyzerState` (`signature_metadata` map in `tree_sitter_analyzer.rs`): if it already carries structured parameter/return information, source the facts from it instead of re-interpreting signature strings, and record the finding in Surprises & Discoveries. Where signature text must be interpreted, reuse the existing per-language helpers (Scala's `signature_return_type` and `member_signature_arity` in `scala_graph/inverted.rs`) rather than writing new ad hoc parsing — the repo's design rules forbid new string mini-parsers where structure exists. Return-type FQN resolution is the two-pass step: after collecting all facts with raw return-type text, resolve each text against the (already-complete) `DefinitionLookupIndex` with the keyed three-way probe Scala uses today in `return_type_fqn` — `(package, simple)`, exact FQN, then normalized FQN.

Caching: store `OnceLock<UsageFactsIndex>` (or `OnceCell`) inside `AnalyzerState` so it shares the wholesale-rebuild invalidation, exposed as `fn usage_facts_index(&self) -> &UsageFactsIndex` on `IAnalyzer` with a default empty implementation like `definition_lookup_index()`. If threading the `SignatureFactsExtractor` through the trait proves awkward, an acceptable fallback is building it eagerly in `index_state`; record whichever you choose in the Decision Log with the reasoning.

Rebase Scala: rewrite `ProjectTypes` in `scala_graph/inverted.rs` to consume `analyzer.definition_lookup_index()` (through whatever forwarding `ScalaAnalyzer` needs — check that `ScalaAnalyzer` delegates `definition_lookup_index()` to its inner `TreeSitterAnalyzer`; Java's wrapper in `src/analyzer/java/mod.rs` shows the delegation pattern) plus `UsageFactsIndex`, keeping its public method surface (`method_targets_for_owner_member`, `inherited_method_targets_for_owner_member`, `member_return_type`, `member_return_type_for_owner_member`, `package_types`, `type_by_normalized_fqn`, `member_by_normalized_fqn`) so `NameResolver` and the scan code do not change behavior. The companion-object preference (prefer the non-`$` FQN when both `Foo` and `Foo$` share a `(package, simple)` key) moves from the deleted `insert_package_type` into Scala's call sites, since the merged map now stores all candidates. `extension_methods_by_name` and the AST-local `factory_returns` precedence stay exactly as they are. Then delete `src/analyzer/usages/symbol_index.rs` and its `mod` line; port its three unit tests to the new homes (the type-lookup test against `DefinitionLookupIndex`, the member/return tests against `UsageFactsIndex`).

Acceptance: `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_scala_test --test usages_scala_graph_test --test intellij_scala_goto_definition --test metals_goto_definition --test get_definition_test` passes; `overloaded_factory_receiver_emits_no_partial_edge` specifically still passes; grep confirms `symbol_index` appears nowhere in `src/`; lint gate clean.

### Milestone 3 — shared visible-name resolver; migrate C#

Goal: one implementation of the probe order "exact FQN → file imports → same package → global unique", and C# resolved through keyed lookups on both paths.

Create `src/analyzer/usages/visible_names.rs` with a per-file import context trait and a resolver function, approximately:

    pub(crate) trait FileImportContext {
        fn imported_type(&self, simple: &str) -> Option<String>; // simple name -> imported FQN
        fn package_of_file(&self) -> &str;
    }

    pub(crate) fn resolve_visible_type<'a>(
        index: &'a DefinitionLookupIndex,
        ctx: &dyn FileImportContext,
        raw_name: &str,
        normalize: &dyn Fn(&str) -> String,
        visible: &dyn Fn(&CodeUnit) -> bool, // per-language visibility filter; C++ passes include-closure membership, others pass |_| true
    ) -> Option<&'a CodeUnit>;

The probe order and the "global fallback only when unique" rule are the contract (Java's `resolve_type_name` in `src/analyzer/java/imports.rs` is the reference algorithm — read it before writing this). Exact signatures may be adapted; record deviations in the Decision Log.

Migrate C#: implement `FileImportContext` for C# from the analyzer's existing using/alias data (`csharp.resolve_visible_type` and `using_aliases_of` show where that lives). Replace the eight linear scans listed in Context and Orientation with keyed lookups: type-by-FQN scans become `definition_lookup_index().fqn(...)`, owner+member scans become `members_for_owner_name(...)`, return-type-for-arity becomes `usage_facts_index()` accessors, and `enclosing_declared_type` switches to the shared `ClassRangeIndex`. In `csharp_graph/inverted.rs`, delete `class_units`, `csharp_method_declaration_index`/`MethodDeclarationIndex`, and `MethodReturnCache`, replacing them with the shared indexes so the forward and inverted paths consume the same instances. C#-specific semantics stay: extension-method receiver matching (keep its own small keyed side table if needed, mirroring Scala's `extension_methods_by_name` pattern), `nameof()` exclusion, object-initializer labels.

Acceptance: `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_csharp_test --test usages_csharp_graph_test --test roslyn_goto_definition` passes; grep shows no `get_all_declarations()` caller remains under `csharp_graph/`; add one regression test in `tests/usage_graph_csharp_test.rs` (InlineTestProject) that resolves a method usage through receiver return-type chaining with many unrelated declarations present, proving the keyed path handles what the scans did.

### Milestone 4 — Go query path

Goal: the query path consumes the same keyed facts as the edge path; the `graph_declarations` family is gone.

In `go_graph/resolver.rs`, replace the `graph_declarations`-based helpers (`graph_direct_member_fqns`, `graph_direct_children`, `graph_embedded_field_type_fqns`, `graph_fqn_exists`, and the collection inside `collect_promoted_receiver_types`) with lookups against `definition_lookup_index()` and `usage_facts_index()` — Go's `constructor_return_types` keeps multi-candidate semantics via `callable_return_candidates`. The cleanest shape is likely to make the query path build or share a `GoEdgeIndex` (it is already tree-free and keyed) rather than introduce a third structure; prefer whichever removes more code, and record the choice. Go-specific logic stays layered on top: struct-embedding promotion (`go_unique_indexed_member_candidate_at_nearest_depth`), structural interface satisfaction, package-directory resolution (`dir_index`).

Acceptance: `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_go_test --test usages_go_graph_test --test gopls_goto_definition` passes; grep confirms `graph_declarations` no longer exists.

### Milestone 5 — Python

Replace the three scan sites: `resolve_receiver_type`'s all-declarations fallback and `target_class_method_named` become keyed probes (`types_in_package`/`fqn`/`members_for_owner_name`); `collect_imported_class_method_return_types` enumerates methods through keyed direct children, then keeps Python's existing return classifier because it is annotation- and body-aware. Python's decorator-sensitive classification, e.g. detecting `classmethod`, stays in Python code — only the declaration enumeration goes through the index. Python's file-local `collect_factory_return_types_from_root` stays as-is: like Scala's `factory_returns`, it is AST-local inference, not workspace lookup.

Acceptance: `BIFROST_SEMANTIC_INDEX=off cargo test --test usages_python_test --test usages_python_graph_test --test intellij_python_find_usages --test basedpyright_goto_definition` passes; grep confirms no `get_all_declarations()` caller remains under `python_graph/`.

### Milestone 6 — C++

Rework `VisibilityIndex` in `cpp_graph/resolver.rs`: keep computing the include-closure per file, but store it as a membership set (files or units) used as the `visible` filter for `resolve_visible_type`, while the actual name lookups go through `definition_lookup_index()` keyed maps instead of filtering the `visible_by_file` bag. Kill `precise_parent_of`'s `get_all_declarations().find(...)` by resolving the parent through `fqn(...)` keyed lookup. The alias index (`using`/`typedef`), overload/argument matching (`cpp_call_match.rs`), and out-of-line member-definition handling stay C++-specific. Also in this milestone: `split_top_level_commas` exists verbatim in both `cpp_graph/resolver.rs` and `cpp_call_match.rs` (`cpp_split_top_level_commas`) — keep one, delete the other.

Acceptance: `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_cpp_test --test usages_cpp_graph_test --test clangd_goto_definition` passes; grep confirms no `get_all_declarations()` caller remains under `cpp_graph/`.

### Milestone 7 — Java and PHP return-fact swap

Replace Java's `MethodReturnCache`/`FileReturnCache` in `java_graph/inverted.rs` and PHP's `CallableReturnCache`/`FileReturnCache` in `php_graph/inverted.rs` (plus the per-lookup re-parsing in `php_graph/syntax.rs::declared_callable_return_type_fq_name`/`declared_field_type_fq_name`) with `usage_facts_index()` lookups. Caution for Java: the current cache infers return types by walking method bodies when the declared signature lacks resolution — verify what `SignatureMetadata`/signatures give for Java before assuming the index can answer; if body inference is genuinely needed for cases signatures cannot answer, keep that path as a fallback behind the index probe and record it. Do not touch `resolve_type_name_in_file`/`resolve_php_type` — they are already the pattern this plan generalizes.

Acceptance: `BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_java_test --test usages_java_graph_test --test jdt_goto_definition --test usage_graph_php_test --test usages_php_graph_test --test phpactor_goto_definition` passes. Note for any new PHP cross-file test fixtures: they need a `composer.json` with a PSR-4 autoload entry (for example `{"autoload":{"psr-4":{"App\\":"src/"}}}`) or candidate-file selection silently finds nothing.

## Concrete Steps

Work from `/mnt/optane/bifrost-shared-usage-index`. After each milestone run, in order:

    cargo fmt
    BIFROST_SEMANTIC_INDEX=off cargo test --test <the milestone's suites listed above>
    cargo clippy --all-targets --all-features -- -D warnings

At the end of the full plan (or any multi-milestone session), additionally run the cross-cutting suites:

    BIFROST_SEMANTIC_INDEX=off cargo test --test usage_graph_test --test usage_graph_identity_test --test cross_language_self_usages --test usages_finder_fallback_test

Clippy must be clean; the repo denies warnings. `#[allow(clippy::too_many_arguments)]` is acceptable where a function legitimately needs many parameters.

## Validation and Acceptance

The refactor is accepted when: every suite named in the milestone acceptance sections passes; `src/analyzer/usages/symbol_index.rs` and `src/analyzer/usages/receiver_facts.rs` are deleted; `grep -rn "get_all_declarations" src/analyzer/usages/` returns no callers on resolution paths in `csharp_graph/`, `python_graph/`, `cpp_graph/` (Rust's `self_like_constructor_returns` in `rust_graph/extractor.rs` is explicitly allowed to remain — out of scope); `grep -rn "graph_declarations" src/analyzer/usages/go_graph/` is empty; and the new unit tests in `definition_lookup_index.rs` and `usage_facts.rs` demonstrate keyed lookup including the normalization and ambiguity-collapse rules.

## Idempotence and Recovery

All changes are ordinary source edits in a dedicated worktree on a dedicated branch; re-running any milestone's steps is safe. Each milestone leaves the tree compiling and green, so work can stop and resume at any milestone boundary using only this document. Do not use `git add -A`; stage only files changed for this plan. Implementation runs delegated to a coding agent must NOT create commits — leave changes in the working tree for review; the reviewer stages from `git status` and commits.

## Artifacts and Notes

The keyed three-way probe that replaces linear type resolution, as it exists in Scala today (`scala_graph/inverted.rs::return_type_fqn`) and generalizes through the merged index:

    type_index
        .type_by_package_simple(package_name, base)
        .or_else(|| type_index.type_by_fqn(base))
        .or_else(|| type_index.type_by_normalized_fqn(&normalized(base)))

The ambiguity-collapse rule for callable return types (from the deleted `symbol_index.rs`, preserved in `UsageFactsIndex`): the first declaration records its return type; any later declaration with the same FQN but a different return type overwrites the entry with "ambiguous" (`None`), and lookups treat absent and ambiguous identically.

## Interfaces and Dependencies

In `src/analyzer/definition_lookup_index.rs`, at the end of Milestone 1 these accessors must exist on `DefinitionLookupIndex` (in addition to everything already there):

    pub(crate) fn types_in_package(&self, package: &str, simple: &str) -> &[CodeUnit];
    pub(crate) fn by_normalized_fqn(&self, normalized: &str) -> &[CodeUnit];
    pub(crate) fn members_for_owner_name(&self, owner_fqn: &str, normalized_owner_fqn: &str, name: &str) -> Vec<&CodeUnit>;

In `src/analyzer/usage_facts.rs`, at the end of Milestone 2:

    pub(crate) fn callable_return_type(&self, fqn: &str) -> Option<&str>;
    pub(crate) fn callable_return_candidates(&self, fqn: &str) -> impl Iterator<Item = &str>;

exposed via `IAnalyzer::usage_facts_index(&self) -> &UsageFactsIndex` with an empty default, mirroring `definition_lookup_index()`.

In `src/analyzer/usages/visible_names.rs`, at the end of Milestone 3: the `FileImportContext` trait and `resolve_visible_type` function as sketched in Milestone 3, with Java's `resolve_type_name` probe order as the behavioral contract.

Use `crate::hash::HashMap`/`HashSet` throughout (the repo's standard hasher), never `BTreeMap` unless ordering is semantically required. Prefer iterators and borrowed returns over cloning in the accessors; these run in hot loops.

Revision note 2026-07-07 / Codex: Executed only Milestones 1 and 2, updated Progress, Surprises & Discoveries, Decision Log, and Outcomes with implementation findings and validation evidence, and left Milestones 3 through 7 untouched for future work.

Revision note 2026-07-07 / Codex: Executed only Milestone 3, updated Progress, Surprises & Discoveries, Decision Log, and Outcomes with the C# migration details and validation evidence, and left Milestones 4 through 7 untouched for future work.

Revision note 2026-07-07 / Codex: Executed only Milestone 4, updated Progress, Surprises & Discoveries, Decision Log, and Outcomes with the Go query-path migration details and validation evidence, and left Milestones 5 through 7 untouched for future work.

Revision note 2026-07-07 / Codex: Executed only Milestone 5, updated Progress, Surprises & Discoveries, Decision Log, Outcomes, and the Milestone 5 work note to record the Python keyed lookup migration and the choice to preserve body-aware return inference, and left Milestones 6 and 7 untouched for future work.

Revision note 2026-07-07 / Codex: Executed only Milestone 6, updated Progress, Surprises & Discoveries, Decision Log, and Outcomes with the C++ keyed lookup migration, exact include-closure membership decision, C++ package/FQN findings, and splitter dedupe, and left Milestone 7 untouched for future work.
