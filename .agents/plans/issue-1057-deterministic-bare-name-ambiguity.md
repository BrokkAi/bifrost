# Deterministic bare-name ambiguity semantics (issue #1057)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with `.agents/PLANS.md` at the repository root.

## Purpose / Big Picture

Bifrost's symbol tools (`get_symbol_sources`, `get_summaries`, `get_definitions_by_reference`) let an agent address a declaration by name. Today, when a bare terminal name matches more than one declaration, the tools sometimes report an ambiguity with candidate selectors and sometimes silently resolve to one declaration — and which one you get depends on invisible workspace state. Concretely, resolving the bare name `getCachedVersion` silently returns a free function in `checker/cached-version.ts`, hiding the method `AutoUpdateCheckerDeps.getCachedVersion`, while the bare name `apply` (which has no top-level namesake) correctly reports ambiguity with two member candidates. The caller cannot predict which behavior it gets, and two spellings of the same symbol can resolve to different declarations with no ambiguity signal.

After this change, bare-name resolution is deterministic and honest across every language and every symbol tool: when more than one distinct declaration matches a name, the response reports ambiguity and lists requestable `path#selector` candidates with a recovery note; when exactly one distinct declaration matches, it resolves as before. This holds for three structural situations the MCP property fuzzer found across all eleven tier-1 languages: (1) a bare name whose only visible match is a top-level namesake while same-named members exist (the dominant case), (2) identical fully-qualified names that live in two files — cross-build twins (Scala `scala-2`/`scala-3` parallel trees), Go build-tag twins, C# partial-class parts — where even the most specific spelling silently picks one, and (3) the `get_definitions_by_reference` surface, which bypasses the shared resolver and reports ambiguity in a different, inconsistent shape.

You can see it working by resolving a name that has both a top-level and a member declaration and observing an `ambiguous` response with two `path#` selectors instead of a silent single hit; and by resolving an identical FQN that exists in two source trees and observing two file-anchored candidates instead of one silently chosen tree.

The fix is inherently general, not per-language: the resolver (`src/analyzer/symbol_lookup.rs`) and the grouping (`distinct_definitions` in `src/searchtools.rs`) are already single, language-agnostic code paths shared by every language, driven by per-language interpretation hooks. We change the shared paths once.

## Progress

- [x] (2026-07-22) M1 — Member-aware bare-name resolution (the dominant case). Added `IAnalyzer::lookup_candidates_by_identifier` (forwarded from every wrapper + merged in `MultiAnalyzer`); added a bare-query pre-stage in `resolve_codeunit_fuzzy_with` (`bare_query_leaf`/`bare_name_resolution`/`is_bare_symbol_query`) that unions exact top-level hits with identifier-indexed members and routes through `resolution_from_matches`; and — see Surprises correction below — made `exact_codeunit_resolution` member-aware for bare names so the `get_symbol_sources` surface is fixed too. Two new tests in `tests/searchtools_definition_selectors.rs` (single-language + mixed-language) pass; `searchtools_definition_selectors` 50 pass, blast-radius suites green, fmt + clippy clean.
- [x] (2026-07-22) M2 — Location-aware distinctness for identical-FQN collisions. Made `distinct_definitions` (now taking `&dyn IAnalyzer`) file-anchor an FQN's units when a genuine cross-file duplicate exists — some `IAnalyzer::signatures(unit)` label declared in more than one file (scala-2/scala-3 twins, Go build-tag twins, C# partial-class parts, which share an empty signature key). Overloads (differing signatures, each in one file) stay merged, so the `scan_usages` overload-union contract is preserved on every surface. Used `signatures(unit)`, not `CodeUnit::signature()` (which is `None` for the top-level functions/classes that reach the grouping and cannot tell an overload from a twin). New twin / same-file-overload / unique-name tests pass; the original cross-file overload `scan_usages` test is unchanged and still passes; `searchtools_definition_selectors` 53, `searchtools_service` 167, `get_definition_test` 610, `searchtools_summary_ranges` 28 green; fmt + clippy clean.
- [ ] M3 — Consistent ambiguity on the `get_definitions_by_reference` surface. Route `resolve_definition_context_symbol` through the same member-aware resolution and `distinct_definitions` grouping so bare and fully-qualified spellings behave identically and ambiguity is reported in the same conditions as the other tools.
- [ ] Final validation: full `--features nlp,python` suites for the affected areas pass; `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings` clean; targeted MCP property fuzzer signatures for #1057 no longer reproduce.

## Surprises & Discoveries

- Observation: The "member-terminal short-name index" that issue #1057's escalation comment predicted would require a schema change **already exists**.
  Evidence: `migrations/cache/0001-current-baseline.sql` defines `CREATE INDEX idx_code_units_lang_identifier_declarations ON code_units(lang, identifier) WHERE in_declarations = 1;`. The `code_units.identifier` column is populated from `CodeUnit::identifier()` (the terminal name; `src/analyzer/store/mod.rs` insert near line 2968/2988), and it is already queried by `Store::declaration_candidate_rows_by_identifier_for_langs` (`src/analyzer/store/mod.rs:1559`) and the inherent helper `TreeSitterAnalyzer::lookup_declarations_by_identifier` (`src/analyzer/tree_sitter_analyzer.rs:4331`). No migration is needed; the fix only has to route bare-name resolution through this existing, indexed lookup.

- Observation: The searchtools layer already re-derives ambiguity from a distinctness grouping; the resolver simply never handed it the full candidate set.
  Evidence: `resolve_selectable_definitions` (`src/searchtools.rs:2533`) collapses `CodeUnitResolution::Resolved` and `Ambiguous` into one `code_units` vector (lines 2571-2573), then calls `distinct_definitions` (line 2613) and decides ambiguity by the number of resulting groups. So `get_symbol_sources` and `get_summaries` will report ambiguity automatically once the resolver returns members and twins; the work concentrates in the resolver and in `distinct_definitions`.

- Observation (M1 correction to the Context section's assumption): `get_symbol_sources` does NOT route bare names through `resolve_codeunit_fuzzy`. Its primary resolution (`src/searchtools.rs` ~line 3147) calls `resolve_selectable_definitions(analyzer, &symbol, exact_codeunit_resolution)`, and `exact_codeunit_resolution` returns the exact top-level FQN hit immediately, only falling back to fuzzy on `NotFound`. So a bare name WITH a top-level namesake never reached the fuzzy member-aware resolver on the sources surface — a second silent-pick site the plan's Surprise #2 overlooked. `get_summaries` does use `resolve_codeunit_fuzzy` directly and is fixed by the resolver change alone.
  Evidence: reverting the resolver change but keeping the sources call unchanged left `get_symbol_sources("getCachedVersion")` returning a single silent source with `ambiguous: []` — the exact #1057 shape. Fix: `exact_codeunit_resolution` now defers to `resolve_codeunit_fuzzy` when `is_bare_symbol_query` is true, keeping exact-first ordering for qualified/multi-segment names (so Go import-path `/` and `::` names are never misrouted). The three `exact_then_fuzzy_codeunit_resolution` fallback sites in `get_symbol_sources` are only reached after this primary path returns `NotFound` (and one is Go-gated), so they are not additional silent-pick sites.

## Decision Log

- Decision: When a bare name matches more than one distinct declaration, report ambiguity with `path#selector` candidates and a recovery note; do not silently pick and do not invent a ranked winner.
  Rationale: Confirmed with the operator (2026-07-22). It matches the behavior bare `apply` already produces, matches the anchored `path#terminal` behavior shipped for #1056, is discoverable and self-correcting for agents, and is the only option that never hides a real declaration. Single-match names still resolve unchanged, so the blast radius is confined to genuinely-multiple-declaration names.
  Date/Author: 2026-07-22 / Claude (approved by Jonathan)

- Decision: Cover all three facets in one plan (bare-name member visibility, identical-FQN cross-file collisions, and the `get_definitions_by_reference` response consistency), as three independently-verifiable milestones.
  Rationale: Confirmed with the operator (2026-07-22). All three share the single silent-preference root the fuzzer campaign identified across 11/11 languages, and the fixes touch the same two shared code paths; splitting them into separate issues would fragment one root cause.
  Date/Author: 2026-07-22 / Claude (approved by Jonathan)

- Decision: Reuse the existing `code_units.identifier` index rather than adding a new schema or an in-memory member index.
  Rationale: The partial index `idx_code_units_lang_identifier_declarations` already answers "declarations whose terminal name is X" in O(log n), including members. Adding anything new would duplicate it and require a cache migration for no benefit.
  Date/Author: 2026-07-22 / Claude

- Decision (M1): Fix the second bare-name silent-pick site by making `exact_codeunit_resolution` member-aware for bare queries only, rather than by leaving it and relying solely on the resolver change.
  Rationale: `get_symbol_sources` resolves via `exact_codeunit_resolution` (exact-first), so the resolver change alone did not fix its silent pick. Routing only bare queries through `resolve_codeunit_fuzzy` there — behind the shared `is_bare_symbol_query` predicate — is the same member-aware semantics applied at the one call site that needed it, and preserves exact-first behavior (Go import paths, `::` names) for every qualified query. It is confined to the sources closure and does not touch `distinct_definitions` (M2) or `resolve_definition_context_symbol` (M3).
  Date/Author: 2026-07-22 / Claude (implemented by the M1 agent; reviewed and accepted)

- Decision (M1 test): the mixed-language ambiguity test pairs JavaScript + TypeScript (both module-scoped, two distinct MultiAnalyzer delegates) rather than a module-scoped + non-module-scoped pair.
  Rationale: exercising the MultiAnalyzer merge is the goal; a non-module-scoped partner would render one candidate as a plain FQN rather than `path#` until M2 file-anchors non-module-scoped languages, muddying the assertion. JS+TS keeps both candidates file-anchored while still crossing two delegates.
  Date/Author: 2026-07-22 / Claude

- Decision: Make identical-FQN-in-different-files distinct at the `distinct_definitions` grouping layer for every language, not only module-scoped ones.
  Rationale: `distinct_definitions` already file-anchors an FQN that appears in more than one *domain*, but for non-module-scoped languages (Scala, Java, C#, Go, C++) the domain discriminator drops the file path, so twins in two files collapse to one group and get silently picked. Extending the discriminator to include the file path for all languages makes twins, build-tag twins, and partial-class parts uniformly become distinct `path#fqn` candidates, while genuine same-file overloads stay grouped.
  Date/Author: 2026-07-22 / Claude

- Decision (M2, implemented — signature-aware distinctness): `distinct_definitions` file-anchors an FQN's units only when a *genuine cross-file duplicate* exists, i.e. when some `CodeUnit::signature()` value within that FQN is declared in more than one distinct file. This distinguishes the two same-FQN-in-two-files shapes that must be treated oppositely:
  - Twins / build-tag twins / partial-class parts share the **same** signature (or, for classes/partial parts, the shared absent/empty `None` signature) across files → collision-split → distinct `path#fqn` candidates → ambiguous. This is what #1057 wants.
  - Overloads share an FQN but have **different** signatures, each in a single file (the canonical "one symbol, multiple declarations" case the codebase models under one FQN) → not split → stay one group. Every surface (get_symbol_sources / get_summaries / scan_usages) keeps merging their call sites under one selector.
  Same-file same-FQN and unique-FQN cases stay one group; module-scoped (JS/TS) rendering is unchanged (the pre-existing cross-domain rule still file-anchors those).
  An earlier iteration keyed the discriminator on `(language, file)` alone, which over-split overloads-in-different-files and forced an incorrect rewrite of `scan_usages_by_reference_includes_all_scala_overloads`; that test is restored to its original silent-merge-of-overloads assertions (status "found", both call sites, no `other.compute` leak) and passes unchanged, confirming overloads remain merged.
  Signature accessor correction: the signature key is `IAnalyzer::signatures(unit) -> Vec<String>`, NOT `CodeUnit::signature() -> Option<&str>`. Empirically (verified with temporary debug prints) `CodeUnit::signature()` is `None` for the top-level Scala functions AND the Scala classes that reach `distinct_definitions` — their real overload labels live in the separate `unit_signatures` map exposed via `IAnalyzer::signatures`. Keying on `CodeUnit::signature()` therefore collapsed overloads and twins to the same `None` key and could not tell them apart (the overload test stayed ambiguous). `IAnalyzer::signatures(unit)` returns distinct parameter-bearing labels for overloads (`def compute(value: Int): Int` vs `def compute(left: Int, right: Int): Int`) and an identical label for twins (`class Widget {` in both scala-2/scala-3 files), which is exactly the needed discriminator. This required threading `&dyn IAnalyzer` into `distinct_definitions` and `code_unit_match_names` and their call sites (all of which already had an analyzer in scope). Signature key type: `Vec<String>` (empty list = shared key → partial-class parts / signature-less twins still split).
  Known limitation (documented, acceptable): if a genuine twin's *rendered* signature happens to differ across build variants (e.g. a return type spelled differently in scala-2 vs scala-3), the pair would merge rather than split — still strictly better than the status-quo silent single pick, and never worse than today.
  Date/Author: 2026-07-22 / Claude

- Decision (M2, C# partial classes): Partial-class parts share the same class FQN with an absent (`None`) signature, so they collide under the `None` signature key and correctly split into two `path#` candidates (the intended, strictly-better-than-silent-pick behavior). No dedicated C# partial-class test was added in this milestone; a same-FQN same-signature member pair in two files (the twin test) exercises the identical mechanism. Partial-class part *merging* into one multi-range symbol remains out of scope.
  Date/Author: 2026-07-22 / Claude

## Outcomes & Retrospective

Nothing yet recorded. Fill in at each milestone and at completion, comparing the result against the Purpose.

## Context and Orientation

All paths are relative to the repository root. The reader is assumed to know nothing about this codebase.

Bifrost analyzes source with tree-sitter and serves a set of tools over the Model Context Protocol (MCP). A "CodeUnit" (`src/analyzer/model.rs`) is one declaration — a class, function, field, or module. It exposes `fq_name()` (fully-qualified name, e.g. `pkg.Foo.bar`), `short_name()` (owner-qualified for members, e.g. `Foo.bar`), `identifier()` (the *terminal* display name, e.g. `bar`; see `src/analyzer/model.rs:684`), `source()` (the declaring file), and kind predicates (`is_class()`, `is_function()`, `is_field()`). An "analyzer" implements the `IAnalyzer` trait (`src/analyzer/i_analyzer.rs`); most languages wrap a generic `TreeSitterAnalyzer`, and a workspace with more than one language is served by `MultiAnalyzer` (`src/analyzer/multi_analyzer.rs`), which merges results from the per-language analyzers.

Name resolution for the symbol tools lives in `src/analyzer/symbol_lookup.rs`. The central function is:

    pub(crate) fn resolve_codeunit_fuzzy_with(
        analyzer: &dyn IAnalyzer,
        input: &str,
        include: impl Copy + Fn(&CodeUnit) -> bool,
    ) -> CodeUnitResolution

`CodeUnitResolution` (same file, line 6) is `Resolved(Vec<CodeUnit>) | Ambiguous(Vec<CodeUnit>) | NotFound`. `resolve_codeunit_fuzzy(analyzer, input)` calls the above with `include = |_| true`. The `include` predicate is how the anchored `path#terminal` flow (#1056) scopes every stage to one file.

The function is *staged*:

1. Stage 1 (exact), `exact_resolution` (line 179): returns `Resolved(analyzer.definitions(symbol).filter(include))` the instant that set is non-empty — with **no uniqueness or member check**. `analyzer.definitions(name)` matches the exact FQN key; a member's FQN is owner-qualified (`pkg.Foo.bar`), so a bare `bar` only ever matches a *top-level* `pkg.bar` here. Members are invisible to this stage.
2. Stage 2 (short-name index), `suffix_resolution_from_index` (line 199): uses `analyzer.lookup_candidates_by_short_name`, which is keyed by the owner-qualified `short_name`, so a bare `bar` does not match member rows here either. Only its embedded suffix-regex sub-scan (`analyzer.search_definitions`) reaches members by terminal name.
3. Stage 3 (full declaration scan), starting at line 120: `analyzer.get_all_declarations()` plus `collect_fuzzy_matches`; this is where members are finally seen by terminal name — but it only runs when stages 1 and 2 both return nothing.

`resolution_from_matches` (line 357) is where ambiguity is decided in stages 2-3: matches are keyed by `fq_name` (`insert_match`, line 351); one key → `Resolved`, more than one → `Ambiguous`. Because stage 1 returns before any of this, a bare name with a top-level namesake never reaches an ambiguity decision. That is the exact "stage boundary" bug issue #1057 describes.

The three tools consume resolution differently, all in `src/searchtools.rs`:

- `get_symbol_sources` (line 3120) and `get_summaries` (its symbol-target branch `summarize_symbol_targets`, line ~2892) both go through the shared glue `resolve_selectable_definitions` (line 2533). That glue flattens `Resolved`/`Ambiguous` into `code_units`, groups with `distinct_definitions` (line 3859), and returns `Ambiguous(AmbiguousSymbol { target, matches, note })` when there is more than one group. `AmbiguousSymbol` is defined at line 641; the note text comes from `ambiguous_symbol_selector_note` (line 2630).
- `get_definitions_by_reference` (the `definitions` surface) does **not** use that glue. It calls `resolve_definition_context_symbol` (line 1774), which short-circuits on `resolve_codeunit_exact` first (line 1785, its own silent-pick site, member-blind and skipping `distinct_definitions`), and only its fuzzy fallback (line 1839) reports ambiguity — as an unstructured `DefinitionDiagnostic { kind: "ambiguous_symbol", message }` string under an overall `status: "not_found"`, a shape unlike the other two tools.

`distinct_definitions` (line 3859) partitions a candidate list into `(selector, units)` groups. It builds `domains_by_fqn: HashMap<fqn, HashSet<(Language, Option<module_path>)>>`, where `module_path` is `Some(rel_path)` only for module-scoped ecosystems (JS/TS) and `None` otherwise. An FQN mapping to more than one domain is file-anchored (selector `path#fqn`); otherwise the selector is the plain FQN (or a file-anchored form for module-scoped languages). Because `module_path` is `None` for Scala/Java/C#/Go/C++, two declarations with the same FQN in different files of those languages collapse to a single domain, hence a single group, hence a silent pick — the cross-build-twin bug.

The MCP property fuzzer that produced the evidence is `src/mcp_property_fuzzer/`; its ledger of #1057 instances is `.agents/plans/mcp-property-fuzzer/m3.jsonl` (signatures `spelling-resolves-to-different-declaration`, `spelling-status-drift`, `summaries-listed-symbol-path-mismatch`). The adjacent #1056 fix (commit `44dc3852`, "resolve path#symbol selectors within the anchor file") is the reference pattern: it fixed the same root for the *anchored* case by scoping every stage to the anchor file via the `include` predicate. This plan fixes the *unanchored* case.

Concrete evidence rows to keep in mind while implementing (from the ledger):

- ts `getCachedVersion` → silently `checker/cached-version.ts:22` (free function) while the method `AutoUpdateCheckerDeps.getCachedVersion` in `hook.ts` is hidden.
- scala `chisel3.VecInitObjIntf.iterate` → the fully-qualified spelling silently resolves to `core/src/main/scala-3/chisel3/AggregateIntf.scala:157`, while the anchored `scala-2` spelling resolves to the twin at `scala-2/.../AggregateIntf.scala:177`. Same FQN, two files.
- scala `get_summaries` lists `chisel3.VerifPrintMacrosDoc` under `scala-2/.../VerificationStatementIntf.scala`, but `get_symbol_sources` for the same FQN reports `scala-3/.../VerificationStatementIntf.scala` — the cross-tool facet of the twin collapse.

## Plan of Work

The work is three milestones. Each is independently verifiable and leaves the tree green.

### Milestone 1 — Member-aware bare-name resolution

Scope: make a bare (single-segment) terminal name see same-named members, so stage 1 no longer silently wins on a top-level namesake. After this, `get_symbol_sources` and `get_summaries` report ambiguity for names like `getCachedVersion` because the resolver hands their shared glue the full candidate set; a name with a single distinct declaration still resolves unchanged.

Step 1a. Expose the existing identifier index on the analyzer trait. In `src/analyzer/i_analyzer.rs`, add a trait method mirroring `lookup_candidates_by_short_name` (line 244):

    fn lookup_candidates_by_identifier(&self, _identifier: &str) -> BTreeSet<CodeUnit> {
        BTreeSet::new()
    }

Implement it for `TreeSitterAnalyzer` (in `src/analyzer/tree_sitter_analyzer.rs`, next to the existing `lookup_candidates_by_short_name` impl at line 5650) by forwarding to the inherent `lookup_declarations_by_identifier` (line 4331). Forward it from every wrapper analyzer that wraps a `TreeSitterAnalyzer` — search for the existing `fn lookup_candidates_by_short_name` implementations (Scala `src/analyzer/scala/mod.rs:711`, Ruby `ruby/mod.rs:371`, PHP `php/mod.rs:519`, TypeScript `typescript/mod.rs:806`, Go `go/mod.rs:495`, Java `java/mod.rs:599`, Python `python/mod.rs:885`) and add the parallel forward beside each, and in `MultiAnalyzer` (`src/analyzer/multi_analyzer.rs:926`) merge across the inner analyzers exactly as `lookup_candidates_by_short_name` does there. C# already has an inherent `lookup_declarations_by_identifier` forward (`src/analyzer/csharp/mod.rs:190`); route the new trait method through it. Where a language has no `TreeSitterAnalyzer` inner (if any), the default empty impl is acceptable.

Rationale for a trait method rather than calling the inherent helper directly: `symbol_lookup.rs` operates on `&dyn IAnalyzer` and must work for `MultiAnalyzer`; only a trait method reaches all analyzers uniformly. This mirrors the established `lookup_candidates_by_short_name` pattern exactly.

Step 1b. Gather members in the bare-name case, inside `resolve_codeunit_fuzzy_with` (`src/analyzer/symbol_lookup.rs:90`). The single-segment condition is: the query, interpreted for the languages in play, is one terminal segment (no `.`/`::`/`/`/`#` structure). Compute it from the existing interpretation helper — a query is bare when `query_symbol_interpretations(language, trimmed)` yields only single-element paths (`path.len() == 1`) for every language. Do not hand-parse the string; reuse `query_symbol_interpretations` / `symbol_selector_leaf` (already in this file, lines 428 and 443).

When the query is bare, stage 1 must not early-return a lone top-level hit while members exist. Replace the "return immediately on first non-empty stage" behavior for the bare case with: collect the union of (a) the current exact matches `analyzer.definitions(trimmed).filter(include)` and (b) the member-and-namesake matches `analyzer.lookup_candidates_by_identifier(leaf).filter(|u| include(u) && u.identifier() == leaf)`, key them the same way stages 2-3 do (`insert_match` by `fq_name`), and produce the result via the existing `resolution_from_matches` (line 357) so the one-vs-many → `Resolved`/`Ambiguous` decision and the `prefer_types_over_their_owner_named_constructors` rule (line 387) are applied uniformly. Keep the non-bare path (multi-segment queries) exactly as it is today — for those, members are already reachable through the suffix stages, and the qualified-name behavior must not change.

Preserve every existing deterministic preference: `prefer_types_over_their_owner_named_constructors` must still collapse a bare type name that also suffix-matches its own owner-named constructor (`pkg.Type` vs `pkg.Type.Type`) down to the type, so that does not become a spurious ambiguity. Because `resolution_from_matches` already calls it, routing the bare case through that function preserves it for free.

Note on breadth of `matches`: for very common terminal names (`get`, `main`) the identifier index can return many declarations. That is the correct ambiguous set, but the rendered `matches` list should stay usable — rely on the existing `distinct_definitions` grouping (which collapses overloads and shares selectors) at the searchtools layer, and if a hard cap is needed, cap the rendered `matches` while stating the total, mirroring how `search_symbols` already signals `truncated`. Decide and record this in the Decision Log during implementation only if a real test surfaces an unwieldy list; do not pre-optimize.

Step 1c. Tests. Add to `tests/searchtools_definition_selectors.rs` (the primary selector/ambiguity suite) an `InlineTestProject` (`tests/common/inline_project.rs`) case reproducing the `getCachedVersion` shape: a top-level free function `getCachedVersion` in one file and a method `getCachedVersion` on a class in another; assert that `get_symbol_sources` and `get_summaries` for the bare name return `ambiguous` with two `path#` selectors and the recovery note, and that a uniquely-named symbol in the same project still resolves. Add a single-language and a mixed-language variant so the `MultiAnalyzer` merge is exercised. Prove the test fails before Step 1b and passes after.

Acceptance for M1: `BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_definition_selectors` passes including the new cases; the pre-existing bare-unique-name tests still pass; `cargo clippy --all-targets --all-features -- -D warnings` is clean. Observable behavior: resolving a bare name that has both a top-level and a member declaration yields an ambiguity with both `path#` selectors instead of a silent single hit.

### Milestone 2 — Location-aware distinctness for identical-FQN collisions

Scope: identical fully-qualified names that live in different files (Scala `scala-2`/`scala-3` twins, Go build-tag twins, C# partial-class parts) must become distinct selectable candidates for every language, not a silent pick. Genuine same-file overloads (e.g. Java method overloads) must stay one group.

Step 2a. In `distinct_definitions` (`src/searchtools.rs:3859`), extend the domain discriminator to include the declaring file path for every language, not only module-scoped ecosystems. Concretely, build the per-FQN domain key from `(language, rel_path_string(unit.source()))` for all languages (keep the existing module-scoped selector rendering). The effect: an FQN present in two files maps to two domains → each unit is file-anchored (`path#fqn`) → two groups → the callers report ambiguity with both `path#` selectors; an FQN present once (the common case) still maps to one domain → unchanged plain selector; same-file overloads share one `(language, path)` domain → stay one group. This is one localized change to how the domain set is computed; the group-formation loop below it is untouched.

Step 2b. Verify the twin candidate set actually reaches `distinct_definitions`. For the exact FQN spelling of a twin, `resolve_codeunit_exact` (`symbol_lookup.rs:76`) returns every declaration whose `fq_name()` equals the query (both twins), and `resolve_selectable_definitions` passes them through. Confirm with a test; no resolver change is expected for the exact-FQN twin case beyond M1. If a twin is only reachable by bare name, M1 already gathers it.

Step 2c. Tests. Add cases to `tests/searchtools_definition_selectors.rs`: (i) two declarations sharing an FQN in two files of a non-module-scoped language (model the Scala `scala-2`/`scala-3` shape with two files declaring the same package/type) resolve to an `ambiguous` response listing both `path#fqn` selectors from both the bare and the fully-qualified spelling; (ii) a same-file overload set (two methods with the same FQN in one file) still resolves as a single group (no regression). Assert the cross-tool consistency the fuzzer flagged: `get_summaries` listing the symbol under file A and `get_symbol_sources` for the same FQN now both surface file A among the candidates rather than silently reporting a different file.

Consideration to record during implementation: C# partial classes become two `path#` candidates under this rule. That is strictly better than the current silent single-part pick and is consistent with the "report ambiguity + selectors" decision; a future refinement could merge partial parts into one multi-range symbol, but that is language-specific and out of scope here. Note this in the Decision Log when the C# behavior is observed in a test.

Acceptance for M2: the new twin/overload tests pass; existing `distinct_definitions`-dependent tests (the JS/TS module-anchored ambiguity cases already in `tests/searchtools_definition_selectors.rs`, e.g. `symbol_sources_disambiguates_same_named_js_functions_by_file_selector`) still pass unchanged; clippy clean. Observable behavior: an identical FQN in two files yields two file-anchored candidates instead of one silently chosen file.

### Milestone 3 — Consistent ambiguity on the `get_definitions_by_reference` surface

Scope: make the `definitions` surface report ambiguity in the same conditions and — as far as its result type allows — the same shape as the other two tools, so bare and fully-qualified spellings of the same reference behave identically.

Step 3a. In `resolve_definition_context_symbol` (`src/searchtools.rs:1774`), stop silently short-circuiting on `resolve_codeunit_exact` for the bare/unanchored case. Route the unanchored branch through the same member-aware resolution used elsewhere (the M1-fixed `resolve_codeunit_fuzzy`) and through `distinct_definitions`, so this surface reports ambiguity exactly when `get_symbol_sources`/`get_summaries` do. Keep its `Result<Vec<CodeUnit>, Vec<DefinitionDiagnostic>>` return type, but make the ambiguity diagnostic carry the same distinct `path#` selector list that the other surfaces list in `AmbiguousSymbol.matches` (it already embeds `code_unit_match_names`; ensure it is computed from the same `distinct_definitions` grouping so the selector strings match across tools). Preserve the anchored (`path#`, path-qualified) branches as they are — they already scope and group correctly.

Do not silently change the JSON status vocabulary agents depend on unless a test shows it is necessary: `get_definitions_by_reference` encodes ambiguity as `status:"not_found"` plus a `diagnostics[].kind == "ambiguous_symbol"` entry (the property fuzzer's `classify_spelling` already reads this shape, `src/mcp_property_fuzzer/service_probes.rs:1584`). The required outcome is that the *conditions* for ambiguity, and the *selector strings* offered, are consistent with the other tools; unifying the literal response type into `AmbiguousSymbol` is a further nicety — do it only if it does not break the fuzzer's classifier and existing definition-surface tests, and record the choice in the Decision Log.

Step 3b. Tests. In the reference-surface test suite (find it via `rg -l "get_definitions_by_reference|definitions_by_reference|resolve_definition_context_symbol" tests src`), add a case where a bare terminal name and its fully-qualified spelling denote a member collision: assert both spellings produce the same ambiguity outcome with the same candidate selectors (this is the fuzzer's `spelling-status-drift` shape). Prove it fails before Step 3a and passes after.

Acceptance for M3: the new reference-surface consistency test passes; `BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_definition_selectors` and the reference-surface suite pass; clippy clean. Observable behavior: for a member-colliding name, `get_definitions_by_reference` no longer silently resolves one declaration while `get_symbol_sources` reports two — both report the same ambiguity with the same selectors.

## Concrete Steps

Run everything from the repository root `/home/jonathan/Projects/bifrost2`.

Orient before editing:

    rg -n "fn resolve_codeunit_fuzzy_with|fn exact_resolution|fn resolution_from_matches" src/analyzer/symbol_lookup.rs
    rg -n "fn distinct_definitions|fn resolve_selectable_definitions|fn resolve_definition_context_symbol" src/searchtools.rs
    rg -n "fn lookup_candidates_by_short_name" src/analyzer

Per milestone, edit the files named in the Plan of Work, then run the focused suite. The core suite for M1/M2 is:

    BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_definition_selectors

Before finishing each milestone, run the lint gate (safe on every machine; `--all-features` is just `nlp,python`):

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings

New ad hoc test projects must use `InlineTestProject` from `tests/common/inline_project.rs` (see existing cases in `tests/searchtools_definition_selectors.rs` for the idiom), per the repository's analyzer-test guidance.

## Validation and Acceptance

End-to-end acceptance is behavioral and phrased as observable tool responses.

1. Member collision (M1). In a two-file project with a top-level `getCachedVersion` and a method `Deps.getCachedVersion`, `get_symbol_sources` and `get_summaries` for the bare name `getCachedVersion` return an `ambiguous` result whose `matches` list both `fileA#getCachedVersion` and `fileB#Deps.getCachedVersion` and whose `note` says to re-call with one selector. Before the change, the same call returns a single silent hit. Prove via the new tests in `tests/searchtools_definition_selectors.rs` (fail before, pass after).

2. Identical-FQN twins (M2). In a project with the same FQN declared in two files, both the bare and the fully-qualified spelling return an `ambiguous` result listing both `path#fqn` candidates; a same-file overload set still resolves as one group. Prove via the new twin/overload tests.

3. Cross-surface consistency (M3). For a member-colliding reference, `get_definitions_by_reference` reports ambiguity with the same candidate selectors as `get_symbol_sources`, for both the bare and fully-qualified spelling. Prove via the reference-surface consistency test.

4. Regression gate. `BIFROST_SEMANTIC_INDEX=off cargo test --test searchtools_definition_selectors` plus the reference-surface suite and any suite touched by the trait-method additions pass; `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings` are clean. Because `default = []`, the full integration suites must be run with `--features nlp,python` where they gate behavior; for the resolver/searchtools suites here the `BIFROST_SEMANTIC_INDEX=off` form above is sufficient and does not download models.

5. Fuzzer confirmation (optional but decisive). Re-run the MCP property fuzzer against the two evidence repos and confirm the #1057 signatures no longer reproduce:

    cargo run --release --bin bifrost_mcp_property_fuzzer -- \
      --clones-root /home/jonathan/Projects/brokkbench/clones \
      --repo chipsalliance__chisel --invariants I2 I3 --cache-mode ephemeral \
      --symbol-filter iterate --out /tmp/claude-1057-check.jsonl

   Expect the `spelling-resolves-to-different-declaration` and `summaries-listed-symbol-path-mismatch` signatures to be gone. This step needs the local corpus clones and is not part of the unit gate.

## Idempotence and Recovery

Every step is additive and repeatable. The only trait-surface change (adding `lookup_candidates_by_identifier` with a default empty body) is backward compatible: analyzers that do not override it return an empty set, and the bare-name augmentation degrades to today's behavior for them. No cache migration is introduced, so switching branches does not require rebuilding `.brokk/bifrost_cache.db`. If a milestone's tests reveal a regression in an existing selector test, prefer fixing the shared code so both the old expectation and the new ambiguity contract hold; only update an existing test's expectation when the new ambiguity is the correct, intended behavior (e.g. a test that previously asserted a silent pick on a genuinely-multiple name), and record that in the Decision Log.

## Interfaces and Dependencies

In `src/analyzer/i_analyzer.rs`, add to the `IAnalyzer` trait:

    fn lookup_candidates_by_identifier(&self, identifier: &str) -> std::collections::BTreeSet<CodeUnit> {
        let _ = identifier;
        std::collections::BTreeSet::new()
    }

Implement/forward it in: `src/analyzer/tree_sitter_analyzer.rs` (forward to inherent `lookup_declarations_by_identifier`), `src/analyzer/multi_analyzer.rs` (merge across inner analyzers), and each wrapper analyzer that already forwards `lookup_candidates_by_short_name` (`scala`, `ruby`, `php`, `typescript`, `go`, `java`, `python`, and `csharp` via its existing inherent forward).

In `src/analyzer/symbol_lookup.rs`, keep the public surface (`resolve_codeunit_fuzzy`, `resolve_codeunit_fuzzy_with`, `resolve_codeunit_exact`, `CodeUnitResolution`) unchanged; the member-aware augmentation is internal to `resolve_codeunit_fuzzy_with` and must route its result through the existing `resolution_from_matches` so `Resolved`/`Ambiguous` semantics and `prefer_types_over_their_owner_named_constructors` are preserved.

In `src/searchtools.rs`, keep the public tool entry points and the `AmbiguousSymbol` shape unchanged; the M2 change is internal to `distinct_definitions`, and the M3 change is internal to `resolve_definition_context_symbol`.

No external libraries or new dependencies are required.
