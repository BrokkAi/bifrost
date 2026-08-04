# Pre-flight behavior inventory: per-language dispatch fallbacks in bifrost-analysis

Taken at commit `ec74ddac` for `.agents/plans/analysis-language-registry-spi.md`
("Design decisions" 1-3 and milestone 1's "Fallback semantics need an inventory"
paragraph). Decision 1 requires that `Language::None` remain a handled input rather than
becoming `unreachable!`; this document records what "handled" means today at each site.
All strings are quoted verbatim from source at that commit; line numbers drift, treat as
search anchors. Companion: `.agents/docs/registry-preflight-census-2026-08.md`.

## 1. Language::None terminal outcomes and absent-language behavior per dispatch site

### 1a. finder.rs — the graph_find_usages match (:719-811)

The match at `analyzer/usages/finder.rs:726-811` is exhaustive with no wildcard. The
`Language::None` arm (`:804-810`):

    Language::None => GraphUsageOutcome::terminal_failure(
        overloads[0].fq_name(),
        GraphFailureReason::UnsupportedTargetLanguage(
            "no graph usage strategy is available for this target language",
        ),
        "UsageFinder",
    ),

Resulting values (`analyzer/usages/outcome.rs:21-82`): variant
`GraphUsageOutcome::TerminalFailure` (note: `TerminalFailure` carries
`#[allow(dead_code)]` and `Language::None` is its only production constructor);
`strategy = "UsageFinder"`; `reason_kind = "unsupported_target_language"`;
`reason = "UsageFinder: no graph usage strategy is available for this target language"`.

Downstream (`finder.rs:256-263`) `TerminalFailure` and `FallbackSafe` are handled
identically -> `FuzzyResult::Failure { fq_name, reason_kind, reason }`; no consumer reads
the enum tag. A registry `None` branch producing `fallback_safe` would be observationally
identical today -- but the surviving `QueryResult` fields (`completion`,
`candidate_files`, `candidate_files_truncated`, `scanned_source_bytes`) are still
computed for a `None` target (candidate discovery/truncation runs before the language
match, `finder.rs:172-232`) and must remain so.

Surfaces: LSP silently drops it (`bifrost-lsp/src/lsp/handlers/usage_hits.rs:14-40`
consume `all_hits_including_imports()`; `FuzzyResult::Failure` falls into the
`_ => BTreeSet::new()` arm of `all_hits_unfiltered`, `usages/model.rs:402-415` -- empty
list, indistinguishable from no usages). MCP scan_usages surfaces a failure row
(`searchtools/scan_usages.rs:3180-3200`): `status = Failure`,
`reason_kind = Some("unsupported_target_language")`, `message = Some(failure.reason)`;
`usage_failure_hint` (`scan_usages.rs:1007-1021`) maps
`("unsupported_target_language", _)` to `None` -- no hint suffix.

### 1b. receiver_query.rs -- three layers, three behaviors

(i) Outer gate `analyze_with_optional_structural_facts` (`:517-561`): a `matches!` list
of nine languages (Cpp, CSharp, Go, Kotlin, Php, Python, Ruby, Rust, Scala); Java routed
separately at `:543-552`; JS/TS at `:554`. Everything else including `Language::None`
returns `unsupported_report(..., "receiver_analysis_language_unsupported", ...)`
(`:554-562`), yielding `ReceiverAnalysisOutcome::Unsupported { reason:
"receiver_analysis_language_unsupported" }` with `site.syntax_kind = "unsupported"` and
default work. Pinned by test `unsupported_language_returns_an_explicit_row`
(`receiver_query.rs:4859-4877`).

(ii) Inner structural dispatches `resolve_structural_type_bounded` (`:2008-2047`) and
`resolve_structural_definition_bounded` (`:2051-2091`) both end
`_ => unreachable!("unsupported structural receiver language")` (`:2046`, `:2090`).
This is the one place where an absent language is a panic -- unreachable only because
gate (i) filters to exactly the same nine languages. The `matches!` list and these two
matches are a single invariant expressed in three places; the registry conversion must
preserve that coupling (ideally collapsing it to one place).

(iii) The graph-unsupported reason at `:2093-2117` -- see section 2.

### 1c. workspace_graph.rs

`UsageEcosystem::of` (`:37-50`): exhaustive, `Language::None => Self::Unknown`.
`as_str`: `Unknown => "unknown"`. `WorkspaceUsageNode::language_label` (`:123-131`):
JVM ecosystem sub-matches Java/Scala/Kotlin with `_ => "jvm"`; otherwise the ecosystem
string, so a `None`-language declaration reports `"unknown"`.

The edge-weight passes (`:341-470`) run per-ecosystem guarded by
`selected_ecosystems.contains`; `UsageEcosystem::Unknown` is never named in any
invocation, so Unknown-ecosystem nodes are emitted as graph nodes
(`nodes = catalog.nodes.clone()`, `:347`) but carry zero edges -- silently, no
diagnostic. Pass order: Go, Python, Rust, Jvm x3 (Java, Scala, Kotlin), CSharp, Cpp,
Php, Ruby (`:374-428`), then JS/TS via `build_jsts_scoped_usage_edges` (`:430-470`).
`WorkspaceUsageCatalog::build_with_cancellation` (`:148-214`) filters only on
`unit.is_synthetic() || !(unit.is_class() || unit.is_callable())` -- not by language,
which is why Unknown nodes exist.

### 1d. scan_usages.rs edge-build sequence (:2472-2615)

Order: Go, JS/TS, Python, Rust, Java/Scala/Kotlin, CSharp, Php, Ruby, Cpp. The merge
closure `record_inverted` (`:2449-2471`) returns early on `None` -- a builder returning
`None` contributes nothing, no diagnostic. `None`-language declarations enter the
catalog under `UsageEcosystem::Unknown`, appear as nodes with `language: "unknown"`,
and get no edges (`catalog.fqns(Unknown)` never requested; `fqns` returns a static
empty set for unrequested ecosystems). `truncated_symbols` rows carry the *ecosystem*
string (`"jvm"`, `"js_ts"`), not the source language, and `limit: MAX_CALLSITES`
(= `DEFAULT_MAX_USAGES` = 1000, `analyzer/usages/inverted_edges.rs:159`,
`finder.rs:27`).

Other `Language::None` early-outs: `candidates.rs:97-99` (sibling expansion continues
past None files), `candidates.rs:410-412` (text candidates empty for None target),
`usages/common.rs:25-35` (`language_for_target_filtered` manufactures `Language::None`
as a rejection signal -- used by `js_ts_graph/resolver.rs:690`),
`scan_usages.rs:1068` (`scan_usages_language_name(None) == "this language"`, used in
`unsupported_target_shape_message` `:1024-1032`), `selectors.rs:1564` (`"none"`).

## 2. The unsupported-reason surface

### 2a. structural_receiver_unsupported_reason (:2093-2117)

Not an enum: `Option<&'static str>` over a two-language guarded match -- `Language::Cpp`
with a `"cpp_c_receiver_unsupported"` diagnostic present => that string; `Language::CSharp`
with `"csharp_dynamic_receiver_unsupported"` => that string; else `None`. Sole caller
`:1192-1196` routes through `neutral_unsupported` (`:2351-2360`) which overwrites the
analysis with `ReceiverAnalysisOutcome::Unsupported { reason }`. The diagnostic kinds
originate in `get_type/cpp.rs:30`, `get_definition/cpp.rs:487`, `get_type/csharp.rs:85`.

### 2b. ReceiverAnalysisOutcome (receiver_analysis.rs:17-23)

`Precise(Vec<T>) | Ambiguous(Vec<T>) | Unknown | Unsupported { reason: &'static str } |
ExceededBudget { limit: &'static str }`. Complete reason-string set passed to
`Unsupported` from receiver_query.rs:

    receiver_analysis_language_unsupported   (not in the nine, not Java, not JS/TS)
    receiver_analyzer_unavailable
    receiver_semantic_workspace_unavailable
    receiver_structural_facts_unavailable
    receiver_source_parse_failed
    receiver_source_snapshot_mismatch
    receiver_input_range_unavailable
    receiver_site_without_receiver
    member_target_site_unsupported
    indexed_source_unavailable
    cpp_c_receiver_unsupported
    csharp_dynamic_receiver_unsupported

### 2c. Where they surface

MCP query_code rows: `structural/search/mod.rs:9088-9101` maps to
`("unsupported", Some(*reason), None)` -> `CodeQueryReceiverAnalysis`. Query
diagnostics (`:7292-7307`): `cpp_c_receiver_unsupported` is special-cased to
`"plain C receiver sites are unsupported (cpp_c_receiver_unsupported)"`; every other
reason renders `"unsupported provider or shape: {reason}"` under
`CodeQueryDiagnosticCode::ReceiverAnalysisPartial` (serializes as
`"receiver_analysis_partial"`). Completion: `ReceiverAnalysisPartial` ->
`QueryOperatorTermination::AnalysisIncomplete` (`:3970-3977`). LSP: no path -- failures
drop to empty hit sets.

### 2d. Policy "unreliable" chain

`ReceiverAnalysisPartial` (with UnsupportedStructuralFeature, MissingStructuralAdapter,
UnsupportedImportAnalysis, SemanticWorkspaceRequired, SemanticCapabilityUnsupported,
TypestateCapabilityUnsupported, ValueFlowCapabilityUnsupported, UsesParserUnsupported)
-> `PolicyIncompleteReason::CapabilityIncomplete` (`bifrost-policy/src/evaluator.rs:
3606-3618`) -> `PolicyRunCompletion::inconclusive` (`:2430-2432`) -> `is_reliable()`
false (`finding.rs:86-88`) -> `report_exit_status` returns `POLICY_EXIT_UNRELIABLE`
(`coordinator.rs:1701-1722`) -> MCP renders literal `"unreliable"`
(`searchtools_service.rs:3259-3268`). Distinction the plan's wording elides: unsupported
*language* arrives via `Inconclusive { [CapabilityIncomplete] }`, not via
`PolicyRunCompletion::Unsupported { capability }` -- the latter is reserved for missing
taint/typestate adapters (`evaluator.rs:584-590`, `:671-677`) and renders differently in
the human report (`render/human.rs:2170-2226`: `"inconclusive (capability_incomplete)"`
vs `"unsupported: "`).

## 3. Dead-code absent-language semantics (code_quality/dead_code_smells.rs)

### 3a. Absent from graph_strategy_for (:2387-2416)

If-chain order: Rust, JsTs, Java, Scala, Go, CSharp, Php, Ruby, Kotlin, then `None`.
Absent: Python and C++ (imports at `:12-15` do not name their strategies). `None`
reaches `analyze_candidate` (`:686-693`):

    "`{fq_name}`: {label} precise usage strategy is unavailable; evidence is inconclusive"

with `language_label` (`:2421-2437`) mapping the twelve languages to display names and
`_ => "graph-backed"` (what `Language::None` gets). The Python variant of this string is
currently unreachable (Python candidates continue unconditionally into the bulk path,
`:159-162`). `skipped` entries render under the literal heading `"Skipped evidence:"`,
each `"- "`-prefixed, capped at 10 with `- ... {n} more skipped symbols`, plus a header
count `- Skipped symbols: {n}` (`:406-408`, `:468-479`).

Asymmetry: `query_graph_usages` (`:2356-2385`) builds candidates from
`default_provider()` (import-graph + text search), NOT
`find_default_candidates_with_cancellation` -- so the Python/Rust candidate hooks of
section 4 never run on the dead-code per-symbol path.

### 3b. Bulk-eligibility routing (:151-238)

Delegating languages (per-language `dead_code_bulk_eligibility` in `usages::*_graph`):
Java (`:1978-2006`), Scala (`:2008-2037`, plus short-circuit to precise when
`ScalaDeadCodeBulkContext::from_analyzer` is `None`), C++ (`:2063-2080`), PHP
(`:2082-2087`). C# is inline (`:2039-2061`): fields, constructor candidates, overloaded
functions, unsafe using-member forms. Python and JS/TS: unconditional bulk. Ruby: bulk
unless `is_field()`. Go: bulk unless `is_field() || go_implicit_entry_point`. Rust:
bulk unless `rust_candidate_needs_precise_member_scan` (`:847-859`, inherent/trait
members). Kotlin: NO arm at all -- every Kotlin candidate takes the per-symbol path
(and `graph_strategy_for` does handle Kotlin). `Language::None`: falls through to
per-symbol, hits 3a's "graph-backed" skip.

Polarity inversion pin: Java/C#/C++ use `!cap_exceeded && !needs_precise` (bulk only if
under cap); Scala uses `cap_exceeded || !needs_precise` (`:225-235`) -- over-cap PUSHES
Scala INTO bulk, where the shared helper emits the cap diagnostic. Load-bearing.

Constants: `DEFAULT_MAX_USAGE_CANDIDATE_FILES = 1000` (`:32`),
`DEFAULT_MAX_INPUT_FILES = 25` (`:30`), `MAX_USAGES_FOR_SMELL = 1` (`:36`, usage_cap
clamped at `:105`).

### 3c. The four pins

Pin 1, Python target-restricted cached path (`:1005-1018`): Python is the only language
whose edge-build closure consumes the `targets` parameter --
`build_cached_python_usage_edges_for_targets(analyzer, nodes, targets)`; all siblings
take `|nodes, _targets|`. `targets` = candidate fq_names only (`:1251`); `nodes` = all
non-synthetic Python declarations passing the predicate plus candidates (`:1243-1250`).

Pin 2, Scala full builder (`:1061-1063`): `build_full_scala_usage_edges(analyzer,
nodes)` -- no `keep_file` predicate, unlike every sibling's `|_| true` workspace-builder
form (Java `:1129`, C# `:1108-1110`, C++ `:1133`, PHP `:1157`, Ruby `:1181`, Rust
`:906`).

Pin 3, Rust availability + file cap (`:861-955`): only dead-code path with a standalone
concrete-analyzer resolution check, and it measures file count from
`rust.get_analyzed_files().len()` (`:883`), not `project().analyzable_files(...)`.
Exact strings:

    "`{fq}`: Rust analyzer capability was unavailable; evidence is inconclusive"
    "`{fq}`: Rust usage graph candidate files exceeded cap {cap} ({n} Rust files); evidence is inconclusive"
    "`{fq}`: Rust usage graph could not be built; evidence is inconclusive"

then four per-candidate truncation diagnostics (`:924-945`) byte-identical to the
generic path's (`:1266-1290`):

    "`{fq}`: too many workspace inbound call sites ({total}, limit {MAX_CALLSITES}); evidence is inconclusive"
    "`{fq}`: too many workspace inbound call sites ({total}, limit {usage_cap}); evidence is inconclusive"
    "`{fq}`: {n} structurally matching usage site(s) could not be proven or disproven; evidence is inconclusive"

Generic-path variants (`:1229-1260`) use `language_label`:

    "`{fq}`: {label} usage graph candidate files exceeded cap {cap} ({n} {label} files); evidence is inconclusive"
    "`{fq}`: {label} usage graph could not be built; evidence is inconclusive"

with file counts from `project().analyzable_files(language)`.

Pin 4, JS/TS scoped-node status (`js_ts_graph/inverted.rs:138-148`, `:563-597`;
consumption `dead_code_smells.rs:1381-1397`): `Resolved` proceeds; `Ambiguous` skips
with `"`{fq}`: JS/TS export identity was ambiguous; evidence is inconclusive"`;
`Unseedable` OR a missing map entry (`None` folded into the same arm, not an error)
skips with `"`{fq}`: JS/TS export seed could not be resolved; evidence is
inconclusive"`. Status derivation: `Unseedable` when canonical export key set empty;
`Ambiguous` on ambiguous alias or as the fall-through; `Resolved` on key match/prefix.
JS/TS file cap SUMS JavaScript + TypeScript analyzable counts (`:1310-1318`) and its
diagnostics use literal `"JS/TS"`:

    "`{fq}`: JS/TS usage graph candidate files exceeded cap {cap} ({n} JS/TS files); evidence is inconclusive"
    "`{fq}`: JS/TS usage graph could not be built; evidence is inconclusive"

## 4. Candidate augmentation and truncation ordering

### 4a. Pre-clone (protected) hooks -- candidates.rs:640-663

In `find_default_candidates_with_cancellation`: fallback policy (import-graph or text),
then Python hook (`:652-655`, `python_usage_candidate_files`), then Rust hook
(`:657-660`, `rust_usage_candidate_files`). Cancellation is a guard on each `if` --
a cancelled token skips both but still returns accumulated candidates (no early
return). Both hooks are inside the default route only (explicit providers bypass).

### 4b. Two budgets, both protection-aware -- finder.rs

Clone at `:189` (`protected_candidates = candidates.clone()`). File-count budget
(`:212-216`): `truncate_candidates` (`:440-468`) fills from sorted protected first,
tops up sorted others; `DEFAULT_MAX_FILES = 1000`. Source-byte budget (`:217-228`,
`admit_candidates_by_source_bytes` `:323-355`): `None` disables; admission sorts
`(!protected.contains(file), file)` so protected admit first; per-file admit iff
`scanned + bytes <= max`; files without indexed_source skipped uncharged; greedy, not
all-or-nothing; cancellation mid-admission -> `cancelled_query_result()`.
`candidate_files_truncated = candidates.len() < all_candidates.len()` (`:229`);
`CANDIDATE_FILE_SAMPLE_LIMIT = 10` (`:469`). Completion priority: Cancelled >
SourceBytesBudgetExhausted > CandidateFilesBudgetExhausted > Complete (`:272-280`).

### 4c. Post-clone (supplemental) PHP augmentation -- finder.rs:191-200

Only when `explicit_provider.is_none()`, per overload: `add_php_composer_candidates`
(`:193`; definition `:362-377`) -> cancellation check (`:194-196`, full abandonment via
`cancelled_query_result()`: empty set, `completion: Cancelled`) ->
`add_php_import_alias_candidates` (`:197`; definition `:379-408`) -> cancellation check
(`:198-200`). These land only in `candidates`, never `protected_candidates` -- first
dropped under either budget. Composer requires
`php.target_has_composer_autoload_visibility(target)` and then extends with EVERY
analyzed PHP file (`:376`) -- the largest expansion on this path, and why it must stay
droppable. Note the PHP cancellation behavior (full abandonment) differs from the
Python/Rust hooks' (skip-and-continue).

### 4d. Exact ordering for a pinning test

1. Query scope; empty-overloads early return; pre-flight cancellation check.
2. Per overload: explicit provider or default route (fallback policy -> Python hook ->
   Rust hook); extend; cancellation check after each overload.
3. `protected_candidates = candidates.clone()` (`:189`).
4. Per overload, default route only: PHP composer -> cancel -> PHP import-alias ->
   cancel.
5. `file_filter` retain on BOTH sets (`:204-207`) -- a filtered-out protected file
   loses protection -- then cancellation check.
6. `all_candidates = candidates.clone()` (`:212`).
7. File-count truncation, protected-first.
8. Source-byte admission, protected-first.
9. Scan scope + `graph_find_usages`.

Test shapes: (a) Python/Rust target with `max_files` = import-graph result size,
hook files survive; (b) PHP composer-visible target with `max_files` = pre-clone size,
composer files are exactly the dropped ones, `completion ==
CandidateFilesBudgetExhausted`; (c) same with cancellation tripped inside augmentation,
`completion == Cancelled`, empty candidate set.

## 5. Ruby's asymmetry -- ruby_graph.rs:73-173

No `RubyQueryResolver` exists; `RubyUsageGraphStrategy::find_graph_usages` inlines the
query (siblings: `<Lang>QueryResolver::try_new` + `find_usages`). Differences a fold-in
must preserve:

1. Empty-overloads guard via `first()` -> `Resolved(FuzzyResult::empty_success())`
   (behaviorally equivalent to siblings).
2. Inline language check: `UnsupportedTargetLanguage("target is not Ruby")`, strategy
   label `"RubyUsageGraphStrategy"` via a `STRATEGY` const (`:40`).
3. Capability check inside `find_graph_usages`, message
   `MissingAnalyzerCapability("Ruby analyzer is unavailable")` -- a distinct string
   from siblings' "analyzer does not expose XAnalyzer" form; do not normalize.
4. Shape gate with no sibling: `RubyTargetSpec::from_target` None ->
   `UnsupportedTargetShape("target shape is unsupported")`.
5. Per-query `RubySemanticIndex::build` after the shape gate.
6. Scan-time candidate augmentation (`:106-115`): inserts the target's own source file
   if `scan_scope.allows` it, plus
   `ruby.zeitwerk_reference_files_for_identifier(&spec.member_name)` filtered by
   `scan_scope.allows` -- performed AFTER all budget enforcement, bypassing max_files
   and max_source_bytes entirely. No sibling does this.
7. Own per-file scan loop (`:119-146`): skip non-Ruby files, read_source (skip on Err),
   `parse_ruby_tree` (skip on None), `RubyFileScan`.
8. Cancellation returns PARTIAL results: `break` then success with accumulated hits
   (`:120-122`, `:166-172`). Go/Python return `empty_success()` on cancellation,
   discarding partial work. The most consequential asymmetry to verify.
9. Post-hoc self-exclusion on both hit tiers (`hit.enclosing != spec.target`, `:148-155`).
10. Cap: `external_usage_hit_count > max_usages` -> `Resolved`-wrapped
    `FuzzyResult::TooManyCallsites { short_name, total_callsites, limit, sample_hits }`
    -- Resolved, not a failure variant. Else `success_with_unproven`.
11. Only the edge path is trait-shaped (`RubyEdgeResolver: UsageEdgeResolver`, `:38`);
    Ruby is asymmetric between its own two paths, not merely against siblings.

Fold-in acceptance: assert the four exact `GraphFailureReason` strings (items 2-4), the
zeitwerk/target-source scan-set expansion with `scan_scope.allows` gating (item 6),
partial-result-on-cancel (item 8), and the Resolved-wrapped TooManyCallsites (item 10).
