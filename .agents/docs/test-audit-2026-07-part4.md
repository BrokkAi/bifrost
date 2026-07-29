# Test audit — part 4: inline `#[cfg(test)]` modules under `src/`

Scope: every inline test module under `src/` (257 files, ~2,100 `#[test]` functions), including the
dedicated inline-test files (`src/analyzer/js_ts/semantic/tests.rs`, `src/analyzer/cpp/tests.rs`,
`src/analyzer/structural/query/tests.rs`, `src/analyzer/semantic/ir/tests.rs`, …). Nothing under
`tests/` was audited — three sibling auditors own that — but `tests/` was searched for subsumption
evidence.

Note: `src/analyzer/{rust,cpp,csharp,go,python,php,js_ts,scala,ruby}/tests.rs` are mostly *implementation*
modules (test-smell detection over analyzed source), not test modules; a naive
`grep -c '#\[test\]'` over them counts string literals inside detector fixtures.

**Headline: this slice is in good shape.** 14 tests are recommended for removal out of ~2,100 (0.7%).
The vast majority of inline tests here are budget/cancellation/stack-safety pins, negative controls,
fail-closed persistence checks, or unit tests of genuinely tricky pure functions. Several whole
subtrees (`src/analyzer/usages/**`, all per-language analyzer dirs, `src/analyzer/structural/**`,
`src/analyzer/store/**`, `src/analyzer/semantic/**`, `src/cache_db.rs`, `src/lsp/**`) produced zero
recommendations after full enumeration.

---

## `src/mcp_registry.rs`

### `core_expands_symbol_then_nlp_then_workspace` (line 271) — **Subsumed**

```rust
let mut expected = symbol_tool_names();
expected.extend(nlp_tool_names());
expected.extend(workspace_tool_names());
assert_eq!(tool_names("core"), expected);
```

`tests/bifrost_mcp_server.rs::bifrost_split_servers_publish_expected_tool_sets` (line 1377) builds the
*identical* expected vector — same nine symbol tools, same `#[cfg(feature = "nlp")] semantic_search`,
same three workspace tools, same order — and asserts it against a real server's `tools/list` response
over stdio. The inline test is the same assertion minus the transport, so it can only fail when the
integration test already fails.

### `searchtools_expands_to_all_toolsets_in_order` (line 304) — **Implementation mirror / Subsumed**

```rust
expected.extend([ "query_code", "run_policy", "get_symbol_locations", /* …23 more… */ ]…);
assert_eq!(tool_names("searchtools"), expected);
```

A 26-name ordered list restating the registry's own toolset concatenation. `tests/bifrost_mcp_server.rs::bifrost_searchtools_server_speaks_mcp_stdio`
(line 186) already pins the full `searchtools` list, in order, per-nlp-feature, through a real server.
The inline copy is not just weaker — it is already **wrong** (it omits `list_policies`, which the
end-to-end list contains), which is exactly the failure mode CLAUDE.md warns about: a mirror that
drifts and is "fixed" by editing the test.

Keep `composition_deduplicates_and_preserves_first_occurrence` (mode-expression dedup/first-occurrence
is a real contract that nothing else tests), `nlp_tools_hidden_for_non_git_root`,
`nlp_accepts_status_without_advertising_it`, and `symbol_does_not_accept_hidden_list_symbols`
(accepted-but-unadvertised is a distinct surface).

---

## `src/searchtools/tests.rs`

### `source_block_fields_are_publicly_constructible` (line 286) — **Tautology / Cannot-fail**

```rust
let _block = SourceBlock { label: "A".to_string(), path: "A.java".to_string(), … };
let _element = SummaryElement { path: "A.java".to_string(), … };
```

Zero assertions; the test is a struct literal. The property it "checks" (fields visible outside the
defining module) is already forced by the compiler at production call sites: `SourceBlock { … }`
literals appear in `src/searchtools_render.rs:1105` and `src/searchtools_service.rs:67`, and
`SummaryElement { … }` in `src/searchtools_render.rs:1163`. If visibility regressed, the crate would
not build with or without this test.

### `split_logical_lines_handles_crlf_lf_and_lone_cr` (line 274) — **Subsumed**

```rust
assert_eq!(super::split_logical_lines("a\r\nb\r\nc"), vec!["a", "b", "c"]);
```

`src/searchtools/sources.rs:788` is `pub(super) fn split_logical_lines(content: &str) -> Vec<&str> { model_context::logical_lines(content) }`
— a one-line pass-through. `src/model_context.rs::logical_lines_match_searchtools_behavior` (line 251)
asserts the identical five input/output pairs against the real implementation. Testing the wrapper
adds only "the delegation still compiles".

---

## `src/model_context.rs`

### `count_lines_handles_mixed_endings` (line 242) — **Subsumed**

```rust
assert_eq!(3, count_lines("a\r\nb\r\nc"));
assert_eq!(1, count_lines("a\r\n"));
```

`count_lines` is defined (line 17) as `logical_lines(content).len()`. The very next test,
`logical_lines_match_searchtools_behavior`, asserts the *full vectors* for the same five inputs;
asserting their lengths is strictly weaker and cannot fail independently.

---

## `src/analyzer/project.rs`

### `overlay_project_default_cap_constant_is_eight_mib` (line 1346) — **Tautology**

```rust
assert_eq!(DEFAULT_MAX_OVERLAY_BYTES, 8 * 1024 * 1024);
```

The assertion restates the constant's definition. The cap's *behavior* is covered by
`overlay_project_rejects_oversized_set_and_falls_back_to_disk`, `overlay_project_oversized_set_clears_prior_overlay`, and
`overlay_project_accepts_set_exactly_at_cap`, all of which use an explicit
`OverlayProject::with_max_bytes(16)` and are therefore unaffected by the default's value. Changing the
default is a one-line edit in two places; the test cannot say whether 8 MiB is the right number, only
that someone typed it twice.

---

## `src/code_quality/cognitive.rs`

`compute_cognitive_complexity` and `compute_cyclomatic_complexity` share the same path-resolution and
input-cap plumbing (`resolve_project_files` / `MAX_FILE_PATHS`, `src/code_quality/mod.rs:71`). Four
cognitive tests are line-for-line copies of the cyclomatic ones with the module name and default
threshold swapped, exercising only that shared code.

### `cognitive_missing_files_silently_skipped` (line 152) — **Subsumed**

```rust
file_paths: vec!["does/not/exist.rs".to_string()],
assert_eq!(result.report, "No methods exceeded the cognitive complexity threshold of 15.");
```
Identical body to `cyclomatic.rs::missing_files_are_silently_skipped` (line 219); the skip happens in
`resolve_project_files`, which is shared.

### `cognitive_absolute_paths_are_rejected_without_panic` (line 168) — **Subsumed**

```rust
file_paths: vec!["/etc/passwd".to_string()],
assert_eq!(result.report, "No methods exceeded the cognitive complexity threshold of 15.");
```
Identical body to `cyclomatic.rs::absolute_paths_are_rejected_without_panic` (line 235), same shared
resolver. (Neither version actually proves *rejection* — an implementation that read `/etc/passwd`
would also report nothing — but the cyclomatic copy at least keeps the "no panic" negative control in
one place.)

### `cognitive_file_paths_above_cap_marks_truncated` (line 184) — **Subsumed**

```rust
let mut paths = vec!["src/lib.rs".to_string(); MAX_FILE_PATHS];
paths.push("src/extra.rs".to_string());
assert!(result.truncated);
```
Byte-for-byte the same as `cyclomatic.rs::file_paths_above_cap_marks_truncated` (line 302); the
`input_truncated` flag is set by the shared `resolve_project_files`.

### `cognitive_threshold_zero_uses_default_of_fifteen` (line 134) — **Subsumed**

```rust
assert!(result.report.contains("threshold of 15"), "expected default 15: {}", result.report);
```
`cognitive_simple_function_returns_empty_report` (line 93) already passes `threshold: 0` and asserts
the *exact* string `"No methods exceeded the cognitive complexity threshold of 15."` — a strict
superset of a `contains("threshold of 15")` check on the same code path.

Cognitive-specific behavior (`cognitive_complex_function_is_flagged_without_source_suffix`,
`cognitive_complexity_equal_to_threshold_is_not_flagged`, `cognitive_simple_function_returns_empty_report`)
stays.

---

## `src/code_quality/cyclomatic.rs`

### `empty_file_paths_returns_empty_report` (line 267) — **Subsumed**

```rust
file_paths: vec![],
assert_eq!(result.report, "No methods exceeded the complexity threshold of 10.");
```

After `resolve_project_files`, an empty input vector and the nonexistent-path input of
`missing_files_are_silently_skipped` (line 219) produce the identical state (`files: []`) and run the
identical remaining code. Three more tests in the same file (`simple_function_under_threshold_…`,
`non_function_code_units_are_ignored`, `absolute_paths_are_rejected_…`) assert the same string; this
is the one whose input can produce nothing else by construction.

---

## `src/analyzer/kotlin/language.rs`

### `grammar_loads_through_tree_sitter_0_25` (line 70) — **Snapshot-of-today**

```rust
assert_eq!(language.abi_version(), 14);
assert_eq!(language.node_kind_count(), 378);
```

`378` is an internal count of the vendored grammar's node types. It says nothing about Bifrost: any
grammar bump breaks it, and the only possible fix is to edit the number. No other language pins this.
The ABI half is redundant too — a wrong ABI means the parser fails to load, which
`kotlin_source_and_script_parse_without_recovery` and every `kotlin/declarations.rs` test would
report immediately. Grammar drift is already handled structurally in two places: `epoch_for`
(`src/analyzer/store/epoch.rs:116-118`) hashes `abi_version` *and* `node_kind_count` into the cache
epoch, so a grammar change automatically invalidates persisted state, and
`assert_kind_table_matches_grammar` validates every mapped node kind against the live grammar.

---

## `src/analyzer/policy/render/human.rs`

### `all_finding_incomplete_reason_spellings_are_stable` (line 3106) — **Cannot-fail**

```rust
assert!(reasons.into_iter().all(|reason| !finding_incomplete_reason(reason).is_empty()));
```

Despite the name, it asserts no spelling. `finding_incomplete_reason` (line 2701) is a `const fn`
exhaustive match returning `&'static str` literals, so the only way to fail is to deliberately write
`""` in a match arm. It is not even a completeness check: the hardcoded `reasons` array omits
`FindingIncompleteReason::DeclaredNonExhaustive`. The real wire-stability contract is covered by the
neighboring tests that assert exact rendered strings (e.g.
`unsupported_analysis_capability_phrases_are_stable`, the `write_policy_diagnostic_code` tests).

---

## `src/analyzer/semantic/capabilities.rs`

### `registry_ordinals_labels_and_storage_are_exhaustive` (line 195) — **Tautology (partial removal)**

```rust
let expected = [ (SemanticCapability::Procedures, "procedures"), /* …30 more… */ ];
for (ordinal, (capability, label)) in expected.into_iter().enumerate() {
    assert_eq!(capability.index(), ordinal);
    assert_eq!(SemanticCapability::ALL[capability.index()], capability);
    assert_eq!(capability.label(), label);
}
```

The 31-entry `expected` table is a verbatim copy of the `semantic_capabilities! { … }` macro input
(line 36). `index()` is `self as usize` on a `#[repr(u8)]` enum and `ALL` is generated in declaration
order, so `capability.index() == ordinal` and `ALL[index()] == capability` hold by construction; and
`label()` is generated from the same `$label` literal the test re-types. Adding a capability requires
editing the table identically — the definition of "breaks on every legitimate change, passes on every
real bug".

**Recommended action is a trim, not a deletion**: drop the `expected` table and its loop, keep the four
tail assertions, which are genuinely load-bearing and cost nothing:

```rust
assert_eq!(iterated, SemanticCapability::ALL);
assert_eq!(SemanticCapability::ALL.len(), SemanticCapability::COUNT);
assert_eq!(capabilities.support.len(), SemanticCapability::COUNT);
// labels sort/dedup → unique-label check
```

---

## BORDERLINE — considered, kept

- **`src/analyzer/policy/adapter_seam_tests.rs:77` `sibling_module_can_install_both_production_adapters`** — no
  runtime assertions, but the file exists to prove the sealed-trait adapter API stays implementable from
  a sibling module without access to private fields. Compile-time coverage of a real visibility contract.
- **`src/analyzer/semantic/icfg.rs:3772` `workspace_icfg_provider_remains_copy` and
  `src/analyzer/semantic/workspace_oracle/dispatch.rs:2992` `workspace_semantic_oracle_remains_copy`** — `fn assert_copy<T: Copy>()`
  with no runtime assertion. Same class as above: a deliberate cheap-handle API pin that fails loudly at
  compile time. Weaker than the seam test (in-crate callers would likely break anyway), but two lines each.
- **`src/analyzer/semantic/ids.rs:1071` `current_semantic_ir_version_is_stable_and_nonzero`** — pins a 64-hex
  fingerprint. Reads as snapshot-of-today, but it is the cache-invalidation contract: an accidental change
  to the hash inputs silently mis-invalidates every persisted artifact. Kept as a regression pin.
  (`assert_ne!(current.as_bytes(), &[0u8; 32])` is dead weight inside it.)
- **`src/lsp/handlers/semantic_tokens.rs:328` `legend_is_stable_and_matches_code_unit_mapping`** — an exact
  ordered name list, but here order *is* the wire contract: LSP clients decode token types by index, and
  the test cross-checks `token_type_for_kind` indices against legend positions. Kept.
- **`src/analyzer/structural/search/tests.rs` `diagnostic_codes_have_exhaustive_stable_impacts_and_completion`** —
  a large hardcoded `(Code, Impact)` table, but `Impact` is not derived from `Code` anywhere in production
  code (each call site assigns both independently), so it is not a mirror of a canonical function.
- **`src/relevance.rs:3195` `benchmark_repeat_calls_with_cached_git_history`** — `#[ignore]`d, zero assertions,
  `eprintln!`-only; the ExecPlan that used it (`.agents/plans/most-relevant-files-weighted-recency-execplan.md`)
  is complete. Not recommended for removal because it is measurement tooling rather than a test, but it is
  the one `#[ignore]`d benchmark in the tree with no runbook or script referencing it, so it is a reasonable
  cleanup if the owner wants inline benchmarks consolidated under `src/benchmark/` / `weight_benchmark.rs`.
- **`src/code_quality/cyclomatic.rs:235` `absolute_paths_are_rejected_without_panic`** — its assertion cannot
  distinguish "rejected" from "read and found no functions". Kept as the single surviving negative control
  for the shared resolver after the cognitive duplicates go; worth renaming rather than deleting.
- **`src/analyzer/usages/inverted_edges.rs:1187` `reference_counts_keep_the_legacy_edge_payload_size`** —
  `size_of::<UsageReferenceCounts>() == 8`. Layout snapshot in form, memory-budget pin in intent (per-edge
  payload of a workspace-wide graph). Covered by the presumed-keep "counter/budget pin" bucket.
- **`src/analyzer/*/structural.rs` `*_kind_table_matches_grammar` (10 languages)** — look like table mirrors,
  but they validate each mapped kind name against the live tree-sitter grammar (`id_for_node_kind != 0`).
  These catch real grammar-upgrade breakage; explicit keeps.
- **`src/analyzer/policy/retained.rs:124` `vector_accounting_includes_spare_capacity_and_nested_owned_bytes`** —
  hand-computed expectation resembling the implementation's arithmetic, but with concrete literal inputs that
  would catch spare capacity being dropped from the accounting.
- **`src/nlp/keys.rs` `component_key_matches_prototype` / `composed_key_matches_prototype` / `b64_matches_python_urlsafe_nopad`** —
  hardcoded golden hashes, but they pin cross-implementation parity with the Python prototype recipe. Keeps.

---

## Coverage notes / confidence

- Fully enumerated: every file with an inline test module, scripted extraction of all 1,904 parseable test
  bodies, then heuristic ranking (zero-assertion bodies, `is_ok`-only bodies, `.len()`-only bodies,
  `vec![]`-of-string-literals equality, Debug/`to_string` equality, constant-vs-literal equality) followed by
  reading every flagged body plus full reads of the highest-count files.
- Zero-recommendation subtrees were each enumerated test-by-test: `src/analyzer/usages/**` + all per-language
  dirs; `src/analyzer/structural/**` + `src/analyzer/*.rs`; `src/analyzer/semantic/**`, `src/analyzer/store/**`,
  `src/cache_db.rs`, `src/schema_version.rs`, `src/compact_graph.rs`; `src/analyzer/policy/**`,
  `src/analyzer/typestate/**`, `src/analyzer/dataflow/**` (`src/analyzer/taint/**` has no inline tests).
- Lower-confidence corners: `src/analyzer/structural/search/tests.rs` (4,446 lines) and
  `src/analyzer/tree_sitter_analyzer.rs` (48 tests) were skimmed by name plus targeted reads rather than read
  end-to-end; both are dense with cache/budget/cancellation machinery and are unlikely to hide tautologies,
  but a line-by-line pass was not done.
