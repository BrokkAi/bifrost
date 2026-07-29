# Test suite audit — consolidated (2026-07)

Four parallel auditors swept the whole suite (291 integration files / ~6,300 tests in `tests/`,
~2,100 inline tests in 257 `src/` files). Per-slice detail lives in
`test-audit-2026-07-part{1,2,3,4}.md`. This file is the coordinator's reviewed merge: every
headline claim was independently spot-checked against the working tree before inclusion, and one
part-4 claim was corrected (below).

## Headline

**~67 removal recommendations out of ~8,400 tests (~0.8%)** — 63 whole tests plus 4
assertion/block-level trims. Zero snapshot-of-today findings in `tests/`; the
implementation-mirror genus CLAUDE.md warns about is nearly extinct (5 `--help` substring tests
and 2 inline registry expansions are the only survivors). The suite is overwhelmingly
behavior-focused: no `is_ok()`-only bodies anywhere in the 291 integration files, dense negative
controls, issue-numbered regression pins throughout.

| Slice | Recommended | Of | Category mix |
|---|---|---|---|
| part 1 (tests/ a–j) | 22 + 2 blocks | 1,880 | 4 taut · 5 mirror · 12 subsumed · 1 cannot-fail |
| part 2 (tests/ j–r) | 15 + 3 partial | ~1,700 | 7 taut · 4 cannot-fail · 6 subsumed · 1 snapshot |
| part 3 (tests/ r–z) | 13 + 3 assertions | 2,404 | 1 taut · 11 subsumed · 1 cannot-fail |
| part 4 (src/ inline) | 13 + 1 trim | ~2,100 | 3 taut · 1 mirror · 8 subsumed · 2 cannot-fail · 1 snapshot |

## Coordinator review notes

- Spot-verified in source: the `EXACT_EQUIVALENCE` constant tautology (p2), the X ⊆ X assertion
  (p3 — correctly scoped as an assertion-level trim, not a whole-test removal), the
  `any(..).then_some(self)` capability-provider cannot-fail family (p2, matches
  `multi_analyzer.rs:1140`), the byte-identical Scala pair (p1, agent diffed bodies), and the
  registry-expansion mirrors (p4).
- **Corrected claim**: part 4 asserted `searchtools_expands_to_all_toolsets_in_order` had
  "already drifted (omits list_policies)". False — the expected list contains `list_policies`
  (`mcp_registry.rs:311`); CI is green. The **subsumption core still holds**: the full
  searchtools list including both nlp branches is pinned end-to-end through a real stdio server
  by `bifrost_searchtools_server_speaks_mcp_stdio`, and the core expansion by
  `bifrost_split_servers_publish_expected_tool_sets`. Both inline expansion tests remain
  recommended for removal as subsumed mirrors — on the corrected rationale.
- Auditor discrimination was good on both sides: p3 overrode its own sub-auditor to KEEP the
  `usage_finder_routes_*` per-language dispatch matrix (membership is the contract), and p1
  demoted an `issue_1121` subsumption to borderline rather than breaking the presumed-keep rule.

## Owner decisions needed (not included in the removal count)

1. **`rust_analyzer_parity.rs` vs `rust_analyzer_test.rs`** — the parity file is a port of the
   predecessor Java suite; three test pairs are genuine duplicates. Pick a side per pair (p3
   lists them); today both are paid for. Recommendation: keep the parity side where it is a
   strict superset (`rust_type_aliases_are_marked`), keep the `rust_analyzer_test.rs` side
   elsewhere.
2. **`issue_1121` / `issue_1093` internal subsumption** — two nested-class pins are exact
   subsets of stronger tests in the same files. Presumed-keep protected them; flagged for the
   owner's call (p1 borderline section).
3. **Strengthen-not-delete list** (would make several kept tests actually load-bearing):
   `usage_finder_routes_*` should all assert `query.graph_failure.is_none()`; three
   `usages_scala_graph_test.rs` decoy fixtures need their missing `assert_no_hit_contains`
   lines; `structural_search_cross_language.rs` L189 should gain an ordered-Vec row check when
   L107 is removed; `cyclomatic.rs::absolute_paths_are_rejected_without_panic` needs a rename or
   stronger assertion; `rust_dead_code_smells.rs` threshold test should narrow its
   verbatim-header assertion to the behavioral tail.
4. **Name-is-a-coverage-lie**: `javascript_double_sigil_names_are_searchable` is a byte-for-byte
   copy of a Scala test and touches no JS. If JS double-sigil searchability is a real contract,
   it needs a genuine JS fixture written; otherwise delete with the rest.

## Execution plan (pending owner sign-off)

Remove the 63 tests + 4 trims in one commit (mechanical; the four part files carry exact
test names and rationale), apply the strengthen list in a second commit, and leave the two
owner-decision pairs for explicit direction. Full suite + clippy gate after each.
