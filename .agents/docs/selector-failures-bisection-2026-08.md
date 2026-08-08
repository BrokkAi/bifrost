# Bisection: four tolerated selector-resolution test failures

**Status: RESOLVED (2026-08-08).** All four tests are green. `6da767e9` is
fixed by `7a22bf53` ("Split the file anchor before the missing-directory
bailout"); `7e7ac9ee` is fixed by `8a27e0cd` ("Seek the identifier index by the
spelling callers address (#1063)"). Both original commits' latency purposes are
preserved and pinned -- see "Resolution" at the end of this document, which
also corrects one of the mechanism sections below: by the time of the fix the
`7e7ac9ee` gate was no longer the sole cause.

The body below is the bisection as written, unedited.

Repo: /mnt/optane/bifrost-nlp, branch bifrost-nlp-ft. Task HEAD: `37540fb3` (2026-08-08).
Method: read-only main tree; all builds/tests ran in a single detached scratch worktree
(`git worktree add --detach`) checked out to successive candidate commits, built with
`cargo test --test suite_symbols` (or the pre-consolidation standalone binary name for
commits older than the suite-consolidation), filtered to just the four tests. Worktree
removed and pruned at the end; main tree was never built or modified.

## Bottom line

Two commits, not four bugs. Both landed the same morning, back-to-back, as latency
fast-paths from the CodeScaleBench grep-hard cleanup work, and both are too aggressive:
they treat "the fast/complete index found nothing" as conclusive, for selector shapes
the change's author did not consider.

| Test | Verdict | First-bad commit |
|---|---|---|
| `summaries_route_file_anchored_selector_with_extension_like_symbol_member` | REGRESSION | `6da767e9` |
| `summaries_and_ancestors_accept_js_file_anchored_selectors` | REGRESSION | `6da767e9` |
| `csharp_generic_type_resolves_without_arity_spelling` | REGRESSION | `7e7ac9ee` |
| `scan_usages_resolves_public_typescript_static_method_symbol` | REGRESSION | `7e7ac9ee` |

Naming correction: the task listed `csharp_generic_type_resolves_without_arity_spelling`
under module `searchtools_fuzzy_symbol_lookup`. It actually lives in
`tests/suite_symbols/searchtools_definition_selectors.rs` (module
`searchtools_definition_selectors`); confirmed by exact-string grep across the tree.

## Test locations

- `tests/suite_symbols/searchtools_definition_selectors.rs:2230` — `csharp_generic_type_resolves_without_arity_spelling`
- `tests/suite_symbols/searchtools_fuzzy_symbol_lookup.rs:364` — `scan_usages_resolves_public_typescript_static_method_symbol`
- `tests/suite_symbols/searchtools_definition_selectors.rs:856` — `summaries_route_file_anchored_selector_with_extension_like_symbol_member`
- `tests/suite_symbols/searchtools_definition_selectors.rs:746` — `summaries_and_ancestors_accept_js_file_anchored_selectors`

## Confirmed failure at task HEAD (37540fb3)

All four red, matching the shapes in the task and in the `searchtools-too-broad-scope-guards`
ExecPlan's stash-verification note (`.agents/plans/searchtools-too-broad-scope-guards.md`,
Surprises & Discoveries):

- `summaries_route_file_anchored_selector_with_extension_like_symbol_member` and
  `summaries_and_ancestors_accept_js_file_anchored_selectors`: `get_summaries` on
  `src/a.js#styles.css` / `src/a.js#Widget` returns `not_found` with note
  `"no workspace file matched this path; check the relative path or pass a glob pattern"`
  (`FILE_NOT_FOUND_NOTE`, `crates/bifrost-analysis/src/searchtools/selectors.rs:66`).
- `csharp_generic_type_resolves_without_arity_spelling`: `get_symbol_sources("CountingCollection")`
  returns `not_found` with note `"no symbol matched; try search_symbols with a substring or
  regex pattern"` (`SYMBOL_NOT_FOUND_NOTE`, `selectors.rs:63`).
- `scan_usages_resolves_public_typescript_static_method_symbol`: `search_symbols` still finds
  `ApiClient.create` fine, but `scan_usages_by_reference(["ApiClient.create"])` comes back
  `NotFound` with the same `SYMBOL_NOT_FOUND_NOTE` message.

## Bisection

Introduction commits (all four are old; none is close to the 2026-08-06 "known red" date):

| Test | Introduced by | Date |
|---|---|---|
| `summaries_and_ancestors_accept_js_file_anchored_selectors` | `b6c9e02f` "Adopt file-anchored definition selectors..." | 2026-07-03 |
| `summaries_route_file_anchored_selector_with_extension_like_symbol_member` | `93056285` "Carry a recovery note on AmbiguousSymbol..." | 2026-07-03 |
| `scan_usages_resolves_public_typescript_static_method_symbol` | `ec9ed178` "Finish JS/TS usagebench parity fixes" | 2026-07-06 |
| `csharp_generic_type_resolves_without_arity_spelling` | `eb092e98` "symbol lookup: offer arity-free aliases for C# generic types" (closed issue #1063) | 2026-07-22 |

Probe results (all four tests run together at each probed commit, except the two
pre-consolidation spot checks which used the old standalone binary names):

| Commit | Date | Result |
|---|---|---|
| `d7eabd9c` | 2026-08-05 23:59 | all 4 GREEN |
| `7a3ffd96` "Use Git paths for clean workspace enumeration" | 2026-08-06 02:14 | all 4 GREEN |
| `e32cad12` "Use native Git status for dirty workspace paths" | 2026-08-06 02:41 | all 4 GREEN |
| **`6da767e9`** "Avoid definition-index fallback for missing directory paths" | 2026-08-06 03:06 | file-anchored 2 RED, csharp+scan_usages 2 GREEN |
| **`7e7ac9ee`** "Bound qualified symbol misses to the complete index" | 2026-08-06 04:00 | all 4 RED |
| `70564619`, `c0220250`, `6f729be7`, `689b75f3` (later coarse probes, superseded) | 2026-08-06/07 | all 4 RED |
| `37540fb3` (task HEAD) | 2026-08-08 | all 4 RED, byte-identical messages |

`6da767e9` and `7e7ac9ee` are adjacent commits in this branch's linear history
(`git log --oneline --reverse d7eabd9c..37540fb3`), so both boundaries are exact —
no further narrowing possible or needed.

**Anti-liveness-family spot checks** (the prior-art concern: a bug fixed once and
unmasked again later, which is what happened with issue_1450/1451). Checked
independently, well before the found regressions, using the pre-consolidation
standalone test binaries:
- File-anchored pair GREEN at `f4e6650a` (2026-07-19), roughly the midpoint between
  their 2026-07-03 introduction and the 2026-08-06 regression.
- csharp + scan_usages pair GREEN at `f1f9e6f6` (2026-08-01), after csharp's
  2026-07-22 introduction and 5 days before the regression.

No red-then-green-then-red pattern found for any of the four; each was continuously
green from introduction to the single first-bad commit identified above.

## Mechanism: `6da767e9` (file-anchored `get_summaries`/`get_symbol_ancestors` tests)

`crates/bifrost-analysis/src/searchtools/summaries.rs`, in
`summarize_symbol_targets_with_cancellation` (current line ~530, added by this commit):

```rust
if (target.contains('/') || target.contains('\\'))
    && !looks_like_explicit_source_file_target(&target)
{
    not_found.push(file_not_found_input(target));
    continue;
}
```

Purpose per the commit message: stop a missing relative-directory target (e.g. a Go
import-path typo) from falling into fuzzy/package resolution, which was building a
399k-row definition index on `get_summaries` (#1608). But the guard runs before any
file-anchor (`path#symbol`) splitting. A file-anchored selector like `src/a.js#Widget`
contains `/` and is not itself "an explicit source file target" (it's file+anchor), so
it is misclassified as a missing directory/package path and short-circuited to
`not_found` with `FILE_NOT_FOUND_NOTE` — even though `src/a.js` is a real file in the
fixture and the anchor-aware resolver, one function away, would have found it. This is
strictly a `get_summaries` regression: `get_symbol_sources` (`sources.rs`) has its own,
unaffected resolution path, which is why `csharp_generic_type_resolves_without_arity_spelling`
(which only calls `get_symbol_sources`, including a `path#symbol`-shaped selector)
stayed green through this commit.

## Mechanism: `7e7ac9ee` (csharp arity-free / TS qualified `scan_usages` tests)

`crates/bifrost-analysis/src/analyzer/symbol_lookup.rs`, in `suffix_resolution_from_index`
(current lines 548 and 560, added by this commit):

```rust
let no_indexed_matches = exact_matches.is_empty() && exact_suffix_matches.is_empty();
...
if analyzer.has_complete_symbol_lookup_index() && no_indexed_matches {
    return Some(CodeUnitResolution::NotFound);
}
```

Purpose per the commit message/plan notes: on a "complete" persisted index, a miss on
the identifier-exact-match stage (stage 1) is treated as conclusive, skipping the
expensive stage-2 regex/pattern table scan (`suffix_resolution.pattern_stage`), which
had cost 53-90s per call on CodeScale repos. The assumption — "if the identifier index
found no alias for the terminal, the pattern regex can't find anything either" — is
false for two shapes stage 1 doesn't cover:
- C# generic types are indexed with CLR arity (`CountingCollection\`1`); the bare
  arity-free alias (`CountingCollection`) was only ever reachable through the stage-2
  scan (this is exactly what `eb092e98`/#1063 had fixed by adding an arity-free alias
  variant — `7e7ac9ee` re-breaks it by skipping the stage that alias needs).
- The TypeScript case (`ApiClient.create`) is owner-qualified; stage 1's exact-index
  terminal lookup misses it the same way, and stage 2 was the path that resolved it.

Both `CSharpAnalyzer` and `TypescriptAnalyzer` (via their common tree-sitter delegate)
now advertise `has_complete_symbol_lookup_index() == true`
(`crates/bifrost-analysis/src/analyzer/csharp/mod.rs`,
`crates/bifrost-analysis/src/analyzer/javascript/mod.rs` and the shared inner
implementation), so both trip the new early return.

## The 2ba5dda4 "already broken on baseline" note — does not apply here

The task asked to check specifically whether the csharp test's failure is the same
thing the `2ba5dda4`-era checkpoint called "already broken on baseline". It is not.
`.agents/docs/codescale-grep-hard-checkpoint-2026-08-07.md`'s "C# arity spellings
(`Name`+backtick+digit) are not seekable and were already broken on baseline" is about
**arity-full** selectors (`Name\`1`) not being reachable through the new *seek*
optimization (a performance/completeness note about the index-seek path added by
`2ba5dda4`, landed 2026-08-07, one day after our regression). Our test
(`csharp_generic_type_resolves_without_arity_spelling`) exercises the opposite shape —
**arity-free** natural spellings — and is a correctness regression (not_found, not slow)
introduced the day before, by `7e7ac9ee`. The spot check above shows it passed cleanly
from its introduction (`eb092e98`, 2026-07-22, closing issue #1063) through 2026-08-01,
so "already broken on baseline" is not an accurate description of this test; it is a
clean regression with a known mechanism.

## Issue tracking

`gh issue list` search found:
- #1063 "C# generic types are unresolvable by natural (arity-free) spellings" —
  CLOSED (fixed by `eb092e98`; this is the issue `7e7ac9ee` re-breaks). No open issue
  currently references the re-break.
- No open issue matches `has_complete_symbol_lookup_index`, `suffix_resolution_from_index`,
  "qualified symbol miss", "file anchored selector", or "no workspace file matched" language
  for either `6da767e9` or `7e7ac9ee`.

Recommendation (not actioned — this task was read-only/no-fix): file one issue for each
commit (or one issue covering both, since they landed together and share a motivation),
noting the shared "conclusive miss" pattern so a fix doesn't reintroduce the original
399k-row-scan / 53-90s-scan costs those commits were solving.

## Cleanup

Scratch worktree `$SCRATCHPAD/bisect-wt/wt-head` removed via `git worktree remove --force`,
`git worktree prune -v` run, `git worktree list` confirms it is gone. Main tree
(`/mnt/optane/bifrost-nlp`) was never built or checked out during this task; its working
tree changes (owned by another agent) are untouched and unrelated to this investigation.
Note: the main tree's HEAD moved from `37540fb3` to `38800fe5` between the start and end
of this task (another agent's ongoing work) — irrelevant to the bisection, which pinned
every probe to explicit SHAs in a detached worktree.

## Resolution (2026-08-08)

### `6da767e9` -- fixed by `7a22bf53`

Mechanism as bisected, confirmed at the line. The missing-directory bailout in
`summarize_symbol_targets_with_cancellation` ran before any anchor splitting,
and `looks_like_explicit_source_file_target("src/a.js#Widget")` is false
because the extension of the whole string is `js#Widget`.

The fix runs `split_workspace_definition_selector` -- the same splitter
`resolve_selectable_definitions` uses one call below, so the two cannot
disagree -- and skips the bailout for a `FileAnchored` selector.

What survives of `6da767e9`'s purpose: all of it. The #1608 case
(`pkg/admission/plugin/webhook`, a missing Go directory path) still bails out
before any definition-index work, because the splitter reads no definitions --
a target with no `#` never reaches the `anchor_is_file` check, and a
slash-bearing anchor is accepted on shape alone. Pinned by
`missing_extensionless_directory_paths_skip_package_and_fuzzy_resolution`
(`searchtools/tests.rs`, the scan-counter pin `6da767e9` itself added:
0 `search_definitions` calls, 0 `analyzed_files` calls).

### `7e7ac9ee` -- fixed by `8a27e0cd`, and the mechanism had moved

The "Mechanism: `7e7ac9ee`" section above is right about the first-bad commit
and right about the shapes, but by task HEAD it was no longer a complete
account of *why the tests were still red*. Two probes at HEAD:

| Probe | csharp | scan_usages |
|---|---|---|
| `7e7ac9ee`'s gate disabled (`suffix_stage_from_index`, line ~560) | RED | RED |
| `0b35bb12`'s gate disabled (`resolve_codeunit_fuzzy_bounded_with`, line ~273) | RED | RED |
| both disabled | GREEN | GREEN |

`0b35bb12` (#1758, 2026-08-07) added a second conclusive-miss gate that decides
fuzzy ambiguity from the indexed candidates instead of `get_all_declarations()`.
It rests on the same claim, stated in its own commit message: "An alias tail is
a spelling of the persisted `identifier`". So removing `7e7ac9ee`'s gate alone
changes nothing -- the second gate answers from the same empty maps.

Neither gate is deletable: green required both off, i.e. restoring the 443.1 s /
4.4 GB `get_all_declarations()` scan `0b35bb12` removed.

**The real defect is the seek, not the gates.** The claim both gates rest on is
false for two languages, and false by design in both cases.
`symbol_path_variants` derives lookup aliases from the *source* spelling, which
`source_identifier_for_target` already defines as differing from the persisted
`identifier` for exactly two languages:

- C#: a generic type is persisted as ``CountingCollection`1``; #1063
  (`eb092e98`) deliberately made the arity-free `CountingCollection` an alias.
- TypeScript: a static member is persisted as `create$static`; the
  `$`-splitting variant makes `create` and `ApiClient.create` aliases.

Instrumented proof on the two fixtures:

```
ident_seek("CountingCollection") -> []
  ScottPlot.CountingCollection`1   identifier=CountingCollection`1
    aliases {[CountingCollection], [ScottPlot, CountingCollection], ...}
ident_seek("create") -> []
  ApiClient.create$static          identifier=create$static
    aliases {[ApiClient, create], [create], ...}
```

While symbol lookup still ended in a whole-workspace scan the hole only cost
time; the gates turned it into a wrong `NotFound`.

The fix widens the seek and keeps both gates.
`decorated_identifier_seeks(language, source_identifier)` (in `common.rs`, next
to `source_identifier_for_target` so the pair cannot drift) returns the extra
index keys: an exact `create$static` for TypeScript, and a prefix range for C#
because CLR arity is a digit run of no fixed width.
`lookup_declarations_by_identifier` seeks those and verifies each row with
`identifier_addresses_target`. The prefix range is a range over the existing
`idx_code_units_lang_identifier_lookup`, so no migration and no new index.

What survives of `7e7ac9ee`'s purpose: all of it, and `0b35bb12`'s and
`2ba5dda4`'s too. Both conclusive-miss gates are unchanged and still fire; what
changed is that the miss they act on is now a real miss. Pins:

- `identifier_prefix_lookup_seeks_the_identifier_index` (store EQP): the new
  prefix query plans as `SEARCH units USING INDEX
  idx_code_units_lang_identifier_lookup`, never `SCAN units`.
- `issue_1063_decorated_identifier_spellings_resolve_without_a_full_declaration_scan`:
  both decorated spellings and a genuine miss resolve with
  `full_declaration_scan_count_for_test() == 0`.
- Unchanged and still green: `complete_symbol_index_miss_skips_broad_fuzzy_scan`
  (#1688), `complete_symbol_index_skips_enclosing_owner_regex_scan`,
  `issue_1758_fuzzy_resolution_decides_ambiguity_without_a_full_declaration_scan`,
  `issue_1688_qualified_go_selector_resolves_without_a_full_declaration_scan`.

### Issue tracking

#1063 was reopened and commented: it was re-broken by `7e7ac9ee` on 2026-08-06
and is fixed again by `8a27e0cd`.
`csharp_generic_type_resolves_without_arity_spelling` is its regression pin and
names the issue in a comment above the test.

### Transferable lesson

A gate that treats "the fast index found nothing" as conclusive inherits every
hole in that index. Both commits here made the same trade correctly and both
were wrong for the same reason: the index is keyed on the persisted spelling,
while resolution compares against aliases built from the source spelling, and
nothing enforced that the two agree. When a fast path is added on the strength
of a claim like "the index has already seen everything a scan could match",
that claim is a testable invariant, not a comment.
