# Usage-graph phase: read-only investigation for the design

Repository `/mnt/optane/bifrost-nlp`, branch `bifrost-nlp-ft`, HEAD `3d57cafd`.
Evidence sources: the source tree, plus the surviving run-3 span summaries and
`/usr/bin/time -v` records under
`.../scratchpad/m4r3/` (`span-summaries.txt`, `r-ext-v3-b*.time`). Raw span logs
were truncated after run 3, so nesting attribution below is from code, not from
span parents; those claims are marked **inferred**.

Nothing was changed. No commits, no issues.

---

## 0. Headline, stated once

**`RustReferenceContext` is a fallback that is built eagerly.**

The scan proves a hit through the v2 fact-backed
`RustAnalyzer::usage_reference_at`. The reference context is consulted only when
that returns non-`Exact`
(`crates/bifrost-analysis/src/analyzer/usages/rust_graph/extractor.rs:486-505`
and `:558-596`: `if ... usage_reference_at(...).is_exact() { return true }` then
`self.refs.resolve_bare(...)` / `reference_context_path_matches_target(...)`).

Yet it is constructed unconditionally, once per candidate file, *before* the
scan of that file begins
(`extractor.rs:130` in `scan_files_for_target`, `extractor.rs:1160` in
`scan_files_for_member_target`). Every candidate pays the whole construction
whether or not the fallback is ever reached. **Confirmed** by reading those call
sites.

Its construction is not a per-site lookup: it eagerly enumerates and canonically
resolves the *entire export surface* of every module the file namespace-imports
or glob-imports, transitively through `pub use *`
(`graph_support.rs:597-621`, `:708-763`, `:845-865`, `:876-945`).

That is the 1,062.51 s of `RustAnalyzer::build_reference_context` over n=1,115
inside a 1,034.43 s `usages::graph_find_usages`.

---

## 1. Context anatomy

`RustReferenceContext` — `crates/bifrost-analysis/src/analyzer/rust/graph_support.rs:37-53`.

| field | what it is | construction cost | size driver | consumers (granularity) | replaceable by v2 rows? |
|---|---|---|---|---|---|
| `package: String` | `rust_package_name(file)` | pure path arithmetic, `graph_support.rs:632` | one short string | `resolve_scoped_owner` rooted-path arm (`:100-105`) | n/a — already free; no row needed |
| `crate_package: String` | `rust_crate_root_package(file)` | pure path arithmetic, `:633` | one short string | same | n/a |
| `named: HashMap<local, fqn>` | `use path::Item;` bindings | 1 store round trip for the binder (`import_binder_of` -> `import_info_of`, `tree_sitter_analyzer.rs:7524`), then per binding a `resolve_module_files` + `canonical_export_fqn` re-export walk (`graph_support.rs:578-596`), plus **all** of this file's own re-exports and star re-exports (`insert_reexport_reference_bindings`, `:765-843`) | one entry per named import + one per re-exported name (a barrel `lib.rs` can be thousands) | `resolve_bare` (per token), `bare_names_resolving_to` (per file, gate seeding) | **Yes, mostly.** `rust_import_targets` already carries `module_path/bound_name/imported_name/visibility/owner_module/local_extent`; `rust_exports` carries the re-export rows. `RustUsageWalks::forward_import_edges_of` + `origin_routes_of` already compose the resolved (written path -> origin identity) relation *with* domain and byte-extent gating this field lacks (`usage_walks.rs:986`, `:1351`). |
| `namespace: HashMap<local, package>` | `use crate::util;` | `resolve_module_package` per binding (`:597-601`) — cargo routes + path arithmetic, cheap | one entry per namespace import | `resolve_bare` fallback, `resolve_scoped_owner` (`:97-99`) | **Yes.** Same `rust_import_targets` row plus `cargo_routes`; `RustImportEdgeKind::Namespace` is the same fact. |
| `scoped: HashMap<"local::Name", fqn>` | *every export name of every namespace-imported module*, transitively through `pub use *` | **the wall.** `insert_namespace_export_bindings` (`:708-735`) does `collect_export_names_from_files` (walks the star-reexport closure, `export_index_of` per reachable file) then `canonical_export_fqn_from_files` **per name**, each of which re-walks the re-export graph (`forward_exported_targets_from_files_with_progress`, `:876-945`) and issues `definitions()` store lookups | **unbounded**: |namespace imports| x |exports of the reachable module closure|. On rustc a single `use rustc_middle::ty;` materialises thousands of entries | `resolve_scoped`, `resolve_scoped_owner` (`:81-111`) — used per *token* in `reference_context_path_fqn` (`extractor.rs:599-623`), only on the non-`Exact` fallback path | **Yes, per-site.** The question "what does `local::Name` mean at byte B in file F" is exactly `usage_reference_at(file, seeds, segments, byte, ...)` (`usage.rs:1140`), answered from `rust_module_scopes` (`module_at_byte`) + `origin_routes_of`. Precomputing the whole cross-product to answer one token is the design error. |
| `glob: HashMap<name, fqn>` | unambiguous `use path::*;` names | same as `scoped`: `collect_glob_reference_bindings` (`:737-763`) enumerates the whole export closure and canonicalises each name | unbounded, same shape | `resolve_bare` fallback (`:64`) | **Yes**, same argument; `RustImportEdgeKind::Glob` + `origin_routes_of` already handle globs per site. |
| `same_file: HashMap<ident, fqn>` | `self.declarations(file)` | one declaration read (`:567-570`) | one entry per declaration in the file | `resolve_bare` (`:63`), `resolve_scoped_owner` (`:108`) | **Yes** — this is `code_units` for the blob, and `RustDeclarationFacts` (`rust_declaration_facts_of`, `rust/mod.rs:172`) is the same thing already memoized. |

Two instances exist per file: `reference_contexts` (reverse) and
`forward_reference_contexts` (forward), differing only by the `forward: bool`
that selects `forward_exported_targets_from_files` over
`exported_targets_from_files` (`graph_support.rs:666-671`). Both go through the
same `build_reference_context_with_progress`, so both count under the same span
name — which is why **n=1,115 can exceed the 1,000-candidate cap**
(`DEFAULT_MAX_FILES = 1000`, `usages/finder.rs:26`; `max_candidate_files` in
`searchtools/scan_usages.rs:881`). The reverse context is built by the scan
(`extractor.rs:130`), the forward one by the resolver's
`RustDefinitionProvider::forward_reference_context` default
(`rust_graph/resolver.rs:35-41`) and by `get_definition/rust.rs:88-91`.
**Duplication is real: the same file can pay the whole export-closure walk
twice**, and the two results differ only in re-export traversal direction.

### Cache budget it lives under

- `reference_contexts` and `forward_reference_contexts` are each a weighted
  `Cache` at `memo_budget / 8` (`rust/mod.rs:539-543`, `:578-582`, `:829-836`,
  `:858-865`), with `memo_budget = AnalyzerConfig::memo_cache_budget_bytes()`
  defaulting to **256 MiB** (`bifrost-core/src/analyzer/config.rs:333`). So each
  cache believes it is bounded at **32 MiB**.
- **The weigher is wrong.** `weight_reference_context`
  (`rust/cache.rs:9-23`) sums `named + namespace + same_file` only. It does
  **not** count `scoped` or `glob` — precisely the two unbounded maps. On a
  glob-heavy tree the caches can hold gigabytes while their accounting reads
  well under 64 MiB total. **Confirmed by reading the weigher.** This is the
  single most concrete memory defect found.
- Cache lifetime: dropped on `update`/`update_all` (`graph_support.rs:500-504`),
  i.e. per analyzer generation, and pinned by
  `forward_reference_context_is_reused_within_analyzer_generation`
  (`graph_support.rs:1861-1888`).

### Cancellation

`extractor.rs:130` / `:1160` call `rust.reference_context_of(file)`, the
*infallible* form, which passes `&|| true` as the progress predicate
(`graph_support.rs:505-508`). Therefore `reference_context_checkpoint` **never
trips inside a scan-driven context build**. A single build is uninterruptible
end to end. This is the exact mechanism behind run 3's observation that "whatever
polls inside `RustAnalyzer::build_reference_context` polls too rarely" — it does
not poll at all. The only cancellation checks are before and after the call, in
the rayon closure (`extractor.rs:127-133`). **Confirmed.**

---

## 2. `graph_find_usages` end to end, and where the 1,034 s / 23.4 GB go

### Path

1. `UsageFinder::query_with_provider_and_source_budget`
   (`usages/finder.rs:146`) opens `AnalyzerQueryScope::new(analyzer)` (`:155`),
   runs `usages::candidate_discovery` (`:173-233`), truncates to `max_files`
   (`:213-216`), admits by source bytes (`:217-228`), then opens
   `usages::graph_find_usages` (`:240`) and dispatches by language (`:719-812`).
2. `RustQueryResolver::find_usages` (`usages/rust_graph.rs:100-204`):
   canonicalise target -> `infer_graph_seeds` -> `usage_binding_seeds` ->
   `effective_scan_files` -> `scan_files_for_target` or
   `scan_files_for_member_target`.
3. `effective_scan_files` (`extractor.rs:37-86`) intersects the candidate set
   with `get_analyzed_files()`; if that is empty and the scope is not
   authoritative it falls back to a **whole-workspace textual sweep**
   (`:64-77` — `file.read_to_string()` per analyzed file). Not hit in the run 3
   cell (candidates were non-empty), but it is a latent whole-tree read.
4. `scan_files_for_target` (`extractor.rs:89-198`): `par_iter` over candidates.
   Per file: `prepared_syntax` (parse or cache hit) -> `RustLexicalScopeIndex::new`
   -> **`reference_context_of`** -> `usage_binding_names` -> `rust_local_use_alias_names`
   (whole-tree walk of the file's AST) -> `scan_node` -> `record_module_qualified_hits`
   -> merge `local_hits` into a shared `Mutex<BTreeSet<UsageHit>>`.
   `scan_files_for_member_target` (`:1115-1275`) is the same shape with more
   per-file work (`trait_implementer_names`, receiver inference).

### Time attribution (600 s budget cell, v3, `span-summaries.txt:185-207`)

| span | n | thread-summed s |
|---|---:|---:|
| `searchtools::scan_usages_backend` | 1 | 1145.49 |
| `usages::graph_find_usages` | 1 | **1034.43** |
| `RustAnalyzer::build_reference_context` | 1115 | **1062.51** |
| `project::collect_workspace_files` | 2701 | 983.23 |
| `RustAnalyzer::export_index_of_declarations` | 3127 | 293.82 |
| `gitblob::dirty_worktree_paths` | 2702 | 234.20 |
| `usages::candidate_discovery` | 1 | 108.59 |
| `sql_definition_candidates.rows[*]` | 148226 | 2319.96 |
| `TreeSitterAnalyzer::global_usage_definition_index_build` | 5 | 3.42 |

Readings:

- **Context construction *is* the graph phase.** 1062.51 s thread-summed against
  a 1034.43 s wall means the parallel scan is almost entirely inside
  `build_reference_context`; the tree-walking scan itself is noise beside it.
  Mean ~0.95 s per context. **Confirmed.**
- `sql_definition_candidates.rows` grows from 98,553 (120 s cell, discovery only)
  to 148,226 (600 s cell) — so the graph phase alone issues **~50,000 extra
  definition-candidate store queries**, all from inside context construction
  (`single_rust_target_fqn`, `rust_member_reexport_targets` at
  `graph_support.rs:947-965`, `rust_declaration_targets_in_files_*`).
- `export_index_of_declarations` n=3,127 at 293.82 s is the export-closure walk:
  `collect_export_names_from_files` and
  `forward_exported_targets_from_files_with_progress` call `export_index_of`
  once per reachable module file per name resolution.
- `global_usage_definition_index` is **not** a time wall (3.42 s, n=5 — once per
  language delegate, merged by `multi_analyzer.rs:773-785`). It is still a
  whole-workspace RAM materialisation of every declaration keyed ten ways
  (`global_usage_definition_index.rs:13-25`), built lazily on the first
  `analyzer.global_usage_definition_index()` call, which is at the top of
  `scan_files_for_target` (`extractor.rs:98`) and
  `scan_files_for_member_target` (`extractor.rs:1136`), and then pinned in a
  `OnceLock` for process lifetime (`tree_sitter_analyzer.rs:8181-8210`). Its RSS
  contribution is **inferred**, not measured.

### RSS attribution — this corrects the kill-gate report

`/usr/bin/time -v` maximum RSS from the surviving `.time` files:

| budget | wall | max RSS | `usages::graph_find_usages` |
|---|---:|---:|---|
| 30 s | 33.49 s | **15.46 GiB** (16,206,596 KB) | absent from span summary |
| 60 s | 63.82 s | **15.75 GiB** (16,516,696 KB) | absent |
| 120 s | 135.35 s | **16.58 GiB** (17,387,160 KB) | 15.39 s |
| 600 s | 1313.58 s | **23.42 GiB** (24,561,920 KB) | 1034.43 s |

So **~15.5 GB accrues before the graph phase runs at all** — that is candidate
discovery plus analyzer construction, at a budget where the graph phase never
started. The graph phase's marginal cost is ~1.1 GB for 15 s of it and ~7.9 GB
for 1,034 s of it, i.e. it grows with candidates processed rather than being the
whole story. Run 3's summary sentence "RSS tracks the usage-graph phase
specifically" was drawn from the cell-(b) contrast (653 s at 0.66 GB, symbol
resolution only) and is **too strong**: cell (b) is 0.66 GB because it never
reaches *discovery*, not because it never reaches the graph.

Where the graph phase's ~8 GB plausibly sits (ordered by confidence):

1. **The mis-weighted reference-context caches** (section 1). Two caches that
   believe they are 32 MiB each while not counting `scoped`/`glob`.
   *Strong inference, from the weigher.*
2. **Request-scoped prepared syntax.** `QUERY_PREPARED_SYNTAX_CACHE_CAPACITY =
   1024` entries and `PREPARED_SYNTAX_STORE_MAX_BYTES = 512 MiB` at a 16x
   bytes-per-source-byte estimate (`tree_sitter_analyzer.rs:53-68`), plus
   `QUERY_FILE_STATE_CACHE_CAPACITY = 1024` hydrated `FileState`s at a documented
   ~50-100 KB each (`:40-52`). Order 0.6-1 GB, bounded. *Confirmed bounds.*
3. **Transient per-file structures held concurrently across ~120 rayon workers**:
   `RustLexicalScopeIndex`, `RustTokenTreeRoleCache`, `receiver_names`, and the
   `Arc<PreparedSyntaxTree>` each worker pins for its file's duration. Peak is
   `parallelism x largest candidate`, not bounded by any budget. *Inferred.*
4. **`GlobalUsageDefinitionIndex`, five of them** (one per language delegate),
   unbounded in workspace size, `OnceLock`-pinned. *Inferred; build time is
   measured at 3.42 s but RSS is not.*

The nine `RustWalkCaches` (`usage_walks.rs:73-100`) are each `memo_budget/16`
= 16 MiB with weighers that do cover their contents (`rust/cache.rs:167-313`);
they are not suspects.

---

## 3. What the context is FOR, per consumer

Every consumer of the context is a **point query about one token**:

| method | call sites | granularity actually needed |
|---|---|---|
| `resolve_bare(name)` | `extractor.rs:501, 607, 618, 2720, 3025`; `resolver.rs:129, 433, 1409`; `get_definition/rust.rs`; `diagnostics.rs:285` | one identifier at one byte |
| `resolve_scoped(path, name)` | `extractor.rs:620, 2723, 3034`; `resolver.rs:1013` | one written path at one byte |
| `resolve_scoped_owner(path)` | `extractor.rs:609`; `resolver.rs:131, 1024` | one written path prefix |
| `bare_names_resolving_to(fqn)` | `extractor.rs:146` (scan gate seeding), `extractor.rs:1169` (owner names), `resolver.rs:1271` | one file, one target fqn — the only genuinely file-level use, and it is an *inverse* query ("which local names in this file bind this fqn"), which `RustBindingSeeds::edges_by_importer` already answers (`usage.rs:601-607`, `usage_binding_local_names` at `:1015-1024`) |

Nothing needs the parsed tree from the *context*. The parsed tree is needed
independently, by the scan, for exact reference spans and expression shapes
(`scan_node`, `record_instance_member_hit`, `receiver_owner_proof`), and it is
already obtained separately via `prepared_syntax`.

What genuinely needs the tree, and cannot come from rows:
- byte spans and enclosing `CodeUnit` of each hit (`UsageHit`, `model.rs:94-107`);
- receiver/expression shape for member targets (`extractor.rs:1582-2400`);
- lexical shadowing at a byte (`RustLexicalScopeIndex`);
- local `use ... as` aliases in function bodies (`rust_local_use_alias_names`,
  `extractor.rs:263-296`) — though `rust_import_targets.local_extent` records
  exactly this and is currently unused by that helper.

What does **not** need the tree, and is already in rows:
- `module_at_byte` -> `rust_module_scopes` / `rust_modules`
  (`usage_queries.rs:310-316`);
- import bindings with owner module, visibility, and local extent ->
  `rust_import_targets` (`usage_queries.rs:319-329`, `facts.rs:53-70`);
- re-exports and globs -> `rust_exports` (`usage_queries.rs:332-336`,
  `facts.rs:41-49`);
- "which files mention this identifier in code context" ->
  `rust_identifier_occurrences` (`usage_queries.rs:360-375`) — the IdIndex
  analogue;
- the composed per-file (written path -> origin identity, domain, extent)
  relation -> `RustUsageWalks::origin_routes_of` (`usage_walks.rs:1351`).

**Verdict on the owner's prior: supported by the code.** Every question the
reference context answers is either (a) already answered per-site by
`usage_reference_at` over the fact tables, or (b) a per-file inverse lookup that
`RustBindingSeeds` already carries. The one thing the context has that the rows
do not is a *precomputed* answer, and precomputation is what costs the second.
Note the rows are also strictly *more* precise: `origin_routes_of` carries
`domain` and byte `extent`, which the flat `HashMap<String, String>` context
cannot express, so a per-site query is not a downgrade in fidelity.

---

## 4. Streaming vs accumulation — verdict: full accumulation, cap applied last

- Hits accumulate into a single `Mutex<BTreeSet<UsageHit>>` shared across the
  whole `par_iter` (`extractor.rs:99, 191-194`), returned only when every
  candidate finishes (`:197`).
- `RustQueryResolver::find_usages` then filters, counts, and **only then**
  compares against `max_usages` (`rust_graph.rs:177-197`).
- When the cap trips, the result is
  `FuzzyResult::TooManyCallsites { ..., sample_hits: hits }` — **the entire hit
  set is carried forward**, not a sample (`rust_graph.rs:191-196`).
- `max_usages` at that comparison is `context.max_callsites` =
  `SCAN_USAGES_MAX_CALLSITES` = `DEFAULT_MAX_USAGES` = **1000**
  (`searchtools/mod.rs:237`, `usages/finder.rs:27`,
  `searchtools/scan_usages.rs:884, 2250-2258`).

So: **contexts are built, and files scanned, for results the cap will discard.**
The cap is a post-filter on the assembled set, never a stop condition. There is
no early-out protocol anywhere between `scan_node` and
`RustQueryResolver::find_usages`; the only early exit is the cancellation token,
which is polled between files and inside `scan_node`, but not inside
`build_reference_context` (section 1).

Partial results *are* preserved on cancellation — the finder returns what the
scan accumulated and marks `Cancelled` (`finder.rs:266-281`), pinned by
`issue_1416_late_cancellation_keeps_the_hits_the_graph_scan_already_proved`
(`finder.rs:601-678`). Any redesign must keep that property.

---

## 5. IntelliJ, result-assembly phase only

Paths relative to `/home/jonathan/Projects/intellij-community` @ `277409ac3905`.
These are the gaps the checked-in report (sections 3.2-3.5) does not cover.

**Streaming / early-out protocol.** `Processor<T>.process(T)` returns `true` to
continue, `false` to stop
(`platform/util/base/src/com/intellij/util/Processor.java:11-17`). `Query<Result>`
exposes `forEach(Processor)` and `findFirst()`
(`platform/core-api/src/com/intellij/util/Query.kt:16,30,42`); `anyMatch` is
implemented as `!forEach { ... false }` (`Query.kt:80`). Every layer of the
search — `processFilesContainingAllKeys`, `processPsiFileRoots`,
`processVirtualFile`, `SingleTargetRequestResultProcessor` — is a `Processor`
chain, so a consumer that stops unwinds the whole pipeline. Bifrost's
`scan_files_for_target` has no analogue: it always visits every candidate.

**Candidate chunking and locality ordering.** `collectFiles`
(`platform/indexing-impl/src/com/intellij/psi/impl/search/PsiSearchHelperImpl.java:1116-1181`)
buckets candidates into four maps: `targetFiles` (files that are the search
target), `nearDirectoryFiles` (siblings of target files),
`containerNameFiles` (also contain the container's name), `restFiles`
(`:1160-1172`). `processCandidatesInChunks` (`:995-1024`) then processes them
**bucket by bucket in that order**, checking the processor's return between
buckets (`:1020-1023`). The buckets do not bound memory directly; they bound
*expected work before the first stop*, so the common case — the user wants a
handful of hits, or the too-many-usages dialog aborts — never touches
`restFiles` at all. `processPsiFileRoots` reports progress as
`alreadyProcessedFiles/totalSize` across buckets (`:452-486`).

**How memory is bounded across thousands of matches.** Two mechanisms, both
directly citable:

1. **The AST of each candidate is weakly reachable during a search.**
   `processPsiFileRoots` wraps the whole traversal in
   `myManager.runInBatchFilesMode(...)`
   (`PsiSearchHelperImpl.java:462`), which increments
   `PsiManagerImpl.myBatchFilesProcessingModeCount`
   (`platform/core-impl/src/com/intellij/psi/impl/PsiManagerImpl.java:566-580`).
   `PsiFileImpl.createTreeElementPointer` then stores the loaded tree as a
   `PatchedWeakReference` instead of the usual `SoftReference`
   (`platform/core-impl/src/com/intellij/psi/impl/source/PsiFileImpl.java:815-822`).
   So a candidate's parsed tree becomes collectable as soon as its scan returns —
   the GC, not a cache size, is the bound. Bifrost's equivalent (a
   request-scoped prepared-syntax cache holding `Arc<PreparedSyntaxTree>` for up
   to 1,024 files / 512 MiB) is a *strong*-reference budget by comparison.
   Stub trees are likewise `Reference<StubTree>`
   (`platform/core-impl/src/com/intellij/psi/impl/source/FileTrees.java:33,147`).

2. **Results are pointers, not PSI.** `UsageInfo` holds a
   `SmartPsiElementPointer<?>` and a `SmartPsiFileRange` — nothing else of the
   tree (`platform/core-api/src/com/intellij/usageView/UsageInfo.java:22-26`).
   A `SmartPsiElementPointer` is explicitly "a pointer to a PSI element which can
   survive PSI reparse"
   (`platform/core-api/src/com/intellij/psi/SmartPsiElementPointer.java:11-24`).
   So IntelliJ *does* hold all results to the end (they populate the Usage View
   tree), but each one is a file + range marker. Bifrost's `UsageHit` is
   comparable in shape (file, offsets, enclosing `CodeUnit`, snippet `String`) —
   the accumulation itself is not the memory problem; the per-candidate
   *machinery* is.

**Volume backstop.** At 1,000 accumulated usages
(`UsageLimitUtil.USAGES_LIMIT`, registry key `ide.find.result.count.warning.limit`,
`platform/usageView/src/com/intellij/usages/UsageLimitUtil.java:15-19`)
`SearchForUsagesRunnable` flips `TooManyUsagesStatus` and shows an abort dialog
(`platform/usageView-impl/src/com/intellij/usages/impl/SearchForUsagesRunnable.java:389-406`).
Crucially, the search **pauses** while the user decides:
`processPsiFileRoots` calls
`TooManyUsagesStatus.getFrom(originalIndicator).pauseProcessingIfTooManyUsages()`
*before each candidate file*
(`PsiSearchHelperImpl.java:470`;
`platform/core-impl/src/com/intellij/openapi/progress/util/TooManyUsagesStatus.java:55-67`).
Note the number is the same 1,000 as Bifrost's `SCAN_USAGES_MAX_CALLSITES` — but
it is checked *as results arrive*, and it gates further candidate work; Bifrost
checks it after every candidate is already done.

**What is re-parsed vs read from stubs during verification.**
`processVirtualFile` (`PsiSearchHelperImpl.java:600-664`) pre-caches file bytes
*outside* the read action (`:603-609`), then under a read action gets
`PsiFile`s from `myManager.findFile(vfile, context)` and hands each root to the
processor. The processor is `adaptProcessor` ->
`LowLevelSearchUtil.processElementsAtOffsets(...)`
(`:1184-1203`), which walks to the PSI element at each *text offset* returned by
the string searcher. So verification is: text search first, AST materialised only
for files that survive the text check, and only walked at the matching offsets —
never a whole-file semantic pass, and never a per-file precomputed import
closure. Declaration lookups reached from the resolve step come from stub
indexes (report section 4.3), not from re-parsing.

---

## 6. The two smaller walls

### 6a. The listing loop (~2.2 whole-tree walks per second)

`project::collect_workspace_files` fires 2,701 times in the 600 s run and 271
times in the 120 s run, always paired 1:1 with `gitblob::dirty_worktree_paths` —
that pairing is internal: in a git repo `collect_workspace_files` *is*
`all_working_tree_paths`, which runs a status scan
(`bifrost-core/src/analyzer/project.rs:960-982`;
`bifrost-core/src/gitblob.rs:135-165`). The walks are `Project::all_files()`
calls that miss `WorkspaceFileListingCache` (`project.rs:529-547, 650-664`).
The one-shot CLI *does* install that cache (`SearchToolsService::new` ->
`UpdateStrategy::WatchFiles` -> `listing_cache_for`,
`bifrost-mcp/src/searchtools_service.rs:1120-1126, 3733-3743`), so near-1:1
call-to-walk ratios mean it is being invalidated almost every call.
**Leading hypothesis (inferred, not span-proven): a watcher feedback loop.**
`handle_event` invalidates the listing cache for any event path that is not
`.bifrost/cache/*` (`project_watcher.rs:107-128, 219-232` — `.git` is *not*
exempt), and then `classify_project_path` calls `project.is_gitignored(rel_path)`
(`project_watcher.rs:191`), whose `FilesystemProject` implementation is
`self.all_files()` (`project.rs:715-722`). So one non-internal FS event costs one
invalidation plus one full walk plus one `git status` — and that `git status` can
itself touch `.git`, producing the next event. This is watcher-thread work, not
query work: it explains why the rate is a constant ~2.2/s on both lineages and in
every phase, and why it is invisible in cells that finish in 5 s. **The design
should exclude it**; it belongs with #1748/#1774 as a shared, pre-existing defect,
and the fix is in `project_watcher.rs`, not in the graph phase.

### 6b. The ~87 s candidate walk (`usage_candidate_files_while`)

`RustAnalyzer::usage_candidate_files_while` (`rust/usage.rs:906-916`) is
`binding_seeds_while` then `importers_of_seeds_while`. The second is cheap: it
unions already-computed `edges_by_importer` keys, module importers, and Cargo
reachability (`usage.rs:546-599`). The cost is in the first. `binding_seeds_while`
(`usage.rs:609-...`) BFS-expands the alias closure, and for each identity in the
frontier calls `edges_binding_identity` (`usage_walks.rs:1142-1163`), whose own
comment names it "the longest single region a usage query spends in the walk
layer". That function takes `importer_candidates_for(identity)` — every file
mentioning the identity's name in code context, plus every file mentioning the
last module component, plus every file importing `crate`/`super`
(`usage_walks.rs:1093-1138`) — and then computes
`forward_import_edges_of(candidate)` **for each** of them. On rustc that
candidate set is large for a common name, and each `forward_import_edges_of`
resolves every `use` in the file via `resolve_segments`, which is what generates
the 98,553 `sql_definition_candidates.rows` calls and the per-short-name
repetition run 3 noted (`rows[Foo]` 100-109 times, `rows[foo]` 57-62). So the
87 s is: fan-out over name-mentioning files x full per-file import-edge
computation x un-deduplicated definition lookups. `forward_import_edges_of` is
cached per file (`usage_walks.rs:986-989`, 16 MiB budget) — with 35k files that
cache is the first thing to thrash. The design may fold this in (it is the same
"answer per site instead of precomputing per file" question) or exclude it
explicitly; it is *not* the graph phase.

---

## 7. Constraints the design must respect

**Contracts / caps**
- `SCAN_USAGES_MAX_DURATION` 3 s default, `SCAN_USAGES_MAX_DURATION_CEILING`
  300 s (`searchtools/scan_usages.rs:767, 772`).
- `DEFAULT_MAX_FILES` / `max_candidate_files` = 1000;
  `SCAN_USAGES_PATH_SCOPED_MAX_FILES` = 10,000;
  `SCAN_USAGES_MAX_SOURCE_BYTES` = 64 MiB;
  `SCAN_USAGES_MAX_CALLSITES` = `DEFAULT_MAX_USAGES` = 1000
  (`searchtools/mod.rs:237-241`, `usages/finder.rs:26-27`).
- `UsageQueryCompletion` distinguishes `Complete` / `Cancelled` /
  `CandidateFilesBudgetExhausted` / `SourceBytesBudgetExhausted`
  (`usages/finder.rs:29-35`); `scan_usages` maps these to `incomplete_reason`.
- `FuzzyResult::TooManyCallsites` currently returns the *whole* hit set as
  `sample_hits`; consumers include `symbol_rename.rs:157`,
  `code_quality/dead_code_smells.rs:750`,
  `structural/search/expansions.rs:483,617,704`.
- `UsageScanScope::is_authoritative()` (set when a path filter is present,
  `scan_usages.rs:533`) changes `effective_scan_files` semantics
  (`extractor.rs:51-53`) and gates the private-member early return
  (`rust_graph.rs:126-134`).
- `RustReferenceContext` is `pub` and re-exported (`rust/mod.rs:62`); `named`,
  `namespace`, `same_file` are `pub(super)` and read directly by
  `weight_reference_context` (`rust/cache.rs:13-21`).
- `warm_usage_reference_contexts` is a whole-workspace fan-out run on a
  background thread at session start unless `BIFROST_WARM_USAGE_ANALYSIS` is
  `0/off/false/disabled` (`rust/usage.rs:891-897`;
  `searchtools_service.rs:3832-3842, 3865-3870`). Any redesign changes what that
  warm means.

**Tests that pin current behavior**
- `graph_support.rs:1861` `forward_reference_context_is_reused_within_analyzer_generation`
  (`Arc::ptr_eq` across a no-op update; also asserts `export_indexes` populated).
- `graph_support.rs:1890` `issue_1228_interrupted_forward_reference_context_is_not_cached`
  and `:1933` `issue_1304_interrupted_inverted_reference_context_is_not_cached` —
  both assert an interrupted build publishes nothing, and both assert
  `resolve_bare` results. A design that removes the eager build must keep the
  "never publish a partial answer" invariant.
- `usages/finder.rs:526` `issue_1228_pre_cancelled_query_skips_candidate_discovery`,
  `:572` `..._cancellation_after_candidate_discovery_is_not_reported_as_empty_success`,
  `:601` `issue_1416_late_cancellation_keeps_the_hits_the_graph_scan_already_proved`.
- `usages/rust_graph.rs:338` `cancelled_cold_candidate_discovery_does_not_publish_partial_index`.
- `tests/suite_issues/issue_1230_rust_scan_complexity.rs`: pins that module
  resolution does not relist the workspace, that listing count does not grow with
  workspace size, that `resolve_module_files` runs once per specifier, that the
  export index is shared by handle, and — importantly —
  `module_resolution_answers_are_unchanged` / `owner_memo_does_not_change_results_without_a_scope`.
- `tests/issue_1175_scan_usages_reparse.rs`: each candidate file is parsed once
  per call and parse count does not grow with reference count.
- `tests/suite_usages/issue_1416_scan_name_gate.rs`,
  `issue_1450_cross_request_prepared_syntax.rs`,
  `issue_1451_cross_request_import_infos.rs`,
  `usage_graph_rust_test.rs`, `usages_rust_*` — behavioral coverage of the Rust
  scan's answers.
- `extractor.rs:497-508` contains a `debug_assert!` that the cheap name gate
  never skips a path that would resolve to the target. Any change to how names
  are gated must keep that assertion true.

**Invariants worth naming explicitly**
- The scan currently proves hits with `usage_reference_at` and falls back to the
  reference context. Removing the fallback is a *behavioral* change, not only a
  performance one; the fallback's coverage (paths that `origin_routes_of` cannot
  route, e.g. dependency-crate targets) needs measuring before it is deleted.
- Both context caches retire with the analyzer generation, so incrementality
  after an edit is already correct; the problem is cold cost per query, not
  staleness.
