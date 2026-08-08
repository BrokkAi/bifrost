# Fenced follow-ups investigation (issues #1847, #1848)

Read-only investigation. Repository `/mnt/optane/bifrost-nlp`, branch `bifrost-nlp-ft`,
code pinned to HEAD `9b3bb23d`. No code changes, no commits, no issue writes.
Author: Opus subagent, 2026-08-08.

Evidence labels: **[C]** confirmed by code read at HEAD or by a runtime measurement in this
session; **[M]** measured in this session (numbers given); **[I]** inferred; **[U]** unknown.

---

# PART A - `global_usage_definition_index` (#1847)

## A1. Anatomy

### Where it lives

| item | location |
|---|---|
| type + all maps | `crates/bifrost-analysis/src/analyzer/global_usage_definition_index.rs:13-25` |
| build | `crates/bifrost-analysis/src/analyzer/tree_sitter_analyzer.rs:5603-5684` (`sql_global_usage_definition_index`) |
| `OnceLock` fields | `tree_sitter_analyzer.rs:1959-1961` |
| lazy init | `tree_sitter_analyzer.rs:8181-8228` (`global_usage_definition_index_handle` / `try_...`) |
| `IAnalyzer` entry point | `tree_sitter_analyzer.rs:8630-8632`, default empty impl `i_analyzer.rs:493-496` |
| cross-language composition | `multi_analyzer.rs:765-785` (`DefinitionIndexHandle::Merged`) |
| handle API | `global_usage_definition_index.rs:628-800` |

### What one entry holds

`GlobalUsageDefinitionIndex` is **eleven** maps, not "an index" **[C]**
(`global_usage_definition_index.rs:13-25`):

| field | key | value | populated for |
|---|---|---|---|
| `by_fqn` | `String` fq name | `Vec<CodeUnit>` | every unit |
| `by_normalized_fqn` | `String` adapter-normalized fq | `Vec<CodeUnit>` | every unit |
| `by_identifier` | `String` identifier | `Vec<CodeUnit>` | every unit |
| `by_file_identifier` | `(ProjectFile, String)` | `Vec<CodeUnit>` | every unit |
| `direct_children_by_fqn` | `String` parent fq (naive `rsplit_once('.')`) | `Vec<CodeUnit>` | every unit with a `.` |
| `direct_children_by_normalized_fqn` | normalized parent fq | `Vec<CodeUnit>` | ditto |
| `types_by_package_simple` | `(String package, String simple)` | `Vec<CodeUnit>` | `unit.is_class()` only |
| `packages` | `HashSet<String>` | - | every distinct package |
| `files_by_package` | `String package` | `Vec<ProjectFile>` | every unit |
| `package_languages` | `String package` | `HashSet<Language>` | every unit + every ancestor package |
| `child_packages_by_parent` | `String parent` | `HashSet<String>` | every ancestor step of every package |

`insert` (`:340-431`) pushes the same `CodeUnit` into up to **7** value vectors.
`CodeUnit` is `Arc<CodeUnitInner>` (`bifrost-core/src/analyzer/model.rs:1932`), so those are
refcount bumps, not deep copies **[C]** - the memory is in the *keys*, the *`Vec` headers and
their heap slots*, and the `CodeUnitInner`s the index keeps alive.

### Size drivers at scale

Per declaration, structurally **[C]** for the shape, **[I]** for the byte totals:

- `CodeUnitInner`: `ProjectFile` (Arc) + `CodeUnitType` + `Option<String> signature` +
  `FqName` (`SmallVec<[SegmentId; 8]>`, so 32 B inline) + `RenderedCodeUnitName` which itself
  holds a fully rendered `display: String` plus four `usize` offsets
  (`model.rs:1865-1882`). Order 170 B of struct plus two heap strings.
- 7 map insertions x (`Vec` header 24 B + a heap allocation for one or two 8-byte `Arc` slots)
  = order 250-400 B before hashbrown's power-of-two slack.
- 4-6 distinct owned `String` keys per unit (`fq`, normalized `fq`, identifier, parent fq,
  normalized parent fq, and the `(package, simple)` pair for classes).

Measured density on this repo (bifrost itself, warm cache, `bifrost --tool usage_graph`) **[M]**:

| language | live blob keys | units in the shard | build |
|---|---:|---:|---:|
| Rust | 1,106 | 62,489 | 468.6 ms |
| Python | 59 | 2,354 | 22.1 ms |
| TypeScript | 57 | 1,753 | 7.9 ms |
| JavaScript | 53 | 971 | 4.7 ms |
| Cpp | 34 | 434 | 2.9 ms |
| Java | 36 | 182 | 1.6 ms |
| (7 more) | 8-20 each | 37-84 each | 0.4-1.2 ms |

56.5 units per Rust file; average `signature` length 40.5 B, average `identifier` 21.7 B
(from the store, `sqlite3` over `code_units where lang='rust' and in_declarations=1`) **[M]**.
38,849 distinct identifiers over 62,489 units, i.e. the `by_identifier` map alone is
~39 k `String` keys. Scaling 56.5 units/file to a 35 k-file tree gives order 2 M units per
Rust shard; at ~1 KB of index-side overhead per unit that is single-digit GB for Rust alone,
which is consistent with (but does not prove) #1847's ~15.5 GB headline **[I]**.

The 15.5 GB attribution itself remains **[I]**: `.agents/docs/graph-phase-investigation-2026-08.md:196-203`
explicitly lists it as inferred ("build time is measured at 3.42 s but RSS is not").

### Build cost and what it reads

`sql_global_usage_definition_index` (`tree_sitter_analyzer.rs:5603-5684`) **[C]**:

1. `live_snapshot().all_paths()` -> rebase -> filter to this delegate's language -> `(oid, lang_key)`
   pairs (`enumerate_live_keys`).
2. `store.definition_lookup_candidate_rows_by_keys(&blob_keys, generations)` - **every** row for
   **every** live blob of that language.
3. `resolve_candidate_rows` hydrates them all into `CodeUnit`s; `retain(!is_file_scope)`.
4. plus `dirty_units_matching(true, |_| true)` (all dirty units) and
   `try_sql_nonpersisted_workspace_declarations_vec_matching` (all non-persisted units).
5. `from_declarations` inserts all of them into the eleven maps and sorts every value vector.

So the build is a whole-workspace `SELECT`, a whole-workspace hydration, and a whole-workspace
insert. Nothing about it is bounded by the question being asked.

**Amplifier [C][M]:** `MultiAnalyzer::global_usage_definition_index` (`multi_analyzer.rs:773-785`)
flat-maps over **every** delegate, so a single call from a Rust-only code path forces the shard
of every language in the workspace. Measured: 12 `global_usage_definition_index_build` spans in
one `usage_graph` invocation on this repo **[M]** (the rustc run saw 5, matching its 5 detected
languages). The doc comment claims this is "exactly the per-language index the delegate would have
built anyway" - true only if every language is eventually queried.

### `OnceLock` lifecycle

- **Built** lazily, on the first `global_usage_definition_index()` / `_shared()` call, serialized
  by `global_usage_definition_index_init: Arc<Mutex<()>>`, counted by
  `global_usage_definition_index_build_count` (`tree_sitter_analyzer.rs:8193-8228`) **[C]**.
- **Shared** by `Clone` and by `clone_with_project` - both `Arc::clone` the same `OnceLock`
  (`:2016-2019`, `:2047-2060`), so every snapshot clone and every overlay session pins the same
  allocation **[C]**.
- **Never invalidated in place.** There is no `reset`, no partial update, no eviction, no weight,
  no budget. Not in any cache-budget mechanism **[C]** (`rg` over the crate finds no writer other
  than the one `set`).
- **Dropped only by replacement.** `IAnalyzer::update(changed_files)` with a non-empty set goes
  through `from_state`, which allocates a *fresh* `OnceLock::new()` (`:2415-2417`); with an empty
  set it returns `self.clone()` and keeps the old one (`:8501-8504`) **[C]**. Pinned by the unit
  test `shared_usage_indices_reuse_generation_allocations_and_reset_on_update`
  (`tree_sitter_analyzer.rs:11015-11066`), which asserts `!Arc::ptr_eq(first, updated)`.
- Consequence: **any** one-file change discards the whole workspace index and the next consumer
  pays the full rebuild. On a session where the watcher keeps delivering changed files (see Part B,
  where `.git/index.lock` is classified as a *project file*), this is a rebuild treadmill **[I]**.
- On error the handle falls back to a shared empty `global_usage_definition_fallback` and records
  the store error (`:8181-8191`) - the failure is visible but the answer silently becomes "nothing
  in the workspace".

There is a **second** index with the identical shape and lifecycle next to it: `usage_facts_index`
/ `UsageFactsIndex` (`tree_sitter_analyzer.rs:1963-1965`, `:8248-8262`, built by
`build_usage_facts_index` from `analyzer.global_usage_definition_index()` at
`usage_facts.rs:70`). Any plan for #1847 should decide about it in the same pass: it is derived
*from* the definition index, so it is a second whole-workspace materialization chained to the
first **[C]**.

## A2. Consumers

~80 call sites reach `IAnalyzer::global_usage_definition_index()` (excluding pure trait
forwarders and tests). By file **[C]**:

| area | sites | representative |
|---|---:|---|
| `usages/*_graph/**` (java, kotlin, cpp, js_ts, scala, ruby, python, rust) | ~55 | `rust_graph/extractor.rs:98`, `:1135`; `rust_graph/inverted.rs:93`; `java_graph/resolver.rs` x7 |
| `analyzer/*/diagnostics.rs` (rust, go, php, python) | 4 | `rust/diagnostics.rs:59` |
| `analyzer/csharp/mod.rs` | 3 | `:346`, `:418`, `:431` |
| `analyzer/java/imports.rs` | 3 | `:234`, `:715`, `:725` |
| `analyzer/kotlin/{imports,types}.rs` | 2 | `imports.rs:161` |
| `analyzer/scala/mod.rs` (`_shared`, `Arc` into `ProjectTypes`) | 1 | `:497-500` |
| `analyzer/usage_facts.rs` | 1 | `:70` (builds the second index) |
| `analyzer/usages/candidates.rs` | 1 | `:182` |
| `searchtools/summaries.rs` | 1 | `:422` (`package_listing`) |

### Question-by-question classification

The store already exposes the bounded query for most of these, and
`AnalyzerDefinitionLookup` (`global_usage_definition_index.rs:130-183, 245-335`) already
implements `BoundedDefinitionLookup` over those bounded queries - forward `get_definition` and
`get_type_by_location` dispatches use it today instead of the resident index **[C]**. That is the
strongest single fact for #1847: **the bounded replacement for the hot half of this API already
exists and is already in production on another dispatch path.**

| handle method | question asked | granularity | already answerable by rows? | backing |
|---|---|---|---|---|
| `fqn(fq)` / `fqn_in_language` | "which declarations have this exact fq" | point | **YES, in production** | `forward_definition_fqn` -> `sql_bounded_definitions_vec` -> `definition_candidate_rows` = one seek on `idx_code_units_lang_short_name`, memoized per request (`tree_sitter_analyzer.rs:6290-6340`) |
| `file_identifier(file, ident)` | "declarations named X in file F" | point | **YES, in production** | `forward_file_identifier` -> `fetch_file_state` (`:5855-5873`) |
| `fqn_direct_children(fq)` | "direct children of this owner" | point | **YES, in production** | `forward_direct_children` -> `IAnalyzer::direct_children`; bounded page via `direct_children_limited` -> `store.direct_children_for_unit_limited` (`:5875-5939`) |
| `package_exists` / `_in_language` | membership | point | **YES, in production** | `forward_package_exists` -> `persisted_package_exists` -> `store.declaration_rows_by_package_for_langs` (`:6971-6993`) |
| `fqn_prefix_exists(prefix)` | "any declaration under this prefix" | existence | **YES, in production** | `forward_fqn_prefix_exists` -> paged `store.declaration_rows_by_package_prefix_page` (`:5948-5990`). The resident version is `by_fqn.keys().any(starts_with)` - a full key scan (`global_usage_definition_index.rs:623-627`) |
| `by_normalized_fqn(n)` | point lookup by normalized fq | point | **NEW NARROW INDEX (already in schema)** | `idx_code_units_lang_normalized_fqn_declarations` exists (`0001-current-baseline.sql:102`); no forward accessor yet |
| `identifier(ident)` | "every declaration with this bare identifier, workspace-wide" | point | **YES (store method exists, not wired to this handle)** | `store.declaration_candidate_rows_by_identifier_for_langs` on `idx_code_units_lang_identifier_lookup` (`0010-identifier-lookup-membership.sql`) |
| `members_for_owner_name(owner, norm_owner, name)` | "member `name` of owner" | point | **YES (store method exists)** | `store.declaration_member_rows_for_owner_for_langs{,_limited}` (`store/mod.rs:2687-2775`) |
| `types_in_package(pkg, simple)` | point | point | **YES (index exists in schema)** | `idx_code_units_lang_package_simple_type_declarations (lang, content_qualifier, simple_type_name) WHERE kind=0` (`0001-current-baseline.sql:105`) |
| `package_types()` | **enumerate every (package, simple) key in the workspace** | enumeration | **needs a decision** - only 4 call sites; a full scan by definition | would be a full `code_units` scan; the honest fix is to narrow the callers |
| `package_exists` (container form) `package_container_exists` | "is this a package or an ancestor of one" | existence | **narrow index needed** | requires DISTINCT `content_qualifier` prefix matching; `declaration_rows_by_package_prefix_page` is close but returns rows, not a boolean over the *ancestor* relation |
| `child_packages(parent)` | "immediate sub-packages" | enumeration (bounded fan-out) | **narrow index needed** | derivable as DISTINCT `content_qualifier` with prefix + one separator; the resident form precomputes the whole ancestor chain for every unit at insert time (`:352-372`) |
| `package_files(pkg)` | "files in this package" | enumeration (bounded) | **YES (store method exists)** | `store.declaration_rows_by_package_for_langs` returns rows carrying the blob; the liveness map gives the path |
| `package_languages(pkg)` | "which languages in this package and its children" | small set | **narrow index needed** | DISTINCT `lang` over the same prefix relation |

**The one named consumer, `summaries.rs:422` `package_listing`** asks four of the package-catalog
questions in a row - `package_container_exists`, `child_packages`, `package_languages`,
`package_files` - for **one** package **[C]** (`searchtools/summaries.rs:406-475`). It is the
clearest case of a bounded question served by a workspace-sized structure: the answer set is one
package's children and files, and every one of the four is a prefix query over
`code_units.content_qualifier` restricted to a single prefix.

**Summary of the classification:** 9 of 14 operations are already answerable by rows and 5 of
those already have a *shipping* bounded implementation. The genuine residue is the **package
catalog** (`packages`, `files_by_package`, `package_languages`, `child_packages_by_parent`) - the
only part of the structure that is a *derivation* rather than a re-materialization - plus the one
enumeration API `package_types()`.

Caveat for Rust **[M]**: `exact_fqn`, `normalized_fqn` and `content_qualifier` are **empty/NULL**
for every Rust row in the store; Rust fq identity lives in the `fq_segments` BLOB and `short_name`.
So the `exact_fqn`/`normalized_fqn`/`content_qualifier` indexes do not serve Rust, and the bounded
Rust path is the `(lang, short_name)` seek plus a hydrate-and-filter. Any package-catalog row
design must therefore not assume `content_qualifier` is populated for Rust.

## A3. Languages

**Per-language shards, composed cross-language at query time.** Each `TreeSitterAnalyzer<A>` owns
exactly one shard, built only from blob keys whose `language_for_file` equals the delegate's own
language (`tree_sitter_analyzer.rs:5611-5636`). `MultiAnalyzer` returns
`DefinitionIndexHandle::Merged(Vec<&shard>)` and every handle method flat-maps the shards; shards
never overlap because a file belongs to exactly one delegate, so no cross-shard dedup is needed
(`global_usage_definition_index.rs:628-660`) **[C]**.

**The v2 pattern applies directly.** The composition seam is already in the right place - the
handle is a query-time composition, not a merged copy. What is wrong is one level down: the shard
is a RAM materialization of rows the store already holds, rather than a query over them. Content
check: everything the index holds comes from
`definition_lookup_candidate_rows_by_keys` + `dirty_units` + `nonpersisted_units`
(`tree_sitter_analyzer.rs:5637-5678`) **[C]** - i.e. **persisted rows plus the two overlay
sources every bounded store query already consults**. The only thing the store does *not* persist
is the *package catalog derivation* (`packages`, `child_packages_by_parent`, `package_languages`,
`files_by_package`), which the index computes at insert time by walking `package_parent_name`
chains (`:352-372`, `:815-825`). That derivation is the one candidate for a new narrow persisted
relation; everything else is per-blob rows plus query-time composition, exactly as in v2.

One language-specific wrinkle that must survive a rewrite **[C]**: the parent key for
`direct_children_by_fqn` is the naive `rsplit_once('.')`, *not* `default_parent_fq_name`, and the
comment at `:410-425` records that switching to the structurally correct segment pop regresses
`usage_graph_csharp_test::csharp_issue701_...`. C# nested-type visibility relies on nested types
being keyed under their **namespace**, not their immediate owner.

## A4. Prior art - IntelliJ's stub index

IntelliJ answers exactly these questions and never materializes the workspace in the heap
(`.agents/docs/intellij-indexing-research-2026-08.md` section 4). A stub is a serialized per-file
declaration skeleton; the "Stubs" index is one on-disk `fileId -> SerializedStubTree` map, and the
question-shaped indexes (`StubIndexKey`: class names, method names, `SUPER_CLASSES`) are separate
on-disk inverted maps `Key -> Set<fileId>` with a `Void` value, derived from the per-file stub tree
at *update* time as a **set difference of the old and new per-file key sets**
(`StubCumulativeInputDiffBuilder.updateStubIndices`, section 4.2). A declaration query is
`getContainingIds(indexKey, key, scope)` -> per-file `StubIdList` -> materialize PSI for **only
those stubs** (section 4.3), so the heap holds the answer, not the workspace; the platform
deliberately keeps stubs behind soft/weak references (section 6.3). Mapped onto Bifrost, the
`code_units` table plus its `(lang, short_name)`, `(lang, identifier)`, `(lang, exact_fqn)`,
`(lang, normalized_fqn)` and `(lang, content_qualifier, simple_type_name)` indexes are exactly the
stub-index level, and `definition_candidate_rows` is exactly `processElements`; the difference is
only that `GlobalUsageDefinitionIndex` reads all of them at once into RAM instead of one key at a
time. IntelliJ also has no analogue of the *whole-workspace* variant: there is no "all declarations
in the project" heap structure to invalidate, which is why a one-file edit costs them a per-file
set difference where it costs Bifrost the entire index (A1 lifecycle).

---

# PART B - the watcher listing feedback loop (#1848)

## B1. Runtime confirmation: **CONFIRMED**, and the culprit path is `.git/index.lock`

### Setup

- Workspace: `git clone --depth 1 --no-local file:///mnt/optane/bifrost-nlp` into the scratch
  directory (verified at `9b3bb23`), plus a linked worktree of that clone for the counterfactual.
  **The live checkout was never modified and no worktree was created in it.**
- Binary: `target/release/bifrost` (built 2026-08-07, after the last change to
  `project_watcher.rs` on 2026-08-04, so it carries the HEAD watcher code), copied to scratch
  and run from the copy.
- Instrument: `BIFROST_TIMING=1` (`bifrost-core/src/profiling.rs:58-61`) - counts
  `project::collect_workspace_files` and `gitblob::dirty_worktree_paths` spans - plus an
  independent recursive `inotify` observer written in Python/ctypes, so the event stream is
  observed *outside* bifrost.
- `BIFROST_SEMANTIC_INDEX=off`.

### Observed chain

**Run 2** (MCP server via stdio, `--root <clone>`, one `get_active_workspace` call, then external
stimuli separated by idle windows):

| t (s) | event | walks in that second |
|---|---|---|
| 0 | server start, initial listing | 1 |
| 0-19 | **idle, no stimulus** | **0** |
| 19.001 | one `echo >> crates/bifrost-core/src/lib.rs` | 50 |
| 20-72 | **no further stimulus of any kind** | **50-56 per second, every second** |
| 73 | process terminated | - |

Total 2,844 whole-tree walks, each with a `gitblob::dirty_worktree_paths` (a `git status`)
nested inside it **[M]**. In the t=55..60 window the *only* spans emitted were 261
`project::collect_workspace_files` and 262 `gitblob::dirty_worktree_paths` - no query work at all.

**Run 3** (same, with the independent inotify observer running across the stimulus):

- 2,613 filesystem events observed in 25 s.
- **2,611 of them are `.git/index.lock`** (CREATE / CLOSE_WRITE / DELETE, three per `git status`).
- The other 2 are the single `crates/bifrost-core/src/lib.rs` touch that started it.
- ~156 events/s against ~52 walks/s = exactly 3 events per walk **[M]**.

**Run 4 - the counterfactual.** Same binary, same stimulus, but the root is a *linked git
worktree* whose `.git` is a file and whose real gitdir lives outside the watched root:

- **2 inotify events** (the source touch), **2 walks total** (startup + the one real event).
- **No loop.** **[M]**

That isolates `.git`-internal events inside the watched root as the necessary cause.

### The chain, now confirmed end to end

1. `dirty_worktree_paths` shells out to `git status --porcelain=v1 -z --untracked-files=all`
   (`bifrost-core/src/gitblob.rs:476-493`) **[C]**; `collect_workspace_files` calls it via
   `all_working_tree_paths` on every git-repo listing (`project.rs:960-982`) **[C]**.
2. `git status` creates and removes `.git/index.lock` on **every** invocation, clean tree or not -
   verified by `strace -e trace=openat` (1 `index.lock` open per run on a clean tree) **[M]**.
3. `handle_event` invalidates the workspace listing for **any** path that is not
   `<root>/.bifrost/cache/**` (`project_watcher.rs:121-128`) - `.git` is not exempt **[C]**.
4. `classify_project_path` then calls `project.is_bifrostignored(rel_path)`
   (`project_watcher.rs:187`), whose `FilesystemProject` implementation calls `self.all_files()`
   (`project.rs:723-733`) - so the *watcher thread itself* performs the walk, on a cache it just
   invalidated. (`is_gitignored` at `:715-722` is a second `all_files()`, served warm.)
   **Note the issue text names `is_gitignored`; the first and always-taken `all_files()` is
   actually inside `is_bifrostignored`, which runs unconditionally and before it.** **[C]**
5. That walk runs `git status`, which writes `.git/index.lock` -> goto 3.

Rate is walk-bound: ~18.5 ms per walk on this 1.5 k-file repo -> ~54 walks/s. On rustc the walk is
slower, giving the ~2.2/s of the original observation. The loop is therefore **not** rate-limited
by anything - it runs as fast as the tree can be walked **[M]**.

### Self-sustaining? Yes, and it is metastable

It does **not** start on its own at server startup (run 2, t=0-19: exactly one walk, then
quiescence): the watcher is installed after the initial listing, so the startup `git status`'s
events are not observed **[I]** for the ordering, **[M]** for the outcome. But **any** first
listing after the watcher is live kicks it, and it then never stops without external help:

- an external file touch (run 2) - loop for the remaining 54 s;
- the service's own query work: a single one-shot `bifrost --tool usage_graph` (no external FS
  activity at all) produced **1,863 walks in 50 s** (~37/s) **[M]**. The one-shot CLI installs
  `UpdateStrategy::WatchFiles` too (`searchtools_service.rs:1120-1126`), so one-shot invocations
  pay this as well.

That last measurement matters for the plan: the loop is not a "long session" problem; it starts
the moment any tool asks for a listing.

## B2. Exemptions, per-event cost, and the minimal correct exemption set

### What `handle_event` exempts today **[C]**

| class | listing invalidated? | classification cost |
|---|---|---|
| `EventKind::Access(_)` | no - early `return` at `:109-111` | none |
| `event.paths.is_empty()` | **yes** (`:121`), then `mark_full_refresh` | none |
| every path under `<root>/.bifrost/cache/**`, or legacy `<root>/.bifrost/bifrost_cache*.db{,-wal,-shm,-journal}` | no (`is_internal_state_path`, `:201-234`) | `classify_project_path` still runs but returns `IgnoredInternal` at `:182-184`, **before** any `all_files()` - so zero walks |
| a path whose basename is `.bifrostignore` | **yes**, then `mark_full_refresh` and return (`:135-142`) | none |
| **everything else, including all of `.git/**`** | **yes** | see below |

### Cost of `classify_project_path` per event class **[C]**

For any non-exempt path: `normalize()` + `strip_prefix` + `is_internal_state_rel_path` (all cheap),
then

- `project.is_bifrostignored(rel_path)` -> `all_files()` -> **cold cache (just invalidated) ->
  one whole-tree walk + one `git status`** -> plus `bifrost_ignore_matcher` rebuild (also reset by
  `invalidate_cached_file_listing`, `project.rs:672-676`);
- if `file.exists()`: `project.is_gitignored(rel_path)` -> `all_files()` again, now warm.

So the marginal cost of one non-exempt event batch is **one whole-tree walk plus one `git status`**,
paid on the watcher thread, plus the cost imposed on the next query (which finds the listing cold
again if any further event arrives).

Two secondary harms of not exempting `.git`, both **[C]**:

- `.git/index.lock` does **not exist** by the time it is classified (git already removed it), so
  `file.exists() && is_gitignored` is false and it falls through to
  `PathDisposition::ProjectFile(".git/index.lock")` - the watcher records a *git lockfile* as a
  changed project file. Draining that delta calls `snapshot.update(&changed_files)`
  (`searchtools_service.rs:3132-3145`), which via `from_state` **discards the
  `global_usage_definition_index` `OnceLock`** (Part A). Part B is therefore a driver of Part A's
  rebuild cost.
- `.git/HEAD` and other *existing* `.git` files are not in `all_files()`, so `is_gitignored` is
  true -> `RefreshFallback` -> `requires_full_refresh` -> `snapshot.update_all()`
  (`searchtools_service.rs:3115-3125`), a full workspace re-analysis.

### Does anything legitimately need `.git` events? Consumers of `.git`-event-driven state

Searched for every path from a `.git` event to state **[C]**:

1. **`requires_full_refresh`** - the only real consumer. Reached from `RefreshFallback`
   (`project_watcher.rs:158-165`), consumed at `searchtools_service.rs:3115-3125`
   (`snapshot.update_all()`, plus `semantic.request_full_build` and `schedule_index_warm`). Two
   unit tests pin the current behavior and would have to be revisited by any exemption:
   `source_events_are_incremental_but_git_events_trigger_full_refresh`
   (`project_watcher.rs:587-615`) and `mixed_source_and_git_events_trigger_full_refresh`
   (`:617-640`), both of which use `.git/HEAD` explicitly.
2. **Nothing else.** No gitblob-liveness, generation-tracking, or blob-cache consumer subscribes
   to watcher events; `store_context.generations` and `liveness` are advanced by the analyzer's own
   update path, not by the watcher (`tree_sitter_analyzer.rs:8501-8560`). `gitblob` reads the repo
   on demand inside `collect_workspace_files`. No code anywhere in `crates/` reads `.git/HEAD`,
   `refs/`, or `packed-refs` in response to a watcher event.

So the *substantive* requirement is: **a HEAD/refs change must still be able to reach
`requires_full_refresh`**, because a branch switch changes tracked-vs-untracked membership and blob
identity for files whose contents may not change. `.git/index.lock` (and `.git/index`) carries no
such information.

### Minimal correct exemption set

`.git` internals are never project files and the codebase already says so in the other listing
path: `collect_workspace_files`'s non-git walker has an explicit
`.filter_entry(|e| e.file_name() != ".git")` with the comment "`.git` is VCS internals, never
source ... walking it is pure cost" (`project.rs:992-999`) **[C]**; and the git path
(`all_working_tree_paths`) can never yield a `.git` path by construction **[C]**.

The narrowest exemption that provably breaks the loop while keeping consumer 1 alive:

- **`<root>/.git/index.lock` and `<root>/.git/index`** must not invalidate the listing and must not
  be classified as project files. Evidence: 2,611 / 2,613 of the loop's events were `index.lock`
  **[M]**, and the counterfactual worktree run shows the loop is exactly these events **[M]**.
- **All other `<root>/.git/**` paths** should be classified as `IgnoredInternal` for the
  *project-file* decision (they can never be project files), while a whitelist -
  `HEAD`, `refs/**`, `packed-refs`, `MERGE_HEAD`, `ORIG_HEAD` - still sets `requires_full_refresh`.
  This preserves both existing tests' intent (a `.git/HEAD` event still forces a full refresh) while
  removing the walk from the event handler.
- Linked worktrees are already immune (the gitdir is outside the root, run 4) **[M]**, so the fix
  only has to reason about in-tree `.git`.

## B3. Bounded fix-shape options (evidence only - not a recommendation)

**Option 1 - exempt `.git` in the watcher (extend `is_internal_state_rel_path`).**
- For: `.git` is provably never a project file - two independent code paths already say so
  (`project.rs:992-999`, `all_working_tree_paths`). The counterfactual run 4 proves the exemption
  is sufficient: with the gitdir outside the root, 2 events and 2 walks, no loop **[M]**. Smallest
  diff; the exemption hook already exists and is already used for `.bifrost/cache`.
- Against: must not silently drop the `requires_full_refresh` semantics that `.git/HEAD` currently
  provides; two existing tests encode that (`project_watcher.rs:587-640`). Requires deciding the
  whitelist (HEAD/refs/packed-refs) rather than a blanket exemption.
- Residual: does not fix the *other* half of the defect - a legitimate source event still costs a
  whole-tree walk *inside the watcher thread* (B2 cost table). It removes the feedback, not the
  per-event cost.

**Option 2 - classify without materializing the listing.**
- For: attacks the actual expense. `is_gitignored` is *defined* as "exists and is absent from
  `all_files()`" (`project.rs:715-722`) and `is_bifrostignored` likewise walks
  (`:723-733`) - a listing-membership test standing in for an ignore-rule test. Replacing both with
  a path-only matcher (the `ignore` crate's `Gitignore` matcher, which
  `collect_workspace_files`'s fallback path already builds) removes the walk from the event
  handler, which removes the `git status`, which removes the feedback - so it also fixes the loop,
  independently of Option 1.
- Against: semantics change. Membership-in-`all_files()` and gitignore-rule-matching differ for
  tracked-but-ignored files (git tracks them; the rules say ignore) and for the git-index-derived
  listing generally, since `all_working_tree_paths` is index+status, not a rules walk. Needs its
  own equivalence pin.
- Residual: the listing is still invalidated on every event, so the *next query* re-walks. Under a
  burst of real edits that is a walk per query, not a walk per event - much better, but not free.
  Note also `is_bifrostignored`, not `is_gitignored`, is the first and unconditional caller **[C]**.

**Option 3 - debounce / coalesce events.**
- For: `notify` already coalesces somewhat (3 `index.lock` events -> 1 walk, measured **[M]**), and
  a debouncer would cut the rate further. Purely local change, no semantic risk.
- Against: **does not break the loop, only slows it.** The loop is self-sustaining because each
  walk generates the next event; a debounce interval `d` simply pins the steady state at `1/d`
  walks per second forever, converting an unbounded loop into a permanent background load. The
  measured rate is already walk-bound (18.5 ms per walk vs a walk every 18.5 ms), so the system is
  already "debounced" by the walk duration and still loops. Weakest of the three on this evidence.

**Cross-cutting evidence for whichever shape is chosen:** the loop costs a whole-tree walk *plus a
`git status` subprocess* per iteration on the watcher thread, it starts from the service's own
first listing (1,863 walks in a 50 s one-shot with zero external FS activity **[M]**), and its
by-product - `.git/index.lock` recorded as a changed project file - feeds `snapshot.update`, which
discards the Part A index. The two fenced follow-ups are coupled through that edge.

---

## Cleanup

All scratch artifacts were created only under
`/tmp/claude-1000/-mnt-optane-bifrost-nlp/b5398767-af2f-42d8-9210-eea66ede9085/scratchpad`:
the shallow clone `probe-repo`, its linked worktree `probe-wt`, the copied `bifrost-probe`
binary, a copy of the probe cache DB, the probe drivers, and the run logs. The live checkout
`/mnt/optane/bifrost-nlp` was never written to and **no `git worktree` was added to it**;
the only `git worktree add` was inside the scratch clone. Removal is recorded in the final
report message.
