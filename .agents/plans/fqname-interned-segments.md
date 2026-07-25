# Replace stringly qualified names with interned, kind-tagged segments (FqName)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.
This document must be maintained in accordance with `.agents/PLANS.md` (repository root
relative path), the canonical rules for ExecPlans.

## Purpose / Big Picture

Bifrost identifies every declaration by a qualified name stored as a plain string
(`package_name` + `short_name` on `CodeUnit`, e.g. `log4cxx.HTMLLayout.getContentType`
or `cutlass::gemm::warp.OperandSharedStorage.OperandLayout`). The structure of that
string — where one segment ends and the next begins, and what kind of segment it is —
is not recorded anywhere. Every consumer re-infers it by splitting on a guessed set of
delimiter characters (`.` `::` `$` `/` `#` `+`), per call site, and the per-language
spelling conventions differ (C++ stores a `::` namespace head with a `.` member tail;
Scala appends `$` for companion objects; file-stem segments may contain literal dots).

That inference is a recurring bug factory. In one week of campaign work the following
all reduced to it: rust raw identifiers containing `#` colliding with `file#symbol`
anchor splitting (issue 1128); the anchor split point itself (issue 1131); a bare
`DbColumn.r#type` misrouted as a `.r` FILE anchor; `::`-qualified references never
matching the shared resolver's `.`-composed candidates (issue 1162); C++'s
mixed-separator store discovered only when normalizing the scope side broke a cutlass
test, leaving a confirmed reachable false "outside the workspace" claim (issue 1163);
and Scala `$`-spelling inconsistencies between surfaces. Counts in the current tree:
about 144 `format!("{parent}.{name}")`-style construction sites and about 227
separator-split sites under `src/analyzer`.

After this change, a qualified name is a `FqName`: a small vector of interned segment
IDs, where each ID identifies a `(text, kind)` pair — kind being Path, Package, Type,
Member, or Companion. Structure is recorded once at construction (where the language
extractor knows exactly what it is emitting) and never inferred again. Native
delimiters remain accepted at the MCP input edge and rendered at the output edge, but
the interior of the system stops splitting strings entirely. Observable outcomes: the
delimiter-bug regression suites (`tests/issue_1128_rust_raw_identifiers.rs`,
`tests/issue_1162_separator_aware_enclosing_scope.rs`, the anchor tests in
`tests/searchtools_definition_selectors.rs`) keep passing with the inference code
deleted; the pinned false-boundary test
`cpp_qualified_nested_namespace_type_current_behavior` in
`tests/issue_1162_separator_aware_enclosing_scope.rs` flips from documenting the bug
to asserting correct resolution (this is issue 1163's fix falling out of the
representation); and a guard test fails the build if separator-splitting reappears in
the analyzer tree.

## Progress

- [x] (2026-07-24) M0: `FqName` + interner module with unit tests and a
      memory/size measurement. Landed as `src/analyzer/fq_name.rs` (registered
      in `src/analyzer/mod.rs`). Ten `--lib fq_name` tests pass; measurement
      recorded in Surprises & Discoveries.
- [x] M1: dual representation — emission points populate `FqName` alongside the
      legacy strings, with an equivalence check (per language; check off individually).
  - [x] rust (2026-07-24)  - [x] cpp (2026-07-24)  - [x] python (2026-07-24)
  - [x] go (2026-07-24)  - [x] php (2026-07-24)  - [x] ruby (2026-07-24)
  - [x] scala (2026-07-24)  - [x] java (2026-07-24)  - [x] csharp (2026-07-24)
  - [x] javascript (2026-07-24)  - [x] typescript (2026-07-24)
  - [x] cleanup: migrate cpp's nested-class Type-Type native `$` rule onto
        `Nested` (2026-07-24, logged in the M1 rust/scala/cpp Decision Log
        entry above; done as part of this wave)
- [x] M2 (2026-07-24): shared services and selectors consume `FqName`; input
      parsing produces it. `parse_symbol_path_fq` added; the default
      `IAnalyzer::parent_of`, `resolve_qualified_in_enclosing_scopes`, and its
      shrinking-scope core migrated to segment composition with empty-fq string
      fallbacks; the issue-1162 reference-normalization shim deleted; the anchor
      splitter left byte-identical (retirement deferred, see Decision Log). Zero
      behavior change proven by the named regression suites plus the touched
      language analyzer/usages suites (all green; tally in Outcomes).
- [x] M3 (2026-07-24): persistence flip. Migration `0012-fq-segments.sql` adds a
      nullable `code_units.fq_segments` BLOB (length-prefixed `(kind, text)`
      pairs); both `code_units` write paths persist each unit's segments and both
      FileState load paths (`read_unit_rows`, `read_unit_rows_bulk`) re-intern
      them into the loaded `CodeUnit`'s `fq`, so FileState-hydrated cache units
      now carry populated `fq`. Every language's epoch `SALT` gained
      `;fq-interned-segments-2026-07` (one sweep). Round-trip proven by
      `tests/analyzer_persistence.rs::warm_fq_segments_survive_store_roundtrip_across_languages`
      (cpp `::`-head + scala Companion + python; 0 warm re-parses) and the
      pre-column upgrade by `cache_db::tests::fq_segments_migration_upgrades_pre_column_database`.
      The string-keyed `get_all_declarations`/candidate-row reconstruction path
      (`sql_all_declarations_vec`, and the `CandidateRow`→`CodeUnit` builders at
      `tree_sitter_analyzer.rs:3958`/`4555`) DELIBERATELY stays string-based
      (empty `fq`) — M4 worklist, not widened here.
- [ ] M4: retire string inference; grep-gate; issue-1163 pilot flip. Also fold
      the candidate-row `CodeUnit` reconstruction (`sql_all_declarations_vec` and
      the two `CandidateRow`→`CodeUnit` builders) onto segments so
      `get_all_declarations` units carry `fq` too, and delete the now-dead
      empty-fq fallback arms in `default_parent_fq_name` /
      `resolve_qualified_in_enclosing_scopes`.

## Surprises & Discoveries

- Observation (M0 memory measurement): interning is a large win because Bifrost's
  qualified names share heavy prefixes (directory/package heads, owner types).
  Evidence — the `measure_interned_vs_legacy_bytes` test builds a real corpus
  from this crate's own `src/` tree (527 `.rs` files → 1581 synthetic fq names:
  each path component a `Path` segment, the file stem a `Type`, two `Member`
  leaves):

        [fq_name measurement] corpus: 527 files, 1581 fq names
        [fq_name measurement] summed legacy string bytes: 43285
        [fq_name measurement] interner entries: 371, unique text bytes: 3646 (+1484 bytes of ids)
        [fq_name measurement] interned/legacy text ratio: 0.084

  Interned unique text is ~8.4% of the summed legacy string bytes (3646 vs
  43285); adding the 4-byte-per-entry id table (1484 bytes) it is still ~12%.
  The memory question is answered with numbers: the interned representation is
  far smaller than the concatenated strings even before counting that each
  `FqName` now stores 4-byte ids instead of owning its own `String`.

- Observation (go): a Go `package_name` is the canonical *import path*
  (`github.com/foo/bar`), so its `/`-separated components are `Path` segments and
  a component that itself contains a literal dot (`github.com`) must stay a single
  segment. Canonical `display()` therefore renders `/` between adjacent `Path`
  segments and `.` at the `Path`→name transition, which is exactly the legacy
  `fq_name()` shape. Evidence: `display_round_trips_go_import_path` asserts
  `github.com/foo/bar.Baz.method`, and every go analyzer/usages suite passes with
  the debug/test equivalence assertion active (it compares `fq.display()` to the
  legacy `package_name.short_name` join for every constructed unit).

- Observation (equivalence assertion fires): a deliberate mutation (appending a
  bogus `Member` segment `"BOGUS_MUTATION"` in `visit_go_type_spec`) made the
  `debug_assert_eq!` in `CodeUnit::with_signature_and_fq` fail loudly across the
  go suites before it was reverted. Evidence:

        thread panicked at src/analyzer/model.rs:1890:
        assertion `left == right` failed: FqName does not round-trip to the legacy
        qualified name (kind=Class, package_name="main", short_name="Target")
          left: "main.Target.BOGUS_MUTATION"
          right: "main.Target"

- Observation (scala Companion `$` was mis-modelled by go/M0): the synthetic
  go/M0 rule rendered a Companion segment with a `$` PREFIX separator
  (`Outer$Foo`), but Scala's real legacy `short_name` uses a trailing `$`
  SUFFIX on the object's own name joined with `.` — top-level `object
  LocalScheduler` -> `LocalScheduler$`; `object Foo { def bar }` -> `Foo$.bar`;
  `class Outer { object Foo }` -> `Outer.Foo$`; `object Outer { object Inner }`
  -> `Outer$.Inner$`. The render/​separator rules and the unit test were
  corrected to the suffix spelling (see Decision Log). Every scala analyzer/
  usages suite passes with the live equivalence assertion active, which is the
  proof the suffix form is the byte-exact legacy spelling.

- Observation (cpp `::`/`$` both needed, and the assertion had to render
  natively): C++'s legacy fq string is mixed-separator — `::` between namespace
  Package components, `$` between nested-class Type components, `.` to the
  terminal member (`cutlass::gemm::warp.Outer$Inner.method`). The canonical
  `.`-join cannot reproduce it, so the M1 equivalence assertion was changed to
  render each unit with `display_native(language)` (the plan's "cpp-specific
  expected-join", generalized: it is a no-op for every non-cpp language). A
  second native rule (`$` between adjacent Type segments) joined the existing
  `::`-between-Package rule.

- Observation (`_module_` scope): Go package-level `var`/`const`/`type alias`
  units carry the synthetic scope segment `GO_MODULE_SCOPE_SEGMENT` (`_module_`)
  in their `short_name` (`_module_.name`). It is emitted as a `Package` segment
  (a module scope), which round-trips identically; its precise kind only matters
  once M2 walks owner chains, and can be revisited there without affecting the M1
  string equivalence.

- Observation (python's `$` is NOT Scala-only): Python's legacy `short_name`
  join is not uniformly `.`-composed. `visit_class_definition` /
  `visit_function_definition` in `src/analyzer/python/declarations.rs` join a
  NESTED class onto ANY parent scope (Class or Function) with a literal `$`
  (`format!("{}${name}", parent.path)`), while a method/field owned directly by
  a class joins with `.`. Evidence from `tests/python_analyzer_test.rs`:
  `nested_local_classes.outer_function$OuterLocal$InnerLocal$DeepLocal` (four
  `$`-joined class levels hanging off a function) and
  `...$InnerLocal.inner_method` (a `.`-joined method on that same nested
  class). The plan's working assumption that python/ruby/php "don't have a
  Companion spelling" undercounted this: the existing `Companion` rendering
  rule (`if cur == Companion return "$"`, unconditional on the previous
  segment's kind) reproduces this exactly with ZERO changes to
  `src/analyzer/fq_name.rs`'s `separator()` logic, once every `$`-preceded
  segment is tagged `Companion` instead of `Type`/`Member`. See the Decision
  Log entry below for the reconciliation.

- Observation (ruby's whole type chain is `$`-joined, package_name is always
  empty): `src/analyzer/ruby/declarations.rs`'s own doc comment already states
  the convention: `package_name` is always `""`; nested namespaces/types join
  in `short_name` with `$` (`new_segments.join("$")` in `visit_class_like`,
  covering BOTH `module`/`class` declarations and multi-segment
  `scope_resolution` names like `class A::B::C`), and a type's members are
  appended after one final `.` (`member_short_name`). Since `package_name` is
  empty the very first segment of every ruby `FqName` never gets a leading
  separator regardless of its tag, so tagging EVERY namespace/type segment
  `Companion` (not just nested ones, unlike python) reproduces the `$`-chain
  exactly, including its first element.

- Observation (php mirrors python's nested-type `$`, and reuses go's
  `_module_` marker under a different literal): `src/analyzer/php/
  declarations.rs`'s `visit_type_declaration` joins a nested type onto its
  parent CLASS SCOPE (php has no function-nested types) with `$`
  (`format!("{}${name}", parent.short_name())`), same `Companion` reconciliation
  as python. Separately, `visit_const_declaration`'s module-level (no
  `scope.class_unit`) branch emits `format!("_module_.{name}")` — a php-local
  string literal `"_module_"`, distinct from (but textually identical to) Go's
  `GO_MODULE_SCOPE_SEGMENT` constant in `src/analyzer/go/mod.rs`. Tagged it as
  a `Package` segment, mirroring the go Decision Log entry above (a synthetic
  module-scope marker, not a real type or member).

- Observation (python's `package_name` field is the FULL module path, not just
  the directory): `PythonAdapter::parse_file` (`src/analyzer/python/
  adapter.rs`) passes `package_name: &module_fq` into `PythonVisitor`, where
  `module_fq = python_module_name(file)` already includes the module's own
  file-stem component (e.g. `mypkg.subpkg.mymodule`), not just the directory
  prefix (`mypkg.subpkg`). Every python `CodeUnit`'s stored `package_name`
  field is therefore this whole dotted path, and the declaration's own
  name/segments are ADDED ON TOP of it in `short_name`. This matters for
  fq-building: the "package prefix" helper must reconstruct the WHOLE
  `module_fq`, not stop at the directory.

- Observation (python/php package paths cannot contain a literal `.`/`\`
  post-normalization, so splitting them is lossless): python module and
  directory components are plain identifiers (Python syntax forbids a literal
  `.` inside one); php's `determine_php_package_name` already replaces `\` with
  `.` before storing `package_name`, and PHP identifiers cannot contain a
  literal `.` either. Both languages therefore get a `python_module_fq` /
  `php_package_fq` helper directly analogous to go's `go_package_fq` — split
  the already-computed `package_name` string on `.` (or `/` for go) and intern
  each component as one segment. This mirrors, rather than violates, the
  landed go precedent and CLAUDE.md's "no mini string parsers" rule (which
  targets replacing AST-derived structure with source-text splitting, not
  re-tokenizing a delimiter-joined string this same code already built from
  structured components).

- Observation (mutation check, done once on python per the plan's M1
  acceptance criterion): appending a bogus `Member` segment
  `"BOGUS_MUTATION"` to a top-level python class's `fq` in
  `visit_class_definition` made the `debug_assert_eq!` in
  `CodeUnit::with_signature_and_fq` (`src/analyzer/model.rs:1890`) fail loudly
  across `python_analyzer_test` before the mutation was reverted. Evidence:

        thread panicked at src/analyzer/model.rs:1890:
        assertion `left == right` failed: FqName does not round-trip to the legacy
        qualified name (kind=Class, package_name="mypackage.packaged_functions", short_name="RegularClass")
          left: "mypackage.packaged_functions.RegularClass.BOGUS_MUTATION"
          right: "mypackage.packaged_functions.RegularClass"

  Confirmed the same mutation trips the assertion identically across every
  top-level class in the fixture corpus (six distinct panics from one test
  run), then reverted; `cargo test --test python_analyzer_test` returned to
  24/24 passing afterward.

- Observation (M2 — the legacy `namespace_prefixes` walk is EXACTLY "cut the
  scope's native string at each literal `.`", which in segment terms is "cut at
  each boundary the native rendering spells `.`"): the whole risk of migrating
  `resolve_qualified_name_in_shrinking_scopes` onto segments was reproducing the
  cpp non-descent (never composing a sibling namespace, the issue-1163 pin)
  while still deleting the verbatim-scope workaround. The key equivalence: for
  the four languages that reach this resolver (rust, cpp, scala, csharp) NO
  segment's text contains an embedded `.` (only Go's `github.com`-style Path
  segments do, and Go never reaches here), so the string `rfind('.')` truncation
  points line up one-for-one with the segment boundaries whose
  `separator_between(..)` is `.`. A cpp `::` namespace boundary and a `$` nested
  boundary are simply not `.`, so the segment walk skips them — identically to
  the string walk, which cannot `rfind('.')` across a `::`. Evidence: with the
  dot-cut rule, `issue_1162_separator_aware_enclosing_scope` stays 10/10 with the
  cutlass `cpp_qualified_nested_namespace_type_current_behavior` pin intact, and
  `get_definition_test` stays 635/635.

- Observation (M2 — segment pop and the legacy `parent_of` scan diverge ONLY on
  an all-`Path` Go unit, which no test exercises, so the migration is safe): the
  default `parent_of` separator set is `[".","$","::","->"]` and does NOT include
  `/`. For a Go module unit whose fq is entirely Path segments
  (`github.com/foo/bar`), the string scan's rightmost `.` lands *inside*
  `github.com` (yielding `github`), whereas the segment pop drops the last Path
  component (yielding `github.com/foo`). This is the exact class of bug the plan
  exists to kill — but for every unit with a real owner (a member/type leaf), the
  rightmost separator is the leaf boundary, so the two arms agree, and the full
  Go suite (`go_analyzer_test`, `go_canonical_fqn_test`, `usages_go_graph_test`,
  `usage_graph_go_test`) is green after the switch — nothing calls `parent_of`
  on an all-Path Go unit in a way that observes the difference. Recorded so the
  divergence is a known, intended M4 correctness gain, not a lurking surprise.

- Observation (M3 — a content-addressed blob shared across paths cannot carry a
  verbatim path-derived fq prefix; caught by three existing store tests): the
  first M3 cut persisted each unit's WHOLE `fq` and decoded it verbatim on load.
  Three `--lib` tests failed immediately —
  `analyzer::store::tests::identical_go_blob_hydrates_with_live_import_paths`,
  `identical_python_blob_hydrates_with_live_path_names`, and a rust
  `cargo_routes` shadowing test — all with the M1 equivalence assertion firing on
  the LOAD-side construction. Evidence:

        FqName does not round-trip to the legacy qualified name
        (kind=Class, language=Go, package_name="example.com/demo/beta", short_name="Client")
          left: "example.com/demo/alpha.Client"    (decoded verbatim fq)
         right: "example.com/demo/beta.Client"     (per-path package_name.short_name)

  The store keys blobs by CONTENT (git-style): two files with identical bytes at
  different import paths (`alpha/client.go`, `beta/client.go`) share ONE persisted
  blob, and `LanguageAdapter::hydrate_content_qualifier` recomputes each unit's
  `package_name` PER PATH on load (Go import path, Python/Rust module path are
  file-derived; `storage_content_qualifier` deliberately stores `""` for them).
  A verbatim fq bakes in the write-path's package prefix, so hydrating the shared
  blob for the other path yields the wrong qualified name — the exact class of
  bug this plan exists to kill, resurfacing at the persistence boundary. Python
  made it starker: `pkg_a.mod` (2 prefix segments) vs `pkg_b.sub.mod` (3), so the
  prefix isn't even the same LENGTH — a text swap can't fix it. Resolution in the
  Decision Log (persist only the content-stable `short_name` tail; rebuild the
  path-dependent package prefix from the per-path `package_name` on load via
  `package_prefix_fq`). After the fix all three tests pass and `--lib` is
  1892/1892. This is precisely the "does the store mutate package_name after
  load?" caution the M3 brief flagged — the answer is yes (per-path re-derivation),
  and the fq had to mirror it.

## Decision Log

- Decision: internal representation is `SmallVec<[SegmentId; 8]>` where `SegmentId`
  is a `u32` interning a `(text, kind)` PAIR — kind is baked into the interned entry,
  not stored in a parallel per-position field.
  Rationale: Jonathan, 2026-07-24 — a parallel packed-kinds field is clunky; the cost
  of occasionally interning the same text under two kinds (two entries for "src") is
  negligible, and baking kind in keeps FqName to a single small vector with pure
  integer comparisons.
- Decision: no scope-trie / parent-pointer compression, now or as part of this plan.
  Rationale: Jonathan, 2026-07-24 — the trie's chain-construction machinery (shared
  mutable hash-consing across parallel extraction, grow-only arena, load-time rebuild)
  is not worth structural prefix sharing when interned IDs already cost 4 bytes per
  segment. If profiling ever shows prefix repetition matters, a trie can hide behind
  the same FqName API later.
- Decision: no canonical-string-plus-boundary-index representation.
  Rationale: Jonathan, 2026-07-24 — strictly clunkier than interned IDs.
- Decision: SegmentIds are process-local; persistence stores segment text+kind, never
  IDs. Rationale: IDs from a hash-consing interner are not stable across processes or
  runs; persisting them would couple the store to interner insertion order.
- Decision (M0): the interner is a single process-global `OnceLock<SegmentInterner>`
  (accessor `crate::analyzer::fq_name::segment_interner()`), not per-workspace.
  Rationale: threading a per-workspace interner through every `CodeUnit`
  constructor across eleven languages is a large mechanical cost with no
  correctness benefit while the legacy strings remain authoritative; entries are
  tiny and text-deduplicated, and the plan explicitly permits one interner per
  process. Date/Author: 2026-07-24, implementation (go/M0 wave).
- Decision (M0): the interner is sharded (16 shards), each an
  `RwLock<{ by_text: FxHashMap<String, SmallVec<[(kind,id);2]>>, entries:
  Vec<(&'static str, kind)> }>`. `SegmentId(u32)` encodes `index*SHARD_COUNT +
  shard` so a bare id resolves without a side table. Segment text is leaked once
  on first insert (`Box::leak`) so `resolve` can return a `&str` that outlives
  the read guard; the interner is grow-only for the process lifetime and bounded
  by the segment vocabulary, so the leak is an arena, not a leak-per-call.
  Rationale: extraction is file-parallel, so `intern` must be lock-cheap; the hot
  (hit) path takes only a read lock and the `String`-keyed map allows borrowed
  `&str` lookups with no allocation. Date/Author: 2026-07-24, implementation.
- Decision (M0): `SmallVec<[SegmentId; 8]>` sourced from a new direct dependency
  `smallvec = "1"` (already present transitively at 1.15.2 in `Cargo.lock`; no
  new crate is downloaded). Rationale: the plan mandates the type; adding it as a
  direct dependency is the sanctioned way to use it. Date/Author: 2026-07-24.
- Decision (M0): canonical `FqName::display` renders `/` between two adjacent
  `Path` segments, `$` before a `Companion` segment, and `.` otherwise;
  `display_native(Cpp, ..)` additionally renders `::` between adjacent `Package`
  segments. Rationale: the plan's "`.`-joined" is the common case, but go's
  legacy `fq_name()` already embeds `/` inside `package_name`
  (`github.com/foo/bar.Sym`), so the canonical display MUST reproduce `/` to
  round-trip. Path segments are always a leading prefix, so `Path`→name is `.`.
  The `Companion`/`::` rules are provisional until scala/cpp are migrated (they
  are unit-tested but unused by go). Date/Author: 2026-07-24.
- Decision (M1 CodeUnit field): `fq: FqName` is added to `CodeUnitInner` and is
  DELIBERATELY EXCLUDED from `CodeUnit`'s identity (`PartialEq`/`Eq`/`Hash`/`Ord`,
  which are hand-written and reference the string fields directly). The unused
  derived `PartialEq/Eq/Hash` on `CodeUnitInner` were dropped (kept `Debug`) so
  no path accidentally includes `fq` in identity. Rationale: `fq` is a redundant
  derived form of the strings, and during dual representation a freshly-extracted
  unit (populated `fq`) and a cache-loaded or not-yet-migrated unit (empty `fq`)
  describing the SAME declaration must compare equal, or every `HashMap<CodeUnit,
  ..>` lookup would break. Non-migrated languages stay compiling because
  `with_signature`/`new` default `fq` to `FqName::new()` (empty) and the
  equivalence assertion is skipped for empty `fq`. Go opts in via the new
  `pub(crate)` `CodeUnit::new_fq` / `with_signature_and_fq`. Date/Author:
  2026-07-24.
- Decision: the issue-1162 landing deliberately left scope-side fq strings verbatim
  (C++'s mixed `::`/`.` store) as a workaround; that workaround inverts at M3 when
  the store carries explicit segments and C++ emits tagged segments like every other
  language. Recorded so nobody "fixes" the workaround independently.
- Decision (M1 rust/scala/cpp): the M1 equivalence assertion in
  `CodeUnit::with_signature_and_fq` now renders `fq.display_native(lang, ..)` where
  `lang = common::language_for_file(source)`, not the canonical `fq.display(..)`.
  Rationale: this is the plan's prescribed "cpp-specific expected-join" realized
  generally. `display_native` equals the canonical rendering for every language
  except C++, so go/rust/scala are unaffected, while C++ units are checked against
  the mixed-separator legacy string (`::` between namespace Package segments, `$`
  between nested-class Type segments) they must reproduce until M3. The unit's
  language is recovered from its file extension (debug/test-only path). Date/Author:
  2026-07-24.
- Decision (M1 scala Companion display rule): the go/M0 Companion rule rendered `$`
  as a *prefix separator* before a Companion segment (`Outer$Foo`, JVM binary-name
  style). Scala's actual legacy `short_name` spells an `object` with a trailing `$`
  *suffix* on its own name (`format!("{raw_name}$")`) joined to neighbours with `.`
  (`LocalScheduler$`, `Outer$.Inner$`, `Outer.Foo$` for an object nested in a class).
  Changed `separator`/`render` in `src/analyzer/fq_name.rs`: a Companion segment now
  emits its text followed by a literal `$` and takes an ordinary `.` separator from
  its neighbours; the `display_companion_uses_dollar` unit test was retargeted to the
  suffix spelling (`display_companion_uses_trailing_dollar_suffix`). Only Scala emits
  Companion segments, so no other language is affected. Rationale: the go/M0 rule was
  unit-tested synthetically and never validated against Scala's real convention; the
  suffix form is what round-trips the legacy strings. Date/Author: 2026-07-24.
- Decision (M1 cpp nested-class `$`): C++ nested classes are stored `Outer$Inner` in
  `short_name` — those `$` are NESTED-CLASS separators (issue #1121), distinct from
  Scala's companion `$` suffix. Each nested class is its own `SegmentKind::Type`
  segment; a new `display_native(Cpp)` rule renders `$` between adjacent Type
  segments (mirroring the existing `::`-between-Package rule). Rationale: preserves
  the per-class structure M2/M3 owner-chain walking needs while round-tripping the
  legacy `$`-joined string. Date/Author: 2026-07-24.
- Decision (M1 rust/scala/cpp package prefixes): each language recovers its package
  prefix by splitting the already-joined legacy `package_name` at construction —
  rust/scala on `.` (module/package components -> `Package` segments), cpp on `::`
  (namespace components -> `Package` segments) — mirroring go's `/`-split
  `go_package_fq`. This is the sanctioned M1 bridge: the legacy strings remain
  authoritative until M3, so reconstructing their components is not the banned
  "regex instead of tree-sitter" (there is no richer AST for an
  already-collapsed path string), and any mis-split fails the equivalence assertion
  loudly. Rust package-level `const`/`static` items additionally carry a
  `_module_` `Package` scope segment (matching go's `_module_`). Date/Author:
  2026-07-24.
- Decision (M1 cpp per-site string reconstruction): rather than thread parent
  `FqName`s through C++'s scope machinery (which stores `package_name`/class
  `short_name` as strings on `ScopeInfo`/`class_unit`), each C++ construction site
  rebuilds the `FqName` from the assembled `package_name` + `short_name` via three
  helpers (`cpp_namespace_fq`, `cpp_class_fq`, `cpp_member_fq`) that split on `::`
  (Package), `$` (Type), and the single member-boundary `.` (Member). Rationale:
  C++ member/owner names never contain a literal `.` and nested classes never a
  `::`, so the split is unambiguous; this avoids invasive plumbing while the strings
  remain authoritative. The template-metadata `primary_fq_name` site keeps an
  empty-`fq` `CodeUnit::new` (it is a throwaway used only for its `.fq_name()`
  string, never indexed). Date/Author: 2026-07-24.
- Decision (M1 python/ruby/php — `Companion` is reused for non-Scala `$`
  spellings, not left unused): the task briefing for this wave assumed
  "Companion only if the language has such a spelling — these three don't."
  Empirically that is wrong for python and php (see the Surprises entries
  above): both join a NESTED type onto ANY parent with a literal `$`, distinct
  from the `.` used for a type's own direct members, and ruby joins its ENTIRE
  namespace/type chain with `$`. Rather than add a new `SegmentKind` or teach
  `src/analyzer/fq_name.rs`'s `separator()` a new (prev, cur) rule — which
  would touch the same shared file the parallel rust/scala/cpp M1 agent is
  also likely to touch — every `$`-preceded segment in python/ruby/php is
  tagged `SegmentKind::Companion`, exactly reusing the existing "renders `$`
  regardless of the previous segment's kind" rule verbatim. The ONLY edit to
  `src/analyzer/fq_name.rs` this wave made is a doc-comment broadening on the
  `Companion` variant (no logic change) noting it is not Scala-exclusive.
  Rationale: `Companion`'s CODE semantics were already general ("a `$`-spelled
  nested-scope boundary"); only its doc comment and the task briefing's mental
  model were Scala-specific. Reusing it needs zero shared-file logic changes,
  carries zero risk to already-landed go or to the parallel agent's cpp/scala
  work, and every python/ruby/php suite (see Validation below) confirms the
  legacy strings still round-trip exactly. `SegmentKind::Unknown` and new
  `separator()` rules remain unintroduced, per the plan's M2 guidance to add
  them "ONLY if matching genuinely needs it." Date/Author: 2026-07-24,
  implementation (python/ruby/php M1 wave).
- Decision (M1 python — `package_name` segments are `Package`, not `Path`):
  python's `package_name` (really the file's whole dotted module path, e.g.
  `mypkg.subpkg.mymodule` — see Surprises above) is `.`-joined throughout,
  unlike go's `/`-joined import path. `FqName::display`'s only special-cased
  adjacency rule is `Path`-`Path` → `/`; tagging python's components `Path`
  would therefore incorrectly render `/` between them. `Package`-`Package`
  renders `.` by default (no rule change needed) and `Package` is already
  documented as "a namespace / package / module", which is exactly what these
  components are. Same reasoning applies to php's namespace components (see
  next entry). Date/Author: 2026-07-24, implementation.
- Decision (M1 php — namespace segments are `Package`; reuses go's `_module_`
  marker convention under php's own literal): php's `determine_php_package_name`
  already normalizes `\`-separated namespace text to `.`-joined text before it
  becomes `package_name`, so — like python — its components are tagged
  `Package`, not `Path`. Separately, php's free (non-class) constant
  declarations use their own pre-existing `"_module_"` string literal
  (unrelated to Go's `GO_MODULE_SCOPE_SEGMENT` constant, though textually
  identical) as a synthetic module-scope marker; it is tagged `Package`,
  mirroring the go Decision Log entry for `GO_MODULE_SCOPE_SEGMENT` above (a
  module-scope marker rather than a real type or member). Date/Author:
  2026-07-24, implementation.
- Decision (M1 python — `Scope` gained its own `fq: FqName` field, tracked
  independent of `capture`/`code_unit`): a python local class is captured
  (gets a `CodeUnit`) unconditionally whenever it has ANY parent scope, but a
  local FUNCTION nested inside another function is captured only when its
  immediate parent is a Class scope — so a function-in-function scope level
  can have `code_unit: None` while a class nested even deeper still needs a
  correct parent `fq` to extend. Storing `fq` on every `Scope` entry
  (mirroring the pre-existing `path: String` field, which is already tracked
  the same way for the legacy string) makes fq construction correct in that
  edge case without falling back to any string reconstruction. Date/Author:
  2026-07-24, implementation.
- Decision (M1 ruby — `assignment_constant_fq` builds a fresh chain rather
  than extending a lexical parent's `fq`): Ruby constant assignment can
  re-open a namespace by explicit path (`A::B::CONST = 1` while lexically
  inside a different `module X`), so `assignment_constant_short_name`'s owner
  segments already come from the assignment's OWN AST-derived name path
  (`extract_name_path`), not necessarily the lexically enclosing type. The
  structured counterpart (`assignment_constant_fq`) mirrors this exactly:
  it builds a new `Companion`-tagged chain from those same owner-segment
  strings via `ruby_member_fq`, rather than reading `.fq()` off some
  in-scope `CodeUnit` (which may not even be the right namespace).
  Date/Author: 2026-07-24, implementation.

- Decision: `SegmentKind::Nested` added for `$`-JOINED nesting (python/php nested
  types, python local functions, ruby namespace chains); `Companion` stays
  scala-only with its trailing-`$` SUFFIX rendering. The two parallel M1 agents
  had implemented opposite `$` conventions on the shared `Companion` kind (scala
  suffix vs p/r/p prefix-join), which collided at integration - they are
  genuinely different concepts and now have different kinds. cpp/java nested
  classes (currently Type + a cpp-native `$` rule) should migrate onto `Nested`
  during the java M1 / M2 cleanup so one mechanism spells `$`-joins.
  Rationale: integration finding, coordinator, 2026-07-24.
- Decision: two usage_graph expectation flips (ruby calls_local, php
  callsSelfMethod) were missed by the #1138 landing and surfaced during this
  wave's validation - flipped with #1138 justifications as part of this
  integration, not new behavior.
  Rationale: coordinator, 2026-07-24.
- Decision (M1 java — nested classes are `.`-joined, NOT `$`-joined; task
  briefing's premise was wrong, same pattern as the earlier python/php
  reconciliation): the briefing for this wave assumed "java nested classes use
  `$` in short_name (`Outer$Inner`)" by analogy with JVM binary names. Empirically
  `visit_class_like` in `src/analyzer/java/declarations.rs` joins a nested class
  onto its parent with a plain `.` (`format!("{}.{}", parent.short_name(),
  simple_name)`) — confirmed by `tests/usage_graph_java_test.rs`'s
  `com.example.Outer.Inner.helper` expectation and `external.rs`'s
  `qualified_name` helper, which is als `.`-joined. The `$`-joined JVM
  convention only appears in `normalize_java_full_name`/`is_java_anonymous_structure`,
  which post-process bytecode-derived strings from a DIFFERENT subsystem
  (`JavaExternalType`, not `CodeUnit`) that this M1 wave does not touch. Every
  java nested class is therefore tagged a plain `SegmentKind::Type` (not
  `Nested`), hanging off its parent's own `fq` exactly like a top-level class
  hangs off the package-path `Package` chain — java needed NO native rule and
  NO `Nested` segments for its class hierarchy. Date/Author: 2026-07-24,
  implementation (java M1 wave).
- Decision (M1 java — the anonymous-lambda `$anon$line:column` marker IS a
  genuine `Nested` join): `lambda_code_unit` in `src/analyzer/java/declarations.rs`
  builds a synthetic name `{parent.short_name()}$anon${line}:{column}` (lambda
  directly in a method) or `{parent.short_name()}.{parent.identifier()}$anon${line}:{column}`
  (lambda in a field/class-level initializer, confirmed by
  `tests/java_lambda_parity.rs`'s `Interface.Interface$anon$5:24` fixture
  expectation). The marker is modelled as ONE `Nested` segment whose OWN text
  is `anon${line}:{column}` (embedding a literal `$` between "anon" and the
  coordinate, which `Nested`'s free-form segment text permits) — `Nested`'s
  unconditional `$` join supplies the leading `$` before it. The
  field/class-level variant additionally re-pushes the parent's own last `fq`
  segment (mirroring `parent.identifier()`) before the `Nested` marker.
  Date/Author: 2026-07-24, implementation.
- Decision (M1 csharp — nested types ARE `$`-joined, confirming the task
  briefing's guess): `visit_type_declaration` in
  `src/analyzer/csharp/declarations.rs` joins a nested type onto its parent
  with a literal `$` (`format!("{}${identity_name}", parent.short_name())`,
  issue #1121-style), tagged `SegmentKind::Nested` with zero new rules (same
  mechanism as python/php/ruby/cpp/java's now-shared `$`-join primitive);
  namespaces (`csharp_join_namespace`, always `.`-joined, never `/`) are
  `Package` segments, mirroring java/python. Date/Author: 2026-07-24,
  implementation.
- Decision (M1 javascript/typescript — `package_name` is ALWAYS empty; there
  is no directory-derived `Path` prefix, contrary to the task briefing's guess
  that this needed empirical path-vs-package verification): every js/ts
  `CodeUnit` constructor passes a literal `""` for `package_name` (grepped:
  zero non-literal uses in `javascript/mod.rs`, `typescript/mod.rs`, or
  `js_ts/model.rs`) — the whole qualified name lives in `short_name`, exactly
  like ruby. Declarations are therefore NOT qualified by directory path at all;
  the only place a file's own name appears is the bare basename (with
  extension, e.g. `utils.js`) used as a synthetic prefix in two places: the
  file's own `Module` `CodeUnit` (`module_code_unit`) and
  `file_scoped_field_name`'s qualifier for a top-level exported field/type-alias
  with no enclosing class. Both are modelled as a single `SegmentKind::Path`
  segment (its designed "may contain literal dots" case, e.g. `utils.test.js`)
  — never split into directory components, since none exist here — followed by
  the ordinary `.`-joined `Member` chain. Added shared helpers
  `js_ts_segment`/`file_scoped_field_fq`/`file_name_path_segment` to
  `src/analyzer/js_ts/model.rs` alongside the pre-existing (string-only)
  `file_scoped_field_name`, and threaded `fq` through `module_code_unit` and
  `add_default_export_unit` there so both javascript and typescript share one
  implementation. Date/Author: 2026-07-24, implementation.
- Decision (M1 typescript — a `$static` suffix and a TS `internal_module`
  namespace need NO new segment kind): `visit_ts_method`/`visit_ts_field` spell
  a static class member as `{name}$static` — a literal suffix baked into the
  member's OWN name text, not a join between two segments — so it is pushed
  as a single ordinary `Member` segment whose text already includes the
  suffix; no new kind or separator rule is needed (segment text is free-form).
  Separately, a TS `internal_module` (namespace) is already treated identically
  to `class_declaration`/`interface_declaration`/`enum_declaration` by
  `visit_ts_class_like` (same `CodeUnitType::Class`, same `.`-joined nesting),
  so it needed no special-casing beyond the ordinary `Type` tagging every
  class-like site already gets. Date/Author: 2026-07-24, implementation.
- Decision (M1 javascript — a CommonJS `object.property` assignment chain
  (`Foo.Bar.baz = ...`) builds its `fq` recursively alongside its `name`
  string, not via re-splitting the joined string): `js_member_assignment_target`
  in `src/analyzer/javascript/mod.rs` already recurses structurally through
  nested `member_expression` nodes to build `target.name` component-by-component
  (`format!("{object_name}.{property_name}")`); `JsMemberAssignmentTarget`
  gained a parallel `fq: FqName` field built the same way (base case: an
  identifier is one `Member` segment; recursive case: the nested call's `fq`
  plus one more `Member` segment) so the structured form is read off the same
  AST recursion that built the string, never off the assembled string itself
  (CLAUDE.md's "no mini string parsers" targets exactly the alternative of
  re-splitting `target.name` on `.`, which was avoided). The sibling
  `js_commonjs_export_assignment_name` branch (a bare `exports.foo = ...`
  property, no chain) builds its `fq` as a single `Member` segment the same way.
  Date/Author: 2026-07-24, implementation.
- Decision (cleanup — cpp nested-class chain migrated from Type+native-rule
  onto the general `Nested` mechanism, per the M1 rust/scala/cpp wave's logged
  plan): `cpp_push_type_chain` in `src/analyzer/cpp/declarations.rs` now tags
  only the OUTERMOST class in a `$`-joined nested-class chain (`Outer$Inner`)
  as `SegmentKind::Type`; every subsequently nested class is
  `SegmentKind::Nested`, reusing the same `$`-join primitive python/php/ruby/
  csharp/java's nested/local scopes already share. The cpp-native
  `Type`-`Type` → `$` rule was deleted from `separator()` in
  `src/analyzer/fq_name.rs` (the `::`-between-Package cpp-native rule stays —
  that one is genuinely cpp-only, not a `$`-join). This is representation-only:
  `display_native(Cpp, ..)` renders byte-identically before and after (the
  `Nested` rule fires unconditionally, same as the deleted cpp-only rule did
  for this case), confirmed by the full cpp suite staying green with identical
  pass counts before and after the retag (cpp_analyzer_test, usages_cpp_graph_test,
  usage_graph_cpp_test, issue_1093_cpp_using_namespace_owner,
  issue_1120_cpp_bare_call_lexical_scope, issue_1121_cpp_nested_class_out_of_line —
  246 tests total, 0 failed both times) and by retargeting the
  `display_native_cpp_nested_class_uses_dollar` unit test to assert BOTH
  `display()` and `display_native(Cpp, ..)` now produce the identical
  `ns.Outer$Inner.method` (previously only the native rendering carried the
  `$`; now the canonical rendering does too, since `Nested` is unconditional —
  this is the intended convergence, not a behavior change to any legacy
  string). Date/Author: 2026-07-24, implementation (java/csharp/js/ts M1 wave).

- Decision (M2 input edge — kind-insensitive user input via a new
  `SegmentKind::Unknown`, NOT best-effort Path/Type tagging): the plan's M2
  paragraph left one question open — tag input segments best-effort (file/slash
  heads → Path, leaf → Member/Type) OR match kind-insensitively. Chose
  kind-insensitive: every segment of a user-supplied path (`parse_symbol_path_fq`
  in `src/analyzer/symbol_lookup.rs`) is interned as `SegmentKind::Unknown`.
  Rationale: (1) users type spellings, not kinds — a best-effort kind is a guess
  that can only be wrong, and the input never needs a kind to be matched; (2)
  the actual M2 consumer of `parse_symbol_path_fq` (the enclosing-scope
  resolver) matches by *rendering* the composed candidate to a string and
  looking it up in the string-keyed `analyzer.definitions` index — so kind is
  irrelevant to matching, it only affects rendering *separators*. `Unknown`
  renders with an ordinary `.` (the default in `separator`), so an input FqName
  renders to exactly `parse_symbol_path(..).join(".")` — the canonical
  normalization the old issue-1162 shim produced — which is what makes the shim
  deletion byte-identical. Tagging heads `Path` would have been WRONG here:
  `Path`-`Path` renders `/`, so a slash-input reference `a/b` would render `a/b`
  instead of the required `a.b`. The "text-level comparison path" the plan asks
  for (interner text-id lookup / kind-differing FqName compare) is therefore NOT
  introduced in M2 — it is genuinely unneeded while consumers match by rendered
  string against the string index. It becomes necessary only at M3, when the
  index turns segment-keyed and matching moves to FqName integer-equality; the
  decision is recorded now and the interner text-id path is deferred to where it
  is actually exercised (respecting the plan's "introduce X ONLY if matching
  genuinely needs it"). `SegmentKind::Unknown` renders `.` in both canonical and
  native spellings (it is never `Package`, so C++'s `::` rule never fires).
  Date/Author: 2026-07-24, implementation (M2).

- Decision (M2 `parent_of` default — segment pop with an empty-fq string
  fallback, factored into `default_parent_fq_name` in `src/analyzer/i_analyzer.rs`):
  a populated `fq` yields the owner by a pure `FqName::parent()` pop rendered
  with `display_native(language)`; a cache-loaded (empty-fq) unit keeps the
  legacy rightmost-of-`[".","$","::","->"]` scan. The M1 equivalence assertion
  guarantees the two arms compute the identical owner name, so the switch is
  zero-behavior-change; both arms are exercised by dual-arm unit tests
  (`parent_of_tests`) that build a `new_fq` unit and its empty-`fq` twin from the
  same strings and assert identical owner names across cpp `::`-heads, dotted
  packages, `$`-nested types, and Go import paths. The rust/scala/java/csharp/
  js/ts `parent_of` overrides are untouched. Rationale: `::` is in the parent-of
  separator set (unlike the shrinking-scope walk), so segment pop and string
  scan agree even when popping into a C++ namespace head — parent-of legitimately
  descends namespaces where the shrinking-scope walk must not. Date/Author:
  2026-07-24, implementation (M2).

- Decision (M2 shrinking-scope migration — `resolve_qualified_name_in_shrinking_scopes_fq`
  composes candidates by segment push, and the reference-normalization shim is
  deleted): `resolve_qualified_in_enclosing_scopes` (`get_definition/mod.rs`) now
  parses the reference once into an `FqName` (`parse_symbol_path_fq`) and, when
  the enclosing scope unit has a populated `fq`, composes each candidate by
  pushing the reference segments onto a scope prefix and rendering natively —
  deleting `normalize_reference_to_fq_segments` entirely (the M1 shim that
  string-joined the parsed reference). The verbatim-scope "workaround" is
  replaced by a precise segment rule: the scope prefix walk descends across a
  boundary ONLY where the native rendering places a literal `.`
  (`SegmentInterner::separator_between(..) == "."`), which reproduces the legacy
  dot-only `namespace_prefixes` walk EXACTLY for the four reaching languages
  (rust/cpp/scala/csharp — none of whose segments contain an embedded dot), and
  in particular never descends a C++ `::`-joined namespace head — so issue #1163
  stays pinned (`cpp_qualified_nested_namespace_type_current_behavior` green)
  until M4 flips it deliberately. Empty-fq scope units (cache-loaded) fall back
  to the retained string core `resolve_qualified_name_in_shrinking_scopes`,
  rendering the reference via `display()` to the same `.`-joined normalization;
  the csharp bounded fork (`resolve_csharp_in_enclosing_scopes`) keeps calling
  that string core unchanged (its scope is bare-name + budget-charged; migrating
  it is a low-value M4 follow-up). Both arms proven identical by
  `issue_1162_separator_aware_enclosing_scope` (10/10, including the cutlass pin)
  and `get_definition_test` (635/635) staying green. Date/Author: 2026-07-24,
  implementation (M2).

- Decision (M2 anchor splitter — retirement deferred, splitter left
  byte-identical): the plan's part-4 ask ("selectors parse into optional
  Path-prefix + symbol segments; the `.r`-lookalike heuristics retire where the
  tagged boundary makes them redundant") is realized as a documented deferral,
  not a code change to `split_definition_selector_with_resolver` in
  `src/searchtools/selectors.rs`. Reason: that splitter runs *before* the input
  is bound to a language, so it cannot parse `DbColumn.r#type` into a single
  raw-identifier `Member` segment to prove the `#` is intra-token — only a
  language-aware `parse_symbol_path_fq` could, and threading a language into the
  pre-resolution splitter is a larger change than M2's zero-behavior bar allows.
  The `anchor_is_file` resolver check — which the plan explicitly keeps as the
  semantic validation — already resolves #1128 correctly (`DbColumn.r` is not a
  file), so the `.r`-lookalike heuristic is NOT yet redundant. The #1128/#1131
  anchor canaries pass UNCHANGED (12/12 and within searchtools_definition_selectors
  73/73), which is the plan's stated bar for this part. A clarifying comment at
  the split site records the segment-model relationship and points here.
  Date/Author: 2026-07-24, implementation (M2).

- Decision (M3 encoding — a length-prefixed binary BLOB, not JSON): the
  `code_units.fq_segments` column is a compact self-describing binary blob —
  for each segment a one-byte kind tag, a little-endian `u32` text length, then
  the UTF-8 segment text (`FqName::encode_segments`/`decode_segments` in
  `src/analyzer/fq_name.rs`). Chosen over a JSON array of `(kind, text)` because
  (1) segment text is free-form and routinely contains the very delimiters the
  system used to split on (`.`, `::`, `$`, `#`) plus quotes/backslashes, so an
  explicit length prefix makes decode unambiguous with ZERO escaping, where JSON
  would need escaping and be bulkier; (2) it needs no serde derive on
  `SegmentKind` and no bincode framing, staying a small dedicated codec that is
  unit-tested in isolation (`encode_decode_round_trips_kind_and_text`,
  `decode_rejects_malformed_blobs`); (3) it matches the store's existing
  "compact binary payload" convention for side tables (which use bincode) while
  being simpler and self-contained. The kind→tag mapping is a persistence
  contract (`SegmentKind::persist_tag`/`from_persist_tag`): tags are appended,
  never renumbered. Interner IDs are process-local and NEVER written — only text
  and kind — so the blob re-interns cleanly in any later process. The column is
  nullable: an empty `fq` (synthetic file-scope units) and any pre-migration row
  store NULL, which decodes to an empty `FqName`. `short_name`/`content_qualifier`
  stay populated (indexes + human inspection); the structured column is
  authoritative for the `FqName` on load. Date/Author: 2026-07-24, implementation
  (M3).

- Decision (M3 load-side scope — `fq` is attached only on the FileState
  hydration path, NOT the candidate-row `get_all_declarations` path): the two
  `code_units` write paths (`write_prepared_blob_unchecked_tx` and the direct
  writer) persist `fq_segments` for every unit, but only the two FileState load
  paths — `read_unit_rows` and `read_unit_rows_bulk` in
  `src/analyzer/store/mod.rs` — decode and re-intern them into the loaded
  `CodeUnit` (via `CodeUnit::with_signature_and_fq`). The separate string-keyed
  enumeration `sql_all_declarations_vec` and the `CandidateRow`→`CodeUnit`
  builders (`src/analyzer/tree_sitter_analyzer.rs:3958` and `:4555`) that back
  `IAnalyzer::get_all_declarations`/definition-candidate resolution
  DELIBERATELY keep building empty-`fq` units from the persisted strings. Those
  rows re-derive from `code_units` (or re-extract via the salt) and were called
  out by the M3 brief as out of scope; folding them onto segments (and deleting
  the empty-fq fallback arms) is M4 worklist. Consequence for testing: the
  round-trip proof observes loaded `fq` through `IAnalyzer::get_declarations(file)`
  (FileState), not `get_all_declarations` — the latter still returns empty-`fq`
  units by design. Date/Author: 2026-07-24, implementation (M3).

- Decision (M3 equivalence-on-load holds for free, given the pre-existing
  package_name round-trip invariant): the M1 debug/test assertion in
  `CodeUnit::with_signature_and_fq` compares `fq.display_native(language)` to
  `package_name.short_name`. On load, `short_name` is the stored column and
  `package_name = adapter.hydrate_content_qualifier(storage_content_qualifier(..))`.
  The cache's correctness ALREADY depends on `hydrate∘storage` reproducing the
  extraction-time `package_name` exactly (otherwise a loaded unit's identity
  would differ from the extracted one and every `HashMap<CodeUnit,..>` lookup
  would break) — so the decoded `fq`, which round-trips to the extraction-time
  `package_name.short_name`, round-trips to the loaded pair too. No store path
  mutates `short_name`/`package_name` after load beyond that hydrate step. The
  assertion therefore fires during the warm-build load in the round-trip test
  (debug build), and the test passing is the verification that it holds on
  loaded units. Date/Author: 2026-07-24, implementation (M3).

- Decision (M3 — persist the content-stable `short_name` TAIL only; rebuild the
  path-derived package prefix on load): a declaration's `fq` is
  `[package prefix] ++ [short_name tail]`. For Go (import paths) and Python/Rust
  (module paths) the package prefix is FILE-PATH-derived and is recomputed
  per-path on load (`hydrate_content_qualifier`), while the content-addressed
  blob store shares one blob across identical-content files at different paths.
  Persisting the whole `fq` therefore bakes in the write-path's prefix and
  mis-hydrates the shared blob at any other path (see the Surprises entry). So
  `code_units.fq_segments` stores ONLY the tail (`encode_unit_fq_segments` strips
  the leading `package_prefix_fq(lang, unit.package_name())` segments), and load
  (`hydrate_unit_fq`) rebuilds the prefix from the PER-PATH `package_name` and
  appends the decoded tail. New shared free fn `package_prefix_fq(lang,
  package_name, interner)` in `src/analyzer/fq_name.rs` splits the already-joined
  `package_name` by language spelling (Go `/`→`Path`; C++ `::`→`Package`; every
  other package-bearing language `.`→`Package`; Ruby/JS/TS carry no package). The
  write side `debug_assert!(fq.starts_with(&prefix))` proves — by interned-ID
  equality, not string compare — that the reconstruction reproduces the
  extractor's leading segments byte-for-byte for every unit across every suite,
  so `package_prefix_fq` is a self-verified mirror of the M1 per-language package
  split, not a drifting second parser. This is the load-side counterpart of the
  sanctioned M1 construction bridge (re-tokenizing a delimiter-joined string the
  code itself built from structured components), not the banned "regex instead of
  tree-sitter": there is no richer AST for an already-collapsed path string and
  path components cannot contain their own separator. For source-derived-package
  languages (java/scala/cpp/csharp/php) `hydrate == storage == extraction
  package_name`, so the rebuilt prefix equals the persisted one and the whole
  thing is a no-op; only the file-path-derived languages actually exercise the
  reconstruction. M4 could move `package_prefix_fq` behind a `LanguageAdapter`
  method delegating to each extractor's existing `*_package_fq` helper to retire
  even this shared split. Date/Author: 2026-07-24, implementation (M3).

- M1 rust/scala/cpp (2026-07-24): all three "hard" languages now populate
  `FqName` at every `CodeUnit` emission point, with the live equivalence
  assertion (`display_native(language)` vs the legacy joined string) active
  across their full suites. Census: rust 7 constructor sites
  (`visit_rust_class_like` Type, `visit_rust_module` Package, `visit_rust_function`
  Member, `register_rust_macro` Member, `visit_rust_field` Member under a
  `_module_` Package scope at top level, `visit_rust_alias` Member, and the
  synthesized `rust_impl_owner` fallback built from strings); scala 8 sites
  (`visit_recovered_type_header` + `visit_type_declaration` Type/Companion, the
  primary-constructor Function, `visit_class_parameter_fields`/`visit_field_declaration`/
  `visit_type_alias`/`visit_enum_case` Member, `visit_function_with_signature`
  Member); cpp 8 live sites (`visit_namespace` Package, class-like + type-alias
  Type via `cpp_class_fq`, two enum-enumerator sites Member, variable Member,
  macro Member, `FunctionInfo::code_unit_with_synthetic` Member via
  `cpp_member_fq`) plus one deliberately-empty throwaway (`primary_fq_name`).
  Two shared-infra changes landed with them: the Scala companion display rule was
  corrected from a `$` prefix separator to a trailing `$` suffix, and the M1
  equivalence assertion now renders `display_native(language)` so C++'s
  `::`/`$` mixed-separator legacy string is the compatibility target (see
  Decision Log). Validation: `cargo fmt` clean; `cargo clippy --all-targets
  --all-features -D warnings` clean; the full targeted suite green — lib 1879,
  cpp_analyzer 43, get_definition 635, issue_1093 9, issue_1120 10, issue_1121 11,
  issue_1128 12, issue_1142 11, issue_1162 10, mcp_property_fuzzer 61,
  rust_analyzer 15, rust_macro_item 9, scala_analyzer 29,
  scala_definition_precedence 52, searchtools_definition_selectors 73,
  searchtools_service 188, usages_cpp_graph 145, usages_rust_graph 202,
  usages_scala_graph 148 (all 0 failed). Mutation check: flipping the scala
  object segment kind `Companion` -> `Type` (dropping the `$`) fired the assertion
  loudly — `FqName does not round-trip ... language=Scala ... short_name="Nested$"`
  — and failed multiple scala tests; reverted. Remaining M1 languages: java,
  python, php, ruby, csharp, javascript, typescript.

- M1 java/csharp/javascript/typescript + cpp cleanup (2026-07-24): the last four
  languages now populate `FqName` at every `CodeUnit` emission point, with the
  live equivalence assertion active across their full suites, and the logged
  cpp `Nested`-migration cleanup landed alongside them. All 11 languages are
  now checked off M1 (see the completion note below).

  Census — java, 8 sites in `src/analyzer/java/declarations.rs`:
  `module_code_unit` (Package chain, via new `java_package_fq`), `visit_class_like`
  (Type — nested classes are `.`-joined here, NOT `$`-joined; see Decision Log),
  `visit_callable`/`visit_compact_constructor` (Function, Member),
  `visit_field_declaration`/`visit_record_components`/`visit_enum_constant`
  (Field, Member), and `lambda_code_unit` (synthetic Function, one `Nested`
  segment whose own text is `anon$line:column`; see Decision Log).

  Census — csharp, 6 sites in `src/analyzer/csharp/declarations.rs`:
  `visit_type_declaration` (Class — nested types ARE `$`-joined, tagged
  `Nested`, confirming the task's guess), `visit_method`/`visit_constructor`
  (Function, Member), `visit_property`/`visit_field_declaration`/
  `visit_enum_member` (Field, Member); namespaces (`csharp_join_namespace`,
  always `.`-joined) are `Package` segments via new `csharp_package_fq`.

  Census — javascript, 12 sites, all in `src/analyzer/javascript/mod.rs` except
  the two shared ones: `module_code_unit`/`add_default_export_unit` (shared,
  `src/analyzer/js_ts/model.rs`), `visit_js_class` (Type), `visit_js_function`
  (Member), `visit_js_method` (Member), `visit_js_constructor_assigned_fields`
  (Member), `visit_js_field` (Member), `visit_js_variable_statement` (Member,
  or the new `file_scoped_field_fq` Path+Member for a top-level exported field)
  plus its nested `surface_code_unit` (bare Member),
  `visit_js_object_literal_properties_for_surface` (Member),
  `visit_js_module_exports_object_literal_properties` (bare Member per root),
  and `js_member_assignment_target`/`JsMemberAssignmentTarget` (recursive
  Member chain built alongside the `name` string; see Decision Log).

  Census — typescript, 13 sites, all in `src/analyzer/typescript/mod.rs`
  reusing the same shared `js_ts::model` helpers: `visit_ts_class_like` (Type,
  real nesting via `internal_module`/class stacking), `visit_ts_function`
  (Member), `visit_ts_value`'s `type_alias_declaration` branch (Member, or
  `file_scoped_field_fq` at top level) and its `variable_declarator` loop
  (Member/`file_scoped_field_fq`) plus its `surface_code_unit`,
  `visit_ts_object_literal_properties` (Member), `visit_ts_method`/
  `visit_ts_field` (Member — the `$static` suffix is baked into the segment's
  own text, no new kind needed; see Decision Log),
  `visit_ts_constructor_assigned_fields` (Member), `visit_ts_enum_member`
  (Member).

  Shared-infra changes: `src/analyzer/js_ts/model.rs` gained `js_ts_segment`,
  `file_name_path_segment` (private), and `file_scoped_field_fq` alongside the
  pre-existing `file_scoped_field_name`, and threaded `fq` through the shared
  `module_code_unit`/`add_default_export_unit` so javascript and typescript
  share one implementation for both. `src/analyzer/cpp/declarations.rs`'s
  `cpp_push_type_chain` now tags only the first (outermost) class in a nested
  chain `Type`, every subsequent one `Nested`; `src/analyzer/fq_name.rs`'s
  `separator()` lost its cpp-native `Type`-`Type` → `$` rule (the `::`-between-
  Package cpp-native rule stays) and its `display_native_cpp_nested_class_uses_dollar`
  unit test was retargeted (see Decision Log for both).

  Validation: `cargo fmt` clean; `cargo clippy --all-targets --all-features -D
  warnings` clean; `--lib` 1879/1879; the full targeted suite green across 63
  test binaries / 2005 tests, 0 failed — `cpp_analyzer_test`, `usages_cpp_graph_test`,
  `usage_graph_cpp_test`, `issue_1093_cpp_using_namespace_owner`,
  `issue_1120_cpp_bare_call_lexical_scope`, `issue_1121_cpp_nested_class_out_of_line`,
  every `csharp_*`/`*_csharp_*` suite plus `issue_csharp_verbatim_identifiers` and
  `roslyn_goto_definition`/`roslyn_find_references`, every `java_*`/`*_java_*`
  suite plus `intellij_java_definition`/`intellij_java_find_usages`, every
  `javascript_*`/`typescript_*`/`*_js_ts_*`/`usage_graph_ts_test` suite, and the
  six shared regression suites (`get_definition_test` 635, `searchtools_service`
  189, `searchtools_definition_selectors` 73, `issue_1128_rust_raw_identifiers`
  12, `issue_1162_separator_aware_enclosing_scope` 10, `mcp_property_fuzzer_service`
  61). A rerun of every prior-wave language's suite (rust, scala, go, python,
  ruby, php analyzer + usages_graph tests) confirmed the shared `fq_name.rs`
  edit changed nothing for them. Mutation check: appending a bogus `Member`
  segment `"BOGUS_MUTATION"` to a top-level java class's `fq` in
  `visit_class_like` fired the `debug_assert_eq!` in
  `CodeUnit::with_signature_and_fq` loudly across every fixture class in
  `java_declarations_parity` (`left: "ClassName.BOGUS_MUTATION"`, `right:
  "ClassName"`) before being reverted; `cargo test --test java_declarations_parity`
  returned to 4/4 passing afterward.

- **M1 complete (2026-07-24):** all 11 languages (go, python, ruby, php, scala,
  rust, cpp, java, csharp, javascript, typescript) now populate `FqName` at
  every `CodeUnit` emission point with a live debug/test-only equivalence
  assertion proving the structured form round-trips to the legacy joined
  string, and the cpp/java `Nested`-vs-`Type` reconciliation from the
  integration Decision Log is fully landed (cpp migrated; java's nested
  classes turned out to be genuinely `.`-joined, not `$`-joined, so they never
  needed `Nested`). `SegmentKind::Nested` is now shared by cpp, java (only for
  the anonymous-lambda marker), csharp, python, php, and ruby — one mechanism
  for every `$`-joined nesting convention in the tree; `SegmentKind::Companion`
  remains scala-only. M2 (shared services and selectors consuming `FqName`;
  input parsing producing it) is next.

- **M2 complete (2026-07-24):** the consolidated shared consumers now operate on
  interned segments, and the MCP input edge produces them. Changes:
  * `SegmentKind::Unknown` added (input-only, renders `.`); `parse_symbol_path_fq`
    added beside `parse_symbol_path` in `src/analyzer/symbol_lookup.rs` — same
    splitter/normalization, every segment `Unknown` (kind-insensitive input; see
    Decision Log).
  * `SegmentInterner::separator_between` added to `src/analyzer/fq_name.rs` (the
    native boundary spelling between two interned segments), plus the `parent`/
    `segments` dead-code allows removed as they went live.
  * default `IAnalyzer::parent_of` (`src/analyzer/i_analyzer.rs`) → segment pop
    via new `default_parent_fq_name`, with the legacy separator scan as the
    empty-fq fallback; six dual-arm `parent_of_tests` prove both arms agree.
  * `resolve_qualified_in_enclosing_scopes` (`get_definition/mod.rs`) → builds an
    `FqName` reference and composes candidates by push via new
    `resolve_qualified_name_in_shrinking_scopes_fq` (dot-cut prefix walk); the
    `normalize_reference_to_fq_segments` shim DELETED; string core retained as
    the empty-fq fallback and for the csharp bounded fork.
  * anchor splitter left byte-identical (retirement deferred; comment + Decision
    Log record why).
  Validation (all `BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python`):
  `cargo fmt` clean; `cargo clippy --all-targets --features nlp,python -D warnings`
  clean; `--lib` targeted fq_name/parent_of/symbol_lookup 19/19; the six named
  regression suites — `get_definition_test` 635, `searchtools_service` 189 (+1
  ignored), `searchtools_definition_selectors` 73, `issue_1128_rust_raw_identifiers`
  12, `issue_1162_separator_aware_enclosing_scope` 10 (cutlass pin intact),
  `mcp_property_fuzzer_service` 61 — plus `searchtools_fuzzy_symbol_lookup` 41,
  `issue_1089` 10, `issue_1126` 12, `issue_1158` 15; and the touched-language
  analyzer/usages suites: cpp (analyzer 43, usages_cpp_graph, usage_graph_cpp 28,
  issue_1093 9, issue_1120 10, issue_1121 11), rust (analyzer 15, usage_graph 21,
  usages_rust_graph), scala (analyzer 29, definition_precedence 52,
  usages_scala_graph), csharp (analyzer 12, usages_csharp_graph), java
  (declarations_parity 4, usages_java_graph), go (analyzer 21, canonical_fqn 24,
  usages_go_graph 16, usage_graph_go 20), python (analyzer 19, usages_python_graph
  16, usage_graph_python 18), php (analyzer 5, usage_graph_php 10), ruby (analyzer
  55, usages_ruby 104, usage_graph_ruby 46) — ALL 0 failed. M3 (persistence flip
  + salt bump) is next; the empty-fq fallback arms in `default_parent_fq_name` and
  `resolve_qualified_in_enclosing_scopes` become live once the cache carries
  segments, and are deleted in M4.

- **M3 complete (2026-07-24):** the cache now carries structured segments and
  FileState-hydrated cache units restore a populated `fq`. Changes:
  * Schema: `migrations/cache/0012-fq-segments.sql` adds a nullable
    `code_units.fq_segments` BLOB; `CURRENT_MIGRATION_VERSION` 11→12 and the new
    const/array/`CURRENT_SCHEMA_OBJECTS` registration in `src/cache_db.rs`.
  * Codec: `FqName::encode_segments`/`decode_segments` (length-prefixed
    `(kind_tag, u32 len, utf8)` per segment) + `SegmentKind::persist_tag`/
    `from_persist_tag` in `src/analyzer/fq_name.rs`; unit-tested round-trip and
    malformed-blob rejection.
  * Content-stable persistence: `package_prefix_fq(lang, package_name, interner)`
    added; `encode_unit_fq_segments` persists only the `short_name` tail (strips
    the `package_prefix_fq` prefix, asserting `starts_with`), `hydrate_unit_fq`
    rebuilds the per-path prefix + appends the tail. Both `code_units` write
    paths and both FileState load paths (`read_unit_rows`, `read_unit_rows_bulk`)
    in `src/analyzer/store/mod.rs` wired.
  * Salt: `;fq-interned-segments-2026-07` appended to all 11 languages'
    `lang_epoch!` SALTs in `src/analyzer/store/epoch.rs` (one sweep).
  * Debug/test accessor `CodeUnit::fq_segments_debug` (kind-name + text) added for
    the round-trip integration test without leaking `SegmentKind`.
  Equivalence-on-load VERIFIED live: the M1 `debug_assert` in
  `with_signature_and_fq` fired on the load-side construction the moment the first
  cut mis-hydrated a content-shared blob (3 store tests), then went green once the
  tail/prefix split landed — direct evidence the assertion guards loaded units.
  Validation (all `BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python`,
  ALL 0 failed): `cargo fmt` clean; `cargo clippy --all-targets --all-features
  -D warnings` clean; `--lib` 1892/1892 (incl. the three `identical_*_blob` /
  `cargo_routes` content-addressing regressions and the new fq_name codec +
  cache_db upgrade tests); `analyzer_persistence` 45 (new
  `warm_fq_segments_survive_store_roundtrip_across_languages`),
  `structural_facts_persistence` 3, `unified_cache` 4, `parse_errors_cache` 6,
  `java_parallel_and_cache` 2, `get_definition_test` 635, `searchtools_service`
  189, `searchtools_definition_selectors` 73, `mcp_property_fuzzer_service` 61;
  canaries `issue_1128` 12, `issue_1162` 10 (cutlass pin intact), `issue_1158` 15,
  `issue_1126` 12, `issue_1089` 10, `issue_1093` 9, `issue_1120` 10, `issue_1121`
  11, `issue_1142` 11; spot languages cpp (`cpp_analyzer` 43, `usages_cpp_graph`
  145, `usage_graph_cpp` 28) and scala (`scala_analyzer` 29, `usages_scala_graph`
  148, `usage_graph_scala` 55). Consumers still string-based for M4: the
  `get_all_declarations`/candidate-row reconstruction path
  (`sql_all_declarations_vec` and the two `CandidateRow`→`CodeUnit` builders at
  `tree_sitter_analyzer.rs:3958`/`:4555`) — it re-derives from `code_units` and
  was out of M3 scope; the definition-lookup/usage-fact rows carry candidate
  identities as strings and re-derive or re-extract via the salt. M4 folds those
  onto segments and deletes the now-live-but-still-present empty-fq fallback arms.

## Context and Orientation

Bifrost is a Rust code analyzer and MCP server. Each source declaration becomes a
`CodeUnit` (defined in `src/analyzer/model.rs`, fields around line 1807):
`package_name: String` (the namespace/package/module prefix, whose spelling is
per-language) and `short_name: String` (the owner-and-member tail, joined with `.`
and with `$` marking nested classes / Scala companions). The full qualified name
("fq name") is derived by joining the two. These strings are persisted in a SQLite
cache: table `code_units`, column `short_name` (see
`migrations/cache/0001-initial.sql` around line 75; `package_name` likewise). The
per-language "analysis epoch" (`src/analyzer/store/epoch.rs`) fingerprints extractor
behavior: when persisted output changes shape, the language's `SALT` string must get
a new `;`-separated token appended, which forces re-extraction of cached rows.

Three shared consumers matter most, all recently consolidated (which is what makes
this migration tractable now):

`parse_symbol_path` (`src/analyzer/symbol_lookup.rs`, around line 713, `pub(crate)`):
the input-edge splitter. Takes a user-supplied symbol string and a language, splits on
the full separator set (`::`, `.`, `\`, `/`, `+`) and applies per-language segment
normalization (rust `r#` stripping, go receiver forms, cpp `operator` names). This is
the ONLY place input strings should ever be split, and after this plan it returns a
`FqName` rather than `Vec<String>`.

`resolve_qualified_name_in_shrinking_scopes` and `resolve_in_enclosing_scopes`
(`src/analyzer/usages/get_definition/mod.rs`): the shared enclosing-scope resolution
service. Today it composes candidate strings `{scope}.{name}` and, since issue 1162,
normalizes the REFERENCE side into `.`-joined segments via `parse_symbol_path` while
leaving the SCOPE side verbatim (because C++'s store is mixed-separator — see the
Decision Log). After M2 it operates on segments.

`enclosing_owner_chain` (`src/analyzer/usages/common.rs`) and the trait method
`IAnalyzer::parent_of` (`src/analyzer/i_analyzer.rs`, default around line 681): owner
chain walking. The default `parent_of` currently walks the fq string looking for
`.`/`$`/`::`/`->` separators — a textbook inference site that M2 replaces with a
segment pop.

Anchor splitting: `split_definition_selector_with_resolver` in
`src/searchtools/selectors.rs` decides whether `a/b.rs#Foo.bar` is a file anchor plus
symbol. Since issue 1131 it only splits at a `#` whose left side names a real file;
issue 1128 added a carve-out for slash-free anchors. With kind-tagged segments the
path/symbol boundary is a tag transition, and this heuristic stack shrinks.

"Emission points" means the ~144 places in per-language extractors (each language's
`declarations.rs` and related visitors under `src/analyzer/<lang>/`) that build
`short_name`/`package_name` by string concatenation, e.g.
`format!("{}.{}", parent.short_name(), name)` in `visit_rust_module`
(`src/analyzer/rust/declarations.rs`) or the `$`-joining nested-class chains in
`split_cpp_name` (`src/analyzer/cpp/declarations.rs`). Each such site knows, at the
moment of concatenation, exactly what kind of segment it is appending — that
knowledge is what the current representation throws away and this plan preserves.

## Interfaces and Dependencies

In a new file `src/analyzer/fq_name.rs` (module registered in
`src/analyzer/mod.rs`), define:

    /// What a qualified-name segment denotes. Baked into the interned entry.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub(crate) enum SegmentKind {
        Path,      // a file/directory step (may contain literal dots)
        Package,   // namespace / package / module
        Type,      // class, struct, enum, trait, interface, object
        Companion, // scala companion-object spelling (renders with `$`)
        Member,    // function, method, field, const, alias, macro
    }

    /// Interned (text, kind) pair. u32; process-local; never persisted.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub(crate) struct SegmentId(u32);

    /// The qualified name. Ordered root-to-leaf. Comparisons are integer memcmp.
    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    pub(crate) struct FqName {
        segments: SmallVec<[SegmentId; 8]>,
    }

    pub(crate) struct SegmentInterner { /* sharded, concurrent */ }

    impl SegmentInterner {
        pub(crate) fn intern(&self, text: &str, kind: SegmentKind) -> SegmentId;
        pub(crate) fn resolve(&self, id: SegmentId) -> (&str, SegmentKind);
    }

    impl FqName {
        pub(crate) fn push(&mut self, id: SegmentId);
        pub(crate) fn parent(&self) -> Option<FqName>;         // slice, no alloc beyond SmallVec copy
        pub(crate) fn last(&self) -> Option<SegmentId>;
        pub(crate) fn starts_with(&self, prefix: &FqName) -> bool;
        pub(crate) fn segments(&self) -> &[SegmentId];
        /// Canonical display: `.`-joined, `$` before Companion segments — exactly
        /// today's user-facing convention, so display output does not change.
        pub(crate) fn display(&self, interner: &SegmentInterner) -> String;
        /// Native display: language-specific separators (`::` between cpp
        /// Package segments, etc.), for surfaces that render native spellings.
        pub(crate) fn display_native(&self, lang: Language, interner: &SegmentInterner) -> String;
    }

The interner lives on the analyzer/workspace object that already owns per-workspace
state (follow how existing per-workspace caches are threaded; one interner per
process is also acceptable since entries are tiny and text-deduplicated — decide in
M0 and record in the Decision Log). Concurrency: extraction runs file-parallel, so
`intern` must be lock-cheap — use a sharded RwLock<HashMap> or an existing concurrent
map already in the dependency tree (moka is present; a plain sharded map is fine).
Do not add new heavyweight dependencies without recording the decision.

SmallVec is already available transitively; if not a direct dependency, add it to
Cargo.toml (record in Decision Log). Eight inline segments covers observed real fq
names (path head + package + owner chain + member); measure in M0.

## Plan of Work

The migration is strictly staged so the tree is green at every commit. The legacy
strings remain authoritative until M3; `FqName` rides alongside and is
equivalence-checked against them, so any construction bug surfaces as a test failure
while the strings still drive behavior.

M0 builds the module in isolation: interner, FqName, unit tests for push/parent/
starts_with/display round-trips including segments containing literal dots, `::`,
`$`, and `#` (the point of the design is that segment text is free-form). Add a
`#[cfg(test)]` size/memory measurement: intern the fq names of a representative
fixture workspace (reuse an existing large test fixture) and print interner entry
count and approximate bytes versus the sum of legacy string lengths, so the memory
question is answered with numbers, not vibes.

M1 makes every emission point ALSO produce the structured form. Add to `CodeUnit` an
`fq: FqName` field populated at construction. Do this language by language, one
commit each, in this order (smallest/cleanest first to shake out the API, the two
known-messy ones last): go, python, ruby, php, java, javascript, typescript, csharp,
rust, scala, cpp. For each language, find every constructor call of `CodeUnit` in its
extractors and thread segment pushes where the strings are concatenated today: the
package prefix becomes Path segments (one per path component, from the workspace-
relative file path already used to build it) plus Package segments (from
namespace/module declarations); owners push Type (or Companion for scala's
`$`-spelled objects); leaves push Member or Type per the unit kind. The equivalence
check: a debug/test-only assertion (behind `#[cfg(any(test, debug_assertions))]`)
that `fq.display(interner)` equals the legacy joined string for every constructed
unit; run each language's full test suite and fix mismatches at the emission point.
Two known reconciliations, to be handled deliberately rather than discovered: C++'s
package strings keep a `::` head today — its emission points push proper Package
segments and the equivalence assertion for cpp compares against a `::`-aware join
(write a cpp-specific expected-join helper in the test support, documenting that the
LEGACY string is the compatibility target until M3); Scala companion objects append
`$` inside short_name — the Companion kind reproduces that in `display`.

M2 moves the consolidated consumers onto segments. `parse_symbol_path` gains a
sibling `parse_symbol_path_fq(language, value, &interner) -> FqName` (input segments
get their kinds assigned best-effort: file-extension-bearing or slash-delimited heads
become Path, the final segment Member-or-Type-unknown — introduce
`SegmentKind::Unknown` ONLY if matching genuinely needs it; prefer kind-insensitive
matching for user input, since users type spellings, not kinds: matching compares
text IDs where kind is unknown. Record whichever choice is made in the Decision
Log with the reasoning). Then migrate, in order: the default `IAnalyzer::parent_of`
(segment pop instead of separator scan); `enclosing_owner_chain` callers that
currently split fq strings; `resolve_qualified_name_in_shrinking_scopes` (compose
candidate FqNames by push instead of `format!("{scope}.{reference}")` — this deletes
the issue-1162 reference-normalization shim and the verbatim-scope workaround
because both sides are now segments); the anchor splitter in
`src/searchtools/selectors.rs` (a selector parses into an optional Path-kind prefix
plus symbol segments; the "does the left side name a real file" resolver check
remains as the semantic validation, but the `.r`-lookalike heuristics go). Each
migration step keeps the old string path compiling and the full test suite green;
behavior must not change in M2 (the regression suites named in Purpose are the
canaries).

M3 flips persistence. Schema migration `migrations/cache/00NN-fq-segments.sql`
(next free number; register in `src/cache_db.rs` per the existing migration
pattern): store segments as a compact serialized column on `code_units` — a single
TEXT/BLOB column holding length-prefixed or JSON-array `(kind, text)` pairs; keep
`short_name`/`package_name` columns populated (they remain useful for indexes and
human inspection) but the structured column becomes authoritative on load. Append
one salt token to EVERY language's `SALT` in `src/analyzer/store/epoch.rs`
(`;fq-interned-segments-2026-07`) since load-side interpretation changes for all
persisted rows. On load, segments are interned into the process interner and the
`FqName` is attached; the legacy-string derivation of structure (any remaining
split-based parsing of stored names) is deleted. C++'s stored `::`-headed
package_name strings stop mattering: cpp reads/writes segments like everyone else,
which is issue 1163's root fix.

M4 retires inference and locks the door. Delete remaining separator-split call
sites in `src/analyzer` (the ~227 count from Purpose is the worklist; each is either
migrated to FqName ops or documented as legitimately operating on non-name text).
Add the guard: a test (e.g. `tests/no_stringly_name_parsing.rs`) that walks
`src/analyzer` source files and fails on banned patterns (`split("::")`,
`split('.')` and friends) outside an explicit allowlist file — the mechanical
enforcement of the existing CLAUDE.md rule against separator mini-parsers. Flip the
issue-1163 pins: `cpp_qualified_nested_namespace_type_current_behavior` in
`tests/issue_1162_separator_aware_enclosing_scope.rs` now asserts RESOLUTION of the
sibling-namespace shape, and the two pinned `boundary_unchecked` sites in
`src/analyzer/usages/get_definition/cpp.rs` (near the strengthened NOTEs from the
issue-1162 landing) become live `gated_boundary` closures. Close issue 1163 with
that evidence.

## Concrete Steps

Work in the repository root (`/home/jonathan/Projects/bifrost2` or a worktree).
After every milestone (and every M1 language):

    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python --lib
    BIFROST_SEMANTIC_INDEX=off cargo test --features nlp,python \
      --test get_definition_test --test searchtools_service \
      --test searchtools_definition_selectors \
      --test issue_1128_rust_raw_identifiers \
      --test issue_1162_separator_aware_enclosing_scope \
      --test mcp_property_fuzzer_service

(plus the touched language's analyzer/usages suites in M1; plus the FULL suite before
the M3 and M4 pushes — `default = []`, so a featureless `cargo test` silently skips
the nlp-gated integration suites; always pass `--features nlp,python`). Commit each
language/milestone separately with why-focused messages. Isolated builds for
validation experiments go through `scripts/with-isolated-cargo-target.sh`.

## Validation and Acceptance

M0: `cargo test --lib fq_name` passes; the measurement test prints interner entries
and byte totals for a large fixture (expect interned bytes well under the summed
legacy string bytes; record the numbers in Surprises & Discoveries).

M1 (per language): the language's full suites pass AND the equivalence assertion
never fires across them — meaning every constructed unit's structured form joins to
exactly the legacy string. A deliberately-broken push (wrong kind or missing segment)
must fail loudly in tests; verify once by mutation before trusting the assertion.

M2: zero behavior change — the six named regression suites pass unmodified; the
issue-1162 shim deletion is proven safe by `issue_1162_separator_aware_enclosing_scope`
staying green.

M3: after the salt bump, a warm workspace re-extracts (observe via the analyzer
persistence tests, `tests/analyzer_persistence*`); all suites green under
`--features nlp,python`.

M4: `tests/no_stringly_name_parsing.rs` passes (and demonstrably fails when a banned
split is introduced — verify once by mutation); the flipped cpp test asserts the
sibling-namespace type RESOLVES where it previously pinned a false boundary — that
flip is the user-visible payoff and closes issue 1163.

## Idempotence and Recovery

Every milestone is additive until M3; reverting any M0–M2 commit returns to a green
tree because legacy strings remain authoritative. M3 is the one-way step: it ships a
schema migration plus a salt bump, and recovery is re-running extraction (the store
is a cache; deleting `.brokk/bifrost_cache.db` is always safe). Never hand-edit the
migration after it lands; add a new one. Use unique scratch patch paths (not
/tmp/fix.patch — it gets clobbered across parallel agents) for any fail-before
verification dances.

## Artifacts and Notes

The delimiter-bug evidence file motivating this plan, for posterity: issues 1128,
1131, 1162, 1163, the `.r`-anchor misroute fixed inside 1128's landing, and the
Scala `$` spelling inconsistency noted in issue 1126's closing comment. The
consolidated chokepoints that make the migration cheap were landed by the 2026-07
cross-language duplication campaign (see `.agents/docs/cross-language-duplication-survey.md`,
whose backlog items 1–6 are all landed on master as of 2026-07-24).

## Revision note (2026-07-24, M1 rust/scala/cpp)

Recorded the completion of M1 for rust, scala, and cpp: `Progress` checkboxes
flipped, three `Surprises & Discoveries` observations added (the scala companion
`$`-suffix correction, the cpp `::`/`$` native-render requirement, and the
mutation-check evidence via go's earlier entry pattern), six `Decision Log`
entries added (native-render equivalence assertion, scala companion suffix rule,
cpp nested-class `$` rule, the `.`/`::`-split package bridge, and cpp per-site
string reconstruction), and an `Outcomes & Retrospective` entry with the full
validation tally. Why: these three languages each carried a known reconciliation
(rust module nesting + `_module_` scope; scala companion `$` spelling; cpp
mixed-separator `::` store and nested-class `$` chains) that required display-rule
and assertion changes beyond the mechanical go/M0 pattern; the plan must capture
those decisions so the next contributor (and M2/M3) inherits the reasoning.

## Revision note (2026-07-24, M2)

Recorded M2 completion: `Progress` M2 checkbox flipped with a summary; four
`Decision Log` entries added (kind-insensitive input via `SegmentKind::Unknown`;
`parent_of` segment pop with empty-fq fallback; the shrinking-scope
segment-composition migration with the issue-1162 shim deletion and the dot-cut
non-descent rule that keeps issue-1163 pinned; and the anchor-splitter deferral
with its reasoning); two `Surprises & Discoveries` observations added (the
`namespace_prefixes`-equals-dot-boundary-cuts equivalence that makes the cpp
non-descent reproducible, and the Go all-`Path`-unit `parent_of` divergence that
no test exercises); and an `Outcomes & Retrospective` M2 entry with the full
validation tally. Why: M2 moves live resolution onto segments while the legacy
strings still drive behavior, so each migration needed an explicit empty-fq
fallback and a recorded proof that both arms agree; the open kind-tagging design
question the plan left for M2 is resolved here (kind-insensitive, `Unknown`), and
the anchor-splitter part is honestly scoped to what a pre-language splitter can do
without regressing the #1128/#1131 canaries. The next contributor (M3) inherits
which fallback arms go live under persistence and which are deleted at M4.

## Revision note (2026-07-24, M3)

Recorded M3 completion: the `Progress` M3 checkbox flipped (with the M4 worklist
extended to fold the candidate-row reconstruction onto segments), a
`Surprises & Discoveries` entry (the content-addressed-blob shared-across-paths
failure and how three existing store tests caught it), four `Decision Log`
entries (length-prefixed-binary encoding vs JSON; load-side scope limited to the
FileState hydration path with the candidate-row path left string-based for M4;
equivalence-on-load holding for free via the pre-existing package_name
round-trip invariant; and persisting the content-stable short_name tail while
rebuilding the path-derived package prefix on load via `package_prefix_fq`), and
an `Outcomes & Retrospective` M3 entry with the full validation tally. Why: M3
is the one-way persistence step, and the single non-obvious risk it carried --
that a content-addressed blob shared across paths recomputes package_name
per-path on load -- turned a naive verbatim-fq persist into a correctness bug
that the load-side M1 equivalence assertion caught immediately; the fix
(persist the tail, rebuild the prefix) and its self-verifying `starts_with`
guard are the load-side mirror of the sanctioned M1 construction bridge, and the
next contributor (M4) inherits exactly which string-based consumers remain and
why the empty-fq fallback arms cannot be deleted until the candidate-row path is
also migrated.
