# Cross-language duplication survey (2026-07-24)

Purpose: ranked backlog of duplication across the 11 language handlers that could be
**better expressed as shared logic plus per-language plugins/extensions**. The mandate
is explicitly NOT "zero copies": a candidate is accepted only when (1) an invariant
must stay in sync across copies (drift = bug class we keep fixing), (2) the plug
surface is small and stable (mass-per-hole test), and (3) it reduces the marginal
cost of the next language or the next policy change. Candidates failing the test are
recorded as "leave as copies" so they are not relitigated.

Evidence arms:
- **CPD** (PMD 7.14, rust lexer, 80-token floor, baseline + ignore-identifiers lanes)
  over `src/analyzer` + `src/searchtools`. Raw reports:
  `cpd-baseline.xml` / `cpd-anon.xml` (session scratch; re-run with
  `pmd cpd --minimum-tokens 80 --language rust --dir src/analyzer --dir src/searchtools`).
  3 files skipped by the lexer (raw-string edge): bounded_output.rs, php/aliases.rs,
  rust/cargo_routes.rs.
- **Concern-axis agent survey**: six read-only surveys (node-text extraction,
  same-owner classification, import binders, boundary-claim emission, traversal
  work-stacks, enclosing-owner resolution), each producing a per-language matrix and
  an identical / parameterizable / intentionally-divergent classification.

## CPD headline (mechanical arm)

- 717 cross-language-handler duplications, ~95.5k duplicated tokens (80-token floor).
- Top clones are exact-token (identifier-identical) — the handlers are literally
  copy-pasted at the top of the distribution; anonymization adds little up there.
- Dominant families:
  1. **semantic/CFG layer**: `{csharp,python,go,php,scala,rust}/semantic.rs` and
     `{java,js_ts}/semantic/control.rs` share 1.5–3.4k tokens pairwise; largest
     single clone 601 tok / 90 ln (csharp/semantic.rs:2261 ↔ java/semantic/control.rs:1072).
     Freshest duplication in the tree (actively developed layer).
  2. **Adapter `mod.rs` boilerplate**: one 414-token run identical across FOUR
     languages (cpp/mod.rs:390, javascript/mod.rs:543, python/mod.rs:684,
     scala/mod.rs:681); 350–516-token pairwise runs across most `{lang}/mod.rs`.
  3. javascript/mod.rs ↔ typescript/mod.rs: 3.4k tokens — likely intentional
     twin-ness; extraction question is "one js_ts adapter parameterized by dialect",
     to be judged by the mandate, not by mass.
- Same-language cross-file: 53 duplications (smaller helpers surface at a 40-token
  floor, e.g. rust graph_support ↔ usage_index runs).

## Concern 1: node-text extraction & identifier normalization (survey complete)

**Verdict: EXTRACT (strong accept).** Invariant-bearing (sigil normalization must
agree across surfaces), tiny plug surface (identifier-kind set + optional sigil
prefix per language), and it closes a live inconsistency.

- ~30+ private copies of the slice→(trim?)→(ident-normalize?) shape, ~200 LOC:
  - 7 byte-identical Rust-lane copies (declarations.rs:22, graph_support.rs:1516,
    lexical_scope.rs:836, get_definition/rust.rs:5226, rust_graph/{hits.rs:395,
    inverted.rs:776, extractor.rs:3065}).
  - 10 plain-slice Group-A declaration helpers (java/python/go/cpp/php/ruby/scala/
    csharp/js_ts).
  - 8–11 byte-identical `nonempty_node_text` copies in the semantic lowering family
    (rust/php/python/go/cpp/csharp/java/js_ts semantic files) — separate one-line win
    in `semantic/lowering.rs`.
- **Latent bug found**: C# strips verbatim-identifier `@` in declarations
  (csharp/declarations.rs:918) and graph extractor (csharp_graph/extractor.rs:315)
  but NOT in the get_definition path — the same inconsistency class #1128 fixed for
  Rust `r#`. PHP `$` is stripped unconditionally at 10+ call sites (one as a byte
  offset: php_graph/extractor.rs:803) instead of kind-gated in a helper.
- Proposed shape: `node_ident_text(node, source, opts{trim})` with per-language hooks
  `is_identifier_kind(kind)` + `IDENT_PREFIX: Option<&str>` ("r#", "@", "$"),
  following the existing common.rs precedent (`rust_identifier_like_node_kind`,
  `strip_raw_identifier_prefix`).
- **Risks (from survey, must be honored in the ExecPlan):**
  - Trim is load-bearing on the usages side (compound spans) and absent on the
    declaration side — keep as an option, do not force one policy; Ruby and Go each
    have same-name helpers with DIFFERENT trim behavior today (reconcile deliberately).
  - PHP `$` gating must be variable-position-aware — a blanket strip can corrupt
    non-variable spans; highest-risk item.
  - C# `@` strip must not touch attributes or `@"..."` verbatim strings.
  - Standardizing on `get(..).unwrap_or("")` changes PHP/Scala panicking slicers to
    empty-string on bad ranges (desirable, but check for tests relying on panic).
  - Group E `utf8_text()` call sites get UTF-8 validation for free; unifying drops it.

## Concern 2: same-owner / self-receiver classification (survey complete)

**Verdict: EXTRACT (strongest accept in the survey).** ~80% of each per-language
implementation is identical policy; the per-language proof reduces to one boolean.
This is also the extraction that makes #1138 a one-time fix instead of 8 more
transcriptions.

- The policy spine is ALREADY shared (UsageHitKind::SelfReceiver,
  into_self_receiver, included_in exclusion, scan_usages partitioning,
  reclassify_self_receiver_hit_at in usages/common.rs:84 — java/php already route
  through it, proving the layer works). What's duplicated: 9 per-language deciders
  + 6 hand-rolled record-ceremony bodies (~30 LOC each, go/csharp/ruby/python) +
  the repeated self-definition guard.
- Proposed shape: `SameOwnerReceiverProof` trait — per-language boolean
  "does this receiver denote the enclosing instance/own type", consumed by two
  shared consumers (scan classification; inverted routing whose contract is
  proof → record_unproven else record). ~250 LOC of existing copies + ~350-400 LOC
  of not-yet-written #1138 copies avoided.
- **Latent misalignments found (dead-code semantics, per-language):**
  - cpp (inverted.rs:476) and js_ts (inverted.rs:1277,1306) DROP same-owner edges
    entirely (neither java's record_unproven nor proven) — self-only-called methods
    have zero inbound edges.
  - rust's correct behavior is ACCIDENTAL: no explicit self branch; `self` just
    never seeds receiver_type(), falling through to record_unproven.
  - python/go/php/ruby/csharp record same-owner as PROVEN (confidently-alive bias).
- **Load-bearing constraints (must be honored):**
  - Ordering: csharp scan-side widening (bare implicit-this) is GATED on its
    inverted routing landing first (the #1014 regression proved this); a shared
    rollout must sequence inverted-before-scan per language.
  - Own-type-static rules are genuinely per-language (java yes, php self::/static::
    but not parent::, csharp not yet) — they live in the proof, not the policy.
    super/parent/base uniformly external — that IS shareable.
  - go's proof is stateful (SELF_RECEIVER_TOKEN seeding exists only in the scan
    context; inverted needs the seeding ported first). scala returns false honestly
    (graph-shape change, not a hook impl — out of scope, per #1138).
  - csharp bare method-group references stay external (delegate capture is real
    usage) — the hook must not flatten that.

## Concern 3: import binders (survey complete)

**Verdict: SPLIT.** No universal binder core — forcing one would be a
union-of-everything god-struct (fails the mass-per-hole test). But three small
extractions inside it are strong accepts.

- Two families exist today: shared `ImportBinder`/`ImportBinding`/`ImportKind`
  (usages/model.rs:474-503) used by exactly rust, python, js_ts; everything else
  bespoke (go: `(HashMap<String,Vec<String>>, dot-imports)`; csharp: three maps;
  php: `PhpUseAliases` three kind-partitioned maps; java: eager `HashMap→CodeUnit`;
  scala: no stored map at all — ordered candidate-tier search; cpp: 11-field
  `OrdinaryTypeImport` with preprocessor-guard activation; ruby: no imports —
  require/Zeitwerk file+constant conventions).
- **Leave as copies (divergence is the design): scala, cpp, ruby.** Tier-search is
  not a lookup; using-directives are scope-ordered and guard-gated; ruby has nothing
  to bind. java is a false friend (binding fused with resolution to CodeUnit).
- **Optional medium-payoff**: extend `ImportBinding` with multi-target values (go)
  and a namespace-partition tag (php/csharp) to bring those three onto the shared
  core. Judge after the accepts land.
- **ACCEPT (small, high-confidence):**
  1. **Shared workspace-boundary predicate** — the #1126/#1089 honest-claim invariant
     is independently implemented 5×: go_import_path_is_workspace (go.rs:788),
     rust_focused_is_workspace_module_namespace (rust.rs:5326),
     php_workspace_exact_namespace_exists (php.rs:959), scala package_exists use
     (scala.rs:716), csharp workspace_namespace_exists (csharp.rs:121) — same
     decision, same comment wording, five codebases. A shared
     `is_workspace_member(prefix)` + `namespace_or_boundary_outcome` helper makes
     the invariant structural. (Feeds Concern 4.)
  2. **`ImportInfo::local_name()`** — the `alias ?? identifier ?? tail-of-path`
     desugar is copied ~8× (rust lexical_scope.rs:49-66, python mod.rs:471, js_ts,
     csharp imports.rs:316, php, go...). One method on the shared ImportInfo model.
  3. **`StructuredImportPath::render_segments(sep)`** — go get_definition/go.rs:765-786
     and scala segment joins reimplement path rendering over the same model type.

## Concern 4: boundary-claim emission (survey complete)

**Verdict: EXTRACT — and this one is a correctness project wearing a refactoring
coat.** 50 confident-boundary emission sites across 10 languages, ~10 distinct
ad-hoc guard mechanisms, invariant enforced by convention only.

- All confident external claims already route through one shared `boundary()`
  helper (get_definition/mod.rs:1289 + the load-bearing message rewrite at :1297).
  What's NOT shared is the gate: `if external-signal && !workspace-internal
  { boundary } else { no_definition }` is fused ad hoc per site.
- **Latent #1126-class bugs found (unguarded confident claims), ranked:**
  1. python.rs:1225,1285 — import-binding boundary fires with NO workspace-module
     check at all (highest risk; the fqn/module paths at 1821/1841 are guarded,
     the import-binding paths aren't).
  2. rust.rs:1022 — pure text heuristic (`rust_reference_looks_external`), no
     enclosing-scope fallback on this branch (unlike siblings 974/2576/2725).
  3. rust.rs:1441 (macros) — only BoundButUnindexed site without the fallback.
  4. cpp.rs:2107,2402 — `cpp_unresolved_include_boundary` is file-coarse (ANY
     unresolved include + looks-external), not symbol-specific.
  5. csharp.rs:684 — static-using check not tied to the specific member.
  6. js_ts.rs:676 — a relative-path typo becomes a confident boundary claim.
  7. scala.rs:5647 — emits before the lexical-namespace probe (asymmetric w/ 5685).
- **Key design insight: two guard families answer DIFFERENT questions** —
  workspace-namespace existence (go/java/php) catches the #1089 shape;
  enclosing-scope member fallback (rust/cpp) catches the #1126 shape. Languages
  implementing only one are exposed to the other's failure mode; python's
  import-binding path has neither. The gate must take both (OR).
- Proposed shape: `gated_boundary(external_signal, workspace_internal_closure,
  boundary_msg, no_def_kind, no_def_msg)` in mod.rs, making it impossible to emit
  `boundary()` without supplying a workspace-internal check; plus a parameterized
  `enclosing_scope_member_fallback` (5 hand-rolled versions today: rust 5309, cpp's
  resolve_in_enclosing_scopes calls, csharp 2869/1831, java nested-type, scala
  exact-owner) — which also gives Ruby (currently zero boundary claims, misses are
  indistinguishable from external) a safe path to ever emit one.
- Message-template consolidation: ~18 near-identical "appears to cross a {LANG}
  {import|include|using} boundary" strings + 10 verbatim scala copies; risk —
  message text is load-bearing (mod.rs rewrite, downstream matching), consolidate
  in lockstep with consumers.

## Ranked backlog (mandate: shared logic + per-language plugs must be BETTER, not
just fewer copies)

**1. Same-owner classification proof hook** (Concern 2). Invariant-bearing, plug =
one boolean per language per context, and it converts the already-tracked #1138
into a single shared-consumer change instead of 8 transcriptions. Sequencing law:
inverted-routing lands before scan-side widening per language (the #1014 C#
regression proved why). Do #1138 AS this extraction — it's the natural pilot.

**2. Boundary-claim gate + shared enclosing-scope member fallback + workspace
predicate** (Concerns 4 + 3.1 + 6.2). Makes the #1126/#1089 invariant structural
and fixes a real latent-bug list in the same motion (python import-binding paths
first). Plug surface: two closures per language.

**3. Node-text / identifier normalization helper** (Concern 1). ~30 copies,
~200 LOC; closes the live C# `@` inconsistency; plugs = identifier-kind set +
sigil prefix. Risks documented (PHP `$` position-awareness, trim policy per lane).

**4. Traversal tier 1** (Concern 5). Promote `walk_tree_iterative` to pub(crate)
(10 frame clones exist due to visibility alone), promote `cpp_subtree_contains`
as the generic `subtree_contains` (~16 copies), add `descendants_of_kind`/
`named_children` (~9 copies). ~350-420 LOC, near-zero design risk.

**5. Owner-chain service** (Concern 6). Generalize
`ResolutionSession::cpp_enclosing_class_chain` (predicate + budget parametric);
fold C#'s line-for-line fork of `resolve_qualified_in_enclosing_scopes` back in.
~230+120 LOC. Hard constraints: trait `parent_of` dispatch, caller-supplied
predicates, budgets thread through, partial-type fan-out.

**6. Small model wins** (Concerns 3 + 5 tier 2). `ImportInfo::local_name()` (~8
copies), `StructuredImportPath::render_segments`, tests/common consolidation of
call_tool/symbol_sources/definition_reference_status (~14 bodies).

**Judge separately (real design work, not backlog items yet):**
- `enumerate_procedures` skeleton + semantic/CFG layer dedup — CPD's #1 family
  (1.5-3.4k tokens pairwise) but it's David's active layer; coordinate, don't
  land under him.
- Shared `ContainerWalk` for declaration visitors (cpp's Container/Node/Siblings
  as seed; 4 typed + 7 tuple-stack languages).
- Extending ImportBinding to admit go/php/csharp (multi-target + partition tag).
- javascript/typescript twin adapters (3.4k tokens; twin-ness may be the honest
  expression — needs the mass-per-hole arithmetic).

**Explicitly leave as copies (divergence is the design):** scala/cpp/ruby import
models; AST-walk owner queries (impl targets, out-of-line owners, bounded
pre-index walkers, sub-CodeUnit scopes, ruby lexical stack, go package model);
range/ancestor containment helpers; CFG/ICFG graph walks; policy value walks.

## Concern 5: traversal work-stacks + test helpers (survey complete)

**Verdict: EXTRACT in tiers** — tier 1 is nearly free, tier 3 is a real refactor to
judge separately. Scale: ~332 hand-rolled work-stack initializations, ~387
`while let Some(pop)` loops; no shared subtree helpers exist outside `usages/`.

- **Tier 1 (ACCEPT, mechanical):**
  1. `walk_tree_iterative` + `TreeWalkAction` (usages/common.rs:118) is already the
     right enter/exit abstraction but is `pub(super)` — TEN frame-walker clones
     exist only because of visibility (4 identical diagnostics ScanFrames in
     js_ts/rust/python/go diagnostics.rs, 4 structured-type frames in
     model.rs/scala/go/csharp declarations, 2 inverted WalkFrames). Promote to
     `pub(crate)` (analyzer/tree_walk.rs), retarget. ~150-200 LOC + 10 enum defs.
  2. `subtree_contains(node, pred)` — ~16 independent bool-DFS copies;
     cpp/identity.rs:203 is already the generic form, promote verbatim. One pair
     (scala contains_repeated_parameter_type) is byte-identical copy-paste.
     ~130-150 LOC.
  3. `descendants_of_kind` / `named_children` — 2 deep + 7 shallow copies (~70 LOC);
     `for_each_descendant` closure walker absorbs a large share of the ~140 inline
     `stack.extend(children)` scans over time (adopt opportunistically, don't sweep).
- **Tier 2 (ACCEPT, small): test-helper consolidation** — call_tool (5 copies),
  symbol_sources (7), definition_reference_status (2), sorted_source_paths — all
  signature-uniform over BuiltInlineTestProject; lift into tests/common/
  (~14 bodies, ~120 LOC). Mirrors existing CLAUDE.md InlineTestProject guidance.
- **Tier 3 (JUDGE SEPARATELY, real design work):**
  1. Shared `ContainerWalk` (Node + resumable Siblings cursor, generic scope
     payload) hosting the 4 typed declaration visitors (cpp/python/php/scala) and
     eventually the 7 tuple-stack languages. Cpp's Container/Node/Siblings is the
     most general seed. ~200+ LOC of dispatch boilerplate, but visit-node bodies
     stay language-specific — mass-per-hole must be computed honestly.
  2. `enumerate_procedures` skeleton — 10 near-clones in the semantic modules
     (sibling-key dedup, declaration_paths, budget/cancel checks) with
     language-specific frame fields (Go adds three). Highest payoff (~10x skeleton
     LOC) and highest design cost; overlaps the CPD semantic-layer family, so
     coordinate with David's active work there rather than landing under him.
- **Leave as copies:** range/ancestor containment helpers (different shape),
  CFG/ICFG graph walks (not syntax trees), policy value walks, the
  dependency-discovery string worklist.

## Concern 6: enclosing-owner resolution (survey complete)

**Verdict: EXTRACT two narrow services; leave all AST-walk owner queries alone.**

- The duplicated primitive is the indexed Shape-A walk
  (`enclosing_code_unit → while !is_class { parent_of }`): ~10 independent copies
  (~230 LOC) across java/csharp/cpp/scala/php/python/js_ts (matrix in survey).
  The memoized shared version ALREADY EXISTS as
  `ResolutionSession::cpp_enclosing_class_chain` (get_definition/mod.rs:701) —
  generalize (drop cpp_ prefix, caller-supplied predicate) and retarget.
- Shape B (resolve name against enclosing fqn chain) is already shared
  (`resolve_in_enclosing_scopes`/`resolve_qualified_in_enclosing_scopes`,
  mod.rs:162/181; adopted by rust/cpp/scala) — but **C# maintains a line-for-line
  private fork** (resolve_csharp_in_enclosing_scopes, csharp.rs:2869) plus 3
  variants, differing only by a definitions source and a scope_step budget check.
  Fold back by making the shared version budget-parametric.
- Third small win: the "progressively shorter namespace prefixes" idiom
  (csharp resolve_in_enclosing_namespace, cpp namespace components) →
  `namespace_prefixes(fqn)` iterator.
- **Do NOT unify (genuinely semantic):** rust impl-target resolution (owner is the
  impl'd type, not the enclosing unit), cpp out-of-line owner recovery, bounded
  pre-index AST walkers (scala/cpp/rust), sub-CodeUnit function/lambda scopes,
  ruby's traversal-maintained lexical stack, go's package model.
- **Hard constraints for the shared service:** must call trait `analyzer.parent_of`
  (rust and scala override it with OPPOSITE precedence — scala needs
  structural-first for `$` companions); predicate stays caller-supplied
  (cpp skips type aliases, java sometimes skips functions); budgets must thread
  through (java/csharp charge scope_step per hop — silently dropping truncation
  guarantees is a regression); csharp partial types need multi-declaration fan-out.

## Ranked backlog (to be finalized when all six surveys land)
