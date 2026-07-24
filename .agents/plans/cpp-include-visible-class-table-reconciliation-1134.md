# C++ include-visible class-table reconciliation for out-of-line member identity (#1134)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agents/PLANS.md` (repository root: `/Users/dave/Workspace/BrokkAi/bifrost/.agents/PLANS.md`). Read that file before revising this plan.


## Purpose / Big Picture

In C++, a class method is usually *declared* in a header and *defined* out-of-line in a `.cpp`. Bifrost treats a declaration and its definition as "the same symbol" only when they compute the identical fully-qualified name (`fq_name`). For a method nested inside a class that is itself nested inside a namespace — `log4cxx::Outer::Inner::method` — the header (parsed inside `namespace log4cxx { class Outer { class Inner { ... } } }`) is indexed as `log4cxx.Outer$Inner.method` (Bifrost writes class-nesting with `$` and the enclosing namespace as the package). The out-of-line definition in the `.cpp`, however, is written as `int Outer::Inner::method() const { ... }`, and extraction — which is strictly per-file and cannot see the header's class layout — has to *guess* whether each qualifier segment (`Outer`, `Inner`) is a namespace or a class. Two shapes still guess wrong today, so the definition indexes under a different `fq_name` than its declaration and the two never unify:

1. **File-scope definition under a using-directive.** `using namespace log4cxx;` followed by `int Outer::Inner::method() const {...}` at file scope. With no enclosing `namespace {}` block, extraction reads `Outer::Inner` as a namespace path and indexes the definition as `Outer.Inner.method` (package `Outer`, owner `Inner`) instead of `log4cxx.Outer$Inner.method`.

2. **Template-specialization twin.** An out-of-line member of a nested class *template*, e.g. `Outer::Inner<int>::method` (even inside a `namespace ns {}` block). The templated-name splitter `split_structured_templated_cpp_name` treats every segment before the first template-id as a namespace path, so `Outer` becomes a namespace segment and the definition indexes as `ns::Outer.Inner.method` (package `ns::Outer`, owner `Inner`) instead of `ns.Outer$Inner.method`.

Both are irreducibly class-table-dependent: the *only* way to know that `Outer` is a class and not a namespace is to consult the classes that are visible to the `.cpp` through its `#include` graph. That table already exists in the analyzer — `CppAnalyzer::visible_type_units(file)` in `src/analyzer/cpp/hierarchy.rs` walks the include graph and returns every class/alias `CodeUnit` reachable from a file, and is currently used only for supertype resolution. This plan adds a **resolution-time identity reconciliation layer**: a new, cross-file mechanism (there is none today) that, keyed on the include-visible class table, canonicalizes the provisional identity of an ambiguous out-of-line member definition so it unifies with its header declaration.

After this change, a user asking Bifrost for the sources of `log4cxx.Outer$Inner.method` (via the `get_symbol_sources` tool) gets **both** the header declaration and the `.cpp` definition back — for both the using-directive shape and the template-specialization shape — exactly as they already do for the plain `namespace {}`-block shape that #1121 fixed. The two currently-pinned "stays on today's behavior" tests flip from asserting non-unification to asserting unification.


## Progress

- [x] (2026-07-24) Read issue #1134, #1121 closing analysis, and the #1121 fix commit `57fc62ea`. Mapped the two remaining shapes to the exact provisional identities extraction produces.
- [x] (2026-07-24) Confirmed the identity/resolution flow: extraction (`split_cpp_name` / `split_structured_templated_cpp_name` in `src/analyzer/cpp/declarations.rs`) births per-file `fq_name`s; the store unifies purely by identical `fq_name`; `CppAnalyzer::get_definitions` (`src/analyzer/cpp/mod.rs:516`) delegates to the inner store's exact-match lookup; `get_symbol_sources` reaches it through `resolve_selectable_definitions(..., exact_codeunit_resolution)`.
- [x] (2026-07-24) Confirmed the class table shape: a nested class `log4cxx::Outer::Inner` is a `CodeUnit` with `package_name() == "log4cxx"` and `short_name() == "Outer$Inner"` (see `src/analyzer/cpp/declarations.rs:1122`). `visible_type_units(file)` returns these.
- [x] (2026-07-24) Wrote this ExecPlan.
- [x] (2026-07-24) M1: Pure reconciliation helper + unit tests. `reconcile_out_of_line_member_identity` in `src/analyzer/cpp/reconcile.rs`; 7 unit tests green (`cargo test --features nlp,python --lib cpp::reconcile` → 7 passed).
- [x] (2026-07-24) M2: `ReconciledDefinitionIndex` in `CppAnalyzer` (`by_canonical_fq: canonical fq -> re-keyed CodeUnit`, `provisional_of: re-keyed -> stored provisional`), built lazily from ambiguous out-of-line definitions via `visible_type_units`. Owner segments reconstructed from the stored identity; using-namespaces recovered by `cpp_file_using_namespaces` (structural AST walk).
- [x] (2026-07-24) M3: overlaid `definitions`, `get_definitions`, `ranges`, and `signature_metadata` on `CppAnalyzer` to fold in / map back the re-keyed definition. Both shapes flipped to assert unification (`file_scope_using_directive_nested_member_unifies`, `template_specialization_nested_member_unifies`); genuine-namespace negative control unchanged. **No epoch salt bump needed** — the overlay is purely resolution-time and leaves every persisted identity untouched. `issue_1121` suite: 12/12 (11 original + template twin) green on default features.
- [ ] M4: audit the remaining resolution surfaces that unify decl/def (`scan_usages`, symbol locations, skeletons) for the two shapes; add behavior-focused coverage where a surface reads stored data by identity and would miss the re-keyed unit. Completed: sources/roles/canonical-selectors (proven by the flipped tests). Remaining: usages + locations audit.
- [ ] Final validation: full cpp suites + searchtools + reference-differential green; `cargo fmt` + `cargo clippy --all-targets --all-features -D warnings` clean.


## Surprises & Discoveries

- Observation: The provisional identities of the two shapes differ in *both* package and owner from the header, not just owner.
  Evidence: File-scope shape indexes package `Outer`, owner `Inner` (header: package `log4cxx`, owner `Outer$Inner`). The reconciliation must recover the namespace as well as the class chain, so it must consult in-scope `using namespace` directives, not only the qualifier segments.

- Observation (blocking, discovered wiring M2/M3): a *pure* query-time overlay on `definitions(fq_name)` cannot produce unification, because the store keys everything by the stored (provisional) identity and the resolution/source path re-resolves through the inner store. Concretely: (1) `resolve_codeunit_exact` (`src/analyzer/symbol_lookup.rs:76`) calls `analyzer.definitions(query)` then *filters to `unit.fq_name() == query`*, dropping any folded-in provisional definition whose `fq_name` is still `Outer.Inner.method`; (2) `get_sources` for a function (`src/analyzer/tree_sitter_analyzer.rs:6919`) re-derives ranges via `self.definitions(unit.fq_name())` grouped by source and `self.ranges(candidate)`, and `ranges` (`:6832`) is `state.ranges.get(code_unit)` — a `HashMap<CodeUnit, Vec<Range>>` keyed by the *whole* stored `CodeUnit` (kind, package, short_name, file). So a re-keyed synthetic canonical unit finds no ranges either.
  Evidence: after overriding `definitions` to fold the provisional def under the canonical `fq_name`, `get_symbol_sources("log4cxx.Outer$Inner.method")` still returned only the header declaration (`using.h`, role `declaration`), not the `using.cpp` definition. Test `file_scope_using_directive_nested_member_unifies` failed with `left: ["using.h"]  right: ["using.cpp"]`.
  Consequence: true unification requires the definition to carry the canonical identity in the store's per-file `ranges`/declarations maps (store-level re-keying), *or* a coordinated resolution-time overlay that (a) returns a re-keyed canonical unit from `definitions`, and (b) maps that canonical unit back to the provisional stored identity on every surface that reads stored data (`get_sources`/`ranges`, occurrence-role classification, symbol locations, usages). The former touches persistence/epoch/incremental/GC; the latter is additive and persistence-neutral but must cover each consumer surface. See the Decision Log entry choosing between them.


## Decision Log

- Decision: Implement the fix as a **resolution-time reconciliation overlay** (Option B) rather than rewriting stored `fq_name`s at extraction (Option A).
  Rationale: The issue mandates a class-table-keyed resolution-time reconciliation *"across all resolution surfaces"* and states extraction is strictly per-file with no include resolution; the include-visible class table (`visible_type_units`) is an analyzer/resolution-layer structure, not available during per-file extraction. An overlay is additive and, as it turned out, leaves persisted identities *entirely* untouched (no epoch bump). Option A would couple extraction to a workspace-global structure and force the whole store through a re-key path.
  Date/Author: 2026-07-24, David Baker Effendi (with Claude)

- Decision: The overlay returns a **re-keyed synthetic `CodeUnit`** (canonical identity, real `.cpp` source/signature) from `definitions`, and maps that unit back to the stored provisional identity on the surfaces that read stored data by identity: `ranges` (range lookup) and `signature_metadata` (callable role + external linkage). The generic resolution/source-block machinery (`resolve_codeunit_exact`, `source_blocks_for_code_unit_with_cache`, occurrence-role classification, `cpp_canonical_selectors`) is then reused unchanged.
  Rationale: The store keys `ranges`, the declarations set, and the definitions index by the whole `CodeUnit`, and `resolve_codeunit_exact` filters to `fq_name == query`. Returning the *provisional* unit gets it filtered out; returning a re-keyed unit passes the filter but has no stored ranges/metadata. Mapping just those two read surfaces back to the provisional unit is the minimal, principled set: `occurrence_role` re-derives from source+range (identity-independent) and `canonical_selector` groups by canonical `fq_name` (works once the re-keyed unit is in `definitions`). Discovered empirically: without the `signature_metadata` map-back the header declaration and `.cpp` definition were misread as an *ambiguous cross-file duplicate* (both units need `External` linkage + `Definition`/`DeclarationOnly` roles for `cpp_callable_definitions_share_identity_evidence` to pair them). The `signature_metadata` override early-returns on non-empty inner metadata, so the lazily-built index is never re-entered during its own construction.
  Date/Author: 2026-07-24, David Baker Effendi (with Claude)

- Decision: Unify both shapes behind a single reconciliation function keyed on `(namespace_candidates, full_owner_segments, member_name, class_table)`.
  Rationale: Both shapes reduce to the same question — given the ordered qualifier segments and a set of candidate enclosing namespaces (the lexical package plus in-scope using-directives), find the partition into (namespace, class-nesting chain) that a visible class `CodeUnit` actually confirms. One helper, two call sites (the two splitters' outputs), one behavior.
  Date/Author: 2026-07-24, David Baker Effendi (with Claude)

- Decision: Reconstruct the reconciler's `owner_segments` from the stored provisional identity itself (package split on `::`, prepended to owner-chain split on `$`) and feed the *entire* qualifier to the reconciler, rather than capturing the lexical-namespace-vs-class boundary at extraction (superseding M2 option (a)/(b) as originally framed).
  Rationale: The reconciler already re-partitions its `owner_segments` at every split point against the class table, so it does not need extraction to pre-separate the lexical namespace from the mis-read class segments — it rediscovers the correct split from the table. Worked example: template shape provisional `ns::Outer.Inner.method` → segments `["ns","Outer","Inner"]`, candidates `[""]`; the reconciler's split at index 1 yields namespace `ns`, chain `Outer$Inner`, confirmed by the visible class `ns.Outer$Inner`. File-scope shape provisional `Outer.Inner.method` → segments `["Outer","Inner"]`, candidates `["", <using-namespaces>]`; split at index 0 with the using-directive `log4cxx` yields `log4cxx.Outer$Inner`. Genuine chain `ns1::ns2.Klass.method` → segments `["ns1","ns2","Klass"]`, candidates `[""]`; the only confirmed split reproduces the provisional identity unchanged. The one input not reconstructible from the stored `CodeUnit` is the file's in-scope `using namespace` targets; recover those at resolution time by a *structural* AST walk of the file (reusing `cpp_using_namespace_target`), not a text scan. This keeps extraction, the store, `CodeUnit`, and `SignatureMetadata` completely untouched — the reconciliation layer is a pure additive resolution-time overlay, and no epoch salt bump is needed for the provisional identities themselves (only for any behavior that begins returning the newly-unified pair, which is served from the overlay, not persisted identities).
  Date/Author: 2026-07-24, David Baker Effendi (with Claude)


## Outcomes & Retrospective

To be written at milestone completion.


## Context and Orientation

The reader is assumed to know nothing about this repository. Key locations:

- `src/analyzer/cpp/declarations.rs` — per-file C++ extraction. `split_cpp_name` (around line 2130) and `split_structured_templated_cpp_name` (around line 2267) turn a declarator's qualified name into `(owner_path: Option<String>, member_name: String, package_name: String)`. `owner_path` uses `$` to join class-nesting steps; `package_name` uses `::` to join namespace segments. A method's `fq_name` is `package.owner.member` with `owner` as written (so `log4cxx` + `Outer$Inner` + `method` renders `log4cxx.Outer$Inner.method`).
- `src/analyzer/cpp/hierarchy.rs` — `CppAnalyzer::visible_type_units(&self, file: &ProjectFile) -> Arc<Vec<CodeUnit>>` (line 22) walks the `#include` graph from `file` and returns every class-or-alias `CodeUnit` reachable, cached per file in `self.visible_type_units_by_file`. This is the **include-visible class table**. It is currently `fn` (private to the module); reconciliation will reuse it.
- `src/analyzer/cpp/mod.rs` — the `CppAnalyzer` struct (line 47) and its `IAnalyzer` impl. `get_definitions(fq_name)` (line 516) currently forwards straight to `self.inner.get_definitions(fq_name)`, an exact `fq_name` match against the store. This is the primary choke point for `get_symbol_sources`.
- `src/analyzer/cpp/identity.rs` — existing C++ identity helpers (declaration-vs-definition role classification, header/body relatedness). New reconciliation helpers live here or in a new sibling module.
- `tests/issue_1121_cpp_nested_class_out_of_line.rs` — the #1121 suite. `file_scope_using_directive_nested_member_stays_on_todays_behavior` (line 362) pins shape 1 to non-unification. Shape 2 (template) is not yet pinned by a dedicated test; a template pin will be added and then flipped.

Terms used in this plan:

- **Out-of-line member definition**: a function body written outside its class, qualified with the class path, e.g. `int Outer::Inner::method() const { ... }`.
- **Provisional identity**: the `(package, owner, member)` triple extraction produces per-file before any cross-file knowledge is applied.
- **Canonical identity**: the identity the header declaration carries — the one the definition *should* unify with.
- **Include-visible class table**: `visible_type_units(file)` — the set of class `CodeUnit`s reachable from `file` via `#include`.
- **Reconciliation**: replacing a provisional identity with a canonical one by confirming, against the class table, that some prefix of the qualifier is a namespace and the remaining segments name a real nested class.


## Plan of Work

The work is a pure helper, then a cached index that applies it, then wiring, then breadth.

### Milestone 1 — Pure reconciliation helper (prototype, fully unit-tested in isolation)

Add a pure function (no analyzer, no I/O) that decides the canonical identity from the qualifier segments plus a minimal class-table view. Signature (in `src/analyzer/cpp/identity.rs` or a new `src/analyzer/cpp/reconcile.rs`):

    /// A minimal, testable view of one visible class: its enclosing namespace
    /// (`::`-joined) and its class-nesting chain (`$`-joined short name).
    pub(crate) struct VisibleClass<'a> {
        pub package: &'a str,
        pub nested_short_name: &'a str, // e.g. "Outer$Inner"
    }

    /// Given the ordered owner segments of an out-of-line member (source order,
    /// e.g. ["Outer", "Inner"] for `Outer::Inner::method`), the member name, the
    /// set of candidate enclosing namespaces (the lexical package first, then any
    /// in-scope `using namespace` targets), and the include-visible class table,
    /// return the canonical `(package, owner_chain, member)` if — and only if —
    /// exactly one visible class confirms a (namespace, class-chain) partition of
    /// the segments. Returns `None` when nothing confirms (leave provisional
    /// identity untouched) or when the confirmation is ambiguous (never guess).
    pub(crate) fn reconcile_out_of_line_member_identity(
        owner_segments: &[&str],
        member: &str,
        namespace_candidates: &[&str],
        class_table: &[VisibleClass<'_>],
    ) -> Option<ReconciledIdentity>;

Algorithm: for each `namespace_candidate` `ns` and each split index `i` in `0..=owner_segments.len()` where the *class chain* `owner_segments[i..]` is non-empty, form the trial namespace `ns_full = join_ns(ns, owner_segments[..i])` (append the leading owner segments that are being read as further namespace nesting) and the trial class chain `chain = owner_segments[i..].join("$")`. If some `VisibleClass` has `package == ns_full && nested_short_name == chain`, that is a confirmed reading. Prefer the reading with the **longest class chain** (smallest `i`), because the deepest confirmed nesting is the most specific true identity; if two *distinct* canonical identities are confirmed with equal-length chains, return `None` (ambiguous — honestly refuse). The candidate ordering ensures the lexical package is tried before using-directive namespaces.

Unit tests (fail-before is trivial since the fn is new; assert correctness):
- File-scope-using shape: `owner=["Outer","Inner"]`, `member="method"`, `namespace_candidates=["", "log4cxx"]`, table has `{package:"log4cxx", nested:"Outer$Inner"}` and `{package:"log4cxx", nested:"Outer"}` → canonical `("log4cxx","Outer$Inner","method")`.
- Template shape inside `namespace ns`: `owner=["Outer","Inner"]`, `namespace_candidates=["ns"]`, table has `{package:"ns", nested:"Outer$Inner"}` → `("ns","Outer$Inner","method")`.
- Genuine namespace chain negative control: `owner=["ns1","ns2","Klass"]`, table has `{package:"ns1::ns2", nested:"Klass"}` but **no** class `{package:"", nested:"ns1$ns2$Klass"}` etc. The confirmed partition is `ns_full="ns1::ns2", chain="Klass"`, which equals the provisional reading — so reconciliation returns that identity unchanged (or `None`, meaning "no rewrite needed"; the two are equivalent for wiring). Test asserts the owner chain is not corrupted into `ns1$ns2$Klass`.
- Nothing visible: empty table → `None`.
- Ambiguous: two visible classes confirming different equal-length readings → `None`.

### Milestone 2 — Reconciliation index in `CppAnalyzer`

Add a per-analyzer, lazily-built index that maps **canonical `fq_name` → provisional `CodeUnit`s** for every ambiguous out-of-line member definition in the workspace. Store it on `CppAnalyzer` (a new `OnceLock`/`Cache` field beside `visible_type_units_by_file`). Population: iterate the store's callable definitions; for each whose provisional identity is an out-of-line member that could be misread (multi-segment owner or template branch, and whose current `fq_name` does *not* already match a header declaration), recover its owner segments and in-scope using-directives, call `reconcile_out_of_line_member_identity` against `visible_type_units(def.source())`, and when it yields a canonical identity different from the provisional one, record `canonical_fq_name -> def`.

To recover owner segments and using-directives at index time without re-parsing, prefer reusing the same structured data the splitters already have. Decide during M2 whether to (a) thread the raw owner segments + using-directive list onto the `CodeUnit`/signature metadata at extraction so the index can read them back, or (b) re-derive them from the stored provisional `fq_name` (owner via `$`/`.` split, namespace via package) plus a fresh scan of the file's `using namespace` directives. Record the choice in the Decision Log. Option (b) keeps extraction untouched but re-reads directives; option (a) is cheaper at query time but perturbs extraction. Start with (b) unless it proves lossy.

### Milestone 3 — Wire `get_definitions`, flip pins, bump epoch salt

Override `CppAnalyzer::get_definitions(fq_name)` to return the union of the inner exact-match result and any provisional `CodeUnit`s the reconciliation index maps from `fq_name`. Confirm `get_symbol_sources("log4cxx.Outer$Inner.method")` now returns both files for both shapes. Flip `file_scope_using_directive_nested_member_stays_on_todays_behavior` to assert unification (rename it accordingly), add and flip a template-shape twin test, and keep the genuine-namespace-chain negative control asserting *no* spurious unification. Bump the cpp epoch salt (see `src/analyzer/store/epoch.rs`, the cpp salt constant `#1121` bumped) with a new token, e.g. `nested-class-out-of-line-class-table-reconcile-2026-07`, because affected definitions now resolve under a new identity.

### Milestone 4 — Breadth across resolution surfaces

`get_symbol_sources` is the headline, but decl/def unification also surfaces in `scan_usages`, occurrence-role labelling (`identity.rs`), and symbol-location tools. Audit each surface that assumes a definition and declaration share `fq_name`, and route it through the reconciliation index (or a shared canonicalization helper) so the two shapes behave consistently everywhere. Add behavior-focused tests (list-then-use style) rather than registry-mirroring assertions, per repo test guidance.


## Concrete Steps

Working directory for all commands: `/Users/dave/Workspace/BrokkAi/bifrost` (or the active worktree root).

M1 build + test:

    cargo test --features nlp,python cpp_reconcile 2>&1 | tail -20

M3 end-to-end pin:

    cargo test --features nlp,python --test issue_1121_cpp_nested_class_out_of_line 2>&1 | tail -30

Full gates before any push:

    cargo fmt
    scripts/with-isolated-cargo-target.sh cargo clippy --all-targets --all-features -- -D warnings
    cargo test --features nlp,python --test issue_1121_cpp_nested_class_out_of_line
    cargo test --features nlp,python cpp 2>&1 | tail -40


## Validation and Acceptance

Acceptance is observable: after M3, running the `issue_1121` suite shows the two flipped tests asserting that `get_symbol_sources("log4cxx.Outer$Inner.method")` returns both the header and the `.cpp` for the using-directive shape, and the analogous canonical name returns both files for the template shape. The genuine-namespace-chain negative control still returns only the single expected file — no spurious cross-match. Each flipped test must fail before its wiring lands and pass after (demonstrate by running the test against the pre-M3 tree). All cpp suites, searchtools, and the reference-differential smoke run stay green; `cargo fmt` and clippy `-D warnings` are clean.


## Idempotence and Recovery

All steps are additive and re-runnable. The reconciliation index is a lazily-built cache; rebuilding it is side-effect-free. The epoch salt bump forces a one-time re-analysis of affected definitions; running the build twice is safe. If M2's identity-recovery approach (a vs b) proves wrong, revert to the other without touching M1's pure helper.


## Artifacts and Notes

Provisional identities established from the code (M0 research):

- File-scope-using shape `int Outer::Inner::method()` under `using namespace log4cxx;`: `split_cpp_name` file-scope multi-segment branch → package `Outer`, owner `Inner`, member `method` → `Outer.Inner.method`. Header: `log4cxx.Outer$Inner.method`.
- Template shape `Outer::Inner<int>::method` inside `namespace ns`: `split_structured_templated_cpp_name`, `owner_start` = first template-id index (1) → explicit_package `Outer`, package `ns::Outer`, owner `Inner` → `ns::Outer.Inner.method`. Header: `ns.Outer$Inner.method`.


## Interfaces and Dependencies

In `src/analyzer/cpp/reconcile.rs` (new) or `src/analyzer/cpp/identity.rs`:

    pub(crate) struct VisibleClass<'a> { pub package: &'a str, pub nested_short_name: &'a str }
    pub(crate) struct ReconciledIdentity { pub package: String, pub owner_chain: String, pub member: String }
    pub(crate) fn reconcile_out_of_line_member_identity(
        owner_segments: &[&str],
        member: &str,
        namespace_candidates: &[&str],
        class_table: &[VisibleClass<'_>],
    ) -> Option<ReconciledIdentity>;

In `src/analyzer/cpp/hierarchy.rs`: relax `visible_type_units` visibility to `pub(crate)` (or add a thin `pub(crate)` accessor) so the reconciliation index can call it.

In `src/analyzer/cpp/mod.rs`: a new field on `CppAnalyzer` for the reconciliation index and an overridden `get_definitions` that consults it.
