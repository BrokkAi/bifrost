# ExecPlan: Port IntelliJ Python find-usages corner cases to bifrost

Living document maintained per `.agent/PLANS.md`.


## Purpose and Big Picture

Borrow IntelliJ Community's curated Python find-usages corner cases
(`PyFindUsagesTest` + `python/testData/findUsages/`) to surface and fix real bugs
in bifrost's find-usages / cursor-resolution paths. IntelliJ's find-usages is
caret/position-based, so the faithful bifrost surface is the LSP server's
`textDocument/references`. Each ported case writes the IntelliJ fixture (caret
preserved inline) into a temp project, drives the real `bifrost` LSP server, and
asserts the resolved `Location` set.

Reference (read-only): `../intellij-community/python/testSrc/com/jetbrains/python/PyFindUsagesTest.java`
and `../intellij-community/python/testData/findUsages/`.

Envelope: bifrost `references` resolves the cursor to one or more `CodeUnit`s
(class / function / method / module-level field / import). IntelliJ cases that
target locals, parameters, lambda params, or comprehension bindings are out of
scope by architecture and are not ported.


## Progress

- 2026-06-30: Built shared LSP client harness `tests/common/lsp_client.rs`
  (`LspServer` owns the subprocess + streams + id counter; `references()` returns
  flattened `RefLocation`s). New suite `tests/intellij_python_find_usages.rs`.
- 2026-06-30: Ported the in-envelope single-file batch (12 cases). Triaged all
  failures. Found and fixed Bug 1; characterized Bug 2.
- 2026-06-30: Suite green — 4 passing (incl. Bug 1 regression), 9 quarantined
  `#[ignore]` with precise reasons. `cargo fmt`, `cargo clippy-no-cuda`, and the
  `bifrost_lsp_server` + `get_definition_test` suites (324 tests) all pass.
- 2026-06-30: Fixed Bug 2a (`self`/`cls` receiver resolution). Suite now 7
  passing / 8 ignored. `conditional_functions` promoted to PASS (adapted to
  bifrost's includeDeclaration=false semantics); added `self_receiver_*`
  regressions. No regressions: Python usage suites, LSP, get-definition all green;
  clippy clean. Remaining ignores re-triaged (see below) — most are no longer
  "same-file member" but distinct, narrower gaps.
- 2026-06-30: Fixed Bug 2b (module-scope receiver seeding). Re-characterized as
  scope-level (module vs function), not same-file. Canonical regressions added to
  `tests/usages_python_graph_test.rs` (56 pass). No regressions; clippy clean.
- 2026-06-30: Added class-body bare-name member-reference matching (WrappedMethod
  [2] -> [2, 9]). Regressions (+ negative in-method guard) in
  `usages_python_graph_test.rs` (58 pass). WrappedMethod/NameShadowing remain
  ignored for precisely-documented deeper reasons (reassignment-target modeling;
  decorator/property attribution). No regressions; clippy clean.


## Surprises and Discoveries

### Bug 1 (FIXED): caret on a method name in a single-method class returned `null`

`textDocument/references` (and any path through `broad_symbol_target_at_position`)
failed to resolve the cursor when it sat on a method name whose class body
contains exactly one method.

Evidence: control `class Foo:\n    def bar(self): pass` with caret on `bar`
returned `result: null` (cursor unresolved). A class with two methods returned
`[]` (resolved). Class names and module-level function names always resolved.

Root cause: in `src/lsp/handlers/broad_symbol.rs`, `code_unit_declaration_name_range`
calls `node_for_exact_range` to find the tree-sitter node matching the CodeUnit's
stored byte range, then reads its `name` field. When a class body is a single
statement, the `block` node and the `function_definition` it wraps share the
exact same byte span. `node_for_exact_range` returned the first exact-span node
its DFS popped — the nameless `block` ancestor — so name resolution failed.

Fix: `node_for_exact_range` now returns the *deepest* node whose span exactly
matches (exact-span nodes form a nested chain; the deepest is the real
declaration node). Regression test:
`method_name_cursor_resolves_in_single_method_class`.

### Bug 2a (FIXED): `self`/`cls`-receiver member usages were not resolved

`self`/`cls` is never assigned a type the way a local or parameter is, so the
receiver-matching path in `src/analyzer/usages/python_graph/extractor.rs`
(`receiver_binds_target`) found no type for it and `self.member` accesses matched
nothing. Fix: when the receiver expression is `self` or `cls`, resolve the
lexically enclosing class (`enclosing_code_unit` -> `target_owner_code_unit`) and
match it against the target member's owner, directly or via the type hierarchy
(so inherited `self.method()` in a subclass resolves too). New method
`ScanCtx::self_receiver_matches_target`. Verified: `self.bar()`, `self.attr`, and
inherited `self.bar()` all resolve (1 hit each); class-qualified and
typed-annotation paths unchanged.

### Bug 2b (FIXED): module-level constructed-local receiver not seeded

`f = Foo(); f.bar()` at module scope yielded 0 hits, while the same code inside a
function yielded 1. Root cause: `collect_scope_facts` built per-function and
per-class scope bindings but never the **module** scope, so a top-level
`f = Foo()` binding was lost and `enclosing_code_unit` resolved the usage to the
module (which had no facts). This was mischaracterized as "same-file" — the real
axis is scope level (module vs function), confirmed by probe: `ctorlocal_func`=1,
`ctorlocal_module`=0.

Fix: `collect_scope_facts` now also collects bindings for `is_module()`
declarations and keys them by the module CodeUnit. Verified `ctorlocal_module`=1;
regression `module_level_constructed_local_resolves_member_usage` in
`tests/usages_python_graph_test.rs`. `init_usages` remains blocked only by the
separate constructor-call -> `__init__` mapping gap.

### Bare-name class-body member references (PARTIAL)

A bare reference to a member inside the owner class body — the Python class
namespace, e.g. `alias = method` or `testMethod = staticmethod(testMethod)` —
was never matched: `handle_identifier_candidate` returned early for any member
target. Fix: match a bare identifier equal to the member name when it sits
directly in the owner class body. "Directly in the class body" means the
enclosing CodeUnit is the class itself or a class-level *field* of it (a
class-level assignment nests the reference inside a field CodeUnit), but NOT a
method — inside a method a bare name does not reach the class members.
New `ScanCtx::node_directly_in_owner_class_body`; regressions
`class_body_bare_member_reference_resolves` and (negative)
`bare_member_name_inside_method_is_not_a_usage`.

This advanced WrappedMethod from [2] to [2, 9]. Two related cases remain
divergent and are documented, not forced:

- WrappedMethod still omits the line-9 LHS of `testMethod = staticmethod(...)`,
  which is an assignment *target* (reassignment) and is modeled as a declaration
  rather than a usage. IntelliJ counts it.
- NameShadowing's `@x.setter` / `@x.deleter` references the property as the
  *object* of a decorator attribute, lexically attached to the setter/deleter
  method; resolving it also needs the getter/setter/deleter property definitions
  merged. Out of scope for the bare-identifier rule.

### Bug 2 (historical): same-file Python member usages are not resolved

Even after Bug 1, caret on a method/attribute resolves but finds zero usages for
same-file instance-receiver accesses.

Evidence (direct, bypassing LSP):

- same-file `f = Foo(); f.bar()`: `UsageFinder` = 0, `PythonExportUsageGraphStrategy` = 0.
- cross-file (`consumer.py` imports `Foo` from `service.py`): `UsageFinder` = 1.

So the Python usage-graph strategy resolves *exported / cross-file* member usages
(matching `constructed_local_receiver_resolves_member_usage` in
`tests/usages_python_graph_test.rs`) but misses some same-file instance-receiver
usages. For an LSP `references` server this is a real gap (IntelliJ counts
same-file usages). This blocks 6 ported cases.

Granular same-file probe (UsageFinder hits for target `m.Foo.bar`):

- class-qualified `Foo.bar(None)` = 1 (works)
- typed-annotation receiver `def run(f: Foo): f.bar()` = 1 (works)
- bare top-level function / class usage = 1 (works)
- constructed local `f = Foo(); f.bar()` = 0  (FAILS — but the cross-file
  equivalent passes)
- self receiver `self.bar()` inside the class = 0  (FAILS)

So Bug 2 decomposes:

- Bug 2a (highest value): `self.`-receiver member usages are not resolved — `self`
  is not typed as the enclosing class for same-file member matching. `self.x` is
  the most common Python member access and is inherently same-file; this is the
  root of the attribute cases (ReassignedInstanceAttribute, ReassignedClassAttribute,
  ConditionalFunctions, NameShadowing).
- Bug 2b: constructed-local receiver (`f = Foo()`) is not seeded with its type
  when the class is defined in the same file, even though the cross-file path
  seeds it correctly (likely the seeding hangs off an import edge that does not
  exist same-file).

Next step: in `src/analyzer/usages/python_graph/` (receiver-type seeding in
`extractor.rs`, `resolver.rs`), make (2a) `self` resolve to the enclosing class
type and (2b) same-file constructor assignments seed the local's type, mirroring
the cross-file seeding path. Fix the root cause; no text-search fallback.


## Decision Log

- 2026-06-30: Drive the port through the LSP `textDocument/references` server
  rather than the CodeUnit-fqName analyzer API. Rationale: IntelliJ find-usages
  is position-based; the caret maps 1:1 to an LSP `Position`, and this path also
  exercises cursor resolution (which is where Bug 1 lived).
- 2026-06-30: Embed fixtures inline in the test (caret preserved, PY-#### cited)
  rather than copying the testData tree into `tests/fixtures/`. Rationale:
  readability and single-file maintainability for small snippets; the server
  still gets real on-disk files via a tempdir. Deviates from the original plan's
  fixtures-dir step.
- 2026-06-30: Type-inference-dependent cases are kept in scope; overload- and
  `.pyi`-stub-dependent cases are out. Untyped-receiver name-only fallback is
  treated as a permanent by-design divergence (bifrost intentionally does not do
  it — see `CLAUDE.md` design philosophy), quarantined `#[ignore = "by design"]`.
- 2026-06-30: Py2 `print` statements in two fixtures modernized to `print(...)`
  so they parse under bifrost's Py3 tree-sitter grammar; the cases test attribute
  usages, not Py2 parsing.


## Triage table (every PyFindUsagesTest method)

PASS:
- ClassUsages, UnresolvedClassInit, FunctionUsagesWithSameNameDecorator,
  ConditionalFunctions (self-attribute, after Bug 2a; adapted to
  includeDeclaration=false).
- Regressions: `method_name_cursor_resolves_in_single_method_class` (Bug 1),
  `self_receiver_method_usage_resolves` + `self_receiver_inherited_method_usage_resolves`
  (Bug 2a).

OPEN gaps (`#[ignore]`, distinct from Bug 2a/2b):
- InitUsages — constructor-call `C()` is not mapped to the class `__init__` method.
- WrappedMethod — finds [2, 9]; omits the line-9 reassignment target (assignment
  target modeled as a declaration). IntelliJ wants [2, 9, 9].
- NameShadowing — decorator member references (`@x.setter`) + property
  getter/setter/deleter merge.

BY DESIGN divergence (`#[ignore]`, will not pass):
- ReassignedInstanceAttribute, ReassignedClassAttribute — bifrost models
  attributes per-class; IntelliJ merges across the hierarchy by name. (After
  Bug 2a bifrost resolves the same-class subset, e.g. [13, 16].)
- ImplicitlyResolvedUsages, ImplicitlyResolvedFieldUsages — untyped-receiver
  name-only fallback.
- Imports — external module not indexed.

OUT OF ENVELOPE (not ported — target is a local/param/comprehension binding):
- ReassignedLocalUsages, NonGlobalUsages, LambdaParameter,
  QualifiedVsUnqualifiedUsages, NestedFunctions, GlobalUsages, GlobalUsages2,
  OuterVariableInGenerator, OuterVariableInListComprehension,
  OverrideVariableInComprehension{1,2}, OverrideVariableByTupleInComprehension{1,2}.

DEFERRED (multi-file, second batch):
- ConstImportedFromAnotherFile, NamespacePackageUsages, *PyiStub (the `.pyi`-stub
  ones are likely by-design out: bifrost does not merge stub files).


## Outcomes and Retrospective

- Delivered: a faithful caret->LSP find-usages harness, a ported pilot, and one
  confirmed root-cause bug fix (Bug 1) with regression coverage. Bug 2 is
  characterized with a minimal reproduction and a concrete next step.
- The pilot already demonstrates bug yield (1 fixed + 1 well-localized), which is
  the gating result for deciding whether to scale to Java find-usages or to the
  much larger `textDocument/definition` resolution corpus.
