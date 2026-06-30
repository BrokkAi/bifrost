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

### Bug 2 (OPEN): same-file Python member usages are not resolved

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
- ClassUsages, UnresolvedClassInit, FunctionUsagesWithSameNameDecorator.
- (plus Bug 1 regression `method_name_cursor_resolves_in_single_method_class`.)

BLOCKED on Bug 2 (`#[ignore]`, should pass once same-file member usages resolve):
- InitUsages (also needs constructor->__init__ mapping), ReassignedInstanceAttribute,
  ReassignedClassAttribute, ConditionalFunctions, NameShadowing, WrappedMethod.

BY DESIGN divergence (`#[ignore]`, will not pass):
- ImplicitlyResolvedUsages, ImplicitlyResolvedFieldUsages (untyped-receiver
  name-only fallback), Imports (external module not indexed).

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
