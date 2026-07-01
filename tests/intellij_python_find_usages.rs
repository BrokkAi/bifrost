//! Python find-usages corner cases ported from IntelliJ Community's
//! `PyFindUsagesTest` (`python/testSrc/com/jetbrains/python/PyFindUsagesTest.java`
//! + `python/testData/findUsages/`).
//!
//! IntelliJ's find-usages is caret/position-based; the faithful bifrost surface
//! is the LSP server's `textDocument/references`. Each test embeds the exact
//! IntelliJ fixture source (with the original `<caret>` marker preserved inline
//! and a provenance comment citing the upstream PY-#### ticket), strips the
//! caret, writes the file(s) into a temp project, and drives the real server.
//!
//! Envelope: bifrost's `references` resolves the cursor to one or more
//! `CodeUnit`s (class / function / method / module-level field / import), so
//! only IntelliJ cases whose target is such a declaration are portable. Cases
//! that target locals, parameters, lambda params, or comprehension bindings are
//! out of scope by architecture and are intentionally not ported (see the
//! ExecPlan `.agent/EXECPLAN_INTELLIJ_PYTHON_FINDUSAGES.md` for the full triage).
//!
//! IntelliJ find-usages excludes the declaration site, so every reference query
//! here uses `includeDeclaration = false`.
//!
//! Triage outcomes are recorded per test (full table in the ExecPlan):
//! - PASS: bifrost matches IntelliJ.
//! - `#[ignore]` "deferred": a precise answer is unavailable (e.g. an untyped
//!   receiver) and a structured name-based best-effort would resolve it, but
//!   that is not yet implemented. Not a design prohibition.
//! - `#[ignore]` "out of scope / model divergence": bifrost is project-scoped
//!   (external modules are not indexed) or models the program differently from
//!   IntelliJ's PSI (e.g. attributes per-class rather than merged by name).
//! - `#[ignore]` <case-specific>: a narrower remaining gap, explained inline.

mod common;

use common::lsp_client::{LspServer, RefLocation, uri_for};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Split a fixture that contains exactly one `<caret>` marker into the cleaned
/// source and the caret's 0-based `(line, character)` LSP position.
///
/// Character is counted in `char`s; the ported fixtures are ASCII, so this
/// equals the UTF-16 code-unit offset that LSP positions use.
fn split_caret(source: &str) -> (String, u64, u64) {
    let idx = source
        .find("<caret>")
        .expect("fixture must contain <caret>");
    let before = &source[..idx];
    let line = before.matches('\n').count() as u64;
    let last_line_start = before.rfind('\n').map(|n| n + 1).unwrap_or(0);
    let character = before[last_line_start..].chars().count() as u64;
    let cleaned = source.replacen("<caret>", "", 1);
    (cleaned, line, character)
}

/// Write a single-file fixture (with inline `<caret>`) into a fresh temp project
/// and return the project, the written file path, and the caret position.
fn single_file_project(name: &str, source_with_caret: &str) -> (TempDir, PathBuf, u64, u64) {
    let (source, line, character) = split_caret(source_with_caret);
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let file = root.join(name);
    std::fs::write(&file, source).expect("write fixture");
    (temp, file, line, character)
}

/// Run a single-file find-usages query and return the resolved locations.
fn references_for(name: &str, source_with_caret: &str) -> (TempDir, PathBuf, Vec<RefLocation>) {
    let (temp, file, line, character) = single_file_project(name, source_with_caret);
    let mut server = LspServer::start(file.parent().unwrap());
    let locations = server.references(&file, line, character, false);
    server.shutdown();
    (temp, file, locations)
}

/// Write several files (exactly one carrying a `<caret>`) into one temp project,
/// run find-usages at the caret, and return the project root + resolved
/// locations across all files.
fn references_multifile(files: &[(&str, &str)]) -> (TempDir, PathBuf, Vec<RefLocation>) {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canon temp");
    let mut caret: Option<(PathBuf, u64, u64)> = None;
    for (name, src) in files {
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        if src.contains("<caret>") {
            let (clean, line, character) = split_caret(src);
            std::fs::write(&path, clean).expect("write caret fixture");
            caret = Some((path, line, character));
        } else {
            std::fs::write(&path, src).expect("write fixture");
        }
    }
    let (caret_path, line, character) = caret.expect("one file must contain <caret>");
    let mut server = LspServer::start(&root);
    let locations = server.references(&caret_path, line, character, false);
    server.shutdown();
    (temp, root, locations)
}

/// Count of resolved locations whose URI ends with each given file name.
fn reference_counts_by_file(locations: &[RefLocation], names: &[&str]) -> Vec<usize> {
    names
        .iter()
        .map(|name| {
            locations
                .iter()
                .filter(|loc| loc.uri.ends_with(name))
                .count()
        })
        .collect()
}

/// Assert the multiset of reference lines (0-based) returned for a caret query,
/// regardless of column.
fn assert_reference_lines(locations: &[RefLocation], file: &Path, expected_lines: &[u64]) {
    let file_uri = uri_for(file);
    let mut got: Vec<u64> = locations
        .iter()
        .filter(|loc| loc.uri == file_uri)
        .map(|loc| loc.line)
        .collect();
    got.sort_unstable();
    let mut expected = expected_lines.to_vec();
    expected.sort_unstable();
    assert_eq!(
        got, expected,
        "reference lines in {file:?} mismatch\n locations: {locations:#?}"
    );
}

// ---------------------------------------------------------------------------
// Multi-file (cross-file) cases
// ---------------------------------------------------------------------------

// IntelliJ PY-27004 ConstImportedFromAnotherFile: caret on `SOME_CONST` in the
// definer. Via LSP `references` bifrost resolves the definer read plus, in the
// consumer, the `from definer import SOME_CONST` binding and the `print` read ->
// [definer=1, consumer=2]. (The import binding is an `Import`-kind hit that the
// find-references surface includes and the call-graph surfaces ignore.)
//
// IntelliJ counts [3, 2]; the two extra definer hits are the `SOME_CONST = ...`
// assignment *targets*, which bifrost models as declarations, not usages — an
// intentional divergence.
#[test]
fn const_imported_from_another_file() {
    let (_t, _root, locations) = references_multifile(&[
        (
            "definer.py",
            "SOME_CONST = False\nif some_cond:\n    SOME_CONST = True\nprint(<caret>SOME_CONST)\n",
        ),
        (
            "consumer.py",
            "from definer import SOME_CONST\nprint(SOME_CONST)\n",
        ),
    ]);
    assert_eq!(
        reference_counts_by_file(&locations, &["definer.py", "consumer.py"]),
        vec![1, 2],
    );
}

// IntelliJ PY-7348 NamespacePackageUsages: caret on `nspkg1`, a PEP-420 namespace
// package (a directory with no `__init__.py`). IntelliJ counts 3 (the two imports
// + the `print(nspkg1)`). bifrost models files as modules and does not synthesize
// a module CodeUnit for an implicit namespace-package directory, so the cursor
// does not resolve and no usages are found. Out of scope by design.
#[test]
#[ignore = "out of scope: bifrost does not model PEP-420 namespace packages (directories without __init__.py)"]
fn namespace_package_usages() {
    let (_t, _root, locations) = references_multifile(&[
        ("b.py", "import nspkg1\n"),
        ("a.py", "import nspkg1.m1\n\nprint(ns<caret>pkg1)\n"),
        ("nspkg1/m1.py", "\n"),
    ]);
    // IntelliJ's expectation: 1 in b.py, 2 in a.py.
    assert_eq!(
        reference_counts_by_file(&locations, &["b.py", "a.py"]),
        vec![1, 2],
    );
}

// ---------------------------------------------------------------------------
// Bug 1 regression: cursor resolution for a method in a single-method class.
//
// A class whose body is exactly one method makes the class `block` node share
// the method's byte span; the declaration-name resolver used to return the
// nameless `block` and fail (`result: null`). After the fix the method name
// resolves (the references request returns an array, not null), even though the
// same-file usage itself is still not found (Bug 2).
// ---------------------------------------------------------------------------
#[test]
fn method_name_cursor_resolves_in_single_method_class() {
    let (_temp, file, line, character) = single_file_project(
        "solo.py",
        "class Foo:\n    def b<caret>ar(self):\n        pass\n",
    );
    let mut server = LspServer::start(file.parent().unwrap());
    let raw = server.references_raw(&file, line, character, false);
    server.shutdown();
    assert!(
        raw["result"].is_array(),
        "caret on a single-method class's method name must resolve (got {})",
        raw["result"]
    );
}

// ---------------------------------------------------------------------------
// Single-file, in-envelope cases — PASSING
// ---------------------------------------------------------------------------

// IntelliJ PY-774 ClassUsages: caret on the class declaration `Cow`; the single
// usage is the `Cow()` construction on the last line.
#[test]
fn class_usages() {
    let (_temp, file, locations) = references_for(
        "ClassUsages.py",
        "class C<caret>ow:\n    def __init__(self):\n        pass\n\nc = Cow()\n",
    );
    assert_reference_lines(&locations, &file, &[4]);
}

// IntelliJ PY-1450 UnresolvedClassInit: caret on class `B`. `B` is never used
// (and its base `C` is unresolved), so there are 0 usages.
#[test]
fn unresolved_class_init() {
    let (_temp, file, locations) = references_for(
        "UnresolvedClassInit.py",
        "class <caret>B(C):\n    def __init__(self):\n        C.__init__(self)\n",
    );
    assert_reference_lines(&locations, &file, &[]);
}

// IntelliJ PY-26006 FunctionUsagesWithSameNameDecorator: caret on the decorated
// inner `foo` (line 13). The `@foo` decorator (line 12) refers to the OUTER
// `foo` (line 0), not this one, so the inner `foo` has 0 usages. Guards against
// same-name function confusion.
#[test]
fn function_usages_with_same_name_decorator() {
    let (_temp, file, locations) = references_for(
        "FunctionUsagesWithSameNameDecorator.py",
        "def foo(baz=None):\n    def _foo(func):\n        def wrapper(*args, **kwargs):\n            func(*args, **kwargs)\n\n        wrapper.baz = baz\n        return wrapper\n\n    return _foo\n\n\n@foo\ndef fo<caret>o():\n    pass\n",
    );
    assert_reference_lines(&locations, &file, &[]);
}

// ---------------------------------------------------------------------------
// Single-file, in-envelope cases — remaining gaps (distinct from Bug 2a)
// ---------------------------------------------------------------------------

// IntelliJ PY-292 InitUsages: caret on `__init__`. The constructor call
// `c = C()` (line 4) invokes `__init__`, so it counts as a usage; `print(C)`
// (line 5) passes the class as a value and does not.
#[test]
fn init_usages() {
    let (_temp, file, locations) = references_for(
        "InitUsages.py",
        "class C:\n    def __i<caret>nit__(self):\n        pass\n\nc = C()\nprint(C)\n",
    );
    assert_reference_lines(&locations, &file, &[4]);
}

// IntelliJ PY-4338 ReassignedInstanceAttribute: caret on `self.bacaba = 3`
// (line 13) in subclass B. After Bug 2a bifrost resolves the same-class B
// usages (excluding the B declaration site) -> [13, 16], but it models
// `A.bacaba` and `B.bacaba` as distinct fields, whereas IntelliJ merges
// `bacaba` across the A/B hierarchy by name -> [2, 5, 10, 13, 16]. Py2 `print`
// modernized to `print(...)`.
#[test]
#[ignore = "by design: bifrost models attributes per-class (no by-name merge across the hierarchy)"]
fn reassigned_instance_attribute() {
    let (_temp, file, locations) = references_for(
        "ReassignedInstanceAttribute.py",
        "class A(object):\n    def __init__(self):\n        self.bacaba = 1\n\n    def foo(self, x):\n        self.bacaba = x\n\nclass B(A):\n    def __init__(self):\n        super(B, self).__init__()\n        self.bacaba = 2\n\n    def foo2(self):\n        self.ba<caret>caba = 3\n\n    def foo3(self):\n        print(self.bacaba)\n",
    );
    assert_reference_lines(&locations, &file, &[2, 5, 10, 13, 16]);
}

// IntelliJ PY-4338 ReassignedClassAttribute: caret on a `self.bacaba` read in
// subclass B (line 16). Same per-class-attribute divergence as above. Py2
// `print` modernized.
#[test]
#[ignore = "by design: bifrost models attributes per-class (no by-name merge across the hierarchy)"]
fn reassigned_class_attribute() {
    let (_temp, file, locations) = references_for(
        "ReassignedClassAttribute.py",
        "class A(object):\n    bacaba = 0\n    def __init__(self):\n        self.bacaba = 1\n\n    def foo(self, x):\n        self.bacaba = x\n\n\nclass B(A):\n    bacaba = 2\n    def __init__(self):\n        super(B, self).__init__()\n        self.bacaba = 3\n\n    def foo2(self):\n        print(self.bac<caret>aba)\n",
    );
    assert_reference_lines(&locations, &file, &[1, 3, 6, 10, 13, 16]);
}

// ---------------------------------------------------------------------------
// Bug 2a fix coverage — same-file `self.`-receiver member usages
// ---------------------------------------------------------------------------

// IntelliJ PY-1448 ConditionalFunctions: caret on attribute `a`
// (`self.a = None`, line 6). IntelliJ counts 3 writes (lines 6, 10, 13). bifrost
// excludes the declaration site (line 6, the `__init__` assignment) under
// includeDeclaration=false and reports the two conditional-method writes — the
// correct result for our semantics; the underlying `self.a` resolution is what
// Bug 2a fixed.
#[test]
fn conditional_functions() {
    let (_temp, file, locations) = references_for(
        "ConditionalFunctions.py",
        "import sys\n\nvar = (sys.platform == 'win32')\n\nclass A():\n    def __init__(self):\n        self.<caret>a = None\n\n    if var:\n        def func(self):\n            self.a = \"\"\n    else:\n        def func(self):\n            self.a = ()\n",
    );
    assert_reference_lines(&locations, &file, &[10, 13]);
}

// Bug 2a regression (not from IntelliJ): a `self.method()` call in a sibling
// method is a usage of that method, and an inherited `self.method()` in a
// subclass resolves through the type hierarchy. Before the fix `self` resolved
// to no type and these returned zero usages.
#[test]
fn self_receiver_method_usage_resolves() {
    let (_temp, file, locations) = references_for(
        "self_method.py",
        "class Foo:\n    def b<caret>ar(self):\n        pass\n\n    def baz(self):\n        self.bar()\n",
    );
    assert_reference_lines(&locations, &file, &[5]);
}

#[test]
fn self_receiver_inherited_method_usage_resolves() {
    let (_temp, file, locations) = references_for(
        "self_inherited.py",
        "class A:\n    def b<caret>ar(self):\n        pass\n\nclass B(A):\n    def baz(self):\n        self.bar()\n",
    );
    assert_reference_lines(&locations, &file, &[6]);
}

// IntelliJ PY-6241 NameShadowing: caret on the `@property` getter `x`. The
// `@x.setter` (line 9) and `@x.deleter` (line 13) decorators reference the
// property `x` as the object of an attribute access in the class body.
#[test]
fn name_shadowing() {
    let (_temp, file, locations) = references_for(
        "NameShadowing.py",
        "class C(object):\n    def __init__(self):\n        self._x = None\n\n    @property\n    def <caret>x(self):\n        \"\"\"I'm the 'x' property.\"\"\"\n        return self._x\n\n    @x.setter\n    def x(self, value):\n        self._x = value\n\n    @x.deleter\n    def x(self):\n        del self._x\n",
    );
    assert_reference_lines(&locations, &file, &[9, 13]);
}

// IntelliJ PY-5458 WrappedMethod: caret on method `testMethod`. IntelliJ counts
// 3: the `MyClass.testMethod(...)` call (line 2) and both `testMethod` tokens in
// `testMethod = staticmethod(testMethod)` (line 9). After the class-body
// bare-name fix bifrost finds [2, 9] — the qualified call and the `staticmethod`
// argument. It still omits the line-9 LHS, which is the assignment *target*
// (a reassignment) and is modeled as a declaration, not a usage.
#[test]
#[ignore = "bifrost finds [2, 9]; omits the line-9 reassignment target (assignment target = declaration)"]
fn wrapped_method() {
    let (_temp, file, locations) = references_for(
        "WrappedMethod.py",
        "class TestClass:\n        def __init__(self):\n                MyClass.testMethod(\"Hello World\")\n\n\nclass MyClass:\n        #@staticmethod\n        def te<caret>stMethod(text):\n                print(text)\n        testMethod = staticmethod(testMethod)\n\n\nif __name__ == '__main__':\n        TestClass()\n",
    );
    assert_reference_lines(&locations, &file, &[2, 9, 9]);
}

// ---------------------------------------------------------------------------
// Single-file, in-envelope cases — name-based best-effort for untyped receivers
//
// When a receiver type cannot be inferred, `recv.member` is attributed to the
// target by name, but only as a contained same-file best-effort: the owner is in
// this file and the member name is unique among local classes. Cross-file untyped
// receivers stay conservative (see the no-hit parity tests in
// usages_python_graph_test.rs).
// ---------------------------------------------------------------------------

// IntelliJ ImplicitlyResolvedUsages: caret on method `unique_long_identifier`.
// `q` is an untyped parameter; `q.unique_long_identifier()` resolves by name
// because `unique_long_identifier` is unique to `Foo` in this file.
#[test]
fn implicitly_resolved_usages() {
    let (_temp, file, locations) = references_for(
        "ImplicitlyResolvedUsages.py",
        "class Foo:\n    def unique_long_identi<caret>fier(self):\n        pass\n\ndef foo(q):\n    q.unique_long_identifier()\n",
    );
    assert_reference_lines(&locations, &file, &[5]);
}

// IntelliJ ImplicitlyResolvedFieldUsages: caret on the attribute write
// `self.unique_some_identifier = 12`. The read `q.unique_some_identifier` has an
// untyped receiver `q`; same name-based best-effort as above.
#[test]
fn implicitly_resolved_field_usages() {
    let (_temp, file, locations) = references_for(
        "ImplicitlyResolvedFieldUsages.py",
        "class Foo:\n    def __init__(self):\n        self.unique_some_identi<caret>fier = 12\n\ndef foo(q):\n    s = q.unique_some_identifier\n",
    );
    assert_reference_lines(&locations, &file, &[5]);
}

// ---------------------------------------------------------------------------
// Single-file, in-envelope cases — OUT OF SCOPE / model divergence
// ---------------------------------------------------------------------------

// IntelliJ PY-1514 Imports: caret on `re` in `import re`. `re` is an external
// (non-project) module; bifrost is a project-scoped analyzer and has no CodeUnit
// for it, so it cannot enumerate `re`'s usages. Out of scope by design.
#[test]
#[ignore = "out of scope: bifrost is project-scoped and does not index external modules like `re`"]
fn imports() {
    let (_temp, file, locations) =
        references_for("Imports.py", "import r<caret>e\n\nx = re.compile('')\n");
    assert_reference_lines(&locations, &file, &[0, 2]);
}
