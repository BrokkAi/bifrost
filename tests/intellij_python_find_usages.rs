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
//! Triage outcomes are recorded per test:
//! - PASS: bifrost matches IntelliJ.
//! - `#[ignore]` "bifrost gap: same-file Python member usages": blocked on the
//!   usage graph not resolving same-file instance-receiver member usages
//!   (Bug 2). These should light up once that gap is closed.
//! - `#[ignore]` "by design": bifrost deliberately differs (no name-only member
//!   fallback for untyped receivers; external modules are not indexed).

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
// Single-file, in-envelope cases — BLOCKED on Bug 2 (same-file member usages)
// ---------------------------------------------------------------------------

// IntelliJ PY-292 InitUsages: caret on `__init__`. IntelliJ resolves the
// constructor call `c = C()` (line 4) to `__init__` => 1 usage.
#[test]
#[ignore = "bifrost gap: same-file Python member usages + constructor->__init__ mapping (Bug 2)"]
fn init_usages() {
    let (_temp, file, locations) = references_for(
        "InitUsages.py",
        "class C:\n    def __i<caret>nit__(self):\n        pass\n\nc = C()\nprint(C)\n",
    );
    assert_reference_lines(&locations, &file, &[4]);
}

// IntelliJ PY-4338 ReassignedInstanceAttribute: caret on `self.bacaba = 3`
// (line 13) in subclass B. IntelliJ merges `bacaba` across the A/B hierarchy by
// name and counts 5 (all `self.bacaba` occurrences). Py2 `print` modernized to
// `print(...)` so the file parses under bifrost's Py3 grammar.
#[test]
#[ignore = "bifrost gap: same-file Python member usages (Bug 2)"]
fn reassigned_instance_attribute() {
    let (_temp, file, locations) = references_for(
        "ReassignedInstanceAttribute.py",
        "class A(object):\n    def __init__(self):\n        self.bacaba = 1\n\n    def foo(self, x):\n        self.bacaba = x\n\nclass B(A):\n    def __init__(self):\n        super(B, self).__init__()\n        self.bacaba = 2\n\n    def foo2(self):\n        self.ba<caret>caba = 3\n\n    def foo3(self):\n        print(self.bacaba)\n",
    );
    assert_reference_lines(&locations, &file, &[2, 5, 10, 13, 16]);
}

// IntelliJ PY-4338 ReassignedClassAttribute: caret on a `self.bacaba` read in
// subclass B (line 16). IntelliJ counts 6, merging the class-level `bacaba = N`
// and the instance writes across A/B. Py2 `print` modernized.
#[test]
#[ignore = "bifrost gap: same-file Python member usages (Bug 2)"]
fn reassigned_class_attribute() {
    let (_temp, file, locations) = references_for(
        "ReassignedClassAttribute.py",
        "class A(object):\n    bacaba = 0\n    def __init__(self):\n        self.bacaba = 1\n\n    def foo(self, x):\n        self.bacaba = x\n\n\nclass B(A):\n    bacaba = 2\n    def __init__(self):\n        super(B, self).__init__()\n        self.bacaba = 3\n\n    def foo2(self):\n        print(self.bac<caret>aba)\n",
    );
    assert_reference_lines(&locations, &file, &[1, 3, 6, 10, 13, 16]);
}

// IntelliJ PY-1448 ConditionalFunctions: caret on attribute `a`
// (`self.a = None`). IntelliJ counts 3: the writes at lines 6, 10, 13 across the
// conditionally-defined `func` methods.
#[test]
#[ignore = "bifrost gap: same-file Python member usages (Bug 2)"]
fn conditional_functions() {
    let (_temp, file, locations) = references_for(
        "ConditionalFunctions.py",
        "import sys\n\nvar = (sys.platform == 'win32')\n\nclass A():\n    def __init__(self):\n        self.<caret>a = None\n\n    if var:\n        def func(self):\n            self.a = \"\"\n    else:\n        def func(self):\n            self.a = ()\n",
    );
    assert_reference_lines(&locations, &file, &[6, 10, 13]);
}

// IntelliJ PY-6241 NameShadowing: caret on the `@property` getter `x`. IntelliJ
// counts 2: the `@x.setter` (line 9) and `@x.deleter` (line 13) decorator
// references.
#[test]
#[ignore = "bifrost gap: same-file Python member usages / decorator references (Bug 2)"]
fn name_shadowing() {
    let (_temp, file, locations) = references_for(
        "NameShadowing.py",
        "class C(object):\n    def __init__(self):\n        self._x = None\n\n    @property\n    def <caret>x(self):\n        \"\"\"I'm the 'x' property.\"\"\"\n        return self._x\n\n    @x.setter\n    def x(self, value):\n        self._x = value\n\n    @x.deleter\n    def x(self):\n        del self._x\n",
    );
    assert_reference_lines(&locations, &file, &[9, 13]);
}

// IntelliJ PY-5458 WrappedMethod: caret on method `testMethod`. IntelliJ counts
// 3: the `MyClass.testMethod(...)` call (line 2) and both `testMethod` tokens in
// `testMethod = staticmethod(testMethod)` (line 9). bifrost resolves the
// class-qualified call on line 2 but not the bare-name reassignments on line 9.
#[test]
#[ignore = "bifrost gap: same-file Python member usages (bare-name member refs, Bug 2)"]
fn wrapped_method() {
    let (_temp, file, locations) = references_for(
        "WrappedMethod.py",
        "class TestClass:\n        def __init__(self):\n                MyClass.testMethod(\"Hello World\")\n\n\nclass MyClass:\n        #@staticmethod\n        def te<caret>stMethod(text):\n                print(text)\n        testMethod = staticmethod(testMethod)\n\n\nif __name__ == '__main__':\n        TestClass()\n",
    );
    assert_reference_lines(&locations, &file, &[2, 9, 9]);
}

// ---------------------------------------------------------------------------
// Single-file, in-envelope cases — BY DESIGN divergence (won't pass)
// ---------------------------------------------------------------------------

// IntelliJ ImplicitlyResolvedUsages: caret on method `unique_long_identifier`.
// `q` is an untyped parameter, so the `q.unique_long_identifier()` call resolves
// in IntelliJ only by name (unique-name fallback). bifrost deliberately does NOT
// do name-only member fallback for untyped receivers.
#[test]
#[ignore = "by design: bifrost does not do name-only member fallback for untyped receivers"]
fn implicitly_resolved_usages() {
    let (_temp, file, locations) = references_for(
        "ImplicitlyResolvedUsages.py",
        "class Foo:\n    def unique_long_identi<caret>fier(self):\n        pass\n\ndef foo(q):\n    q.unique_long_identifier()\n",
    );
    assert_reference_lines(&locations, &file, &[5]);
}

// IntelliJ ImplicitlyResolvedFieldUsages: caret on the attribute write
// `self.unique_some_identifier = 12`. The read `q.unique_some_identifier` has an
// untyped receiver `q`; bifrost will not resolve it by name alone.
#[test]
#[ignore = "by design: bifrost does not do name-only member fallback for untyped receivers"]
fn implicitly_resolved_field_usages() {
    let (_temp, file, locations) = references_for(
        "ImplicitlyResolvedFieldUsages.py",
        "class Foo:\n    def __init__(self):\n        self.unique_some_identi<caret>fier = 12\n\ndef foo(q):\n    s = q.unique_some_identifier\n",
    );
    assert_reference_lines(&locations, &file, &[5]);
}

// IntelliJ PY-1514 Imports: caret on `re` in `import re`. `re` is an external
// module, not a project symbol, so bifrost does not index or resolve it.
#[test]
#[ignore = "by design: bifrost does not index external (non-project) modules"]
fn imports() {
    let (_temp, file, locations) =
        references_for("Imports.py", "import r<caret>e\n\nx = re.compile('')\n");
    assert_reference_lines(&locations, &file, &[0, 2]);
}
