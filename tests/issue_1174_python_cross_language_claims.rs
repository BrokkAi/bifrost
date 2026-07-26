//! Regression coverage for issue #1174.
//!
//! pythonnet-shaped repositories drive .NET from Python: the Python tests name
//! CLR types by their exact CLR fully-qualified name (`Python.Test.ClassCtorTest2`,
//! `Test.ULongEnum.Max`), and the C# declarations for those names are indexed in
//! the very same workspace. Python's resolution path is language-scoped, so it
//! saw none of them and the workspace-boundary gate claimed a workspace-indexed
//! type was "outside this partial Python workspace analysis".
//!
//! Two invariants are pinned here:
//!
//! * Honesty (the #1126/#1089 invariant): a confident outside-the-workspace
//!   claim is never wrong about a workspace-internal target, whatever language
//!   declares it.
//! * Cross-language best-effort: when Python indexes nothing at the fq and some
//!   other language indexes a declaration at *exactly* that fq, get_definition
//!   returns it — the same shape Scala already uses for Java.
//!
//! Negative controls prove the resolution stays exact-fq: a genuinely external
//! module still draws the boundary claim, a merely same-simple-name C# class is
//! never substituted for an unresolved Python import, and ordinary Python
//! resolution is untouched.

mod common;

use common::{BuiltInlineTestProject, InlineTestProject, call_search_tool_json};
use serde_json::{Value, json};

const CSHARP: &str = r#"namespace Python.Test
{
    public class ClassCtorTest2
    {
        public string value;

        public ClassCtorTest2(string v)
        {
            value = v;
        }
    }

    public enum ULongEnum : ulong
    {
        Zero = 0,
        Max = 18446744073709551615
    }
}

namespace Other.Space
{
    public class Widget
    {
        public int Size;
    }
}
"#;

const HELPERS_PY: &str = r#"class Helper:
    def run(self):
        return 1
"#;

const TEST_PY: &str = r#"import clr
from Python.Test import ClassCtorTest2
import Python.Test as Test
import missing_third_party.sub as External
import unknown_widgets as UnknownNs
from helpers import Helper


class SubClassCtorTest(ClassCtorTest2):
    def __init__(self, v):
        ClassCtorTest2.__init__(self, v)
        self.size = ClassCtorTest2.value


def check_enum_member():
    return Test.ULongEnum.Max


def check_enum_type():
    return Test.ULongEnum


def check_external():
    return External.Absent


def check_same_simple_name():
    return UnknownNs.Widget


def check_python_import():
    return Helper()
"#;

const CSHARP_PATH: &str = "src/testing/classtest.cs";
const PY_PATH: &str = "tests/test_class.py";

fn project() -> BuiltInlineTestProject {
    InlineTestProject::new()
        .file(CSHARP_PATH, CSHARP)
        .file("helpers.py", HELPERS_PY)
        .file(PY_PATH, TEST_PY)
        .build()
}

/// Click the first occurrence of `needle` on the line whose trimmed text is
/// exactly `line_text`.
fn click(root: &std::path::Path, line_text: &str, needle: &str) -> Value {
    let matching: Vec<_> = TEST_PY
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim() == line_text)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "line {line_text:?} must select exactly one line"
    );
    let (line_index, line) = matching[0];
    let column = line
        .find(needle)
        .unwrap_or_else(|| panic!("needle {needle:?} not on line {line:?}"));
    let args =
        json!({"references":[{"path": PY_PATH, "line": line_index + 1, "column": column + 1}]})
            .to_string();
    call_search_tool_json(root, "get_definitions_by_location", &args)
}

fn status(value: &Value) -> String {
    value["results"][0]["status"]
        .as_str()
        .unwrap_or("?")
        .to_string()
}

fn definitions(value: &Value) -> Vec<(String, String)> {
    value["results"][0]["definitions"]
        .as_array()
        .map(|definitions| {
            definitions
                .iter()
                .map(|definition| {
                    (
                        definition["fqn"].as_str().unwrap_or_default().to_string(),
                        definition["path"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn diagnostics(value: &Value) -> String {
    value["results"][0]["diagnostics"].to_string()
}

fn assert_resolves_to_csharp(value: &Value, expected_fqn: &str, context: &str) {
    assert_eq!(
        status(value),
        "resolved",
        "{context}: expected resolved: {value}"
    );
    assert_eq!(
        definitions(value),
        vec![(expected_fqn.to_string(), CSHARP_PATH.to_string())],
        "{context}: wrong definition: {value}"
    );
}

/// The honesty invariant: whatever the outcome, it must not be a confident
/// claim that a workspace-indexed target sits outside the workspace.
fn assert_not_outside_workspace_claim(value: &Value, context: &str) {
    assert_ne!(
        status(value),
        "unresolvable_import_boundary",
        "{context}: must not draw an outside-the-workspace claim: {value}"
    );
    let diagnostics = diagnostics(value);
    assert!(
        !diagnostics.contains("outside the indexed workspace")
            && !diagnostics.contains("outside this partial"),
        "{context}: must not claim the target is outside the workspace: {value}"
    );
}

// --- Cross-language resolution (and honesty) for the pythonnet shapes ---------

/// `class SubClassCtorTest(ClassCtorTest2)`: a bare name bound by
/// `from Python.Test import ClassCtorTest2`, whose C# class is indexed at that
/// exact fq.
#[test]
fn imported_clr_class_resolves_to_the_csharp_declaration() {
    let project = project();
    let outcome = click(
        project.root(),
        "class SubClassCtorTest(ClassCtorTest2):",
        "ClassCtorTest2",
    );
    assert_not_outside_workspace_claim(&outcome, "base class");
    assert_resolves_to_csharp(&outcome, "Python.Test.ClassCtorTest2", "base class");
}

/// `ClassCtorTest2.__init__(self, v)`: the owner of a pythonnet constructor call.
#[test]
fn clr_class_call_owner_resolves_to_the_csharp_declaration() {
    let project = project();
    let outcome = click(
        project.root(),
        "ClassCtorTest2.__init__(self, v)",
        "ClassCtorTest2",
    );
    assert_not_outside_workspace_claim(&outcome, "call owner");
    assert_resolves_to_csharp(&outcome, "Python.Test.ClassCtorTest2", "call owner");
}

/// `Test.ULongEnum.Max`: a member reached through the CLR namespace alias — the
/// exact fuzzer shape that drew "`Test.ULongEnum.Max` resolves to
/// `Python.Test.ULongEnum.Max`, which is outside this partial Python workspace
/// analysis".
#[test]
fn clr_namespace_qualified_member_resolves_to_the_csharp_declaration() {
    let project = project();
    let outcome = click(project.root(), "return Test.ULongEnum.Max", "Max");
    assert_not_outside_workspace_claim(&outcome, "enum member");
    assert_resolves_to_csharp(&outcome, "Python.Test.ULongEnum.Max", "enum member");
}

/// The type half of the same reference: `Test.ULongEnum`.
#[test]
fn clr_namespace_qualified_type_resolves_to_the_csharp_declaration() {
    let project = project();
    let outcome = click(project.root(), "return Test.ULongEnum", "ULongEnum");
    assert_not_outside_workspace_claim(&outcome, "enum type");
    assert_resolves_to_csharp(&outcome, "Python.Test.ULongEnum", "enum type");
}

/// A member accessed on a receiver that could only be typed cross-language:
/// `ClassCtorTest2.value` is a C# field of a C#-declared owner.
#[test]
fn member_of_a_cross_language_receiver_resolves() {
    let project = project();
    let outcome = click(project.root(), "self.size = ClassCtorTest2.value", "value");
    assert_not_outside_workspace_claim(&outcome, "cross-language member");
    assert_resolves_to_csharp(
        &outcome,
        "Python.Test.ClassCtorTest2.value",
        "cross-language member",
    );
}

/// The bare CLR namespace alias itself (`Test`) names no single declaration, but
/// it is a namespace this workspace indexes — so it must never draw the
/// outside-the-workspace claim.
#[test]
fn clr_namespace_alias_is_not_claimed_outside_the_workspace() {
    let project = project();
    let outcome = click(project.root(), "return Test.ULongEnum.Max", "Test");
    assert_not_outside_workspace_claim(&outcome, "namespace alias");
}

/// A name that does not exist under an indexed CLR namespace is honestly
/// unresolved, not a workspace-boundary crossing.
#[test]
fn missing_member_of_an_indexed_clr_namespace_is_not_a_boundary_claim() {
    let project = InlineTestProject::new()
        .file(CSHARP_PATH, CSHARP)
        .file(
            PY_PATH,
            "import Python.Test as Test\n\n\ndef check():\n    return Test.NotDeclaredAnywhere\n",
        )
        .build();
    let args = json!({"references":[{"path": PY_PATH, "line": 5, "column": 17}]}).to_string();
    let outcome = call_search_tool_json(project.root(), "get_definitions_by_location", &args);
    assert_not_outside_workspace_claim(&outcome, "missing CLR member");
    assert!(
        definitions(&outcome).is_empty(),
        "missing CLR member must not resolve: {outcome}"
    );
}

// --- Negative controls -------------------------------------------------------

/// A genuinely external import — no language in this workspace declares
/// `missing_third_party.sub` — must still draw the confident boundary claim.
/// This is the same code path (`python_fqn_outcome`) the pythonnet shapes take.
#[test]
fn genuinely_external_import_still_draws_the_boundary_claim() {
    let project = project();
    let outcome = click(project.root(), "return External.Absent", "Absent");
    assert_eq!(
        status(&outcome),
        "unresolvable_import_boundary",
        "external import must keep its boundary claim: {outcome}"
    );
    assert!(
        definitions(&outcome).is_empty(),
        "external import must not resolve: {outcome}"
    );
}

/// Cross-language resolution is exact-fq only: `unknown_widgets.Widget` is
/// unresolved, and the workspace's `Other.Space.Widget` — same simple name,
/// different fq — must never be substituted for it.
#[test]
fn same_simple_name_in_another_language_is_never_substituted() {
    let project = project();
    let outcome = click(project.root(), "return UnknownNs.Widget", "Widget");
    assert!(
        definitions(&outcome).is_empty(),
        "a same-simple-name C# class must not be produced for `unknown_widgets.Widget`: {outcome}"
    );
    assert_eq!(
        status(&outcome),
        "unresolvable_import_boundary",
        "unindexed `unknown_widgets` module must keep its boundary claim: {outcome}"
    );
}

/// Ordinary same-language resolution is unchanged.
#[test]
fn python_import_still_resolves_to_the_python_declaration() {
    let project = project();
    let outcome = click(project.root(), "return Helper()", "Helper");
    assert_eq!(status(&outcome), "resolved", "python import: {outcome}");
    assert_eq!(
        definitions(&outcome),
        vec![("helpers.Helper".to_string(), "helpers.py".to_string())],
        "python import must resolve to the Python class: {outcome}"
    );
}

/// A member on a Python receiver still reports the Python-scoped miss.
#[test]
fn python_receiver_member_miss_is_reported_as_python() {
    let project = InlineTestProject::new()
        .file(CSHARP_PATH, CSHARP)
        .file("helpers.py", HELPERS_PY)
        .file(
            PY_PATH,
            "from helpers import Helper\n\n\ndef check():\n    return Helper.nope\n",
        )
        .build();
    let args = json!({"references":[{"path": PY_PATH, "line": 5, "column": 19}]}).to_string();
    let outcome = call_search_tool_json(project.root(), "get_definitions_by_location", &args);
    assert_not_outside_workspace_claim(&outcome, "python member miss");
    assert!(
        diagnostics(&outcome).contains("not indexed as a Python definition"),
        "python receiver misses stay Python-scoped: {outcome}"
    );
}
