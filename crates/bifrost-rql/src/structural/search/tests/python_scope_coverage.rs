use super::*;
use brokk_bifrost_test_macros::hardwon;

fn search(source: &str, query: &str) -> CodeQueryResult {
    let (_project, workspace) = inline_project::python_workspace(&[("sample.py", source)]);
    execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &CodeQuery::from_source(query).expect("query"),
    )
}

#[test]
#[hardwon("c80ed4df7fbc: opposite triple quotes prematurely closed commented docstrings")]
fn commented_docstrings_require_the_opening_delimiter() {
    let source = "# def example():\n#     '''\n#     \"\"\"\n# payload stays inside the string\n#     '''\n#     return 1\nactive = 1\n";
    let result = search(
        source,
        "(python-commented-out-code (language python (comment)))",
    );
    let blocks = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => value.comment_block_text.as_deref(),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        blocks,
        [source.trim_end_matches("active = 1\n").trim_end()],
        "{}",
        result.render_text()
    );
}

#[test]
fn constructor_identity_comparisons_follow_python_value_categories() {
    let source = "def check():\n    a = int() is int()\n    b = list() is list()\n    c = object() is object()\n    d = bool() is bool()\n";
    let result = search(
        source,
        "(python-comparison-using-is (language python (comparison)))",
    );
    let texts = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::StructuralMatch { value } => value.text.as_str(),
            _ => panic!("structural comparison"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        texts,
        ["int() is int()", "list() is list()"],
        "{}",
        result.render_text()
    );
}

#[test]
fn raise_legality_distinguishes_exception_and_value_builtins() {
    let source = "def check():\n    raise int()\n    raise list()\n    raise ValueError()\n";
    let result = search(source, "(python-raise-legality (language python (throw)))");
    let rows = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => {
                Some((value.range.start_line, value.outcome))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [(2, "illegal"), (3, "illegal"), (4, "legal")],
        "{}",
        result.render_text()
    );
}

#[test]
fn builtin_range_exclusion_respects_lexical_shadows() {
    let source = "def builtin():\n    for x in list(range(3)):\n        consume(x)\ndef shadow(range, list):\n    for x in list(range(3)):\n        consume(x)\n";
    let result = search(
        source,
        "(python-variable-definitions (python-variable-of (bindings :name \"x\")))",
    );
    let rows = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value }
                if value.definition_kind == Some("loop_target") =>
            {
                Some((value.range.start_line, value.loop_policy_excluded))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [(2, Some(true)), (5, Some(false))],
        "{}",
        result.render_text()
    );
}

#[test]
fn lifecycle_omissions_are_attributed_to_the_first_omitting_class() {
    let source = "class A:\n    def __init__(self):\n        self.a = 1\nclass B(A):\n    def __init__(self):\n        self.b = 2\nclass C(B):\n    def __init__(self):\n        self.c = 3\nclass D(A):\n    def __init__(self):\n        A.__init__(self)\n";
    let result = search(
        source,
        "(python-call-relations (enclosing-decl (language python (identifier))))",
    );
    let rows = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonHierarchyFact { value }
                if value.fact_kind == "call_lifecycle" && value.outcome == "missing_call" =>
            {
                Some(value.root.as_ref().expect("root").fq_name.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rows, ["sample.B", "sample.C"], "{}", result.render_text());
}

#[test]
fn inherited_cleanup_requires_the_original_receiver() {
    let source = "class Parent:\n    def __del__(self):\n        self.close()\nclass Child(Parent):\n    def __del__(self):\n        Parent.__del__(self)\n";
    let result = search(
        source,
        "(python-call-relations (enclosing-decl (language python (identifier))))",
    );
    let rows = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonHierarchyFact { value }
                if value.fact_kind == "call_context"
                    && value.member_name.as_deref() == Some("__del__") =>
            {
                Some(value.outcome)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rows, ["approved_cleanup"], "{}", result.render_text());
}

#[test]
fn explicit_base_delegation_and_inherited_documentation_preserve_exemptions() {
    let source = "class Base:\n    def run(self):\n        \"\"\"Run the operation.\"\"\"\n        value = 1\n        return value\nclass Middle(Base):\n    def run(self):\n        value = 2\n        return value\nclass Child(Middle):\n    def run(self):\n        value = 3\n        return value\nclass Delegate(Base):\n    def run(self):\n        return Base.run(self)\n";
    let result = search(
        source,
        "(python-documentation (enclosing-decl (language python (identifier))))",
    );
    let rows = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } if value.is_override.is_some() => {
                Some((value.range.start_line, value.outcome))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        [
            (2, "no_issue"),
            (7, "issue"),
            (11, "issue"),
            (15, "excluded")
        ],
        "{}",
        result.render_text()
    );
}

#[test]
#[hardwon(
    "409a4f663f49: loop exits ignored binding: a nested function's return and an inner loop's break counted as leaving the outer iteration, and a return inside a nested loop was missed"
)]
fn nested_loop_redefinition_accounts_for_current_iteration_exits() {
    for (prior, expected) in [
        (
            "if flag:\n                for other in items:\n                    return",
            true,
        ),
        ("for other in items:\n                return", true),
        ("if flag:\n                break", true),
        ("if flag:\n                continue", true),
        ("if flag:\n                return", true),
        ("def nested():\n                return", false),
        ("for other in items:\n                break", false),
    ] {
        let source = format!(
            "def check(items, flag):\n    for x in items:\n        for x in items:\n            {prior}\n            x = replacement\n        consume(x)\n"
        );
        let result = search(
            &source,
            "(python-variable-nested-loops (python-variable-of (bindings :name \"x\")))",
        );
        let rows = result
            .results
            .iter()
            .filter_map(|item| match &item.value {
                CodeQueryResultValue::PythonRuleFact { value } => value.nested_loop_reused,
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(rows, [expected], "{prior}: {}", result.render_text());
    }
}
