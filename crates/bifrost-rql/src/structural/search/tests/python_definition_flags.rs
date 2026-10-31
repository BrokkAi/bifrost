use super::*;
use brokk_bifrost_test_macros::hardwon;

fn definitions(source: &str) -> CodeQueryResult {
    let (_project, workspace) = inline_project::python_workspace(&[("sample.py", source)]);
    execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &CodeQuery::from_source("(python-variable-definitions (python-variable-of (bindings)))")
            .expect("query"),
    )
}

#[test]
#[hardwon("c3f43da338ee: qualified ancestry borrowed an unrelated local base's methods")]
fn qualified_bases_do_not_borrow_local_methods() {
    let result = definitions(
        "class Base:\n    def m(self): pass\nclass Child(ns.Base):\n    def m(self): pass\nclass Local(Base):\n    def m(self): pass\n",
    );
    for (line, expected) in [(4, None), (6, Some(true))] {
        let rows = result
            .results
            .iter()
            .filter_map(|item| match &item.value {
                CodeQueryResultValue::PythonRuleFact { value }
                    if value.range.start_line == line =>
                {
                    Some(value)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1, "{result:#?}");
        assert_eq!(rows[0].is_overriding_method, expected, "{result:#?}");
    }
}

#[test]
#[hardwon("c3f43da338ee: transitive builtin object ancestry made override answers unknown")]
fn transitive_object_is_a_known_root() {
    let result = definitions("class A(object):\n    pass\nclass B(A):\n    def m(self): pass\n");
    let rows = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } if value.range.start_line == 4 => {
                Some(value)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "{result:#?}");
    assert_eq!(rows[0].is_overriding_method, Some(false), "{result:#?}");
}

#[test]
fn definitions_preserve_parameter_assignment_and_decorator_flags() {
    let source = "import pytest as p\nimport unittest as u\ndef f(x, y=y, z=other): pass\ndef g():\n    x=x\n    y=x\n    a: int\n    b: int = 1\n    n=1\n    n=n+1\n@decorate\nclass C: pass\nclass D: pass\n@p.fixture\ndef fixture(): pass\n@u.fixture\ndef nonfixture(): pass\n@p.mark\ndef marked(): pass\ndef plain(): pass\n";
    let result = definitions(source);
    let facts = result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => value.as_ref(),
            other => panic!("unexpected {other:?}"),
        })
        .collect::<Vec<_>>();
    for (line, name, optimizing, assignment, annotation, decorated) in [
        (3, "x", false, false, false, false),
        (3, "y", true, false, false, false),
        (3, "z", false, false, false, false),
        (5, "x", false, true, false, false),
        (6, "y", false, false, false, false),
        (7, "a", false, false, true, false),
        (8, "b", false, false, false, false),
    ] {
        let rows = facts
            .iter()
            .filter(|fact| fact.range.start_line == line && fact.name.as_deref() == Some(name))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1, "{line}:{name}: {result:#?}");
        let row = rows[0];
        assert_eq!(
            (
                row.optimizing_parameter,
                row.self_assignment,
                row.annotation_only,
                row.is_decorated
            ),
            (
                Some(optimizing),
                Some(assignment),
                Some(annotation),
                Some(decorated)
            ),
            "{line}:{name}: {result:#?}"
        );
    }
    let last = facts
        .iter()
        .find(|fact| fact.range.start_line == 10)
        .expect("final assignment");
    assert_eq!(last.definition_is_unused, Some(true), "{result:#?}");
}

#[test]
fn local_methods_distinguish_both_override_directions() {
    let result = definitions(
        "class A(object):\n    def m(self): pass\nclass B(A, metaclass=type):\n    def m(self): pass\n",
    );
    for (line, expected) in [
        (2, (Some(false), Some(true))),
        (4, (Some(true), Some(false))),
    ] {
        let rows = result
            .results
            .iter()
            .filter_map(|item| match &item.value {
                CodeQueryResultValue::PythonRuleFact { value }
                    if value.range.start_line == line =>
                {
                    Some(value)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1, "{result:#?}");
        assert_eq!(
            (rows[0].is_overriding_method, rows[0].is_overridden_method),
            expected,
            "{result:#?}"
        );
    }
}
