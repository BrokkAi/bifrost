use super::*;

#[brokk_bifrost_test_macros::hardwon(
    "54da9184f4aa: receiver stores and returned receiver values were classified as no read"
)]
#[test]
fn receiver_evaluation_includes_attribute_stores_and_return_values() {
    let source = "class Base:\n    def __init__(self):\n        self.setup()\n    def setup(self):\n        pass\nclass Store(Base):\n    def setup(self):\n        self.field = 1\nclass Return(Base):\n    def setup(self):\n        return self\nclass Argument(Base):\n    def setup(self):\n        consume(self)\nclass Augmented(Base):\n    def setup(self):\n        self.field += 1\n";
    let (_project, workspace) = inline_project::python_workspace(&[("sample.py", source)]);
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &CodeQuery::from_source(
            "(python-call-relations (enclosing-decl (language python (identifier))))",
        )
        .expect("query"),
    );
    let reads = result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonHierarchyFact { value }
                if value.outcome == "init_calls_subclass" =>
            {
                Some(value.target_reads_self)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reads,
        [Some(true), Some(true), Some(true), Some(true)],
        "{}",
        result.render_text()
    );
}

fn query(files: &[(&str, &str)], source: &str) -> CodeQueryResult {
    let (_project, workspace) = inline_project::python_workspace(files);
    execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::default(),
        &CodeQuery::from_source(source).expect("query"),
    )
}

fn rule_rows(result: &CodeQueryResult) -> Vec<&CodeQueryPythonRuleFact> {
    result
        .results
        .iter()
        .filter_map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => Some(value.as_ref()),
            _ => None,
        })
        .collect()
}

#[test]
fn unittest_assertions_recognize_imported_test_case_spellings() {
    for import in [
        "from unittest import TestCase",
        "from unittest.case import TestCase",
        "from unittest.case import TestCase as TC",
    ] {
        let base = if import.ends_with("TC") {
            "TC"
        } else {
            "TestCase"
        };
        let source = format!(
            "{import}\nclass Checks({base}):\n    def check(self):\n        assert False\n"
        );
        let result = query(
            &[("sample.py", &source)],
            "(python-assertion-context (language python (assertion)))",
        );
        assert_eq!(
            rule_rows(&result)
                .iter()
                .map(|r| r.test_scope)
                .collect::<Vec<_>>(),
            [Some("yes")],
            "{import}: {}",
            result.render_text()
        );
    }
}

#[test]
fn class_state_tracks_store_targets_and_constructor_names() {
    for (body, stateful, special) in [
        (
            "def run(self, mapping, key):\n        mapping[key] = 1",
            true,
            false,
        ),
        (
            "def run(self, mapping, key):\n        return mapping[key]",
            false,
            false,
        ),
        (
            "def run(self, obj):\n        return (local := obj.field)",
            false,
            false,
        ),
        ("def run(self, obj):\n        obj.field = 1", true, false),
        (
            "def run(self, resource):\n        with resource.context as local:\n            pass",
            false,
            false,
        ),
        (
            "def __new__(cls):\n        return object.__new__(cls)",
            false,
            false,
        ),
        ("def __str__(self):\n        return 'value'", false, true),
    ] {
        let source = format!("class Ordinary:\n    {body}\n");
        let result = query(
            &[("sample.py", &source)],
            "(python-useless-class (enclosing-decl (language python (identifier))))",
        );
        let rows = rule_rows(&result);
        assert_eq!(
            rows.iter()
                .map(|r| (r.is_stateful, r.has_special_method))
                .collect::<Vec<_>>(),
            [(Some(stateful), Some(special))],
            "{body}: {}",
            result.render_text()
        );
    }
}

#[test]
fn literal_destructor_conditions_prune_only_impossible_branches() {
    for (condition, expected) in [
        ("10", 2),
        ("0x10", 2),
        ("True", 2),
        ("not False", 2),
        ("0", 1),
        ("False", 1),
        ("not True", 1),
    ] {
        let source = format!(
            "class Destructor:\n    def __del__(self, flag):\n        if {condition}:\n            if flag:\n                pass\n"
        );
        let result = query(
            &[("sample.py", &source)],
            "(python-overly-complex-delete (enclosing-decl (language python (identifier))))",
        );
        assert_eq!(
            rule_rows(&result)
                .iter()
                .map(|r| r.cyclomatic_complexity)
                .collect::<Vec<_>>(),
            [Some(expected)],
            "{condition}: {}",
            result.render_text()
        );
    }
}

#[test]
fn fact_identity_includes_owner_and_anchor_extent() {
    let fact = |source: &str, selector: &str| {
        let result = query(&[("sample.py", source)], selector);
        let rows = rule_rows(&result);
        assert_eq!(rows.len(), 1, "{}", result.render_text());
        rows[0].clone()
    };
    let selector = "(python-documentation (enclosing-decl (language python (identifier))))";
    let first = fact("def alpha():\n    x = 1\n    return x\n", selector);
    let replay = fact("def alpha():\n    x = 1\n    return x\n", selector);
    let renamed = fact("def bravo():\n    x = 1\n    return x\n", selector);
    assert_eq!(first.id, replay.id);
    assert_ne!(first.owner_id, renamed.owner_id);
    assert_eq!(first.range, renamed.range);
    assert_ne!(first.id, renamed.id);
    let selector = "(python-assertion-context (language python (assertion)))";
    let short = fact("assert True\n", selector);
    let long = fact("assert True or False\n", selector);
    assert_eq!(short.range.start_column, long.range.start_column);
    assert_eq!(short.owner_id, long.owner_id);
    assert_ne!(short.range.end_column, long.range.end_column);
    assert_ne!(short.id, long.id);
}

#[test]
fn documentation_diagnostics_deduplicate_per_file_and_namespace() {
    let source = "def first():\n    return 1\ndef second():\n    return 2\nbroken = (\n";
    let result = query(
        &[("one.py", source), ("two.py", source)],
        "(python-documentation (enclosing-decl (language python (identifier))))",
    );
    let messages = result
        .diagnostics
        .iter()
        .filter(|d| d.message.contains("syntax"))
        .map(|d| d.message.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        [
            "python_documentation_incomplete: syntax unavailable at one.py",
            "python_documentation_incomplete: syntax unavailable at two.py"
        ],
        "{}\n{:#?}",
        result.render_text(),
        result.diagnostics
    );
}

#[test]
fn lexical_super_parameter_does_not_prove_trivial_delegation() {
    let source = "class Middle:\n    def __init__(self, super):\n        super().__init__()\nclass Child(Middle):\n    def __init__(self, factory):\n        Middle.__init__(self, factory)\n        Middle.__init__(self, factory)\n";
    let result = query(
        &[("sample.py", source)],
        "(python-call-relations (enclosing-decl (language python (identifier))))",
    );
    let flags = result
        .results
        .iter()
        .filter_map(|i| match &i.value {
            CodeQueryResultValue::PythonHierarchyFact { value }
                if value.outcome == "multiple_calls" =>
            {
                Some(value.target_non_trivial)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(flags, [Some(true)], "{}", result.render_text());
}
#[brokk_bifrost_test_macros::hardwon(
    "54da9184f4aa: unknown receiver reads emitted an unregistered hierarchy reason and panicked"
)]
#[test]
fn receiver_global_declarations_keep_reads_unknown() {
    let result = query(
        &[(
            "sample.py",
            "class Base:\n    def __init__(self):\n        self.setup()\n    def setup(self):\n        pass\nclass Child(Base):\n    def setup(self):\n        global external\n        external = 1\n",
        )],
        "(python-call-relations (enclosing-decl (language python (identifier))))",
    );
    let reads = result
        .results
        .iter()
        .filter_map(|i| match &i.value {
            CodeQueryResultValue::PythonHierarchyFact { value }
                if value.outcome == "init_calls_subclass" =>
            {
                Some((value.target_reads_self, value.coverage, value.reason))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reads,
        [(None, "open", Some("target_receiver_read_unavailable"))],
        "{}",
        result.render_text()
    );
}
