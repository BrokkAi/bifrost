use super::*;

fn execute_python_files(files: &[(&str, &str)], step: &str) -> CodeQueryResult {
    let project = files.iter().fold(
        InlineTestProject::with_language(Language::Python),
        |project, (path, source)| project.file(*path, *source),
    );
    let project = project.build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source(&format!("({step} (language python (throw)))"))
        .expect("Python raise query should parse");
    execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    )
}

fn execute_python_query(source: &str, step: &str) -> CodeQueryResult {
    execute_python_files(&[("raises.py", source)], step)
}

fn python_rule_facts(result: &CodeQueryResult) -> Vec<&CodeQueryPythonRuleFact> {
    result
        .results
        .iter()
        .map(|item| match &item.value {
            CodeQueryResultValue::PythonRuleFact { value } => value.as_ref(),
            other => panic!("raise rule step returned {other:?}"),
        })
        .collect()
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#4645: resolved builtin exception roots were treated as open in workspace ancestry"
)]
fn raise_legality_uses_builtin_identity_and_workspace_exception_ancestry() {
    let source = "class Plain:\n    pass\n\nclass LocalError(Exception):\n    pass\n\nclass Derived(LocalError):\n    pass\n\nclass ValueError:\n    pass\n\ndef plain_class():\n    raise Plain\n\ndef legal_class():\n    raise Derived\n\ndef legal_instance():\n    raise Derived()\n\ndef literal():\n    raise 1\n\ndef shadowed_builtin():\n    raise ValueError()\n\ndef dynamic(value):\n    raise value\n";
    let result = execute_python_files(
        &[
            ("raises.py", source),
            (
                "builtin.py",
                "def builtin_exception():\n    raise ValueError() from None\n",
            ),
        ],
        "python-raise-legality",
    );
    let facts = python_rule_facts(&result);
    assert_eq!(facts.len(), 7, "{result:#?}");
    let outcomes = facts
        .iter()
        .map(|fact| {
            (
                fact.path.as_str(),
                fact.raised_expression.as_deref().unwrap_or("<bare>"),
                fact.outcome,
                fact.completeness,
                fact.exception_class.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    for (path, expression, outcome) in [
        ("raises.py", "Plain", "illegal"),
        ("raises.py", "Derived", "legal"),
        ("raises.py", "Derived()", "legal"),
        ("raises.py", "1", "illegal"),
        ("builtin.py", "ValueError()", "legal"),
        ("raises.py", "ValueError()", "illegal"),
        ("raises.py", "value", "open"),
    ] {
        assert!(
            outcomes
                .iter()
                .any(|(found_path, found_expression, found_outcome, _, _)| {
                    *found_path == path
                        && *found_expression == expression
                        && *found_outcome == outcome
                }),
            "missing {path}:{expression} => {outcome}: {outcomes:?}"
        );
    }
    assert!(facts.iter().any(|fact| {
        fact.path == "raises.py"
            && fact.raised_expression.as_deref() == Some("Plain")
            && fact
                .exception_class
                .as_deref()
                .is_some_and(|name| name.ends_with("Plain"))
    }));
    assert!(facts.iter().any(|fact| {
        fact.path == "raises.py"
            && fact.raised_expression.as_deref() == Some("Derived")
            && fact
                .exception_class
                .as_deref()
                .is_some_and(|name| name.ends_with("Derived"))
    }));
    assert!(facts.iter().any(|fact| {
        fact.path == "raises.py"
            && fact.raised_expression.as_deref() == Some("Derived()")
            && fact
                .exception_class
                .as_deref()
                .is_some_and(|name| name.ends_with("Derived"))
    }));
    assert!(facts.iter().any(|fact| {
        fact.path == "builtin.py"
            && fact.raised_expression.as_deref() == Some("ValueError()")
            && fact.exception_class.as_deref() == Some("builtins.ValueError")
    }));
    assert!(facts.iter().any(|fact| {
        fact.path == "builtin.py"
            && fact.raised_expression.as_deref() == Some("ValueError()")
            && !fact
                .raised_expression
                .as_deref()
                .unwrap()
                .contains("from None")
    }));
}

#[test]
fn special_method_raise_facts_match_exception_protocols_and_keep_open_boundaries() {
    let source = "from abc import abstractmethod\n\nclass Protocols:\n    def __getitem__(self, key):\n        raise ValueError()\n\n    def __delitem__(self, key):\n        raise KeyError()\n\n    def __getattr__(self, name):\n        raise TypeError()\n\n    def __lt__(self, other):\n        raise ValueError('order')\n\n    @abstractmethod\n    def __add__(self, other):\n        raise ValueError('abstract')\n\n    def __int__(self):\n        raise ValueError('cast')\n\n    def __hash__(self):\n        raise ValueError('hash')\n\n    def __bool__(self):\n        raise NotImplementedError()\n\nclass Handled:\n    def __getitem__(self, key):\n        try:\n            raise ValueError('handled')\n        except ValueError:\n            raise KeyError()\n";
    let result = execute_python_query(source, "python-special-method-raise");
    let facts = python_rule_facts(&result);
    let by_expression = facts
        .iter()
        .map(|fact| {
            (
                fact.raised_expression.as_deref().unwrap_or("<bare>"),
                fact.outcome,
                fact.completeness,
                fact.expected_exception.as_deref(),
                fact.reason.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    for expected in [
        (
            "ValueError()",
            "unexpected",
            "complete",
            Some("LookupError or TypeError"),
        ),
        (
            "KeyError()",
            "allowed",
            "complete",
            Some("LookupError or TypeError"),
        ),
        (
            "TypeError()",
            "allowed",
            "complete",
            Some("AttributeError or TypeError"),
        ),
        (
            "ValueError('order')",
            "unexpected",
            "complete",
            Some("TypeError"),
        ),
        (
            "ValueError('abstract')",
            "excluded",
            "complete",
            Some("ArithmeticError or TypeError"),
        ),
        (
            "ValueError('cast')",
            "unexpected",
            "complete",
            Some("no implementation required unless overriding inherited behavior"),
        ),
        (
            "ValueError('hash')",
            "unexpected",
            "complete",
            Some("__hash__ = None"),
        ),
        (
            "NotImplementedError()",
            "allowed",
            "complete",
            Some("TypeError"),
        ),
        (
            "ValueError('handled')",
            "open",
            "partial",
            Some("LookupError or TypeError"),
        ),
    ] {
        assert!(
            by_expression
                .iter()
                .any(|found| (found.0, found.1, found.2, found.3) == expected),
            "missing {expected:?}: {by_expression:?}"
        );
    }
    // Multiple raises in one special method share CodeQL's method finding anchor.
    assert_eq!(facts.len(), 9, "{result:#?}");
}
