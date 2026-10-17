use super::*;

fn python_pythagorean_query() -> CodeQuery {
    CodeQuery::from_source(
        r#"(filter :where ((resolved_external_callee eq "math.sqrt"))
          (exact-external-callee
            (call-shape
            (union
            (language python
            (call :callee (identifier) :arity 1
              :args ((binary_expression
                :operator (text/regex "^\\+$")
                :left (binary_expression
                  :operator (text/regex "^\\*\\*$")
                  :left (identifier)
                  :right (numeric_literal :integer-value "2"))
                :right (binary_expression
                  :operator (text/regex "^\\*\\*$")
                  :left (identifier)
                  :right (numeric_literal :integer-value "2"))))))
            (language python
            (call :callee (identifier) :arity 1
              :args ((binary_expression
                :operator (text/regex "^\\+$")
                :left (binary_expression
                  :operator (text/regex "^\\*$")
                  :left (identifier :capture "left_component")
                  :right (identifier :capture "left_component"))
                :right (binary_expression
                  :operator (text/regex "^\\*$")
                  :left (identifier :capture "right_component")
                  :right (identifier :capture "right_component"))))))))))"#,
    )
    .expect("Pythagorean structural query")
}

#[test]
fn python_pythagorean_selects_sums_of_literal_squares_and_same_name_products() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            concat!(
                "import math\n",
                "import math as m\n",
                "from math import sqrt as root\n",
                "math.sqrt(a**2 + b**2)\n",
                "m.sqrt(c*c + d*d)\n",
                "root(e**2 + f**2)\n",
                "math.sqrt(g + h)\n",
                "math = object()\n",
                "math.sqrt(i**2 + j**2)\n",
                "other.sqrt(i**2 + j**2)\n",
                "sqrt(k**2 + l**2)\n",
            ),
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());

    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &python_pythagorean_query(),
    );
    let mut matching_lines = result
        .results
        .iter()
        .map(|item| {
            let CodeQueryResultValue::CallShape { value } = &item.value else {
                panic!("Pythagorean query returns call-shape rows");
            };
            assert_eq!(
                value.resolved_external_callee.as_deref(),
                Some("math.sqrt"),
                "only the import resolver's exact math.sqrt identity survives"
            );
            value.range.start_line
        })
        .collect::<Vec<_>>();
    matching_lines.sort_unstable();
    matching_lines.dedup();
    assert_eq!(matching_lines, [4, 5, 6], "{}", result.render_text());
    assert_eq!(result.completion(), CodeQueryCompletion::Complete);
}

#[test]
fn python_pythagorean_query_follows_single_assignment_local_values() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "main.py",
            concat!(
                "import math\n",
                "def hypotenuse(a, b):\n",
                "    a2 = a ** 2\n",
                "    b2 = b * b\n",
                "    return math.sqrt(a2 + b2)\n",
            ),
        )
        .build();
    let workspace = project.workspace_analyzer(AnalyzerConfig::default());
    let query = CodeQuery::from_source(
        r#"(filter :where ((resolved_external_callee eq "math.sqrt"))
          (exact-external-callee
            (call-shape
              (language python
                (call :callee (identifier) :arity 1
                  :args ((binary_expression :operator (text/regex "^\\+$")
                    :left (identifier :local-value
                      (binary_expression :operator (text/regex "^\\*\\*$")
                        :left (identifier)
                        :right (numeric_literal :integer-value "2")))
                    :right (identifier :local-value
                      (binary_expression :operator (text/regex "^\\*$")
                        :left (identifier :capture "component")
                        :right (identifier :capture "component"))))))))))"#,
    )
    .expect("local-value Pythagorean query");
    let result = execute_workspace(
        &workspace,
        &brokk_bifrost_flow::FlowWorkspaceState::new(),
        &query,
    );
    assert_eq!(result.completion(), CodeQueryCompletion::Complete);
    assert_eq!(result.results.len(), 1, "{}", result.render_text());
    let CodeQueryResultValue::CallShape { value } = &result.results[0].value else {
        panic!("Pythagorean query returns a call-shape row");
    };
    assert_eq!(value.range.start_line, 5);
}
