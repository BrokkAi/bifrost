use super::*;
use brokk_bifrost_test_macros::hardwon;

#[test]
#[hardwon("0630cfd35600: property_name checked the starting value's section at every ancestor")]
fn nested_configuration_scalar_joins_its_enclosing_property_setter() {
    for configuration in [
        r#"{"class":"Foo","property":{"name":"port","value":8080}}"#,
        r#"{"class":"Foo","name":"outer","property":{"name":"port","value":8080}}"#,
    ] {
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "Foo.java",
                "class Foo { public void setPort(int port) {} public void setOuter(int outer) {} }",
            )
            .file("config.json", configuration)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        for (absence, expected) in [(false, 1), (true, 0)] {
            let query = CodeQuery::from_sexp(&format!(
            r#"(correlate
              :relation (configuration-code :match scalar-member :absence {absence})
              :code (where "Foo.java" (enclosing-decl (method)))
              :configuration (where "config.json" (configuration-facts :format json :node-kind scalar :scalar-kind integer)))"#
        )).unwrap();
            let result = execute_workspace(
                &workspace,
                &brokk_bifrost_flow::FlowWorkspaceState::new(),
                &query,
            );
            assert_eq!(result.results.len(), expected, "{}", result.render_text());
            for item in &result.results {
                let CodeQueryResultValue::CrossDomain { value } = &item.value else {
                    panic!("expected a configuration-code join");
                };
                let Some(results::CodeQueryResultRef::Declaration { fq_name, .. }) = &value.code
                else {
                    panic!("expected the joined setter declaration");
                };
                assert_eq!(fq_name, "Foo.setPort", "the nearest property name wins");
            }
        }
    }
}
