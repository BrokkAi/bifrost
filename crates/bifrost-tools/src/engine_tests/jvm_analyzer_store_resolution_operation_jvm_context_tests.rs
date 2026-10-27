#[cfg(test)]
mod jvm_extraction_tests {

    use brokk_bifrost_core::analyzer::Language;

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "0242909d77ed: Java census G03 (2026-10-15): mismatched package paths retain targets without proving cross-file source access"
    )]
    fn java_cross_file_source_access_requires_package_aligned_paths() {
        use brokk_bifrost_jvm_analysis::analyzer::java::JavaAnalyzer;

        use brokk_bifrost_jvm_analysis::analyzer::java::native_points::resolve_java_definition_bounded;

        use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;

        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;

        use brokk_bifrost_analysis::test_support::token_range;

        let source = "package fixture; class Caller { Target target; }";
        for (caller_path, target_path, expected_status) in [
            (
                "src/Caller.java",
                "src/Target.java",
                DefinitionLookupStatus::Incomplete,
            ),
            (
                "src/fixture/Caller.java",
                "src/fixture/Target.java",
                DefinitionLookupStatus::Resolved,
            ),
        ] {
            let fixture = InlineTestProject::with_language(Language::Java)
                .file(caller_path, source)
                .file(target_path, "package fixture; public class Target {}")
                .build();
            let analyzer = JavaAnalyzer::new(fixture.project_dyn());
            let file = fixture.file(caller_path);
            let (start_byte, end_byte) = token_range(source, "Target target", "Target");
            let site = ResolvedReferenceSite {
                path: caller_path.into(),
                text: "Target".into(),
                focus_start_byte: start_byte,
                focus_end_byte: end_byte,
                range: brokk_bifrost_core::analyzer::model::Range {
                    start_byte,
                    end_byte,
                    start_line: 0,
                    end_line: 0,
                },
            };
            let result = resolve_java_definition_bounded(
                BoundedReceiverQuery {
                    analyzer: &analyzer,
                    file: &file,
                    source,
                    tree: None,
                    site: &site,
                    budget: Default::default(),
                    cancellation: None,
                },
                || {},
            );
            let BoundedResolution::Complete { value, .. } = result else {
                panic!("{caller_path}: {result:?}");
            };
            assert_eq!(value.status, expected_status, "{caller_path}: {value:?}");
            let [target] = value.definitions.as_slice() else {
                panic!("{caller_path}: retained target missing: {value:?}");
            };
            assert_eq!(target.source(), &fixture.file(target_path));
            assert_eq!(target.fq_name(), "fixture.Target");
            if expected_status == DefinitionLookupStatus::Incomplete {
                assert!(
                    value
                        .diagnostics
                        .iter()
                        .any(|reason| reason.kind == "java-source-access-open"),
                    "{value:?}"
                );
            } else {
                assert!(value.diagnostics.is_empty(), "{value:?}");
            }
        }
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#6757: public definition diagnostics embedded allocation-order identities"
)]
fn public_definition_diagnostics_are_identical_across_worker_counts() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    // String's member inventory retains an applicability obligation with
    // shared operands when this argument has no known type.
    let source = "class Use { void use(String value) { value.substring(unknown); } }";
    let original = std::env::var_os("BIFROST_PARALLELISM");
    let mut captures = Vec::new();
    for workers in [1, 4] {
        // nextest runs this test in its own process. Set the value before
        // constructing any analyzer, and drop all workers before changing it.
        unsafe { std::env::set_var("BIFROST_PARALLELISM", workers.to_string()) };
        let fixture = InlineTestProject::with_language(Language::Java)
            .file("Use.java", source)
            .file("Other.java", "class Other { Missing first; }")
            .file("Third.java", "class Third { Absent second; }")
            .build();
        let config = AnalyzerConfig::default();
        assert_eq!(config.parallelism(), workers);
        let workspace = fixture.workspace_analyzer(config);
        use brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery;
        use brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite;
        use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
        let start = source.find("substring").unwrap();
        let site = ResolvedReferenceSite {
            path: "Use.java".to_owned(),
            text: "substring".to_owned(),
            focus_start_byte: start,
            focus_end_byte: start + "substring".len(),
            range: brokk_bifrost_core::analyzer::model::Range {
                start_byte: start,
                end_byte: start + "substring".len(),
                start_line: 0,
                end_line: 0,
            },
        };
        let file = fixture.file("Use.java");
        let result = brokk_bifrost_jvm_analysis::analyzer::java::native_points::resolve_java_definition_bounded(
            BoundedReceiverQuery { analyzer: workspace.analyzer(), file: &file, source, tree: None,
                site: &site, budget: Default::default(), cancellation: None }, || {},
        );
        let BoundedResolution::Complete { value, .. } = result else {
            panic!("{result:?}")
        };
        let response = serde_json::json!({"status": format!("{:?}", value.status),
            "diagnostics": value.diagnostics.iter().map(|diagnostic| serde_json::json!({
                "kind": diagnostic.kind, "message": diagnostic.message,
            })).collect::<Vec<_>>()});
        let diagnostics = &response["diagnostics"];
        assert!(
            diagnostics
                .as_array()
                .is_some_and(|values| !values.is_empty()),
            "{response:#}"
        );
        let rendered = serde_json::to_string(diagnostics).unwrap();
        assert!(
            rendered.contains("operands"),
            "fixture must exercise operand evidence: {response:#}"
        );
        assert!(!rendered.contains("SemanticId"), "{response:#}");
        assert!(
            rendered.contains("shared:"),
            "fixture must project shared operands: {response:#}"
        );
        // Operand identity fields must be stable strings, never numeric aliases.
        let mut operand_count = 0;
        for diagnostic in diagnostics.as_array().unwrap() {
            let message = diagnostic["message"].as_str().unwrap();
            if let Ok(evidence) = serde_json::from_str::<serde_json::Value>(message)
                && let Some(semantic) = evidence["semantic"].as_str()
                && let Ok(details) = serde_json::from_str::<serde_json::Value>(semantic)
                && let Some(operands) = details["operands"].as_array()
            {
                operand_count += operands.len();
                assert!(
                    operands
                        .iter()
                        .all(|operand| operand["identity"].is_string()),
                    "{details:#}"
                );
            }
        }
        assert!(
            operand_count > 0,
            "fixture must render identity operands: {response:#}"
        );
        captures.push(rendered);
    }
    match original {
        Some(value) => unsafe { std::env::set_var("BIFROST_PARALLELISM", value) },
        None => unsafe { std::env::remove_var("BIFROST_PARALLELISM") },
    }
    assert_eq!(captures[0], captures[1]);
}
