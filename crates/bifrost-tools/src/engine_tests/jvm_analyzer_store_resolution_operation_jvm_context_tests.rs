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
