//! Analyzer-side regression coverage for the C++ inverse type scan.

#[cfg(test)]
mod effective_using_scale_tests {

    use crate::analyzer::usages::cpp_graph::CppDispatch;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use crate::analyzer::CppAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
    use brokk_bifrost_core::analyzer::CodeUnitIndex;
    use brokk_bifrost_core::hash::HashSet;
    use brokk_bifrost_cpp::graph::extractor::*;
    use brokk_bifrost_cpp::graph::resolver::*;
    use brokk_bifrost_test_macros::hardwon;
    use std::sync::Arc;

    #[test]
    #[hardwon(
        "#1496: unrelated C++ qualified types made inverse target resolution take 56 seconds"
    )]
    fn type_scan_prunes_unrelated_qualified_types_before_target_resolution() {
        const UNRELATED_TYPES: usize = 128;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        ProjectFile::new(root.clone(), "target.h")
            .write(
                "namespace target { struct Wanted {}; }\nusing WantedAlias = target::Wanted;\nstruct TargetHolder { using type = target::Wanted; };\n",
            )
            .expect("write target header");
        let consumer = ProjectFile::new(root.clone(), "consumer.cpp");
        let mut source = String::from(
            "#include \"target.h\"\ntarget::Wanted direct_use;\nWantedAlias alias_use;\nTargetHolder::type nested_alias_use;\nnamespace noise {\n",
        );
        for index in 0..UNRELATED_TYPES {
            source.push_str(&format!(
                "template<typename T> struct Type{index} {{ using type = T; }};\n"
            ));
        }
        source.push_str("}\n");
        for index in 0..UNRELATED_TYPES {
            source.push_str(&format!(
                "typename noise::Type{index}<int>::type value_{index};\n"
            ));
        }
        consumer.write(&source).expect("write consumer");

        let project = Arc::new(TestProject::new(&root, Language::Cpp));
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("ephemeral workspace should build");
        let analyzer = workspace.analyzer();
        let cpp = resolve_analyzer::<CppAnalyzer>(analyzer).expect("C++ analyzer");
        let query_scope = AnalyzerQueryScope::new(analyzer);
        let query_token = query_scope.token();
        let dispatch = CppDispatch::new(analyzer, query_token);
        let graph = dispatch.source();
        let roots = HashSet::from_iter([consumer.clone()]);
        let visibility = VisibilityIndex::build(cpp, query_token, &graph, &roots);
        let target = cpp
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_class() && unit.fq_name() == "target.Wanted")
            .expect("target declaration");
        let spec = TargetSpec::from_target(&graph, &target).expect("type target spec");
        let prepared = cpp
            .prepared_syntax(query_token, &consumer)
            .expect("prepared consumer");
        let target_group = HashSet::from_iter([target]);
        let mut hits = std::collections::BTreeSet::new();
        let mut unproven_hits = std::collections::BTreeSet::new();
        let mut raw_match_count = 0;
        let mut limit_exceeded = false;
        let mut state = ScanState {
            max_usages: usize::MAX,
            hits: &mut hits,
            unproven_hits: &mut unproven_hits,
            raw_match_count: &mut raw_match_count,
            limit_exceeded: &mut limit_exceeded,
        };

        reset_type_reference_candidate_scan_count_for_test();
        scan_prepared_file(
            &graph,
            &visibility,
            &consumer,
            &prepared,
            &[],
            None,
            &spec,
            &target_group,
            &mut state,
        );

        let hit_text = hits
            .iter()
            .map(|hit| &source[hit.start_offset..hit.end_offset])
            .collect::<Vec<_>>();
        assert!(
            hit_text.contains(&"target::Wanted"),
            "direct target reference must survive: {hit_text:?}"
        );
        assert!(
            hit_text.iter().any(|text| text.contains("WantedAlias")),
            "alias-preserving target reference must survive: {hit_text:?}"
        );
        let nested_alias_start = source
            .find("TargetHolder::type nested_alias_use")
            .expect("qualified nested alias use");
        assert!(
            hits.iter().any(|hit| {
                hit.start_offset == nested_alias_start
                    && hit.end_offset == nested_alias_start + "TargetHolder::type".len()
            }),
            "an ordinary qualified alias reference must retain its complete type range: {hit_text:?}"
        );
        let scanned = type_reference_candidate_scan_count_for_test();
        assert!(
            scanned < UNRELATED_TYPES / 4,
            "unrelated structured qualified types must be rejected before target-specific resolution; scanned {scanned}"
        );
    }
}
