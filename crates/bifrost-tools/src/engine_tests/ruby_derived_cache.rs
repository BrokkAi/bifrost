#[cfg(test)]
mod ruby_extraction_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::build_direct_import_topology;

    use brokk_bifrost_core::path_utils::rel_path_string;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_ruby_analysis::RubyAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;
    use std::path::PathBuf;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::test_support::completed_topology;

    use brokk_bifrost_analysis::analyzer::structural::derived_cache::test_support::generous_limits;

    #[test]
    fn topology_deduplicates_cycle_edges_and_orders_neighbors() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let a = ProjectFile::new(root.clone(), PathBuf::from("a.rb"));
        let b = ProjectFile::new(root.clone(), PathBuf::from("b.rb"));
        let c = ProjectFile::new(root.clone(), PathBuf::from("c.rb"));
        a.write(
            "require_relative 'c'\nrequire_relative 'b'\nrequire_relative 'b'\ndef from_a; end\n",
        )
        .expect("write a");
        b.write("require_relative 'a'\ndef from_b; end\n")
            .expect("write b");
        c.write("def from_c; end\n").expect("write c");
        let analyzer = RubyAnalyzer::from_project(TestProject::new(root, Language::Ruby));

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let first = completed_topology(build_direct_import_topology(
            &analyzer,
            token,
            &CancellationToken::default(),
            generous_limits(),
        ));
        let second = completed_topology(build_direct_import_topology(
            &analyzer,
            token,
            &CancellationToken::default(),
            generous_limits(),
        ));

        assert_eq!(first.resolved_files(), 3);
        assert_eq!(first.resolved_edges(), 3);
        assert_eq!(
            first
                .imports_of(&a)
                .expect("supported source")
                .iter()
                .map(rel_path_string)
                .collect::<Vec<_>>(),
            vec!["b.rb", "c.rb"]
        );
        assert_eq!(
            first
                .importers_of(&a)
                .expect("complete reverse relation")
                .iter()
                .map(rel_path_string)
                .collect::<Vec<_>>(),
            vec!["b.rb"]
        );
        for file in [&a, &b, &c] {
            assert_eq!(first.imports_of(file), second.imports_of(file));
            assert_eq!(first.importers_of(file), second.importers_of(file));
        }
        assert_eq!(first.retained_bytes(), second.retained_bytes());
    }
}
