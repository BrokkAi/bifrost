#[cfg(test)]
mod ruby_extraction_tests {
    use brokk_bifrost_analysis::analyzer::usages::traits::GraphUsageAnalyzer;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_ruby_analysis::analyzer::usages::ruby_graph::RubyUsageGraphStrategy;

    use brokk_bifrost_python_analysis::analyzer::python::PythonAnalyzer;

    use brokk_bifrost_core::analyzer::model::CodeUnitType;
    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_core::analyzer::usages::scan_scope::UsageScanScope;

    use std::path::PathBuf;

    use brokk_bifrost_ruby_analysis::analyzer::usages::ruby_graph::test_support::declaration;

    use brokk_bifrost_ruby_analysis::analyzer::usages::ruby_graph::test_support::fallback_diagnostic;

    use brokk_bifrost_ruby_analysis::analyzer::usages::ruby_graph::test_support::ruby_analyzer;

    use brokk_bifrost_ruby_analysis::analyzer::usages::ruby_graph::test_support::zeitwerk_project;
    #[test]
    fn the_three_ruby_gates_keep_their_exact_diagnostics() {
        let (_temp, root) = zeitwerk_project();
        let analyzer = ruby_analyzer(&root);
        let candidates = HashSet::default();
        let scope = UsageScanScope::new(&candidates);
        let strategy = RubyUsageGraphStrategy::new();

        let python_target = CodeUnit::new(
            ProjectFile::new(root.clone(), PathBuf::from("app/models/user.py")),
            CodeUnitType::Function,
            "app.models.user",
            "build",
        );
        let language_gate = fallback_diagnostic(strategy.find_graph_usages(
            &analyzer,
            &[python_target],
            &scope,
            100,
        ));
        assert_eq!(language_gate.strategy, "RubyUsageGraphStrategy");
        assert_eq!(language_gate.reason_kind, "unsupported_target_language");
        assert_eq!(
            language_gate.reason,
            "RubyUsageGraphStrategy: target is not Ruby"
        );

        let user_file = ProjectFile::new(root.clone(), PathBuf::from("app/models/user.rb"));
        let target = declaration(&analyzer, &user_file, "build");
        let not_ruby_analyzer =
            PythonAnalyzer::from_project(TestProject::new(root.clone(), Language::Python));
        let capability_gate = fallback_diagnostic(strategy.find_graph_usages(
            &not_ruby_analyzer,
            std::slice::from_ref(&target),
            &scope,
            100,
        ));
        assert_eq!(capability_gate.strategy, "RubyUsageGraphStrategy");
        assert_eq!(capability_gate.reason_kind, "missing_analyzer_capability");
        assert_eq!(
            capability_gate.reason,
            "RubyUsageGraphStrategy: Ruby analyzer is unavailable"
        );

        let macro_target = CodeUnit::new(user_file, CodeUnitType::Macro, "", "User.build");
        let shape_gate = fallback_diagnostic(strategy.find_graph_usages(
            &analyzer,
            &[macro_target],
            &scope,
            100,
        ));
        assert_eq!(shape_gate.strategy, "RubyUsageGraphStrategy");
        assert_eq!(shape_gate.reason_kind, "unsupported_target_shape");
        assert_eq!(
            shape_gate.reason,
            "RubyUsageGraphStrategy: target shape is unsupported"
        );
    }
}
