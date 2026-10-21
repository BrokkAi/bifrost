#[cfg(test)]
mod python_extraction_tests {
    use brokk_bifrost_analysis::analyzer::CodeUnitIndex;

    use std::sync::Arc;

    use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::CallApplicationKind;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallArgument;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallBindingCache;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallBindingStatus;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallSite;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::call_sites::CallSyntaxKind;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::ExactCallLocation;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::bind_call_site_arguments;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::call_span;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::test_support::generous_limits;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_python_analysis::analyzer::PythonAnalyzer;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    #[test]
    fn exact_dispatch_retains_python_imported_callable_proof() {
        let source = "import subprocess\ndef caller(command):\n    return subprocess.run(command, shell=True)\n";
        let fixture =
            AnalyzerFixture::new_for_language(Language::Python, &[("external.py", source)]);
        let lookup = CallRelationService::dispatch_at_bounded(
            fixture.analyzer.analyzer(),
            AnalyzerQueryScope::new(fixture.analyzer.analyzer()).token(),
            &ExactCallLocation {
                file: ProjectFile::new(fixture.project_root(), "external.py"),
                call_span: call_span(source, "subprocess.run(command, shell=True)"),
            },
            Arc::from(source),
            generous_limits(),
            None,
        );

        assert_eq!(
            lookup.status,
            Some(DefinitionLookupStatus::UnresolvableImportBoundary),
            "{lookup:#?}"
        );
        assert_eq!(lookup.boundary, Some(BoundaryStatus::ExternalIndexed));
        assert_eq!(
            lookup.boundaries,
            vec![CallDispatchBoundaryKind::External {
                callee_text: Some("subprocess.run".into()),
                normalized_static_owner: None,
                external_callee_identity: None,
            }]
        );
        let proof = lookup
            .exact_external_call
            .as_ref()
            .expect("Python import proof");
        assert_eq!(proof.canonical_callee(), "subprocess.run");
        assert_eq!(
            proof.call_application(),
            CallApplicationKind::PackageFunction
        );
        assert_eq!(proof.parameter_count(), 2);
    }
    #[test]
    fn unresolved_python_receiver_does_not_claim_a_complete_formal_binding() {
        let source = "class Service:\n    def run(self, payload):\n        pass\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let service_file = ProjectFile::new(root.clone(), "service.py");
        service_file.write(source).expect("write source");
        let analyzer =
            PythonAnalyzer::from_project(TestProject::new(root.clone(), Language::Python));
        let callee = analyzer
            .search_definitions("run", false)
            .into_iter()
            .find(CodeUnit::is_callable)
            .expect("instance method");
        let call_file = ProjectFile::new(root, "missing_caller.py");
        let caller = CodeUnit::new(call_file.clone(), CodeUnitType::Function, "", "caller");
        let range = Range {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
        };
        let mut site = CallSite {
            file: call_file,
            range,
            callee_range: range,
            caller,
            callee,
            kind: CallSyntaxKind::Method,
            proof: UsageProof::Proven,
            receiver: Some(range),
            arguments: vec![CallArgument {
                range,
                name: None,
                position: Some(0),
                formal_index: None,
                formal_name: None,
                variadic: false,
                spread: false,
            }],
        };

        let status =
            bind_call_site_arguments(&analyzer, &mut site, &mut CallBindingCache::default());

        assert_eq!(status, CallBindingStatus::Unavailable);
        assert_eq!(site.arguments[0].formal_index, None);
    }
}

#[cfg(test)]
mod python_residency_tests {

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationDiagnosticCode;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationLimits;

    use brokk_bifrost_analysis::analyzer::usages::call_relations::CallRelationService;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_core::analyzer::model::Language;

    #[brokk_bifrost_test_macros::hardwon(
        "#5113: editor's 20-hit projection omitted caller evidence from the semantic survey"
    )]
    #[test]
    fn incoming_explicit_budget_retains_unproven_callers_beyond_editor_projection() {
        use brokk_bifrost_analysis::inline_project::InlineTestProject;
        let mut source = String::from(
            "class Service:\n    def update(self):\n        pass\nclass OtherService:\n    def update(self):\n        pass\n",
        );
        for index in 0..40 {
            source.push_str(&format!(
                "def caller{index}(receiver):\n    receiver.update()\n"
            ));
        }
        let project = InlineTestProject::with_language(Language::Python)
            .file("app.py", &source)
            .build();
        let workspace = project
            .workspace_analyzer(brokk_bifrost_core::analyzer::config::AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let target = analyzer
            .get_definitions("app.Service.update")
            .into_iter()
            .next()
            .unwrap();
        let scope = AnalyzerQueryScope::new(analyzer);
        let limits = CallRelationLimits {
            max_files: usize::MAX,
            max_source_bytes: usize::MAX,
            max_candidates: 4096,
        };
        let editor =
            CallRelationService::incoming_bounded(analyzer, scope.token(), &target, limits, None);
        assert!(
            editor
                .sites
                .iter()
                .all(|site| site.proof == UsageProof::Unproven),
            "{editor:?}"
        );
        assert_eq!(editor.sites.len(), 20);
        assert!(
            editor
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == CallRelationDiagnosticCode::CandidatesOmitted)
        );
        let survey = CallRelationService::incoming_with_unproven_limit(
            analyzer,
            scope.token(),
            &target,
            limits,
            4096,
            None,
        );
        assert_eq!(survey.sites.len(), 40, "{survey:?}");
        assert!(!survey.truncated, "{survey:?}");
        assert!(survey.diagnostics.is_empty(), "{survey:?}");
    }
}
