#[cfg(test)]
#[doc(hidden)]
pub mod go_extraction_support_1 {

    use brokk_bifrost_jvm_analysis::analyzer::java::JavaAnalyzer;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeCatalog;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeSelectedFragment;

    use brokk_bifrost_analysis::analyzer::resolution::batch::MAX_REFERENCE_SEEDS_PER_BATCH;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactReferenceBatchAnswer;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredResolutionFragment;

    use brokk_bifrost_analysis::analyzer::resolution::typed_fact_lowering::LoweredTypedFragment;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PreloadedFactResolutionService;

    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};

    use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

    use brokk_bifrost_core::analyzer::Language;

    #[doc(hidden)]
    pub const PROJECTOR_SOURCE: &str = "package demo;\n\nclass External {}\n\nclass Owner {\n    int value;\n    void write(External external) {\n        value = 1;\n    }\n}\n";
    #[doc(hidden)]
    pub struct NativeEdgeProjectionFixture {
        #[doc(hidden)]
        pub _project: BuiltInlineTestProject,
        #[doc(hidden)]
        pub analyzer: JavaAnalyzer,
        #[doc(hidden)]
        pub file: ProjectFile,
        #[doc(hidden)]
        pub fragment: BindingFragmentId,
        #[doc(hidden)]
        pub source: &'static str,
        #[doc(hidden)]
        pub facts: FileResolutionFacts,
        #[doc(hidden)]
        pub lexical: LoweredResolutionFragment,
        #[doc(hidden)]
        pub typed: LoweredTypedFragment,
        // Preserve the original fixture service and its initialization work.
        #[allow(dead_code)]
        service: PreloadedFactResolutionService,
        #[doc(hidden)]
        pub batch: FactReferenceBatchAnswer,
    }
    #[doc(hidden)]
    pub fn native_edge_projection_fixture() -> NativeEdgeProjectionFixture {
        native_edge_projection_fixture_for(
            "Projector.java",
            PROJECTOR_SOURCE,
            b"native-edge-projector-laws",
            b"native-edge-projector-laws:demo",
        )
    }
    pub(crate) fn native_edge_projection_fixture_for(
        file_name: &str,
        source: &'static str,
        fragment_seed: &[u8],
        package_seed: &[u8],
    ) -> NativeEdgeProjectionFixture {
        let project = InlineTestProject::with_language(Language::Java)
            .file(file_name, source)
            .build();
        native_edge_projection_fixture_from_project(
            project,
            file_name,
            source,
            fragment_seed,
            package_seed,
        )
    }
    pub(crate) fn native_edge_projection_fixture_from_project(
        project: BuiltInlineTestProject,
        file_name: &str,
        source: &'static str,
        fragment_seed: &[u8],
        _package_seed: &[u8],
    ) -> NativeEdgeProjectionFixture {
        let file = project.file(file_name);
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let facts =
            brokk_bifrost_analysis::native_resolution_test_support::parse_java_resolution_facts(
                &file, source,
            );
        let fragment = BindingFragmentId::for_test(fragment_seed);
        let lexical = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
        .lexical()
        .clone();
        let typed = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
        .typed()
        .clone();
        let service = PreloadedFactResolutionService::from_lowered_fragments(
            [lexical.clone()],
            [typed.clone()],
        );
        let mut batches = Vec::new();
        let summary = service
            .stage_all_reference_batches(
                MAX_REFERENCE_SEEDS_PER_BATCH,
                &CancellationToken::new(),
                &mut |batch| {
                    batches.push(batch.clone());
                    Ok(())
                },
            )
            .expect("the inline native edge fixture must stage");
        assert_eq!(
            summary.reference_enumeration_completion(),
            &ResolutionCompletion::Complete
        );
        assert_eq!(batches.len(), 1, "one file must produce one retained batch");
        let batch = batches.pop().expect("one retained batch was asserted");
        assert_eq!(batch.fragment(), fragment);

        NativeEdgeProjectionFixture {
            _project: project,
            analyzer,
            file,
            fragment,
            source,
            facts,
            lexical,
            typed,
            service,
            batch,
        }
    }
    #[doc(hidden)]
    pub fn native_edge_catalog(
        fixture: &NativeEdgeProjectionFixture,
    ) -> FactReferenceEdgeCatalog<'_> {
        FactReferenceEdgeCatalog::from_selected_fragments(
            &fixture.analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                fixture.file.clone(),
                fixture.source,
                &fixture.facts,
                &fixture.lexical,
                &fixture.typed,
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
            )],
            &CancellationToken::new(),
        )
        .expect("the native edge catalog must match the inline analyzer snapshot")
        .expect("uncancelled native edge catalog construction must publish atomically")
    }
}
