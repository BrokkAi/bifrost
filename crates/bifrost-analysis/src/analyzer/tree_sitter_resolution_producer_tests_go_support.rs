#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod go_extraction_support_0 {

    use crate::analyzer::store::resolution_selection::SelectedResolutionLanguage;
    use crate::analyzer::tree_sitter_analyzer::*;

    use crate::inline_project::InlineTestProject;

    use git2::{ObjectType, Oid};

    use std::sync::Arc;

    #[doc(hidden)]
    pub fn assert_native_overlay_publication<A: LanguageAdapter>(
        adapter: A,
        path: &str,
        disk_source: &str,
        overlay_source: &str,
        reference_name: &str,
        target_name: &str,
    ) {
        use crate::analyzer::resolution::{
            LoweredSemanticRole, ResolutionCompletion, SelectedSemanticLocator,
        };
        use crate::analyzer::store::resolution_operation::{
            SelectedResolutionContextMetrics, SelectedResolutionLocated,
            SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
            SelectedResolutionOperationOutcome,
        };
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
        let language = adapter.language();
        let storage = language.config_label();
        let fixture = InlineTestProject::with_language(language)
            .file(path, disk_source)
            .build();
        let disk = TreeSitterAnalyzer::new(fixture.project_dyn(), adapter);
        let file = fixture.file(path);
        let overlay = Arc::new(crate::OverlayProject::new(fixture.project_dyn()));
        assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
        let mut analyzer = disk.clone_with_project(Arc::new(overlay.snapshot()));
        let parsed = analyzer
            .fetch_file_state(&file)
            .expect("live parsed content");
        let facts = parsed.resolution_facts.clone();
        let name = facts
            .names
            .iter()
            .find(|name| name.spelling == reference_name)
            .unwrap()
            .id;
        let site = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.name == name && identifier.role == ResolutionIdentifierRole::Reference
            })
            .unwrap()
            .site;
        // Exercise publication after eviction, not just the in-memory producer.
        analyzer.source_snapshot_file_states = Arc::new(map_with_capacity(0));
        analyzer.query_file_state_snapshot.store(None);
        analyzer.transient_file_states.lock().unwrap().clear();
        analyzer
            .query_read_cache_lock()
            .file_states
            .write()
            .unwrap()
            .clear();
        let hydrated = analyzer
            .fetch_file_state(&file)
            .expect("hydrated display rows");
        assert!(!hydrated.declarations.is_empty());
        assert!(hydrated.source_facts.is_none());
        let snapshots = analyzer.selected_workspace_snapshots();
        let cancellation = CancellationToken::new();
        let SelectedResolutionOverlayInputsOutcome::Ready {
            masks,
            content_mounts,
        } = analyzer
            .selected_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
            .unwrap()
        else {
            panic!("hydrated {language:?} overlay publication must be ready");
        };
        assert_eq!(masks.len(), 1);
        assert_eq!(content_mounts.len(), 1);
        assert_eq!(content_mounts[0].persisted_relative_path(), path);
        assert_eq!(content_mounts[0].publication().owner(), &snapshots[storage]);
        assert_eq!(
            content_mounts[0].publication().blob_oid(),
            Oid::hash_object(ObjectType::Blob, overlay_source.as_bytes()).unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(file.abs_path()).unwrap(),
            disk_source
        );
        let languages = [SelectedResolutionLanguage::new(storage, language)];
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts);
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("published {language:?} overlay operation must be ready");
        };
        let context = operation
            .empty_contexts(&ResolutionCompletion::Complete)
            .unwrap();
        let result = operation
            .resolve_reference(
                context,
                &SelectedSemanticLocator::new(storage, path, site, LoweredSemanticRole::Reference),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            result
        else {
            panic!("overlay reference must remain natively located");
        };
        assert_eq!(answer.binding().targets().len(), 1, "{answer:?}");
        let target_sites = facts
            .identifiers
            .iter()
            .filter(|identifier| {
                identifier.role == ResolutionIdentifierRole::Declaration
                    && facts.names[identifier.name.index()].spelling == target_name
            })
            .map(|identifier| identifier.site.get())
            .collect::<Vec<_>>();
        assert!(
            answer.binding().targets().iter().all(|target| {
                target
                    .local_key()
                    .is_some_and(|key| target_sites.contains(&key))
            }),
            "expected {target_name} at {target_sites:?}, got {answer:?}"
        );
        cancellation.cancel();
        assert!(matches!(
            analyzer
                .selected_resolution_overlay_inputs(snapshots.as_ref(), &cancellation)
                .unwrap(),
            SelectedResolutionOverlayInputsOutcome::Cancelled
        ));
    }
    #[doc(hidden)]
    pub fn assert_native_unit_projection<A: LanguageAdapter>(
        fixture: &crate::inline_project::BuiltInlineTestProject,
        adapter: A,
        path: &str,
        source: &str,
        after_open: impl FnOnce(),
    ) {
        use crate::analyzer::resolution::{
            LoweredSemanticRole, ResolutionCompletion, SelectedSemanticLocator,
        };
        use crate::analyzer::store::resolution_operation::{
            SelectedNativeDefinition, SelectedNativeDefinitions, SelectedResolutionContextMetrics,
            SelectedResolutionLocated, SelectedResolutionOperationInput,
            SelectedResolutionOperationOpenOutcome, SelectedResolutionOperationOutcome,
        };
        use crate::analyzer::usages::get_definition::BoundedResolution;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;

        let file = fixture.file(path);
        let language = adapter.language();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&adapter.parser_language_for_file(&file))
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let parsed = adapter.parse_file(&file, source, &tree);
        let expected = parsed
            .declarations()
            .iter()
            .find(|unit| unit.terminal_name() == "target")
            .unwrap()
            .clone();
        let facts = &parsed.resolution_facts;
        let name = facts
            .names
            .iter()
            .find(|name| name.spelling == "target")
            .unwrap()
            .id;
        let site = facts
            .identifiers
            .iter()
            .find(|identifier| {
                identifier.name == name && identifier.role == ResolutionIdentifierRole::Reference
            })
            .unwrap()
            .site;
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), adapter);
        let snapshots = analyzer.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new(
            language.config_label(),
            language,
        )];
        let cancellation = CancellationToken::new();
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("ordinary native operation must open");
        };
        let context = operation
            .empty_contexts(&ResolutionCompletion::Complete)
            .unwrap();
        after_open();
        let result = operation
            .resolve_native_reference_units_bounded(
                context,
                &SelectedSemanticLocator::new(
                    language.config_label(),
                    path,
                    site,
                    LoweredSemanticRole::Reference,
                ),
                ReceiverAnalysisBudget::default(),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let BoundedResolution::Complete {
            value: result,
            work,
        } = result
        else {
            panic!("ordinary native projection must fit the default budget");
        };
        assert!(work.scope_nodes > 0);
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            result
        else {
            panic!("native reference and projection must publish together");
        };
        assert_eq!(answer.answer.binding().targets().len(), 1);
        let SelectedNativeDefinitions::Ready(units) = answer.definitions else {
            panic!("ordinary declaration must project to its parser unit");
        };
        assert_eq!(
            units,
            vec![(
                answer.answer.binding().targets()[0],
                SelectedNativeDefinition::Unit(expected)
            )]
        );
        for (budget, cancelled) in [
            (ReceiverAnalysisBudget::tiny(), false),
            (ReceiverAnalysisBudget::default(), true),
        ] {
            let token = CancellationToken::new();
            let input = SelectedResolutionOperationInput::new(
                analyzer.project(),
                analyzer.workspace_id(),
                snapshots.as_ref(),
                &languages,
                &[],
            );
            let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
                .analyzer_store()
                .open_selected_resolution_operation(input, &token)
                .unwrap()
            else {
                panic!("retry must open before stopping");
            };
            let context = operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            if cancelled {
                token.cancel();
            }
            let stopped = operation
                .resolve_native_reference_units_bounded(
                    context,
                    &SelectedSemanticLocator::new(
                        language.config_label(),
                        path,
                        site,
                        LoweredSemanticRole::Reference,
                    ),
                    budget,
                    &token,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap();
            if cancelled {
                assert!(matches!(stopped, BoundedResolution::Cancelled { .. }));
            } else {
                assert!(matches!(stopped, BoundedResolution::Exceeded { .. }));
            }
        }
    }
    #[doc(hidden)]
    pub fn native_type_projection<A: LanguageAdapter>(
        fixture: &crate::inline_project::BuiltInlineTestProject,
        adapter: A,
        path: &str,
        source: &str,
    ) -> crate::analyzer::store::resolution_operation::SelectedNativeReferenceTypes {
        use crate::analyzer::resolution::{ResolutionCompletion, SelectedSemanticLocator};
        use crate::analyzer::store::resolution_operation::{
            SelectedResolutionContextMetrics, SelectedResolutionLocated,
            SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
            SelectedResolutionOperationOutcome,
        };
        use crate::analyzer::usages::get_definition::BoundedResolution;
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
        let language = adapter.language();
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), adapter);
        let snapshots = analyzer.selected_workspace_snapshots();
        let languages = [SelectedResolutionLanguage::new(
            language.config_label(),
            language,
        )];
        let cancellation = CancellationToken::new();
        let input = SelectedResolutionOperationInput::new(
            analyzer.project(),
            analyzer.workspace_id(),
            snapshots.as_ref(),
            &languages,
            &[],
        );
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = analyzer
            .analyzer_store()
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("selected type fixture must open")
        };
        let context = operation
            .empty_contexts(&ResolutionCompletion::Complete)
            .unwrap();
        let start = source.rfind("target").expect("fixture reference");
        let result = operation
            .resolve_native_type_site_bounded(
                context,
                &SelectedSemanticLocator::for_reference_range(
                    language.config_label(),
                    path,
                    start,
                    start + "target".len(),
                ),
                ReceiverAnalysisBudget::default(),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let BoundedResolution::Complete {
            value:
                SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)),
            work,
        } = result
        else {
            panic!("selected type projection must finish")
        };
        assert!(work.scope_nodes > 0);
        answer
    }
}
