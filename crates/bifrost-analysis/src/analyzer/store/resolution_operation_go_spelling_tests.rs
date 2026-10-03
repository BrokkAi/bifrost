use super::*;

const SPELLING_SOURCE: &str = r#"package consumer
 type Outer struct{ Member int }
 var X Outer
 func beforeAfter() { _ = X.Member; type X struct{}; _ = X.Member }
 func innerValue() { type X struct{}; { var X Outer; _ = X.Member } }
 func invalidValue() { type X int; _ = X }
"#;

#[test]
fn go_spelling_persisted_and_unsaved_content_match_preload() {
    use crate::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;

    for unsaved in [false, true] {
        let baseline = if unsaved {
            "package consumer\nvar X int\nfunc use() { _ = X }\n"
        } else {
            SPELLING_SOURCE
        };
        let fixture = GoRootResolutionOperationFixture::with_consumer(baseline);
        let cancellation = CancellationToken::default();
        let (state, facts) = parsed_operation_source_state(
            fixture._project_root.path(),
            GO_ROOT_CONSUMER_PATH,
            SPELLING_SOURCE,
            &GoAdapter,
        );
        let masks = if unsaved {
            vec![SelectedResolutionOverlayMask::replacement(
                "go",
                GO_ROOT_CONSUMER_PATH,
            )]
        } else {
            Vec::new()
        };
        if unsaved {
            fixture.project.set_overlay_content(
                ProjectFile::new(fixture._project_root.path(), GO_ROOT_CONSUMER_PATH),
                SPELLING_SOURCE,
            );
        }
        let open = || {
            let mut content_mounts = Vec::new();
            if unsaved {
                let snapshot = &fixture.snapshots["go"];
                let oid = Oid::hash_object(ObjectType::Blob, SPELLING_SOURCE.as_bytes()).unwrap();
                let prepared = AnalyzerStore::prepare_parsed_blob(
                    oid,
                    "go",
                    snapshot.generation,
                    &GoAdapter,
                    Arc::clone(&state),
                )
                .unwrap();
                let ResolutionContentPublicationOutcome::Ready(content) = fixture
                    .store
                    .publish_selected_parsed_content(
                        snapshot,
                        GO_ROOT_CONSUMER_PATH,
                        prepared,
                        &cancellation,
                    )
                    .unwrap()
                else {
                    panic!("Go edited publication must be ready")
                };
                content_mounts.push(
                    SelectedResolutionContentMountRequest::new(
                        content.into_parts().0,
                        WorkspaceFileRow {
                            rel_path: GO_ROOT_CONSUMER_PATH.to_owned(),
                            blob_oid: oid,
                        },
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    )
                    .with_live_overlay_content_digest(
                        brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                            SPELLING_SOURCE.as_bytes(),
                        ),
                    ),
                );
            }
            let SelectedResolutionOperationOpenOutcome::Ready(operation) = fixture
                .store
                .open_selected_resolution_operation(
                    SelectedResolutionOperationInput::new(
                        &fixture.project,
                        &fixture.workspace_id,
                        &fixture.snapshots,
                        &fixture.languages,
                        &masks,
                    )
                    .with_content_mounts(content_mounts),
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("Go spelling operation must open")
            };
            *operation
        };
        let operation = open();
        let fragment = operation
            .mounts()
            .unwrap()
            .iter()
            .find(|mount| mount.persisted_relative_path() == GO_ROOT_CONSUMER_PATH)
            .unwrap()
            .fragment();
        drop(operation);
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            fragment,
            crate::analyzer::resolution::test_shared_names(),
            Language::Go,
            &facts,
        );
        let preload = PreloadedFactResolutionService::from_lowered_fragments(
            [lowered.lexical().clone()],
            [lowered.typed().clone()],
        );
        let declarations = facts
            .identifiers
            .iter()
            .filter(|id| {
                facts.names[id.name.index()].spelling == "X"
                    && id.role == ResolutionIdentifierRole::Declaration
            })
            .map(|id| semantic_at(&lowered, id.site, LoweredSemanticRole::Definition))
            .collect::<Vec<_>>();
        let references = facts
            .identifiers
            .iter()
            .filter(|id| {
                facts.names[id.name.index()].spelling == "X"
                    && id.role == ResolutionIdentifierRole::Reference
            })
            .collect::<Vec<_>>();
        assert_eq!(declarations.len(), 5);
        assert_eq!(references.len(), 4);
        for (reference, target) in references.into_iter().zip([
            Some(declarations[0]),
            Some(declarations[1]),
            Some(declarations[3]),
            None,
        ]) {
            let expected = preload
                .resolve_reference(
                    semantic_at(&lowered, reference.site, LoweredSemanticRole::Reference),
                    &cancellation,
                )
                .unwrap();
            assert_eq!(expected.binding().targets(), target.as_slice());
            let operation = open();
            let contexts = operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            let locator = SelectedSemanticLocator::new(
                "go",
                GO_ROOT_CONSUMER_PATH,
                reference.site,
                LoweredSemanticRole::Reference,
            );
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                actual,
            )) = operation
                .resolve_reference(
                    contexts,
                    &locator,
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap()
            else {
                panic!("Go spelling answer must be native")
            };
            assert_eq!(
                actual, expected,
                "unsaved={unsaved}, reference={reference:?}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(fixture._project_root.path().join(GO_ROOT_CONSUMER_PATH))
                .unwrap(),
            baseline
        );
    }
}
