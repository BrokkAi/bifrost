use super::*;

#[test]
fn selected_go_member_metadata_preserves_embeddings_receivers_and_indexed_access() {
    use super::super::super::planner_statistics::pinned_plans::{explain_pin, pinned};
    use crate::analyzer::resolution::GoMemberDeclarationKind;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    let mut source = String::from(
        "package consumer; type Contract interface { Call() }; type Base struct{}; type Box struct{ *Base; Method Base }; func (b Base) Value() {}; func (b *Base) Pointer() {}; ",
    );
    for index in 0..513 {
        source.push_str(&format!("type F{index} struct{{ Base }}; "));
    }
    for statistics in PlannerStatisticsState::BOTH {
        let fixture = GoRootResolutionOperationFixture::with_consumer(&source);
        fixture
            .store
            .conn
            .execute(move |connection| statistics.install(connection));
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let mount = operation
            .mount_table()
            .mount_for_path("go", GO_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            mount.fragment(),
            &operation.ready.shared_names(),
            Language::Go,
            &fixture.consumer_facts,
        );
        let definition = |name, namespace| {
            semantic_at(
                &lowered,
                site_for_identifier(
                    &fixture.consumer_facts,
                    name,
                    ResolutionIdentifierRole::Declaration,
                    namespace,
                ),
                LoweredSemanticRole::Definition,
            )
        };
        let contract = definition("Contract", ResolutionNamespace::Type);
        let base = definition("Base", ResolutionNamespace::Type);
        let boxed = definition("Box", ResolutionNamespace::Type);
        let value = definition("Value", ResolutionNamespace::Callable);
        let pointer = definition("Pointer", ResolutionNamespace::Callable);
        let mut definitions = lowered
            .lexical()
            .semantics()
            .iter()
            .filter(|row| row.role() == LoweredSemanticRole::Definition)
            .map(|row| row.semantic())
            .collect::<Vec<_>>();
        // Duplicate requests spanning batches must not duplicate embedding paths.
        definitions.push(boxed);
        let typed = operation.ready.typed_source();
        let lookup = |namespace| {
            crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
                Language::Go,
                namespace,
                "Method",
            )
            .semantic(&operation.ready.shared_names())
        };
        let value_lookup = lookup(ResolutionNamespace::Value);
        let callable_lookup = lookup(ResolutionNamespace::Callable);
        let lookup_requests = [(mount.fragment(), value_lookup)];
        assert_eq!(
            typed
                .go_callable_lookups(&lookup_requests, &cancellation)
                .unwrap()
                .unwrap(),
            vec![(value_lookup, callable_lookup)]
        );
        for requested in [
            &[base, boxed, value, pointer, contract][..],
            definitions.as_slice(),
        ] {
            let rows = typed
                .go_member_declarations(requested, &cancellation)
                .unwrap()
                .unwrap();
            assert_eq!(rows.len(), if requested.len() == 5 { 5 } else { 519 });
            let find = |definition| {
                &rows
                    .iter()
                    .find(|row| row.definition == definition)
                    .unwrap()
                    .kind
            };
            assert_eq!(find(contract), &GoMemberDeclarationKind::Interface);
            assert_eq!(
                find(base),
                &GoMemberDeclarationKind::Struct { fields: vec![] }
            );
            let GoMemberDeclarationKind::Struct { fields } = find(boxed) else {
                panic!("Box struct metadata")
            };
            assert_eq!(fields.len(), 2);
            for (name, embedded) in [("Base", true), ("Method", false)] {
                let lookup = crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Callable,
                    name,
                )
                .semantic(&operation.ready.shared_names());
                let field = fields
                    .iter()
                    .find(|field| field.callable_lookup == lookup)
                    .unwrap();
                assert_eq!(field.embedded, embedded);
                assert!(field.field.is_some());
                assert!(field.value_type.is_some());
            }
            assert_eq!(
                find(value),
                &GoMemberDeclarationKind::Method {
                    pointer_receiver: Some(false)
                }
            );
            assert_eq!(
                find(pointer),
                &GoMemberDeclarationKind::Method {
                    pointer_receiver: Some(true)
                }
            );
            let plan = explain_pin(
                operation.ready.inventory.connection(),
                &pinned("go_member_declarations"),
            );
            for alias in [
                "mount",
                "interior",
                "semantic",
                "source",
                "go_source",
                "bridge",
                "declaration",
                "owner_type",
                "field",
                "field_bridge",
                "field_semantic",
                "value",
                "callable",
                "receiver",
            ] {
                assert!(
                    plan.iter()
                        .any(|detail| detail.starts_with(&format!("SEARCH {alias} "))),
                    "{alias} must use selected keys with {statistics}: {plan:#?}"
                );
            }
            assert!(
                plan.iter()
                    .any(|detail| detail.contains("source_go_fields_by_owner")),
                "{statistics}: {plan:#?}"
            );
            assert!(
                plan.iter()
                    .all(|detail| !detail.contains("AUTOMATIC") && !detail.contains("TEMP B-TREE")),
                "{statistics}: {plan:#?}"
            );
        }
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            typed
                .go_callable_lookups(&lookup_requests, &cancelled)
                .unwrap()
                .is_none()
        );
        assert!(
            typed
                .go_member_declarations(&definitions, &cancelled)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            typed
                .go_member_declarations(&definitions, &cancellation)
                .unwrap()
                .unwrap()
                .len(),
            519
        );
    }
}

#[test]
fn go_pointer_transfer_reopened_selection_matches_preload() {
    for binding in ["value := *p", "var value = *p"] {
        let source = format!(
            "package sample; type Item struct{{}}; func f(p *Item) Item {{ {binding}; return value }}"
        );
        let fixture = GoResolutionOperationFixture::with_source(&source);
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let fragment = operation.mounts().unwrap()[0].fragment();
        drop(operation);
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            fragment,
            crate::analyzer::resolution::test_shared_names(),
            Language::Go,
            &fixture.facts,
        );
        let site = site_for_identifier(
            &fixture.facts,
            "value",
            ResolutionIdentifierRole::Reference,
            ResolutionNamespace::Value,
        );
        let reference = semantic_at(&lowered, site, LoweredSemanticRole::Reference);
        let item = semantic_at(
            &lowered,
            site_for_identifier(
                &fixture.facts,
                "Item",
                ResolutionIdentifierRole::Declaration,
                ResolutionNamespace::Type,
            ),
            LoweredSemanticRole::Definition,
        );
        let preload = PreloadedFactResolutionService::from_lowered_fragments(
            [lowered.lexical().clone()],
            [lowered.typed().clone()],
        );
        let expected = preload.resolve_reference(reference, &cancellation).unwrap();
        assert!(
            expected.projected_frontiers().iter().any(|frontier| {
                frontier
                    .possible_values()
                    .iter()
                    .any(|value| value.ty().identity() == item && value.ty().indirection() == 0)
            }),
            "dereference must retain the selected Item identity: {expected:?}"
        );
        let locator = SelectedSemanticLocator::new(
            "go",
            GO_SOURCE_PATH,
            site,
            LoweredSemanticRole::Reference,
        );
        // Independent selected operations hydrate the persisted transform rows each time.
        for _ in 0..2 {
            let operation = fixture.open_ready(&cancellation);
            let context = operation
                .empty_contexts(&ResolutionCompletion::Complete)
                .unwrap();
            let mut metrics = SelectedResolutionContextMetrics;
            let actual = operation
                .resolve_reference(context, &locator, &cancellation, &mut metrics)
                .unwrap();
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                actual,
            )) = actual
            else {
                panic!("selected pointer fixture must resolve from its persisted bundle");
            };
            assert_eq!(actual, expected);
        }
    }
}
