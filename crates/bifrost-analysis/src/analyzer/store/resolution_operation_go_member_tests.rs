use super::*;
use crate::analyzer::store::resolution_operation::package_context::SelectedPackageRows;

#[test]
fn selected_go_package_members_group_matches_per_lookup_with_staged_rename() {
    use crate::analyzer::store::resolution_stage::codec::{encode_node, encode_semantic};

    let provider = "package provider; type Item struct{}; type Replacement struct{}";
    let fixture = GoRootResolutionOperationFixture::with_sources([
        GO_ROOT_CONSUMER_SOURCE,
        provider,
        GO_ROOT_DECOY_SOURCE,
    ]);
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let mount = operation
        .mount_table()
        .mount_for_path("go", GO_ROOT_PROVIDER_PATH)
        .unwrap()
        .unwrap();
    let SelectedPackageRows::Ready(ordinary) = operation
        .selected_package_members_by_lookup(mount.ordinal(), &cancellation)
        .unwrap()
    else {
        panic!("not cancelled");
    };
    let mut members = ordinary.values().flatten().copied().collect::<Vec<_>>();
    let item = members
        .iter()
        .find(|member| {
            member.source_site
                == site_for_identifier(
                    &fixture.provider_facts,
                    "Item",
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type,
                )
        })
        .copied()
        .expect("Item package member");
    let replacement_lookup = members
        .iter()
        .find(|member| member.lookup != item.lookup)
        .map(|member| member.lookup)
        .expect("Replacement package member lookup");
    members
        .iter_mut()
        .find(|member| member.definition == item.definition && member.namespace == item.namespace)
        .expect("Item package member identity")
        .lookup = replacement_lookup;
    let lookups = ordinary.keys().copied().collect::<BTreeSet<_>>();

    operation
        .ready
        .inventory
        .with_owned_temp_write(|connection| {
            connection.execute(
                "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",
                rusqlite::params![mount.ordinal().get(), [41_u8; 32].as_slice(), [42_u8; 32].as_slice()],
            )?;
            let producer = connection.last_insert_rowid();
            for member in &members {
                connection.execute(
                    "INSERT INTO temp.selected_resolution_stage_package_members(host_ordinal,producer_id,token_key,domain_shared,definition_key,source_site,root_scope_key,namespace,lookup_shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    rusqlite::params![
                        mount.ordinal().get(),
                        producer,
                        encode_semantic(member.token),
                        member.domain.shared_name_id().unwrap().get(),
                        encode_semantic(member.definition),
                        member.source_site.get(),
                        encode_node(member.root_scope),
                        member.namespace.label(),
                        member.lookup.shared_name_id().unwrap().get(),
                    ],
                )?;
            }
            Ok(())
        })
        .unwrap();

    let SelectedPackageRows::Ready(grouped) = operation
        .selected_package_members_by_lookup(mount.ordinal(), &cancellation)
        .unwrap()
    else {
        panic!("not cancelled");
    };
    let actual = grouped.values().flatten().copied().collect::<BTreeSet<_>>();
    let mut oracle = BTreeSet::new();
    for lookup in lookups {
        let SelectedPackageRows::Ready(members) = operation
            .selected_package_members_for_lookup(mount.ordinal(), lookup, &cancellation)
            .unwrap()
        else {
            panic!("not cancelled");
        };
        oracle.extend(members);
    }
    assert_eq!(actual, oracle);
    assert!(
        !actual.contains(&item),
        "the staged rename withdraws the old key"
    );
    assert!(
        actual
            .iter()
            .any(|member| member.definition == item.definition
                && member.lookup == replacement_lookup),
        "the staged rename retains Item under its replacement lookup"
    );
}

#[test]
fn selected_go_package_member_mount_queries_seek_in_both_statistics_states() {
    use super::super::super::planner_statistics::pinned_plans::{explain_pin, pinned};
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

    for statistics in PlannerStatisticsState::BOTH {
        let fixture = GoRootResolutionOperationFixture::new();
        fixture
            .store
            .conn
            .execute(move |connection| statistics.install(connection));
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let mount = operation
            .mount_table()
            .mount_for_path("go", GO_ROOT_PROVIDER_PATH)
            .unwrap()
            .unwrap();
        for (name, index) in [
            ("native_package_members_by_mount", "PRIMARY KEY"),
            (
                "native_stage_package_members_by_mount",
                "selected_resolution_stage_package_members_host",
            ),
        ] {
            let mut pin = pinned(name);
            pin.params = vec![rusqlite::types::Value::Integer(i64::from(
                mount.ordinal().get(),
            ))];
            let plan = explain_pin(operation.ready.inventory.connection(), &pin);
            assert!(
                plan.iter()
                    .any(|detail| detail.starts_with("SEARCH p USING") && detail.contains(index)),
                "{name} with {statistics}: {plan:?}"
            );
            assert!(
                plan.iter().all(|detail| !detail.starts_with("SCAN p")
                    && !detail.contains("AUTOMATIC")
                    && !detail.contains("TEMP B-TREE")),
                "{name} with {statistics}: {plan:?}"
            );
        }
    }
}

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
        let contract_call = definition("Call", ResolutionNamespace::Callable);
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
            let GoMemberDeclarationKind::Interface { methods } = find(contract) else {
                panic!("Contract interface metadata")
            };
            let call_lookup = crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
                Language::Go,
                ResolutionNamespace::Callable,
                "Call",
            )
            .semantic(&operation.ready.shared_names());
            assert!(methods.iter().any(|method| {
                method.callable_lookup == call_lookup && method.definition == Some(contract_call)
            }));
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
