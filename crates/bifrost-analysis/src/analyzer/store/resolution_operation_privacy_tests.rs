use super::*;

use std::path::Path;

use crate::analyzer::resolution::{
    BindingNodeId, FactPageVisitor, LoweredSemanticRole, SelectedResolutionMountOrdinal,
    SelectedTypedFactSource, TypedFactRequest,
};
use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, ResolutionIdentifierRole, ResolutionNamespace, ResolutionSiteId,
};
use brokk_bifrost_core::analyzer::rust_facts::RustVisibility;
use brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId;
use rusqlite::params;

fn persisted_target_authority_request(
    operation: &SelectedResolutionOperation<'_, '_>,
    facts: &FileResolutionFacts,
) -> (
    SelectedResolutionMountOrdinal,
    BindingNodeId,
    ResolutionSiteId,
    i64,
) {
    let source_site = site_for_identifier(
        facts,
        "target",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Value,
    );
    let mount = operation
        .mounts()
        .unwrap()
        .iter()
        .find(|mount| mount.persisted_relative_path() == RUST_ROOT_PROVIDER_PATH)
        .expect("Rust authority fixture provider mount");
    let (halves, _) = operation
        .rust_root_halves(
            &RustRootHalfScope::new(
                operation.mounts().unwrap().iter(),
                operation.mounts().unwrap().iter(),
            ),
            &CancellationToken::default(),
            None,
        )
        .expect("selected Rust authority export halves")
        .expect("selected Rust authority export halves are available");
    let target_demand = crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
        brokk_bifrost_core::analyzer::Language::Rust,
        ResolutionNamespace::Value,
        "target",
    )
    .semantic(&operation.ready.shared_names());
    let node = halves
        .iter()
        .find_map(|half| {
            let SelectedRootPathHalf::Export {
                identity,
                demand,
                definition,
                ..
            } = half
            else {
                return None;
            };
            (identity.fragment() == mount.fragment() && *demand == target_demand)
                .then_some(*definition)
        })
        .expect("selected provider target export definition node");
    let record = operation
        .ready
        .inventory
        .mounts()
        .unwrap()
        .iter()
        .find(|record| record.persisted_relative_path() == RUST_ROOT_PROVIDER_PATH)
        .expect("selected provider mount record");
    (mount.ordinal(), node, source_site, record.blob_id())
}

fn persisted_target_source_site(fixture: &RustRootResolutionOperationFixture) -> ResolutionSiteId {
    site_for_identifier(
        &fixture.provider_facts,
        "target",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Value,
    )
}

fn persisted_provider_blob_id(fixture: &RustRootResolutionOperationFixture) -> i64 {
    let provider_oid = fixture
        .selected_sources
        .iter()
        .find(|source| source.relative_path.as_path() == Path::new(RUST_ROOT_PROVIDER_PATH))
        .expect("Rust authority fixture provider source")
        .content_oid
        .to_string();
    fixture
        .store
        .conn
        .execute(move |connection| {
            connection.query_row(
                "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
                [provider_oid],
                |row| row.get(0),
            )
        })
        .expect("persisted Rust authority fixture blob")
}

#[test]
fn persisted_node_authority_follows_semantic_site_bridge_and_property() {
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    let (mount, node, source_site, blob_id) =
        persisted_target_authority_request(&operation, &fixture.provider_facts);

    // The interior translates the export's definition node to the source site
    // the authority chain admits; the persisted row keeps that chain.
    let translated = operation
        .ready
        .lexical_source()
        .definition_source_site(mount, node, &CancellationToken::default())
        .expect("interior definition source site")
        .expect("uncancelled interior read")
        .expect("a persisted export definition node declares a source site");
    assert_eq!(translated, source_site);
    let authorities = read_selected_rust_declaration_authority_with_cancellation(
        &operation.ready.inventory,
        &[(mount, translated)],
        &CancellationToken::default(),
        None,
    )
    .expect("persisted Rust declaration authority")
    .expect("uncancelled authority read");
    assert_eq!(authorities.len(), 1);
    let authority = &authorities[0];

    let (stored_site, stored_declaration, stored_visibility): (i64, i64, String) = operation
        .ready
        .inventory
        .connection()
        .query_row(
            "SELECT semantic.source_site, native.declaration_id, property.visibility
               FROM resolution_semantic_sites AS semantic
               JOIN source_native_declaration_bridges AS native
                 ON native.blob_id = semantic.blob_id
                AND native.source_site = semantic.source_site
               JOIN source_rust_declaration_properties AS property
                 ON property.blob_id = native.blob_id
                AND property.declaration_id = native.declaration_id
              WHERE semantic.blob_id = ?1
                AND semantic.source_site = ?2
                AND semantic.semantic_role = 'definition'",
            params![blob_id, source_site.get()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("canonical persisted source authority row");
    assert_eq!(
        authority.source_site,
        ResolutionSiteId::new(stored_site as u32)
    );
    assert_eq!(authority.source_site, source_site);
    assert_eq!(
        authority.declaration,
        SourceDeclarationId::new(stored_declaration as u32)
    );
    assert_eq!(authority.visibility, RustVisibility::Public);
    assert_eq!(stored_visibility, "public");
}

#[test]
fn persisted_node_authority_cancellation_returns_none_then_retries() {
    let fixture = RustRootResolutionOperationFixture::new();
    let open_cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&open_cancellation);
    let (mount, _, source_site, _) =
        persisted_target_authority_request(&operation, &fixture.provider_facts);

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    assert!(
        read_selected_rust_declaration_authority_with_cancellation(
            &operation.ready.inventory,
            &[(mount, ResolutionSiteId::new(0))],
            &cancelled,
            None,
        )
        .expect("cancelled source-site authority read")
        .is_none()
    );
    let retried = read_selected_rust_declaration_authority_with_cancellation(
        &operation.ready.inventory,
        &[(mount, source_site)],
        &CancellationToken::default(),
        None,
    )
    .expect("retried persisted authority")
    .expect("uncancelled authority read");
    assert_eq!(retried.len(), 1);
}

#[test]
fn persisted_node_authority_rejects_missing_native_bridge() {
    let fixture = RustRootResolutionOperationFixture::new();
    let source_site = persisted_target_source_site(&fixture);
    let blob_id = persisted_provider_blob_id(&fixture);
    fixture
        .store
        .conn
        .execute(move |connection| {
            connection
                .execute_batch(
                    "DROP TRIGGER source_native_declaration_bridges_no_delete_after_seal",
                )
                .expect("allow missing-bridge fixture mutation");
            connection.execute(
                "DELETE FROM source_native_declaration_bridges
              WHERE blob_id = ?1 AND source_site = ?2",
                params![blob_id, source_site.get()],
            )
        })
        .expect("remove native bridge test row before opening operation");
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    let (mount, _, requested_site, _) =
        persisted_target_authority_request(&operation, &fixture.provider_facts);

    let error = read_selected_rust_declaration_authority_with_cancellation(
        &operation.ready.inventory,
        &[(mount, requested_site)],
        &CancellationToken::default(),
        None,
    )
    .expect_err("missing native bridge must fail closed");
    assert!(
        error
            .to_string()
            .contains("incomplete Rust declaration authority"),
        "unexpected missing-bridge diagnostic: {error}"
    );
}

#[test]
fn persisted_node_authority_rejects_missing_rust_property() {
    let fixture = RustRootResolutionOperationFixture::new();
    let source_site = persisted_target_source_site(&fixture);
    let blob_id = persisted_provider_blob_id(&fixture);
    let declaration: i64 = fixture
        .store
        .conn
        .execute(move |connection| {
            connection.query_row(
                "SELECT declaration_id
                   FROM source_native_declaration_bridges
                  WHERE blob_id = ?1 AND source_site = ?2",
                params![blob_id, source_site.get()],
                |row| row.get(0),
            )
        })
        .expect("native declaration for property deletion");
    fixture
        .store
        .conn
        .execute(move |connection| {
            connection
                .execute_batch(
                    "DROP TRIGGER source_rust_declaration_properties_no_delete_after_seal",
                )
                .expect("allow missing-property fixture mutation");
            connection.execute(
                "DELETE FROM source_rust_declaration_properties
              WHERE blob_id = ?1 AND declaration_id = ?2",
                params![blob_id, declaration],
            )
        })
        .expect("remove Rust property test row before opening operation");
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    let (mount, _, requested_site, _) =
        persisted_target_authority_request(&operation, &fixture.provider_facts);

    let error = read_selected_rust_declaration_authority_with_cancellation(
        &operation.ready.inventory,
        &[(mount, requested_site)],
        &CancellationToken::default(),
        None,
    )
    .expect_err("missing Rust property must fail closed");
    assert!(
        error
            .to_string()
            .contains("incomplete Rust declaration authority"),
        "unexpected missing-property diagnostic: {error}"
    );
}

#[test]
fn persisted_raw_reference_and_declaration_authority_cancel_then_retry() {
    let fixture = RustRootResolutionOperationFixture::new();
    let cancellation = CancellationToken::default();
    let operation = fixture.open_ready(&cancellation);
    let reference_site = site_for_identifier(
        &fixture.consumer_facts,
        "alias",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let definition_site = persisted_target_source_site(&fixture);
    let lexical = operation.ready.lexical_source();
    let locate = |path, site, role| {
        let crate::analyzer::store::resolution_lexical::SelectedSemanticLookupOutcome::Found(found) =
            lexical
                .lookup_semantic_sites(
                    &SelectedSemanticLocator::new("rust", path, site, role),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .expect("locate canonical selected semantic")
        else {
            panic!("raw Rust reader fixture semantic must be selected")
        };
        assert_eq!(found.len(), 1);
        found[0].semantic()
    };
    let reference = locate(
        RUST_ROOT_CONSUMER_PATH,
        reference_site,
        LoweredSemanticRole::Reference,
    );
    let definition = locate(
        RUST_ROOT_PROVIDER_PATH,
        definition_site,
        LoweredSemanticRole::Definition,
    );
    let source = operation.ready.typed_source();

    let cancelled = CancellationToken::default();
    cancelled.cancel();
    let mut ignored_reference_rows = Vec::new();
    let mut collect_cancelled_reference =
        |rows: &[crate::analyzer::resolution::SelectedTypedRow<
            crate::analyzer::resolution::LoweredRustReferenceContext,
        >]| {
            ignored_reference_rows.extend(rows.iter().cloned());
            Ok(true)
        };
    let cancelled_outcome = source
        .visit_rust_reference_context_pages(
            TypedFactRequest::new(&[reference]),
            &cancelled,
            &mut FactPageVisitor::new(&mut collect_cancelled_reference),
        )
        .expect("cancelled persisted reference-context read");
    assert!(cancelled_outcome.is_cancelled());
    assert!(ignored_reference_rows.is_empty());

    let mut ignored_declaration_rows = Vec::new();
    let mut collect_cancelled_declaration =
        |rows: &[crate::analyzer::resolution::SelectedTypedRow<
            crate::analyzer::resolution::LoweredRustDeclarationAuthority,
        >]| {
            ignored_declaration_rows.extend(rows.iter().cloned());
            Ok(true)
        };
    let cancelled_declaration_outcome = source
        .visit_rust_declaration_authority_pages(
            TypedFactRequest::new(&[definition]),
            &cancelled,
            &mut FactPageVisitor::new(&mut collect_cancelled_declaration),
        )
        .expect("cancelled persisted declaration-authority read");
    assert!(cancelled_declaration_outcome.is_cancelled());
    assert!(ignored_declaration_rows.is_empty());

    let mut reference_rows = Vec::new();
    let mut collect_reference = |rows: &[crate::analyzer::resolution::SelectedTypedRow<
        crate::analyzer::resolution::LoweredRustReferenceContext,
    >]| {
        reference_rows.extend(rows.iter().cloned());
        Ok(true)
    };
    let reference_outcome = source
        .visit_rust_reference_context_pages(
            TypedFactRequest::new(&[reference]),
            &CancellationToken::default(),
            &mut FactPageVisitor::new(&mut collect_reference),
        )
        .expect("retried persisted reference-context read");
    assert!(reference_outcome.is_exhausted());
    assert_eq!(reference_rows.len(), 1);
    assert_eq!(reference_rows[0].row().reference(), reference);

    let mut declaration_rows = Vec::new();
    let mut collect_declaration = |rows: &[crate::analyzer::resolution::SelectedTypedRow<
        crate::analyzer::resolution::LoweredRustDeclarationAuthority,
    >]| {
        declaration_rows.extend(rows.iter().cloned());
        Ok(true)
    };
    let declaration_outcome = source
        .visit_rust_declaration_authority_pages(
            TypedFactRequest::new(&[definition]),
            &CancellationToken::default(),
            &mut FactPageVisitor::new(&mut collect_declaration),
        )
        .expect("retried persisted declaration-authority read");
    assert!(declaration_outcome.is_exhausted());
    assert_eq!(declaration_rows.len(), 1);
    assert_eq!(declaration_rows[0].row().definition(), definition);
    assert_eq!(declaration_rows[0].row().source_site(), definition_site);
    assert_eq!(
        declaration_rows[0].row().visibility(),
        Some(&RustVisibility::Public)
    );
}

#[test]
fn persisted_rust_authority_keeps_nested_module_parent_and_cfg() {
    use crate::analyzer::resolution::{
        LoweredRustDeclarationAuthority, LoweredRustReferenceContext, SelectedTypedRow,
    };
    use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, RustSourceContextKind};
    let mut fixture = RustRootResolutionOperationFixture::new();
    let (state, facts) = fixture.replace_persisted_consumer_source(concat!(
        "#[cfg(feature = \"enabled\")]\n",
        "pub mod nested {\n",
        "  pub(crate) fn target() {}\n",
        "  pub fn caller() { target(); }\n",
        "}\n",
    ));
    let source = state.source_facts.as_ref().unwrap();
    let root = source
        .rust_items
        .contexts
        .iter()
        .find(|context| context.kind == RustSourceContextKind::FileRoot)
        .unwrap();
    let module = source
        .rust_items
        .contexts
        .iter()
        .find(|context| context.kind == RustSourceContextKind::Module)
        .unwrap();
    let reference_site = site_for_identifier(
        &facts,
        "target",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Value,
    );
    let module_site = site_for_identifier(
        &facts,
        "nested",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Type,
    );
    let target_site = site_for_identifier(
        &facts,
        "target",
        ResolutionIdentifierRole::Declaration,
        ResolutionNamespace::Value,
    );
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let lexical = operation.ready.lexical_source();
    let locate = |site, role| {
        let crate::analyzer::store::resolution_lexical::SelectedSemanticLookupOutcome::Found(found) =
            lexical
                .lookup_semantic_sites(
                    &SelectedSemanticLocator::new("rust", RUST_ROOT_CONSUMER_PATH, site, role),
                    &cancellation,
                    &ResolutionSession::unbounded(),
                )
                .unwrap()
        else {
            panic!("selected source site");
        };
        assert_eq!(found.len(), 1);
        found[0].semantic()
    };
    let typed = operation.ready.typed_source();
    let mut references = Vec::new();
    typed
        .visit_rust_reference_context_pages(
            TypedFactRequest::new(&[locate(reference_site, LoweredSemanticRole::Reference)]),
            &cancellation,
            &mut FactPageVisitor::new(&mut |rows: &[SelectedTypedRow<
                LoweredRustReferenceContext,
            >]| {
                references.extend_from_slice(rows);
                Ok(true)
            }),
        )
        .unwrap();
    assert_eq!(references.len(), 1);
    let reference = references[0].row();
    assert_eq!(
        reference.source_occurrence(),
        source.native_site_occurrences[reference_site.get() as usize]
    );
    assert_eq!(reference.module_context(), module.context);
    assert_eq!(reference.module_declaration(), module.owner);
    assert_eq!(
        reference.cfg_condition(),
        &RustCfgCondition::Atom("feature = \"enabled\"".to_owned())
    );
    let mut definitions = Vec::new();
    typed
        .visit_rust_declaration_authority_pages(
            TypedFactRequest::new(&[
                locate(module_site, LoweredSemanticRole::Definition),
                locate(target_site, LoweredSemanticRole::Definition),
            ]),
            &cancellation,
            &mut FactPageVisitor::new(&mut |rows: &[SelectedTypedRow<
                LoweredRustDeclarationAuthority,
            >]| {
                definitions.extend_from_slice(rows);
                Ok(true)
            }),
        )
        .unwrap();
    assert_eq!(definitions.len(), 2);
    let module_definition = definitions
        .iter()
        .find(|row| row.row().source_site() == module_site)
        .unwrap()
        .row();
    assert_eq!(module_definition.module_context(), root.context);
    assert_eq!(module_definition.module_declaration(), None);
    let target = definitions
        .iter()
        .find(|row| row.row().source_site() == target_site)
        .unwrap()
        .row();
    assert_eq!(target.module_context(), module.context);
    assert_eq!(target.visibility(), Some(&RustVisibility::Crate));
    assert_eq!(
        target.cfg_condition(),
        &RustCfgCondition::Atom("feature = \"enabled\"".to_owned())
    );
}

#[test]
fn persisted_rust_authority_batch_order_is_request_order_independent() {
    use crate::analyzer::resolution::{SemanticId, TypedFactRequest};
    let mut fixture = RustRootResolutionOperationFixture::new();
    fixture.replace_persisted_consumer_source(
        "pub fn first() {} pub fn second() {} pub fn caller() { first(); second(); }",
    );
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let (ordinal,blob)=operation.ready.inventory.connection().query_row("SELECT m.mount_ordinal,m.blob_id FROM temp.selected_resolution_mounts m WHERE (SELECT count(*) FROM resolution_rust_reference_contexts r WHERE r.blob_id=m.blob_id)>=2 AND (SELECT count(*) FROM resolution_rust_declaration_authorities d WHERE d.blob_id=m.blob_id)>=2 ORDER BY m.mount_ordinal LIMIT 1",[],|row| Ok((row.get::<_,u32>(0)?,row.get::<_,i64>(1)?))).unwrap();
    let typed = operation.ready.typed_source();
    for table in [
        "resolution_rust_reference_contexts",
        "resolution_rust_declaration_authorities",
    ] {
        let keys = operation
            .ready
            .inventory
            .connection()
            .prepare(&format!(
                "SELECT semantic_key FROM {table} WHERE blob_id=?1 ORDER BY semantic_key LIMIT 2"
            ))
            .unwrap()
            .query_map([blob], |row| row.get::<_, u32>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let expected = keys
            .iter()
            .map(|key| SemanticId::local(ordinal, *key))
            .collect::<Vec<_>>();
        assert!(
            std::panic::catch_unwind(|| {
                let duplicate = [expected[0], expected[0]];
                let _request = TypedFactRequest::new(&duplicate);
            })
            .is_err(),
            "duplicate typed request keys are rejected at construction"
        );
        for requested in [vec![expected[1], expected[0]], expected.clone()] {
            let mut observed = Vec::new();
            if table == "resolution_rust_reference_contexts" {
                typed
                    .visit_rust_reference_context_pages(
                        TypedFactRequest::new(&requested),
                        &cancellation,
                        &mut FactPageVisitor::new(&mut |rows| {
                            observed.extend(rows.iter().map(|row| row.row().reference()));
                            Ok(true)
                        }),
                    )
                    .unwrap();
            } else {
                typed
                    .visit_rust_declaration_authority_pages(
                        TypedFactRequest::new(&requested),
                        &cancellation,
                        &mut FactPageVisitor::new(&mut |rows| {
                            observed.extend(rows.iter().map(|row| row.row().definition()));
                            Ok(true)
                        }),
                    )
                    .unwrap();
            }
            assert_eq!(observed, expected);
        }
    }
}

#[test]
fn persisted_contract_reference_keeps_exact_trait_member_association() {
    use crate::analyzer::resolution::SemanticId;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind;
    let mut fixture = RustRootResolutionOperationFixture::new();
    let (_, facts) = fixture.replace_persisted_consumer_source(
        "trait Factory { fn make(); } struct Item; impl Factory for Item { fn make() {} }",
    );
    let expected = site_for_identifier(
        &facts,
        "Factory",
        ResolutionIdentifierRole::Reference,
        ResolutionNamespace::Type,
    );
    let cancellation = CancellationToken::new();
    let operation = fixture.open_ready(&cancellation);
    let mount = operation
        .ready
        .inventory
        .mount_record_for_path("rust", RUST_ROOT_CONSUMER_PATH)
        .unwrap()
        .unwrap();
    let rows=operation.ready.inventory.connection().prepare("SELECT definition,member_kind,reference_site FROM resolution_contract_references WHERE blob_id=?1 ORDER BY definition,member_kind,position").unwrap().query_map([mount.blob_id()],|row|Ok((row.get::<_,u32>(0)?,row.get::<_,i64>(1)?,row.get::<_,u32>(2)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    assert_eq!(rows.len(), 1, "one implementation method: {rows:?}");
    assert_eq!((rows[0].1, rows[0].2), (1, expected.get()));
    let sites = operation
        .ready
        .lexical_source()
        .contract_reference_sites(
            mount.ordinal(),
            SemanticId::local(mount.ordinal().get(), rows[0].0),
            ResolutionMemberKind::Method,
            &cancellation,
        )
        .unwrap()
        .unwrap();
    assert_eq!(sites, vec![expected]);
    eprintln!("B1 exact trait contract definition/kind/site={rows:?}");
}
