//! Boundary assertions for source-preserving producer publication.
//! The allowlist is positive: every unlisted table and accounting column is refused.

use super::*;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::collections::BTreeSet;

// Audited FK closure of the resolution, IR and surface publication headers.
// Keep this explicit so a schema change cannot silently widen write authority.
const DERIVED_TABLES: &[&str] = &[
    "candidate_macro_semantic_ir_allocations",
    "candidate_macro_semantic_ir_blocks",
    "candidate_macro_semantic_ir_call_arguments",
    "candidate_macro_semantic_ir_call_control_classes",
    "candidate_macro_semantic_ir_call_control_coverage",
    "candidate_macro_semantic_ir_call_control_obligations",
    "candidate_macro_semantic_ir_call_sites",
    "candidate_macro_semantic_ir_callable_targets",
    "candidate_macro_semantic_ir_candidates",
    "candidate_macro_semantic_ir_captures",
    "candidate_macro_semantic_ir_cleanup_actions",
    "candidate_macro_semantic_ir_cleanup_anchors",
    "candidate_macro_semantic_ir_cleanup_nodes",
    "candidate_macro_semantic_ir_cleanup_owners",
    "candidate_macro_semantic_ir_cleanup_projection_members",
    "candidate_macro_semantic_ir_cleanup_projections",
    "candidate_macro_semantic_ir_control_edges",
    "candidate_macro_semantic_ir_declaration_segments",
    "candidate_macro_semantic_ir_drops",
    "candidate_macro_semantic_ir_event_async_suspends",
    "candidate_macro_semantic_ir_event_callables",
    "candidate_macro_semantic_ir_event_offsets",
    "candidate_macro_semantic_ir_event_synchronizations",
    "candidate_macro_semantic_ir_event_transfers",
    "candidate_macro_semantic_ir_events",
    "candidate_macro_semantic_ir_evidence",
    "candidate_macro_semantic_ir_footprint_call_target_obligations",
    "candidate_macro_semantic_ir_footprint_coverage",
    "candidate_macro_semantic_ir_footprint_coverage_classes",
    "candidate_macro_semantic_ir_gaps",
    "candidate_macro_semantic_ir_guard_facts",
    "candidate_macro_semantic_ir_guarded_pattern_projections",
    "candidate_macro_semantic_ir_guarded_pattern_steps",
    "candidate_macro_semantic_ir_incomplete_facts",
    "candidate_macro_semantic_ir_locators",
    "candidate_macro_semantic_ir_loop_sites",
    "candidate_macro_semantic_ir_memory_locations",
    "candidate_macro_semantic_ir_move_outs",
    "candidate_macro_semantic_ir_partial_flow_heads",
    "candidate_macro_semantic_ir_partial_flows",
    "candidate_macro_semantic_ir_pointer_accesses",
    "candidate_macro_semantic_ir_pointer_aliases",
    "candidate_macro_semantic_ir_pointer_invalidations",
    "candidate_macro_semantic_ir_pointer_origins",
    "candidate_macro_semantic_ir_points",
    "candidate_macro_semantic_ir_ports",
    "candidate_macro_semantic_ir_procedures",
    "candidate_macro_semantic_ir_receiver_type_facts",
    "candidate_macro_semantic_ir_result_type_classes",
    "candidate_macro_semantic_ir_scope_ends",
    "candidate_macro_semantic_ir_source_mappings",
    "candidate_macro_semantic_ir_statement_entries",
    "candidate_macro_semantic_ir_switch_cases",
    "candidate_macro_semantic_ir_switch_facts",
    "candidate_macro_semantic_ir_texts",
    "candidate_macro_semantic_ir_values",
    "csharp_global_using_extent",
    "legacy_resolution_declaration_visibility_properties",
    "python_binding_export_operations",
    "python_binding_guards",
    "python_binding_imports",
    "python_binding_predicates",
    "python_binding_site_guards",
    "python_binding_source",
    "python_import_module_operands",
    "python_member_annotations",
    "python_member_base_operands",
    "python_member_call_arguments",
    "python_member_class_keywords",
    "python_member_classes",
    "python_member_decorator_receivers",
    "python_member_decorators",
    "python_member_member_roles",
    "python_member_operation_names",
    "python_member_operations",
    "python_member_parameters",
    "python_member_receiver_writes",
    "python_member_sites",
    "python_member_super_contexts",
    "python_member_super_members",
    "python_member_type_slots",
    "python_module_registry_writes",
    "python_package_path_extensions",
    "resolution_additional_definition_namespaces",
    "resolution_binary_operations",
    "resolution_binding_directives",
    "resolution_binding_events",
    "resolution_binding_observations",
    "resolution_binding_projections",
    "resolution_binding_scopes",
    "resolution_binding_slots",
    "resolution_call_argument_lists",
    "resolution_call_arguments",
    "resolution_call_obligations",
    "resolution_callable_parameter_lists",
    "resolution_callable_parameter_owners",
    "resolution_callable_parameter_semantics",
    "resolution_callable_signatures",
    "resolution_closure_literals",
    "resolution_closure_members",
    "resolution_compilation_imports",
    "resolution_construction_requirements",
    "resolution_contract_references",
    "resolution_csharp_friend_attributes",
    "resolution_declaration_modifiers",
    "resolution_declaration_types",
    "resolution_declared_type_arguments",
    "resolution_deferred_member_owners",
    "resolution_definition_property_gaps",
    "resolution_definition_unit_crosswalks",
    "resolution_extension_receivers",
    "resolution_extern_aliases",
    "resolution_fragment_interiors",
    "resolution_function_shape_parameters",
    "resolution_function_shapes",
    "resolution_gap_reasons",
    "resolution_gaps",
    "resolution_generic_formal_defaults",
    "resolution_generic_formals",
    "resolution_generic_type_alias_parameters",
    "resolution_go_package_imports",
    "resolution_implicit_root_candidates",
    "resolution_import_selectors",
    "resolution_inherent_implementations",
    "resolution_intrinsic_seed_identities",
    "resolution_intrinsic_seeds",
    "resolution_invocation_roles",
    "resolution_jvm_alias_owner_segments",
    "resolution_jvm_aliases",
    "resolution_macro_type_candidates",
    "resolution_macro_type_elements",
    "resolution_macro_type_segments",
    "resolution_member_owner_properties",
    "resolution_member_scope_properties",
    "resolution_member_type_coverage",
    "resolution_named_argument_labels",
    "resolution_node_catalog",
    "resolution_package_members",
    "resolution_package_object_exports",
    "resolution_package_references",
    "resolution_package_route_segments",
    "resolution_package_routes",
    "resolution_path_endpoint_headers",
    "resolution_path_terminal_headers",
    "resolution_paths",
    "resolution_qualified_routes",
    "resolution_reference_execution_contexts",
    "resolution_reference_lookup_identities",
    "resolution_reference_package_contexts",
    "resolution_root_import_demands",
    "resolution_root_import_segments",
    "resolution_root_imports",
    "resolution_root_route_segments",
    "resolution_rust_declaration_authorities",
    "resolution_rust_impl_declarations",
    "resolution_rust_reference_contexts",
    "resolution_rust_reverse_gap_candidates",
    "resolution_rust_structural_trait_impls",
    "resolution_semantic_catalog",
    "resolution_semantic_sites",
    "resolution_singleton_relations",
    "resolution_sites",
    "resolution_supertypes",
    "resolution_trait_implementations",
    "resolution_type_arguments",
    "resolution_type_components",
    "resolution_type_frontiers",
    "resolution_type_productions",
    "resolution_type_transfers",
    "resolution_typed_fact_lookups",
    "resolution_underlying_types",
    "rust_crate_inherent_impls",
    "rust_crate_root_references",
    "rust_crate_trait_impls",
    "rust_crate_unresolved_inherent_impls",
    "rust_crate_unresolved_trait_impls",
    "semantic_ir_allocations",
    "semantic_ir_blocks",
    "semantic_ir_call_arguments",
    "semantic_ir_call_control_classes",
    "semantic_ir_call_control_coverage",
    "semantic_ir_call_control_obligations",
    "semantic_ir_call_sites",
    "semantic_ir_callable_targets",
    "semantic_ir_captures",
    "semantic_ir_cleanup_actions",
    "semantic_ir_cleanup_anchors",
    "semantic_ir_cleanup_nodes",
    "semantic_ir_cleanup_owners",
    "semantic_ir_cleanup_projection_members",
    "semantic_ir_cleanup_projections",
    "semantic_ir_control_edges",
    "semantic_ir_declaration_segments",
    "semantic_ir_drops",
    "semantic_ir_event_async_suspends",
    "semantic_ir_event_callables",
    "semantic_ir_event_offsets",
    "semantic_ir_event_synchronizations",
    "semantic_ir_event_transfers",
    "semantic_ir_events",
    "semantic_ir_evidence",
    "semantic_ir_footprint_call_target_obligations",
    "semantic_ir_footprint_coverage",
    "semantic_ir_footprint_coverage_classes",
    "semantic_ir_gaps",
    "semantic_ir_guard_facts",
    "semantic_ir_guarded_pattern_projections",
    "semantic_ir_guarded_pattern_steps",
    "semantic_ir_incomplete_facts",
    "semantic_ir_locators",
    "semantic_ir_loop_sites",
    "semantic_ir_memory_locations",
    "semantic_ir_move_outs",
    "semantic_ir_partial_flow_heads",
    "semantic_ir_partial_flows",
    "semantic_ir_pointer_accesses",
    "semantic_ir_pointer_aliases",
    "semantic_ir_pointer_invalidations",
    "semantic_ir_pointer_origins",
    "semantic_ir_points",
    "semantic_ir_ports",
    "semantic_ir_procedures",
    "semantic_ir_publications",
    "semantic_ir_receiver_type_facts",
    "semantic_ir_result_type_classes",
    "semantic_ir_scope_ends",
    "semantic_ir_source_mappings",
    "semantic_ir_statement_entries",
    "semantic_ir_switch_cases",
    "semantic_ir_switch_facts",
    "semantic_ir_texts",
    "semantic_ir_values",
    "surface_ids",
    "surface_sets",
];

pub fn source_publications(
    store: &AnalyzerStore,
    keys: &[BlobKey],
) -> Vec<SourcePublicationWitness> {
    let keys = keys.to_vec();
    store.conn.execute(move |conn| {
        keys.iter()
            .map(|key| {
                SourcePublicationWitness::read(conn, key)
                    .unwrap()
                    .expect("healthy source publication")
            })
            .collect()
    })
}

fn permits_write(action: AuthAction<'_>) -> bool {
    match action {
        AuthAction::Insert {
            table_name: "resolution_declaration_visibility_properties",
        } => true,
        AuthAction::Insert { table_name } | AuthAction::Delete { table_name }
            if DERIVED_TABLES.contains(&table_name) =>
        {
            true
        }
        AuthAction::Update { table_name, .. } if DERIVED_TABLES.contains(&table_name) => true,
        AuthAction::Insert {
            table_name: "resolution_identities" | "blob_payload_costs" | "csharp_using_publications",
        } => true,
        // #13416 keeps the connection-local workspace selection fresh through
        // persistent triggers. They bump this cache-invalidation counter from
        // every writer, including derived publication. It carries no answer
        // content, so it is explicit bookkeeping outside DERIVED_TABLES.
        AuthAction::Insert {
            table_name: "workspace_selection_epochs",
        }
        | AuthAction::Update {
            table_name: "workspace_selection_epochs",
            ..
        } => true,
        AuthAction::Delete {
            table_name:
                "resolution_unit_summary_versions"
                | "rust_resolution_unit_summary_versions"
                | "csharp_using_publications",
        } => true,
        AuthAction::Update {
            table_name: "resolution_identities",
            column_name: "semantic_language" | "namespace" | "spelling",
        } => true,
        AuthAction::Update {
            table_name: "resolution_identity_recipe_generation",
            column_name: "generation",
        } => true,
        AuthAction::Update {
            table_name: "blob_payload_costs",
            column_name: "payload_bytes",
        } => true,
        AuthAction::Update {
            table_name: "blobs",
            column_name: "cascade_logical_rows" | "cascade_payload_bytes",
        } => true,
        AuthAction::Update {
            table_name: "csharp_compilation_using_coverage",
            column_name: "publications_installed" | "reasons",
        } => true,
        AuthAction::Insert { .. } | AuthAction::Delete { .. } | AuthAction::Update { .. } => false,
        _ => true,
    }
}

fn assert_derived_table_boundary(conn: &Connection) {
    let mut children = HashMap::<String, Vec<String>>::default();
    let mut statement = conn
        .prepare(
            "SELECT schema.name, fk.\"table\" FROM sqlite_schema AS schema
         JOIN pragma_foreign_key_list(schema.name) AS fk WHERE schema.type='table'",
        )
        .unwrap();
    for row in statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
    {
        let (child, parent) = row.unwrap();
        children.entry(parent).or_default().push(child);
    }
    let mut pending = vec![
        "resolution_fragment_interiors".to_owned(),
        "semantic_ir_publications".to_owned(),
        "surface_sets".to_owned(),
        "python_binding_source".to_owned(),
        "python_import_module_operands".to_owned(),
        "python_package_path_extensions".to_owned(),
        "resolution_binding_scopes".to_owned(),
    ];
    let mut derived = BTreeSet::new();
    while let Some(table) = pending.pop() {
        if derived.insert(table.clone()) {
            pending.extend(children.remove(&table).unwrap_or_default());
        }
    }
    assert_eq!(
        derived,
        DERIVED_TABLES
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        "the reviewed derived write boundary must cover exactly the publication FK families"
    );
}

/// Run the production writer with the reviewed write boundary enforced by SQLite.
pub fn audit_publications(
    store: &AnalyzerStore,
    prepared: Vec<PreparedAnalysisPublication>,
) -> (
    Vec<PersistPreparedOutcome<PreparedAnalysisPublication>>,
    PersistBatchStats,
    u64,
) {
    let counters = store.prepared_write_counters();
    store.conn.execute(move |conn| {
        assert_derived_table_boundary(conn);
        let denied = Arc::new(Mutex::new(BTreeSet::new()));
        let sink = Arc::clone(&denied);
        let before = conn.total_changes();
        let result = connection_authorizer::with_test_authorizer(
            conn,
            move |context: AuthContext<'_>| {
                if context.database_name == Some("main") && !permits_write(context.action) {
                    sink.lock().unwrap().insert(format!("{:?}", context.action));
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            },
            |conn| {
                PreparedPersistenceWriter::new(conn, counters, CancellationToken::default())
                    .persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION)
            },
        );
        assert!(
            denied.lock().unwrap().is_empty(),
            "writes outside derived authority: {:?}",
            denied.lock().unwrap()
        );
        (result.0, result.1, conn.total_changes() - before)
    })
}

/// A sealed derived job must not reopen the canonical Rust type decoder.
pub fn publish_without_source_recount(
    store: &AnalyzerStore,
    prepared: PreparedAnalysisPublication,
) -> (
    Vec<PersistPreparedOutcome<PreparedAnalysisPublication>>,
    PersistBatchStats,
) {
    let counters = store.prepared_write_counters();
    store.conn.execute(move |conn| {
        connection_authorizer::with_test_authorizer(
            conn,
            |context: AuthContext<'_>| {
                if matches!(
                    context.action,
                    AuthAction::Read {
                        table_name: "source_rust_type_segments",
                        ..
                    }
                ) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            },
            |conn| {
                PreparedPersistenceWriter::new(conn, counters, CancellationToken::default())
                    .persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION)
            },
        )
    })
}

/// The transaction body used by public selected-content admission. Admission
/// may add its captured owner's root; source rows remain outside its authority.
pub fn audit_selected_publication(
    store: &AnalyzerStore,
    owner: WorkspaceSnapshotId,
    path: String,
    prepared: PreparedParsedBlob,
) -> resolution_publication::ResolutionContentPublicationOutcome {
    store.conn.execute(move |conn| {
        let denied = Arc::new(Mutex::new(BTreeSet::new()));
        let sink = Arc::clone(&denied);
        let outcome = connection_authorizer::with_test_authorizer(
            conn,
            move |context: AuthContext<'_>| {
                let owner_root = matches!(
                    context.action,
                    AuthAction::Insert {
                        table_name: "workspace_resolution_content_roots"
                    }
                );
                if context.database_name == Some("main")
                    && !owner_root
                    && !permits_write(context.action)
                {
                    sink.lock().unwrap().insert(format!("{:?}", context.action));
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            },
            |conn| {
                resolution_publication::publish_selected_parsed_content_conn(
                    conn,
                    owner,
                    path,
                    prepared,
                    CancellationToken::default(),
                )
            },
        )
        .unwrap();
        assert!(
            denied.lock().unwrap().is_empty(),
            "selected admission wrote outside its authority: {:?}",
            denied.lock().unwrap()
        );
        outcome
    })
}

/// Compare with the unchanged full-source publication path, including cascades.
pub fn measure_source_replacement(
    store: &AnalyzerStore,
    prepared: Vec<PreparedParsedBlob>,
) -> (Vec<PersistBlobOutcome>, PersistBatchStats, u64) {
    let counters = store.prepared_write_counters();
    store.conn.execute(move |conn| {
        let before = conn.total_changes();
        let (outcomes, stats) = source_publication::repair_prepared_blobs_on_connection(
            conn,
            prepared,
            counters,
            CancellationToken::default(),
            PersistBatchTargets::PRODUCTION,
        );
        (outcomes, stats, conn.total_changes() - before)
    })
}

/// Install a predecessor publication without changing canonical source identity.
pub fn expire_resolution(store: &AnalyzerStore, lang: &str) {
    let lang = lang.to_owned();
    store.conn.execute(move |conn| {
        let _fixture = sealed_families::Fixture::new(conn);
        conn.execute("UPDATE resolution_fragment_interiors SET producer_epoch='10979-predecessor-resolution' WHERE lang=?1", [&lang]).unwrap();
        conn.execute("UPDATE resolution_producer_epochs SET producer_epoch='10979-predecessor-resolution' WHERE lang=?1", [&lang]).unwrap();
    });
}

pub fn expire_semantic_ir(store: &AnalyzerStore, lang: &str) {
    let lang = lang.to_owned();
    store.conn.execute(move |conn| {
        conn.execute("UPDATE semantic_ir_publications SET producer_epoch='10979-predecessor-ir' WHERE lang=?1", [&lang]).unwrap();
        conn.execute("UPDATE semantic_ir_producer_epochs SET producer_epoch='10979-predecessor-ir' WHERE lang=?1", [&lang]).unwrap();
    });
}

pub struct ResolutionPublicationFailure<'store> {
    store: &'store AnalyzerStore,
}

pub fn fail_resolution_publication(store: &AnalyzerStore) -> ResolutionPublicationFailure<'_> {
    store.conn.execute(|conn| conn.execute_batch(
        "CREATE TEMP TRIGGER reject_test_resolution_publication BEFORE INSERT ON main.resolution_fragment_interiors
         BEGIN SELECT RAISE(ABORT, 'injected resolution publication failure'); END"
    ).unwrap());
    ResolutionPublicationFailure { store }
}

impl Drop for ResolutionPublicationFailure<'_> {
    fn drop(&mut self) {
        self.store.conn.execute(|conn| {
            conn.execute_batch("DROP TRIGGER temp.reject_test_resolution_publication")
                .unwrap()
        });
    }
}

/// Content rows, with database-owned backing IDs translated to full content keys.
/// Surface witnesses identify the canonical backing, whose replacement is exactly
/// the difference under test; the source-preserving arm separately pins them.
pub fn derived_rows(store: &AnalyzerStore) -> Vec<(String, Vec<String>)> {
    store.conn.execute(|conn| {
        let blob_keys = conn
            .prepare("SELECT id, blob_oid, lang, hex(parse_variant) FROM blobs")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    format!(
                        "{}/{}/{}",
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?
                    ),
                ))
            })
            .unwrap()
            .collect::<std::result::Result<HashMap<_, _>, _>>()
            .unwrap();
        let surface_keys = conn
            .prepare("SELECT set_id, blob_id FROM surface_sets")
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<std::result::Result<HashMap<_, _>, _>>()
            .unwrap();
        let operation_keys = conn
            .prepare("SELECT id,blob_id,site,form FROM python_member_operations")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    (
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ),
                ))
            })
            .unwrap()
            .map(|row| {
                let (id, (blob, site, form)) = row.unwrap();
                (id, format!("{}/{site}/{form}", blob_keys[&blob]))
            })
            .collect::<HashMap<_, _>>();
        let python_surface_sets = conn.prepare(
            "SELECT sets.set_id FROM surface_sets sets JOIN blobs ON blobs.id=sets.blob_id WHERE blobs.lang='python'"
        ).unwrap().query_map([], |row| row.get::<_,i64>(0)).unwrap()
            .collect::<std::result::Result<BTreeSet<_>,_>>().unwrap();
        let mut result = Vec::new();
        for &table in DERIVED_TABLES {
            let blob_columns = conn
                .prepare(
                    "SELECT \"from\" FROM pragma_foreign_key_list(?1)
                 WHERE \"to\"='blob_id' OR (\"table\"='blobs' AND \"to\"='id')",
                )
                .unwrap()
                .query_map([table], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<BTreeSet<_>, _>>()
                .unwrap();
            let mut statement = conn.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = statement
                .column_names()
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>();
            let mut rows = statement.query([]).unwrap();
            let mut values = Vec::new();
            while let Some(row) = rows.next().unwrap() {
                let mut cells = Vec::new();
                for (index, column) in columns.iter().enumerate() {
                    if table == "surface_sets" && column == "publication_witness" {
                        continue;
                    }
                    // Cleanup rows have allocation-only backing IDs. Their
                    // procedure/node/ordinal/anchor/projection keys and every
                    // foreign key use the logical columns retained below.
                    if column == "id"
                        && matches!(
                            table,
                            "semantic_ir_cleanup_nodes"
                                | "semantic_ir_cleanup_actions"
                                | "semantic_ir_cleanup_anchors"
                                | "semantic_ir_cleanup_owners"
                                | "semantic_ir_cleanup_projections"
                                | "candidate_macro_semantic_ir_cleanup_nodes"
                                | "candidate_macro_semantic_ir_cleanup_actions"
                                | "candidate_macro_semantic_ir_cleanup_anchors"
                                | "candidate_macro_semantic_ir_cleanup_owners"
                                | "candidate_macro_semantic_ir_cleanup_projections"
                        )
                    {
                        continue;
                    }
                    let value: rusqlite::types::Value = row.get(index).unwrap();
                    let value = match (column.as_str(), value) {
                        // Python's surface space 3 is the blob owner itself;
                        // other languages assign that space to other entities.
                        ("dense_id", rusqlite::types::Value::Integer(id))
                            if table == "surface_ids" && row.get::<_,i64>("id_space").unwrap() == 3
                                && python_surface_sets.contains(&row.get::<_,i64>("set_id").unwrap()) => blob_keys[&id].clone(),
                        ("id", rusqlite::types::Value::Integer(id))
                            if table == "python_member_operations" =>
                        {
                            operation_keys[&id].clone()
                        }
                        ("operation", rusqlite::types::Value::Integer(id))
                            if table == "python_member_operation_names" =>
                        {
                            operation_keys[&id].clone()
                        }
                        (_, rusqlite::types::Value::Integer(id))
                            if blob_columns.contains(column) =>
                        {
                            blob_keys[&id].clone()
                        }
                        ("set_id", rusqlite::types::Value::Integer(id))
                            if table == "surface_sets" || table == "surface_ids" =>
                        {
                            blob_keys[&surface_keys[&id]].clone()
                        }
                        (_, value) => format!("{value:?}"),
                    };
                    cells.push((column, value));
                }
                values.push(format!("{cells:?}"));
            }
            values.sort_unstable();
            result.push((table.to_owned(), values));
        }
        result
    })
}
