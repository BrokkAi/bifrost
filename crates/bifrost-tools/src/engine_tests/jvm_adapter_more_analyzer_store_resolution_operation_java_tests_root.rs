#[cfg(test)]
#[doc(hidden)]
pub mod jvm_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
    use brokk_bifrost_analysis::native_resolution_test_support::BatchResolutionFragmentSource;
    use brokk_bifrost_analysis::native_resolution_test_support::SelectedTypedFactSource;

    use std::sync::Arc;

    use std::collections::BTreeSet;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::FactReverseResolutionMetrics;

    use brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::java_query_tests::JAVA_ROOT_CONSUMER_PATH;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::java_query_tests::JAVA_ROOT_DECOY_PATH;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::java_query_tests::JAVA_ROOT_PROVIDER_PATH;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::java_query_tests::JAVA_ROOT_SOURCES;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::MutableGenerationProject as MutableGenerationProject;

    use git2::ObjectType;

    use git2::Oid;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PreloadedFactResolutionService;

    use brokk_bifrost_analysis::analyzer::resolution::model::ResolutionCompletion;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionIdentifierRole;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::SelectedFactOperationBlueprintConstruction;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionContextMetrics;

    use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedResolutionContextSet;

    use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedResolutionContextValidationOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionLocated;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperation;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationInput;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOpenOutcome;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceId;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshots;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::tests::java_query_tests::assert_java_import_route_proof_delta;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::parsed_operation_state as parsed_operation_state;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_mount_lookup;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::semantic_at as semantic_at;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::site_for_identifier as site_for_identifier;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::try_site_for_identifier as try_site_for_identifier;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::mount_lookup as mount_lookup;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::resolution_operation_tests_go_support::operation_fixture_support::assert_empty_context_metrics as assert_empty_context_metrics;
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5600: JVM preparation classified and checked one reference at a time"
    )]
    fn jvm_preparation_batches_classification_membership_and_recipe_reads() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContext;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection,
            finish_production_selected_sql_trace_on_connection,
        };
        let mut source = String::from(
            "package a; class Use extends dep.Base implements dep.I1, dep.I2, dep.I3, dep.I4 { ",
        );
        for n in 0..300 {
            source.push_str(&format!("dep.Type{n} field{n}; "));
        }
        source.push('}');
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                source.as_str(),
                "package dep; public class Base {} interface I1 {} interface I2 {} interface I3 {} interface I4 {}",
                "package z; class Other {}",
            ],
            ["src/a/Use.java", "src/dep/Base.java", "src/z/Other.java"],
            &[],
        );
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let connection = operation.ready.inventory.connection();
        begin_production_selected_sql_trace_on_connection(connection);
        assert!(matches!(
            operation
                .jvm_import_context(Language::Java, "src/a/Use.java", &cancellation)
                .unwrap(),
            JvmImportContext::Ready { .. }
        ));
        let cost = finish_production_selected_sql_trace_on_connection(connection);
        let membership = cost
            .statements
            .iter()
            .zip(&cost.rows_by_statement)
            .filter(|(sql, _)| {
                sql.contains("SELECT DISTINCT reference")
                    && sql.contains("resolution_supertypes_reference")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            membership.len(),
            2,
            "305 source references use two bounded membership pages: {cost:?}"
        );
        assert_eq!(
            membership.iter().map(|(_, rows)| **rows).sum::<usize>(),
            5,
            "all five positive memberships survive"
        );
        assert!(
            !cost.statements.iter().any(
                |sql| sql.starts_with("SELECT EXISTS(SELECT 1 FROM main.resolution_supertypes")
            )
        );
        assert!(
            cost.statements
                .iter()
                .zip(&cost.rows_by_statement)
                .any(|(sql, rows)| sql.starts_with("SELECT node.local_key,node.kind") && *rows > 1),
            "shared classification actually batched"
        );
        let recipes = cost
            .statements
            .iter()
            .filter(|sql| {
                sql.starts_with(
                    "SELECT id, semantic_language, namespace, spelling, identity_digest",
                )
            })
            .count();
        assert_eq!(
            recipes, 2,
            "preparation recipes are prefetched in two pages: {cost:?}"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5600: wildcard import token metadata was reread and must respect staged NULL suppression"
    )]
    fn jvm_import_token_projection_is_operation_owned_and_stage_sensitive() {
        use brokk_bifrost_analysis::analyzer::resolution::SemanticId;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection,
            finish_production_selected_sql_trace_on_connection,
        };
        let fixture = JavaRootResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let mount = operation
            .ready
            .inventory
            .mount_record_for_path("java", JAVA_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let source = mount.ordinal();
        let blob = mount.blob_id();
        let connection = operation.ready.inventory.connection();
        let token: u32 = connection.query_row("SELECT local_key FROM resolution_semantic_catalog WHERE blob_id=?1 AND import_route_kind IS NOT NULL LIMIT 1", [blob], |row| row.get(0)).unwrap();
        let semantic = SemanticId::local(source.get(), token);
        begin_production_selected_sql_trace_on_connection(connection);
        let first = operation
            .jvm_import_token_metadata(blob, source, semantic, &cancellation)
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(
            &first,
            &operation
                .jvm_import_token_metadata(blob, source, semantic, &cancellation)
                .unwrap()
                .unwrap()
        ));
        let cost = finish_production_selected_sql_trace_on_connection(connection);
        assert_eq!(cost.statement_count(), 1, "memo hit emits no SQL: {cost:?}");
        operation.ready.inventory.with_owned_temp_write(|conn| {
            conn.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",rusqlite::params![source.get(),[201u8;32].as_slice(),[202u8;32].as_slice()])?;
            let producer = conn.last_insert_rowid();
            conn.execute("INSERT INTO temp.selected_resolution_stage_semantic_coordinates(host_ordinal,producer_id,dense_key,runtime_key,identity_digest) VALUES(?1,?2,0,?3,?4)",rusqlite::params![source.get(),producer, i64::try_from(semantic.get()).unwrap(),[203u8;32].as_slice()])?;
            Ok(())
        }).unwrap();
        begin_production_selected_sql_trace_on_connection(connection);
        let staged = operation
            .jvm_import_token_metadata(blob, source, semantic, &cancellation)
            .unwrap()
            .unwrap();
        let cost = finish_production_selected_sql_trace_on_connection(connection);
        assert!(!Arc::ptr_eq(&first, &staged));
        assert!(first.selected_route_kind().is_some());
        assert!(
            staged.selected_route_kind().is_none(),
            "staged NULL suppresses the main route in the decoded projection"
        );
        assert_eq!(
            cost.statement_count(),
            1,
            "direct stage write forces an actual read"
        );
        let row = connection
            .query_row(
                &cost.statements[0],
                rusqlite::params![
                    blob,
                    token,
                    source.get(),
                    i64::try_from(semantic.get()).unwrap(),
                    Option::<i64>::None
                ],
                |row| {
                    Ok((
                        row.get::<_, bool>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .unwrap();
        assert!(
            row.0 && row.1.is_none() && row.2.is_some(),
            "staged coordinate retains NULL route independently of ordinary selector/route: {row:?}"
        );
        let absent = SemanticId::local(source.get(), u32::MAX);
        begin_production_selected_sql_trace_on_connection(connection);
        let empty = operation
            .jvm_import_token_metadata(blob, source, absent, &cancellation)
            .unwrap()
            .unwrap();
        assert!(Arc::ptr_eq(
            &empty,
            &operation
                .jvm_import_token_metadata(blob, source, absent, &cancellation)
                .unwrap()
                .unwrap()
        ));
        assert_eq!(
            finish_production_selected_sql_trace_on_connection(connection).statement_count(),
            1
        );
        operation.ready.inventory.note_stage_content_commit();
        assert!(!Arc::ptr_eq(
            &staged,
            &operation
                .jvm_import_token_metadata(blob, source, semantic, &cancellation)
                .unwrap()
                .unwrap()
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6291: JVM fallback source discovery read every mount's reverse inventory"
    )]
    fn jvm_fallback_anchor_horizon_bounds_gaps_but_keeps_overlay_inventory() {
        use brokk_bifrost_analysis::analyzer::resolution::selected_context::{
            SelectedRootPathHalf, visit_selected_root_import_half_pages,
        };
        use brokk_bifrost_analysis::analyzer::resolution::{
            BindingNodeId, EndpointSignature, FactPageVisitor, SelectedSemanticProvenance,
            StackPattern,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
            demand_closure::Read,
            selected_sql_trace::{
                begin_production_selected_sql_trace_on_connection,
                finish_production_selected_sql_trace_on_connection,
            },
            source_demand::root_source_set,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionOverlayMask;
        let paths = ["src/a/Use.java", "src/dep/Target.java", "src/z/Other.java"];
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                "package a; import dep.Target; class Use { Target field; }",
                "package dep; public class Target {}",
                "package z; class Other {}",
            ],
            paths,
            &[],
        );
        // Give every host a distinct reverse inventory reason, including hosts
        // whose paths cannot carry this exact source anchor.
        fixture.store.conn.execute(|connection| {
            connection.execute("INSERT INTO resolution_gap_reasons(blob_id,reason,site,origin) SELECT blob_id,930002,0,2 FROM resolution_fragment_interiors", []).unwrap();
            connection.execute("INSERT INTO resolution_gaps(blob_id,covers,subject,lookup,gap,reason) SELECT blob_id,3,0,0,930002,930002 FROM resolution_fragment_interiors", []).unwrap();
        });
        let cancellation = CancellationToken::new();
        let masks = [SelectedResolutionOverlayMask::removal("java", paths[2])];
        for overlay in [false, true] {
            let input = SelectedResolutionOperationInput::new(
                &fixture.project,
                &fixture.workspace_id,
                &fixture.snapshots,
                &fixture.languages,
                if overlay { &masks } else { &[] },
            );
            let SelectedResolutionOperationOpenOutcome::Ready(operation) = fixture
                .store
                .open_selected_resolution_operation(input, &cancellation)
                .unwrap()
            else {
                panic!("fixture selection is ready");
            };
            let source = operation
                .mount_table()
                .mount_for_path("java", paths[0])
                .unwrap()
                .unwrap();
            let lexical = operation.ready.lexical_source();
            let mut endpoint = None;
            let outcome = visit_selected_root_import_half_pages(
                &operation.ready.context_identities,
                &lexical,
                &lexical,
                Some(&[source.ordinal()]),
                &cancellation,
                &mut FactPageVisitor::new(&mut |page| {
                    for half in page {
                        if let SelectedRootPathHalf::Import {
                            anchor_semantic,
                            route,
                            token,
                            demand,
                            ..
                        } = half
                        {
                            endpoint = Some(EndpointSignature::new(
                                BindingNodeId::universal_root(),
                                StackPattern::closed(
                                    std::iter::once(*anchor_semantic)
                                        .chain(route.iter().copied())
                                        .chain([*token, *demand])
                                        .collect::<Vec<_>>(),
                                ),
                                StackPattern::closed([]),
                            ));
                        }
                    }
                    Ok(true)
                }),
            )
            .unwrap();
            assert!(outcome.is_exhausted());
            let endpoint = endpoint.expect("authored import supplies a fallback endpoint");
            assert!(matches!(
                lexical
                    .semantic_provenance(endpoint.symbols().fixed()[0].symbol(), &cancellation)
                    .unwrap(),
                Some(SelectedSemanticProvenance::FragmentLocal(_))
            ));
            assert!(
                endpoint.symbols().fixed()[1]
                    .symbol()
                    .shared_name_id()
                    .is_some(),
                "slot one is a route segment, so the package-token shortcut cannot apply"
            );
            // Invalidate setup's completion memo without changing the source
            // inventory, so the trace proves that fallback SQL actually ran.
            operation.ready.inventory.with_owned_temp_write(|connection| {
                connection.execute("UPDATE temp.selected_resolution_scope_mounts SET mount_ordinal=mount_ordinal", [])?;
                Ok(())
            }).unwrap();
            let connection = operation.ready.inventory.connection();
            let count = |mount: Option<u32>| {
                connection.query_row(
                "SELECT COUNT(*) FROM resolution_gaps gap JOIN temp.selected_resolution_mounts mounted ON mounted.blob_id=gap.blob_id WHERE gap.covers IN (0,3) AND (?1 IS NULL OR mounted.mount_ordinal=?1)",
                [mount], |row| row.get::<_, usize>(0),
            ).unwrap()
            };
            let source_rows = count(Some(source.ordinal().get()));
            let all_rows = count(None);
            assert!(all_rows > source_rows && source_rows > 0);
            begin_production_selected_sql_trace_on_connection(connection);
            let answer = root_source_set(
                &operation.ready,
                &lexical,
                &endpoint,
                None,
                &ResolutionSession::unbounded(),
                &cancellation,
            )
            .unwrap();
            let trace = finish_production_selected_sql_trace_on_connection(connection);
            assert!(
                matches!(answer, Read::Ready { value: Some(_), .. }),
                "the fallback must discover its actual source half"
            );
            let reads = trace
                .statements
                .iter()
                .zip(&trace.rows_by_statement)
                .filter(|(sql, _)| {
                    sql.starts_with("SELECT m.mount_ordinal, h.reason")
                        && sql.contains("resolution_gaps_fragment_wide")
                })
                .collect::<Vec<_>>();
            assert_eq!(reads.len(), 1, "overlay={overlay}: {trace:?}");
            assert_eq!(
                reads[0].0.contains("json_each"),
                !overlay,
                "overlay={overlay}: {trace:?}"
            );
            assert_eq!(
                *reads[0].1,
                if overlay { all_rows } else { source_rows },
                "overlay={overlay}: {trace:?}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6291: package selection enumerated unrelated hosts and must retain staged-only uncertainty"
    )]
    fn selected_jvm_named_package_hosts_skip_closed_decoys_but_keep_staged_members() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContext;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::package_context::SelectedPackageRows;
        use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec::{
            encode_node, encode_semantic,
        };
        let paths = [
            "src/dep/Use.java",
            "src/dep/Target.java",
            "src/dep/Other.java",
        ];
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                "package dep; class Use { Target field; Missing absent; }",
                "package dep; public class Target {}",
                "package dep; class Other {}",
            ],
            paths,
            &[],
        );
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        *operation.ready.jvm_context_profile.borrow_mut() = Some(Default::default());
        let other = operation
            .ready
            .inventory
            .mount_record_for_path("java", paths[2])
            .unwrap()
            .unwrap()
            .ordinal();
        let derived_other = || {
            operation
                .ready
                .jvm_context_profile
                .borrow()
                .as_ref()
                .unwrap()
                .calls
                .keys()
                .any(|(kind, key)| {
                    *kind == "derive_package_members" && key.contains(&format!("mount: {other:?},"))
                })
        };
        assert!(matches!(
            operation
                .jvm_import_context(Language::Java, paths[0], &cancellation)
                .unwrap(),
            JvmImportContext::Ready { .. }
        ));
        assert!(
            operation
                .ready
                .jvm_context_profile
                .borrow()
                .as_ref()
                .unwrap()
                .calls("derive_named_package_targets")
                > 0,
            "the name-first selector actually ran"
        );
        assert!(
            !derived_other(),
            "a closed host with no requested member is not enumerated"
        );
        // A staged member alone, with no staged path or gap, must keep its host
        // in the uncertainty inventory independently of the requested names.
        let SelectedPackageRows::Ready(members) = operation
            .selected_package_members_by_lookup(other, &cancellation)
            .unwrap()
        else {
            panic!("fixture members ready");
        };
        let member = *members.values().next().unwrap().first().unwrap();
        operation.ready.inventory.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",
                rusqlite::params![other.get(), [191_u8;32].as_slice(), [192_u8;32].as_slice()])?;
            let producer = connection.last_insert_rowid();
            connection.execute("INSERT INTO temp.selected_resolution_stage_package_members(host_ordinal,producer_id,token_key,domain_shared,definition_key,source_site,root_scope_key,namespace,lookup_shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![other.get(), producer, encode_semantic(member.token), member.domain.shared_name_id().unwrap().get(), encode_semantic(member.definition), member.source_site.get(), encode_node(member.root_scope), member.namespace.label(), member.lookup.shared_name_id().unwrap().get()])?;
            Ok(())
        }).unwrap();
        assert!(matches!(
            operation
                .jvm_import_context(Language::Java, paths[0], &cancellation)
                .unwrap(),
            JvmImportContext::Ready { .. }
        ));
        assert!(
            derived_other(),
            "staged-only host authority survives an ordinary name miss"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6291: named JVM import selection repeated empty reads and must not cache absence across staged writes"
    )]
    fn selected_jvm_named_import_targets_cache_empty_answers_and_invalidate_staged_uncertainty() {
        let fixture = JavaRootResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        *operation.ready.jvm_context_profile.borrow_mut() = Some(Default::default());
        let statement = brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JVM_IMPORT_TARGET_MOUNTS;
        let read = |namespace| {
            operation
                .jvm_named_import_targets(
                    statement,
                    "dep",
                    "NoSuchOwner",
                    &[namespace],
                    Language::Java,
                    &cancellation,
                )
                .unwrap()
                .unwrap()
        };
        let derivations = || {
            operation
                .ready
                .jvm_context_profile
                .borrow()
                .as_ref()
                .unwrap()
                .calls("derive_named_import_targets")
        };
        let first = read(ResolutionNamespace::Type);
        assert!(first.is_empty());
        assert_eq!(derivations(), 1, "the empty SQL read actually ran");
        assert!(Arc::ptr_eq(&first, &read(ResolutionNamespace::Type)));
        assert_eq!(derivations(), 1, "the empty answer is shared");
        assert!(read(ResolutionNamespace::Value).is_empty());
        assert_eq!(derivations(), 2, "namespace is part of the key");
        operation.ready.inventory.note_stage_content_commit();
        let after_publication = read(ResolutionNamespace::Type);
        assert!(after_publication.is_empty());
        assert!(!Arc::ptr_eq(&first, &after_publication));
        assert_eq!(derivations(), 3, "content publication invalidates absence");
        let host = operation
            .mounts()
            .unwrap()
            .iter()
            .find(|mount| mount.persisted_relative_path() == JAVA_ROOT_PROVIDER_PATH)
            .unwrap()
            .ordinal()
            .get();
        let producer = operation.ready.inventory.with_owned_temp_write(|connection| {
            connection.execute(
                "INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)",
                rusqlite::params![host,[181u8;32].as_slice(),[182u8;32].as_slice()],
            )?;
            let producer = connection.last_insert_rowid();
            connection.execute(
                "INSERT INTO temp.selected_resolution_stage_gaps(host_ordinal,producer_id,covers,gap_key,reason_key,source_site,origin) VALUES(?1,?2,2,0,0,0,0)",
                rusqlite::params![host,producer],
            )?;
            Ok(producer)
        }).unwrap();
        assert!(
            !read(ResolutionNamespace::Type).is_empty(),
            "a staged gap keeps its package host eligible"
        );
        assert_eq!(derivations(), 4, "direct TEMP writes invalidate absence");
        operation
            .ready
            .inventory
            .with_owned_temp_write(|connection| {
                connection.execute(
                    "DELETE FROM temp.selected_resolution_stage_producers WHERE producer_id=?1",
                    [producer],
                )?;
                Ok(())
            })
            .unwrap();
        assert!(read(ResolutionNamespace::Type).is_empty());
        assert_eq!(
            derivations(),
            5,
            "removing staged authority refreshes the answer"
        );
        cancellation.cancel();
        assert!(
            operation
                .jvm_named_import_targets(
                    statement,
                    "dep",
                    "NoSuchOwner",
                    &[ResolutionNamespace::Type],
                    Language::Java,
                    &cancellation
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            derivations(),
            5,
            "a cancelled read does not publish an answer"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "7052beabe6ed: JVM demand roots repeatedly rebuilt identical file contexts"
    )]
    fn selected_jvm_file_context_reuses_derivation_only_within_one_operation() {
        let fixture = JavaRootResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        *operation.ready.jvm_context_profile.borrow_mut() = Some(Default::default());
        let derivations = |operation: &SelectedResolutionOperation<'_, '_>, kind: &str| {
            operation
                .ready
                .jvm_context_profile
                .borrow()
                .as_ref()
                .unwrap()
                .calls(kind)
        };
        let source_mount = |operation: &SelectedResolutionOperation<'_, '_>| {
            operation
                .mounts()
                .unwrap()
                .iter()
                .find(|mount| mount.persisted_relative_path() == JAVA_ROOT_CONSUMER_PATH)
                .unwrap()
                .ordinal()
        };
        let check_import_facts = |operation: &SelectedResolutionOperation<'_, '_>| {
            let blob = operation
                .ready
                .inventory
                .mount_record_by_ordinal(source_mount(operation))
                .unwrap()
                .blob_id();
            let alias_before = derivations(operation, "derive_alias_rows");
            for _ in 0..2 {
                assert!(
                    operation
                        .jvm_alias_rows(blob, "absentAlias", &cancellation)
                        .unwrap()
                        .unwrap()
                        .is_empty()
                );
            }
            assert_eq!(
                derivations(operation, "derive_alias_rows"),
                alias_before + 1
            );
            assert!(
                operation
                    .jvm_alias_rows(blob, "differentAlias", &cancellation)
                    .unwrap()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                derivations(operation, "derive_alias_rows"),
                alias_before + 2
            );
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            assert!(
                operation
                    .jvm_alias_rows(blob, "absentAlias", &cancelled)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                derivations(operation, "derive_alias_rows"),
                alias_before + 2
            );
            let first =
                operation.jvm_generated_lookup(Language::Java, ResolutionNamespace::Type, "Use");
            let second =
                operation.jvm_generated_lookup(Language::Java, ResolutionNamespace::Type, "Use");
            assert!(Arc::ptr_eq(&first, &second));
            let statement = brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JVM_IMPORT_TARGET_MOUNTS;
            for _ in 0..2 {
                let _rows = operation.jvm_import_targets(statement, "dep").unwrap();
            }
            assert_eq!(derivations(operation, "derive_import_targets"), 1);
            let lookup = ResolutionLookupSemanticRecipe::new(
                Language::Java,
                ResolutionNamespace::Type,
                "Use",
            )
            .semantic(&operation.ready.shared_names());
            for _ in 0..2 {
                assert!(matches!(
                operation
                    .jvm_package_members_for_lookup(source_mount(operation), lookup, &cancellation)
                    .unwrap(),
                brokk_bifrost_analysis::analyzer::store::resolution_operation::package_context::SelectedPackageRows::Ready(_)
            ));
            }
            assert_eq!(derivations(operation, "derive_package_members"), 1);
            let brokk_bifrost_analysis::analyzer::store::resolution_operation::package_context::SelectedPackageRows::Ready(members) = operation
            .jvm_package_members_for_lookup(source_mount(operation), lookup, &cancellation)
            .unwrap()
        else {
            panic!("fixture package members are ready");
        };
            let definition = members
                .first()
                .expect("the fixture publishes class Use")
                .definition;
            let node = operation
                .ready
                .lexical_source()
                .lookup_definition_node(definition, &cancellation)
                .unwrap()
                .unwrap();
            for _ in 0..2 {
                let rows = operation
                    .jvm_endpoint_classifications(node, &cancellation)
                    .unwrap()
                    .unwrap();
                assert!(rows.iter().any(|row| row.definition() == Some(definition)));
                assert!(
                    operation
                        .jvm_declaration_visibilities(definition, &cancellation)
                        .unwrap()
                        .is_some()
                );
            }
            assert_eq!(derivations(operation, "derive_endpoint"), 1);
            assert_eq!(derivations(operation, "derive_visibility"), 1);
            (lookup, node, definition)
        };
        let (lookup, node, definition) = check_import_facts(&operation);
        for _ in 0..2 {
            assert!(
                operation
                    .jvm_root_exports(source_mount(&operation), &cancellation)
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(
            derivations(&operation, "derive_root_exports"),
            1,
            "the same selected root inventory is read once"
        );
        for _ in 0..2 {
            assert!(matches!(
            operation
                .jvm_import_context(Language::Java, JAVA_ROOT_CONSUMER_PATH, &cancellation)
                .unwrap(),
            brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContext::Ready { .. }
        ));
        }
        assert_eq!(
            derivations(&operation, "derive_file_context"),
            1,
            "the same selected file is derived once"
        );

        // #5600: another name must not replay invariant import/provider work or
        // recompile already published provider cells inside this one request.
        let import_derivations = derivations(&operation, "derive_import");
        let java_import_derivations = derivations(&operation, "derive_java_import");
        let implicit_derivations = derivations(&operation, "derive_implicit_context");
        let compile_context = |context: brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContext| {
        let brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContext::Ready { context, .. } = context else {
            panic!("fixture context is ready");
        };
        let SelectedResolutionContextValidationOutcome::Ready(context) = (*context)
            .validate_exact_mounts(
                operation.mount_table().mount_count(),
                &selected_mount_lookup(operation.mount_table()),
                &cancellation,
            )
            .unwrap()
        else {
            panic!("fixture context validates");
        };
        assert!(matches!(
            operation
                .ready.collect_blueprint_with_projection_memo(
                    context,
                    Some(&operation.jvm_context_blueprints),
                    &cancellation,
                    &ResolutionSession::unbounded()
                )
                .unwrap(),
            SelectedFactOperationBlueprintConstruction::Ready(_)
        ));
    };
        compile_context(
            operation
                .jvm_import_context(Language::Java, JAVA_ROOT_CONSUMER_PATH, &cancellation)
                .unwrap(),
        );
        let root_compilations = derivations(&operation, "compile_root_context_cell");
        let package_compilations = derivations(&operation, "compile_package_context_cell");
        assert!(root_compilations > 0, "the fixture has a source import");
        for name in ["Target", "Unrelated", "Target"] {
            compile_context(
                operation
                    .jvm_import_context_for_name(
                        Language::Java,
                        JAVA_ROOT_CONSUMER_PATH,
                        name,
                        &cancellation,
                    )
                    .unwrap(),
            );
        }
        assert_eq!(derivations(&operation, "derive_file_context"), 1);
        assert_eq!(derivations(&operation, "derive_import"), import_derivations);
        assert_eq!(
            derivations(&operation, "derive_java_import"),
            java_import_derivations
        );
        assert_eq!(
            derivations(&operation, "derive_implicit_context"),
            implicit_derivations
        );
        assert_eq!(
            derivations(&operation, "compile_root_context_cell"),
            root_compilations
        );
        assert_eq!(
            derivations(&operation, "compile_package_context_cell"),
            package_compilations
        );

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let endpoint_reads = derivations(&operation, "derive_endpoint");
        let visibility_reads = derivations(&operation, "derive_visibility");
        assert!(
            operation
                .jvm_endpoint_classifications(node, &cancelled)
                .unwrap()
                .is_none()
        );
        assert!(
            operation
                .jvm_declaration_visibilities(definition, &cancelled)
                .unwrap()
                .is_none()
        );
        assert_eq!(derivations(&operation, "derive_endpoint"), endpoint_reads);
        assert_eq!(
            derivations(&operation, "derive_visibility"),
            visibility_reads
        );
        let member_reads = derivations(&operation, "derive_package_members");
        assert!(matches!(
        operation
            .jvm_package_members_for_lookup(source_mount(&operation), lookup, &cancelled)
            .unwrap(),
        brokk_bifrost_analysis::analyzer::store::resolution_operation::package_context::SelectedPackageRows::Cancelled
    ));
        assert_eq!(
            derivations(&operation, "derive_package_members"),
            member_reads
        );
        let root_reads = derivations(&operation, "derive_root_exports");
        assert!(
            operation
                .jvm_root_exports(source_mount(&operation), &cancelled)
                .unwrap()
                .is_none()
        );
        assert_eq!(derivations(&operation, "derive_root_exports"), root_reads);
        for path in [JAVA_ROOT_CONSUMER_PATH, JAVA_ROOT_PROVIDER_PATH] {
            assert!(matches!(
            operation
                .jvm_import_context(Language::Java, path, &cancelled)
                .unwrap(),
            brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContext::Cancelled
        ));
        }
        assert!(matches!(
        operation
            .jvm_import_context(Language::Java, JAVA_ROOT_PROVIDER_PATH, &cancellation)
            .unwrap(),
        brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContext::Ready { .. }
    ));
        assert_eq!(
            derivations(&operation, "derive_file_context"),
            2,
            "cancelled input did not poison a second file"
        );
        drop(operation);

        let operation = fixture.open_ready(&cancellation);
        *operation.ready.jvm_context_profile.borrow_mut() = Some(Default::default());
        check_import_facts(&operation);
        assert!(
            operation
                .jvm_root_exports(source_mount(&operation), &cancellation)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            derivations(&operation, "derive_root_exports"),
            1,
            "a new operation reads its own root inventory"
        );
        assert!(matches!(
        operation
            .jvm_import_context(Language::Java, JAVA_ROOT_CONSUMER_PATH, &cancellation)
            .unwrap(),
        brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JvmImportContext::Ready { .. }
    ));
        assert_eq!(
            derivations(&operation, "derive_file_context"),
            1,
            "a new operation derives its own context"
        );
    }
    #[test]
    fn selected_java_root_context_matches_preload_reopens_and_excludes_decoy() {
        let fixture = JavaRootResolutionOperationFixture::new();
        assert!(assert_java_root_parity(&fixture));
        let fixture = fixture.reopen();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            fixture.open(&cancelled),
            SelectedResolutionOperationOpenOutcome::Cancelled
        ));
        assert!(assert_java_root_parity(&fixture));
    }
    #[test]
    fn selected_java_provider_withdrawal_invalidates_old_context_and_keeps_import_open() {
        let mut fixture = JavaRootResolutionOperationFixture::new();
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let old_context = fixture.contexts_for(&operation);
        drop(operation);
        fixture
            .source_rows
            .retain(|row| row.rel_path != JAVA_ROOT_PROVIDER_PATH);
        let snapshot = fixture
            .store
            .sync_workspace_inputs_for_workspace(
                &fixture.workspace_id,
                "java",
                fixture.snapshots["java"].generation,
                &fixture.source_rows,
                &[],
                &[],
                &fixture
                    .package_rows
                    .iter()
                    .filter(|row| row.rel_path != JAVA_ROOT_PROVIDER_PATH)
                    .cloned()
                    .collect::<Vec<_>>(),
                &[],
                &[],
                &fixture.configuration,
                &[],
                &[],
            )
            .unwrap();
        fixture
            .store
            .reconcile_jvm_package_context(&snapshot)
            .unwrap();
        fixture.snapshots.insert("java".to_owned(), snapshot);
        let operation = fixture.open_ready(&cancellation);
        let mounts = operation.mounts().unwrap();
        assert_eq!(mounts.len(), 2);
        assert!(
            old_context
                .validate_exact_mounts(mounts.len(), &mount_lookup(mounts), &cancellation)
                .is_err()
        );
        let context = fixture.contexts_for(&operation);
        let site = fixture.target_field_reference();
        let answer = operation
            .resolve_reference(
                context,
                &SelectedSemanticLocator::new(
                    "java",
                    JAVA_ROOT_CONSUMER_PATH,
                    site,
                    LoweredSemanticRole::Reference,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            answer
        else {
            panic!("selected Java reference remains located after provider withdrawal");
        };
        assert!(answer.binding().targets().is_empty());
        assert!(matches!(
            answer.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
    }
    #[test]
    fn selected_java_explicit_type_import_beats_on_demand_in_either_order() {
        for source in [
            "package use; import dep.Target; import decoy.*; class Use { Target field; }",
            "package use; import decoy.*; import dep.Target; class Use { Target field; }",
        ] {
            let fixture = JavaRootResolutionOperationFixture::with_consumer(source);
            assert!(assert_java_root_parity(&fixture));
        }
    }
    #[test]
    fn selected_java_nested_type_shadows_explicit_and_on_demand_imports() {
        let fixture = JavaRootResolutionOperationFixture::with_consumer(
            "package use; import dep.Target; import decoy.*; class Use { static class Target {} Target field; }",
        );
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let context = fixture.contexts_for(&operation);
        let source_mount = operation
            .mounts()
            .unwrap()
            .iter()
            .find(|mount| mount.persisted_relative_path() == JAVA_ROOT_CONSUMER_PATH)
            .unwrap();
        let lowered =
            brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                source_mount.fragment(),
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                Language::Java,
                &fixture.consumer_facts,
            );
        let declaration = site_for_identifier(
            &fixture.consumer_facts,
            "Target",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        );
        let expected = semantic_at(&lowered, declaration, LoweredSemanticRole::Definition);
        let reference = fixture.target_field_reference();
        let answer = operation
            .resolve_reference(
                context,
                &SelectedSemanticLocator::new(
                    "java",
                    JAVA_ROOT_CONSUMER_PATH,
                    reference,
                    LoweredSemanticRole::Reference,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            answer
        else {
            panic!("selected Java field type reference must be located");
        };
        assert_eq!(answer.binding().targets(), &[expected]);
    }
    #[test]
    fn selected_java_known_source_witness_keeps_open_inventory_separate() {
        const POM: &str = "<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version></project>";
        for configuration in [vec![("pom.xml", POM)], Vec::new()] {
            let fixture = JavaRootResolutionOperationFixture::with_layout(
                JAVA_ROOT_SOURCES[0].1,
                [
                    "src/main/java/use/Use.java",
                    "src/main/java/dep/Target.java",
                    "src/main/java/decoy/Target.java",
                ],
                &configuration,
            );
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let context = fixture.contexts_for(&operation);
            assert_ne!(
                context.inventory_completion(),
                &ResolutionCompletion::Complete
            );
            let reference = site_for_identifier(
                &fixture.consumer_facts,
                "Target",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            );
            let answer = operation
                .resolve_reference(
                    context,
                    &SelectedSemanticLocator::new(
                        "java",
                        &fixture.consumer_path,
                        reference,
                        LoweredSemanticRole::Reference,
                    ),
                    &cancellation,
                    &mut SelectedResolutionContextMetrics,
                )
                .unwrap();
            let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(
                answer,
            )) = answer
            else {
                panic!("source-owned Java reference must remain located");
            };
            let [target] = answer.binding().targets() else {
                panic!("{answer:?}");
            };
            let witnesses = answer
                .binding()
                .witnesses()
                .iter()
                .filter(|witness| witness.target() == *target)
                .collect::<Vec<_>>();
            assert!(!witnesses.is_empty(), "{answer:?}");
            assert!(
                witnesses
                    .iter()
                    .any(|witness| witness.completion() == &ResolutionCompletion::Complete),
                "a known Java source target is visible through Maven membership or the implicit project: {answer:?}",
            );
        }
    }
    #[test]
    fn selected_java_source_root_access_rejects_only_proven_main_to_test() {
        const POM: &str = "<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version></project>";
        for (caller, provider, visible) in [
            (
                "src/main/java/use/Use.java",
                "src/test/java/dep/Target.java",
                false,
            ),
            (
                "src/test/java/use/Use.java",
                "src/main/java/dep/Target.java",
                true,
            ),
        ] {
            let fixture = JavaRootResolutionOperationFixture::with_layout(
                JAVA_ROOT_SOURCES[0].1,
                [caller, provider, "src/main/java/decoy/Target.java"],
                &[("pom.xml", POM)],
            );
            assert_java_provider_visibility(&fixture, visible);
        }
        let custom = JavaRootResolutionOperationFixture::with_layout(
            JAVA_ROOT_SOURCES[0].1,
            [
                "src/main/java/use/Use.java",
                "src/test/java/dep/Target.java",
                "src/main/java/decoy/Target.java",
            ],
            &[(
                "pom.xml",
                "<project><groupId>example</groupId><artifactId>app</artifactId><build><sourceDirectory>custom</sourceDirectory></build></project>",
            )],
        );
        assert_java_provider_visibility(&custom, true);
        let ambiguous = JavaRootResolutionOperationFixture::with_layout(
            JAVA_ROOT_SOURCES[0].1,
            [
                "src/main/java/use/Use.java",
                "src/main/nested/src/test/java/dep/Target.java",
                "src/main/java/decoy/Target.java",
            ],
            &[("pom.xml", POM), ("src/main/nested/pom.xml", POM)],
        );
        assert_java_provider_visibility(&ambiguous, true);
    }
    #[test]
    fn selected_java_static_import_cannot_borrow_type_import_authority() {
        let fixture = JavaRootResolutionOperationFixture::with_consumer(
            "package use; import static dep.Target; class Use { Target field; }",
        );
        assert_java_provider_visibility(&fixture, false);
    }
    #[test]
    fn selected_java_package_candidates_seek_published_package_index() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::plan_rows;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        let fixture = JavaRootResolutionOperationFixture::with_layout(
            JAVA_ROOT_SOURCES[0].1,
            [
                "src/main/java/use/Use.java",
                "src/main/java/dep/Target.java",
                "src/main/java/decoy/Target.java",
            ],
            &[(
                "pom.xml",
                "<project><groupId>example</groupId><artifactId>app</artifactId><version>1</version></project>",
            )],
        );
        for statistics in PlannerStatisticsState::BOTH {
            fixture
                .store
                .conn
                .execute(move |connection| statistics.install(connection));
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let rows = plan_rows(
                operation.ready.inventory.connection(),
                &pinned("jvm_native_import_target_mounts"),
            )
            .unwrap();
            assert!(
                rows.iter()
                    .any(|row| row.contains("idx_workspace_file_package_rows_name")
                        && row.contains("package_name=?")),
                "{statistics:?}: {rows:?}"
            );
            assert!(
                rows.iter()
                    .any(|row| row.contains("SEARCH mounted") && row.contains("file_version_id=?")),
                "{statistics:?}: {rows:?}"
            );
            let connection = operation.ready.inventory.connection();
            let context: i64 = connection
                .query_row("SELECT context_id FROM jvm_context_revisions", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let version = |path: &str| {
                connection.query_row(
            "SELECT file_version_id FROM temp.selected_resolution_mounts WHERE storage_language='java' AND persisted_relative_path=?1",
            [path], |row| row.get::<_,i64>(0)).unwrap()
            };
            let mut access_query = pinned("jvm_native_source_access");
            access_query.params = vec![
                rusqlite::types::Value::Integer(context),
                rusqlite::types::Value::Integer(version(&fixture.consumer_path)),
                rusqlite::types::Value::Text(fixture.consumer_path.clone()),
                rusqlite::types::Value::Integer(version(&fixture.source_rows[1].rel_path)),
                rusqlite::types::Value::Text(fixture.source_rows[1].rel_path.clone()),
            ];
            let access_rows = plan_rows(connection, &access_query).unwrap();
            assert!(
                access_rows
                    .iter()
                    .any(|row| row.contains("idx_jvm_source_root_files_source")),
                "{statistics:?}: {access_rows:?}"
            );
            for forbidden in ["SCAN f", "SCAN m", "AUTOMATIC", "TEMP B-TREE"] {
                assert!(
                    !access_rows.iter().any(|row| row.contains(forbidden)),
                    "{statistics:?}: {access_rows:?}"
                );
            }
            for forbidden in [
                "SCAN mounted",
                "SCAN package",
                "AUTOMATIC",
                "TEMP B-TREE",
                "CO-ROUTINE",
            ] {
                assert!(
                    !rows.iter().any(|row| row.contains(forbidden)),
                    "{statistics:?}: {rows:?}"
                );
            }
        }
    }
    #[test]
    fn selected_java_direct_dependency_access_requires_exact_coordinates_and_scope() {
        const TARGET_POM: &str = "<project><groupId>example</groupId><artifactId>provider</artifactId><version>2</version></project>";
        for (role, scope, version, expected) in [
            ("main", "compile", "2", "known"),
            ("main", "provided", "2", "known"),
            ("test", "test", "2", "known"),
            ("main", "test", "2", "unknown"),
            ("main", "compile", "3", "unknown"),
        ] {
            let caller = format!("consumer/src/{role}/java/use/Use.java");
            let consumer_pom = format!(
                "<project><groupId>example</groupId><artifactId>consumer</artifactId><version>1</version><dependencies><dependency><groupId>example</groupId><artifactId>provider</artifactId><version>{version}</version><scope>{scope}</scope><optional>true</optional></dependency></dependencies></project>"
            );
            let fixture = JavaRootResolutionOperationFixture::with_layout(
                JAVA_ROOT_SOURCES[0].1,
                [
                    &caller,
                    "provider/src/main/java/dep/Target.java",
                    "decoy/Target.java",
                ],
                &[
                    ("consumer/pom.xml", &consumer_pom),
                    ("provider/pom.xml", TARGET_POM),
                ],
            );
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let connection = operation.ready.inventory.connection();
            let context: i64 = connection
                .query_row("SELECT context_id FROM jvm_context_revisions", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let file = |path: &str| {
                connection.query_row(
            "SELECT file_version_id FROM temp.selected_resolution_mounts WHERE storage_language='java' AND persisted_relative_path=?1",
            [path], |row| row.get::<_,i64>(0)).unwrap()
            };
            let access: String = connection
            .query_row(
                brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::SOURCE_ACCESS,
                params![
                    context,
                    file(&caller),
                    caller,
                    file("provider/src/main/java/dep/Target.java"),
                    "provider/src/main/java/dep/Target.java"
                ],
                |row| row.get(0),
            )
            .unwrap();
            assert_eq!(
                access, expected,
                "role={role}, scope={scope}, version={version}"
            );
            drop(operation);
            // Unknown classpath membership retains a partial source candidate;
            // this positive direct declaration never certifies a closed classpath.
            assert_java_provider_visibility(&fixture, true);
        }
    }
    #[test]
    fn java_import_context_checks_actual_declaration_visibility() {
        for (consumer, visible) in [
            (
                "package use; import dep.Target; class Use { Target field; }",
                false,
            ),
            (
                "package dep; import dep.Target; class Use { Target field; }",
                true,
            ),
            (
                "package use; import dep.*; class Use { Target field; }",
                false,
            ),
        ] {
            let fixture = JavaRootResolutionOperationFixture::with_source_texts(
                [
                    consumer,
                    "package dep; class Target {}",
                    JAVA_ROOT_SOURCES[2].1,
                ],
                [
                    JAVA_ROOT_CONSUMER_PATH,
                    JAVA_ROOT_PROVIDER_PATH,
                    JAVA_ROOT_DECOY_PATH,
                ],
                &[],
            );
            assert_java_provider_visibility(&fixture, visible);
        }
    }
    #[test]
    fn selected_java_same_package_types_preserve_import_precedence() {
        let fields = (0..20)
            .map(|index| format!("Target field{index};"))
            .collect::<Vec<_>>()
            .join(" ");
        for (imports, same_package_wins) in [
            ("", true),
            ("import dep.*;", true),
            ("import dep.Target;", false),
        ] {
            let consumer = format!("package use; {imports} class Use {{ {fields} }}");
            let fixture = JavaRootResolutionOperationFixture::with_source_texts(
                [
                    &consumer,
                    "package use; class Target {}",
                    "package dep; public class Target {}",
                ],
                [
                    JAVA_ROOT_CONSUMER_PATH,
                    "src/use/Target.java",
                    "src/dep/Target.java",
                ],
                &[],
            );
            assert_java_provider_visibility(&fixture, same_package_wins);
            assert_java_definition_visibility(
                &fixture,
                &fixture.decoy_facts,
                &fixture.source_rows[2].rel_path,
                !same_package_wins,
            );
        }
    }
    #[test]
    fn selected_package_metadata_reads_are_scoped_and_indexed() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::package_context::SelectedPackageRows;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SharedNameInterner;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::plan_rows;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        let target_fields = (0..20)
            .map(|index| format!(" Target target{index};"))
            .collect::<String>();
        let mut consumer = format!("package use; class Use {{{target_fields}");
        let mut provider = String::from("package use; class Target {}");
        for index in 0..128 {
            consumer.push_str(&format!(" Name{index} field{index};"));
            provider.push_str(&format!(" class Name{index} {{}}"));
        }
        consumer.push('}');
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [&consumer, &provider, JAVA_ROOT_SOURCES[2].1],
            [
                JAVA_ROOT_CONSUMER_PATH,
                JAVA_ROOT_PROVIDER_PATH,
                JAVA_ROOT_DECOY_PATH,
            ],
            &[],
        );
        for statistics in PlannerStatisticsState::BOTH {
            fixture
                .store
                .conn
                .execute(move |connection| statistics.install(connection));
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let caller = operation
                .mount_table()
                .mount_for_path("java", JAVA_ROOT_CONSUMER_PATH)
                .unwrap()
                .unwrap();
            let target = operation
                .mount_table()
                .mount_for_path("java", JAVA_ROOT_PROVIDER_PATH)
                .unwrap()
                .unwrap();
            let SelectedPackageRows::Ready(references) = operation
                .selected_package_references(caller.ordinal(), &cancellation)
                .unwrap()
            else {
                panic!("not cancelled");
            };
            assert_eq!(references.len(), 148);
            let source = site_for_identifier(
                &fixture.consumer_facts,
                "Target",
                ResolutionIdentifierRole::Reference,
                ResolutionNamespace::Type,
            );
            let reference = references
                .iter()
                .find(|reference| reference.source_site == source)
                .unwrap();
            let same_lookup = references
                .iter()
                .filter(|candidate| candidate.lookup == reference.lookup)
                .collect::<Vec<_>>();
            assert_eq!(same_lookup.len(), 20);
            assert!(
                same_lookup
                    .iter()
                    .all(|candidate| candidate.token == reference.token)
            );
            let SelectedPackageRows::Ready(members) = operation
                .selected_package_members_for_lookup(
                    target.ordinal(),
                    reference.lookup,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("not cancelled");
            };
            assert_eq!(members.len(), 1);
            assert_eq!(
                members[0].source_site,
                site_for_identifier(
                    &fixture.provider_facts,
                    "Target",
                    ResolutionIdentifierRole::Declaration,
                    ResolutionNamespace::Type
                )
            );
            // Populate the stage with the ordinary reader's complete result. The
            // two readers use different coordinate domains and SQL joins; equality
            // is a round-trip law, not a second invocation of one implementation.
            let mut all_members = BTreeSet::new();
            for reference in &references {
                let SelectedPackageRows::Ready(rows) = operation
                    .selected_package_members_for_lookup(
                        target.ordinal(),
                        reference.lookup,
                        &cancellation,
                    )
                    .unwrap()
                else {
                    panic!("not cancelled");
                };
                all_members.extend(rows);
            }

            use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec::encode_node;

            use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec::encode_semantic;
            operation.ready.inventory.with_owned_temp_write(|connection| {
            for (ordinal, marker) in [(caller.ordinal(), 1_u8), (target.ordinal(), 2_u8)] {
                connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)", params![ordinal.get(), [marker; 32].as_slice(), [marker; 32].as_slice()])?;
                let producer = connection.last_insert_rowid();
                if ordinal == caller.ordinal() {
                    for row in &references {
                        connection.execute("INSERT INTO temp.selected_resolution_stage_package_references(host_ordinal,producer_id,token_key,domain_shared,reference_key,choice_key,source_site,root_scope_key,namespace,lookup_shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", params![ordinal.get(),producer,encode_semantic(row.token),row.domain.shared_name_id().unwrap().get(),encode_semantic(row.reference),encode_semantic(row.choice.expect("package choice is lowered")),row.source_site.get(),encode_node(row.root_scope),row.namespace.label(),row.lookup.shared_name_id().unwrap().get()])?;
                    }
                } else {
                    for row in &all_members {
                        connection.execute("INSERT INTO temp.selected_resolution_stage_package_members(host_ordinal,producer_id,token_key,domain_shared,definition_key,source_site,root_scope_key,namespace,lookup_shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![ordinal.get(),producer,encode_semantic(row.token),row.domain.shared_name_id().unwrap().get(),encode_semantic(row.definition),row.source_site.get(),encode_node(row.root_scope),row.namespace.label(),row.lookup.shared_name_id().unwrap().get()])?;
                    }
                }
            }
            Ok(())
        }).unwrap();
            let SelectedPackageRows::Ready(staged_references) = operation
                .selected_package_references(caller.ordinal(), &cancellation)
                .unwrap()
            else {
                panic!("not cancelled");
            };
            assert_eq!(staged_references, references);
            let SelectedPackageRows::Ready(staged_members) = operation
                .selected_package_members_for_lookup(
                    target.ordinal(),
                    reference.lookup,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("not cancelled");
            };
            assert_eq!(staged_members, members);
            let stored = operation
                .ready
                .shared_names()
                .to_persisted(reference.lookup.shared_name_id().unwrap())
                .unwrap()
                .get();
            for (name, ordinal, lookup) in [
                ("native_package_references", caller.ordinal(), None),
                ("native_stage_package_references", caller.ordinal(), None),
                ("native_package_members", target.ordinal(), Some(stored)),
                (
                    "native_stage_package_members",
                    target.ordinal(),
                    Some(reference.lookup.shared_name_id().unwrap().get()),
                ),
            ] {
                let mut query = pinned(name);
                query.params = vec![rusqlite::types::Value::Integer(i64::from(ordinal.get()))];
                if let Some(lookup) = lookup {
                    query
                        .params
                        .push(rusqlite::types::Value::Integer(i64::from(lookup)));
                }
                let rows = plan_rows(operation.ready.inventory.connection(), &query).unwrap();
                for forbidden in ["SCAN p", "SCAN candidate", "AUTOMATIC", "TEMP B-TREE"] {
                    assert!(
                        !rows.iter().any(|row| row.contains(forbidden)),
                        "{name} {statistics:?}: {rows:?}"
                    );
                }
            }
            // Changing the staged lookup must suppress the old ordinary name,
            // while retaining the same definition under its new staged name.
            let replacement = references
                .iter()
                .find(|row| row.lookup != reference.lookup)
                .unwrap()
                .lookup;
            operation.ready.inventory.with_owned_temp_write(|connection| {
            connection.execute("UPDATE temp.selected_resolution_stage_package_members SET lookup_shared=?1 WHERE definition_key=?2 AND host_ordinal=?3", params![replacement.shared_name_id().unwrap().get(), encode_semantic(members[0].definition), target.ordinal().get()])?;
            Ok(())
        }).unwrap();
            let SelectedPackageRows::Ready(old_name) = operation
                .selected_package_members_for_lookup(
                    target.ordinal(),
                    reference.lookup,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("not cancelled");
            };
            assert!(
                old_name.is_empty(),
                "stage rename must withdraw ordinary lookup: {old_name:?}"
            );
            let SelectedPackageRows::Ready(new_name) = operation
                .selected_package_members_for_lookup(target.ordinal(), replacement, &cancellation)
                .unwrap()
            else {
                panic!("not cancelled");
            };
            assert!(
                new_name
                    .iter()
                    .any(|row| row.definition == members[0].definition)
            );
            cancellation.cancel();
            assert!(matches!(
                operation
                    .selected_package_references(caller.ordinal(), &cancellation)
                    .unwrap(),
                SelectedPackageRows::Cancelled
            ));
            assert!(matches!(
                operation
                    .selected_package_members_for_lookup(
                        target.ordinal(),
                        reference.lookup,
                        &cancellation
                    )
                    .unwrap(),
                SelectedPackageRows::Cancelled
            ));
        }
    }
    #[test]
    fn selected_java_missing_explicit_import_does_not_fall_through_to_package_peer() {
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                "package use; import missing.Target; class Use { Target field; }",
                "package use; class Target {}",
                JAVA_ROOT_SOURCES[2].1,
            ],
            [
                JAVA_ROOT_CONSUMER_PATH,
                JAVA_ROOT_PROVIDER_PATH,
                JAVA_ROOT_DECOY_PATH,
            ],
            &[],
        );
        assert_java_provider_visibility(&fixture, false);
        assert_java_definition_visibility(
            &fixture,
            &fixture.decoy_facts,
            &fixture.source_rows[2].rel_path,
            false,
        );
    }
    #[test]
    fn selected_java_nested_type_imports_follow_owner_chains_and_visibility() {
        for (consumer, provider, visible) in [
            (
                "package use; import dep.Outer.Target; class Use { Target field; }",
                "package dep; public class Outer { public static class Target {} }",
                true,
            ),
            (
                "package use; import dep.Outer.*; class Use { Target field; }",
                "package dep; public class Outer { public class Target {} }",
                true,
            ),
            (
                "package use; import dep.Outer.Inner.Target; class Use { Target field; }",
                "package dep; public class Outer { public static class Inner { public static class Target {} } }",
                true,
            ),
            (
                "package use; import dep.Wrong.Target; class Use { Target field; }",
                "package dep; public class Outer { public static class Target {} }",
                false,
            ),
            (
                "package use; import dep.Outer.Target; class Use { Target field; }",
                "package dep; public class Outer { private static class Target {} }",
                false,
            ),
            (
                "package use; import dep.Outer.Target; class Use { Target field; }",
                "package dep; class Outer { public static class Target {} }",
                false,
            ),
            (
                "package use; import dep.Outer.Inner.Target; class Use { Target field; }",
                "package dep; public class Outer { private static class Inner { public static class Target {} } }",
                false,
            ),
        ] {
            let fixture = JavaRootResolutionOperationFixture::with_source_texts(
                [consumer, provider, JAVA_ROOT_SOURCES[2].1],
                [
                    JAVA_ROOT_CONSUMER_PATH,
                    "src/dep/Outer.java",
                    JAVA_ROOT_DECOY_PATH,
                ],
                &[],
            );
            assert_java_provider_visibility(&fixture, visible);
        }
    }
    #[test]
    fn selected_java_static_imports_require_static_access_and_preserve_namespace() {
        for (consumer, provider, namespace, visible) in [
            (
                "package use; import static dep.Outer.Target; class Use { int field = Target; }",
                "package dep; public class Outer { public static int Target; }",
                ResolutionNamespace::Value,
                true,
            ),
            (
                "package use; import static dep.Outer.*; class Use { int field = Target; }",
                "package dep; public class Outer { public static int Target; }",
                ResolutionNamespace::Value,
                true,
            ),
            (
                "package use; import static dep.Outer.Target; class Use { int field = Target; }",
                "package dep; public class Outer { public int Target; }",
                ResolutionNamespace::Value,
                false,
            ),
            (
                "package use; import static dep.Outer.Target; class Use { int field = Target; }",
                "package dep; public class Outer { private static int Target; }",
                ResolutionNamespace::Value,
                false,
            ),
            (
                "package use; import static dep.Outer.Target; class Use { int field = Target(); }",
                "package dep; public class Outer { public static int Target() { return 1; } }",
                ResolutionNamespace::Callable,
                true,
            ),
            (
                "package use; import static dep.Outer.*; class Use { int field = Target(); }",
                "package dep; public class Outer { public static int Target() { return 1; } }",
                ResolutionNamespace::Callable,
                true,
            ),
            (
                "package use; import static dep.Outer.Target; class Use { int field = Target(); }",
                "package dep; public class Outer { public int Target() { return 1; } }",
                ResolutionNamespace::Callable,
                false,
            ),
            (
                "package use; import static dep.Outer.Target; class Use { Target field; }",
                "package dep; public class Outer { public static class Target {} }",
                ResolutionNamespace::Type,
                true,
            ),
            (
                "package use; import static dep.Outer.Target; class Use { Target field; }",
                "package dep; public class Outer { public class Target {} }",
                ResolutionNamespace::Type,
                false,
            ),
        ] {
            let fixture = JavaRootResolutionOperationFixture::with_source_texts(
                [consumer, provider, JAVA_ROOT_SOURCES[2].1],
                [
                    JAVA_ROOT_CONSUMER_PATH,
                    "src/dep/Outer.java",
                    JAVA_ROOT_DECOY_PATH,
                ],
                &[],
            );
            assert_java_named_definition_visibility(
                &fixture,
                &fixture.provider_facts,
                &fixture.source_rows[1].rel_path,
                "Target",
                namespace,
                visible,
            );
        }
    }
    #[test]
    fn selected_java_static_type_import_precedence_preserves_value_namespace() {
        for (consumer, provider, imported_type) in [
            (
                "package use; import static dep.Outer.Target; class Use { Target field; }",
                "package dep; public class Outer { public static class Target {} }",
                true,
            ),
            (
                "package use; import static dep.Outer.*; class Use { Target field; }",
                "package dep; public class Outer { public static class Target {} }",
                false,
            ),
        ] {
            let fixture = JavaRootResolutionOperationFixture::with_source_texts(
                [consumer, provider, "package use; public class Target {}"],
                [
                    JAVA_ROOT_CONSUMER_PATH,
                    "src/dep/Outer.java",
                    "src/use/Target.java",
                ],
                &[],
            );
            assert_java_provider_visibility(&fixture, imported_type);
            assert_java_definition_visibility(
                &fixture,
                &fixture.decoy_facts,
                "src/use/Target.java",
                !imported_type,
            );
        }
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                "package use; import static dep.Outer.Target; class Use { Target field; int value = Target; }",
                "package dep; public class Outer { public static int Target; }",
                "package use; public class Target {}",
            ],
            [
                JAVA_ROOT_CONSUMER_PATH,
                "src/dep/Outer.java",
                "src/use/Target.java",
            ],
            &[],
        );
        assert_java_definition_visibility(
            &fixture,
            &fixture.decoy_facts,
            "src/use/Target.java",
            true,
        );
        assert_java_named_definition_visibility(
            &fixture,
            &fixture.provider_facts,
            "src/dep/Outer.java",
            "Target",
            ResolutionNamespace::Value,
            true,
        );
    }
    #[test]
    fn selected_java_import_access_rejects_protected_members_across_packages() {
        for (declaration, use_body, namespace) in [
            (
                "protected static class Target {}",
                "Target field;",
                ResolutionNamespace::Type,
            ),
            (
                "protected static int Target;",
                "int field = Target;",
                ResolutionNamespace::Value,
            ),
            (
                "protected static int Target() { return 1; }",
                "int field = Target();",
                ResolutionNamespace::Callable,
            ),
        ] {
            for package in ["use", "dep"] {
                let consumer = format!(
                    "package {package}; import static dep.Outer.Target; class Use {{ {use_body} }}"
                );
                let provider = format!("package dep; public class Outer {{ {declaration} }}");
                let fixture = JavaRootResolutionOperationFixture::with_source_texts(
                    [&consumer, &provider, JAVA_ROOT_SOURCES[2].1],
                    [
                        JAVA_ROOT_CONSUMER_PATH,
                        "src/dep/Outer.java",
                        JAVA_ROOT_DECOY_PATH,
                    ],
                    &[],
                );
                assert_java_named_definition_visibility(
                    &fixture,
                    &fixture.provider_facts,
                    "src/dep/Outer.java",
                    "Target",
                    namespace,
                    package == "dep",
                );
            }
        }
    }
    #[test]
    fn selected_java_inheritance_metadata_uses_indexed_source_rows_and_honors_cancellation() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::resolution::fact_source::JavaInheritanceDeclarationKind;

        use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;

        let mut source = String::from("package use; class Use {");
        for ordinal in 0..513 {
            source.push_str(&format!("public void method{ordinal}() {{}}\n"));
        }
        source.push('}');
        for statistics in PlannerStatisticsState::BOTH {
            let fixture = JavaRootResolutionOperationFixture::with_consumer(&source);
            fixture
                .store
                .conn
                .execute(move |connection| statistics.install(connection));
            let cancellation = CancellationToken::new();
            let operation = fixture.open_ready(&cancellation);
            let mount = operation
                .mount_table()
                .mount_for_path("java", JAVA_ROOT_CONSUMER_PATH)
                .unwrap()
                .unwrap();
            let lowered =
                brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    mount.fragment(),
                    &operation.ready.shared_names(),
                    Language::Java,
                    &fixture.consumer_facts,
                );
            let definitions = lowered
                .lexical()
                .semantics()
                .iter()
                .filter(|row| row.role() == LoweredSemanticRole::Definition)
                .map(|row| row.semantic())
                .collect::<Vec<_>>();
            assert_eq!(definitions.len(), 515);
            let typed = operation.ready.typed_source();
            for count in [1, 256, 515] {
                let rows = typed
                    .java_inheritance_declarations(&definitions[..count], &cancellation)
                    .unwrap()
                    .expect("live selected metadata");
                assert_eq!(rows.len(), count);
                for row in &rows {
                    assert_eq!(row.package.named(), Some("use"));
                    match row.kind {
                        JavaInheritanceDeclarationKind::Type { is_interface, .. } => {
                            assert!(!is_interface)
                        }
                        JavaInheritanceDeclarationKind::Method {
                            is_abstract,
                            is_static,
                            visibility,
                        } => {
                            assert_eq!(is_abstract, Some(false));
                            assert!(!is_static);
                            assert_eq!(visibility, DeclaredVisibility::Public);
                        }
                    }
                }
                let endpoints = typed
                    .java_access_endpoints(&definitions[..count], &cancellation)
                    .unwrap()
                    .expect("live Java access metadata");
                assert_eq!(endpoints.len(), count);
                let roots = endpoints
                    .iter()
                    .map(|row| {
                        assert_eq!(row.package.as_deref(), Some("use"));
                        row.outermost_type
                            .expect("method and type share an outer type")
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(roots.len(), 1);
                let access_plan = explain_pin(
                    operation.ready.inventory.connection(),
                    &pinned("java_access_endpoints"),
                );
                for alias in [
                    "mount", "interior", "site", "semantic", "meta", "parent", "scope",
                ] {
                    assert!(
                        access_plan
                            .iter()
                            .any(|detail| detail.starts_with(&format!("SEARCH {alias} "))),
                        "Java access must seek {alias} with {statistics}: {access_plan:#?}"
                    );
                }
                let plan = explain_pin(
                    operation.ready.inventory.connection(),
                    &pinned("java_inheritance_declarations"),
                );
                for alias in [
                    "mount", "interior", "source", "semantic", "bridge", "link", "units", "meta",
                ] {
                    assert!(
                        plan.iter()
                            .any(|detail| detail.starts_with(&format!("SEARCH {alias} "))),
                        "selected metadata must seek {alias} with {statistics}: {plan:#?}"
                    );
                }
                let synthetic_plan = explain_pin(
                    operation.ready.inventory.connection(),
                    &pinned("java_synthetic_type_bodies"),
                );
                for alias in [
                    "mount", "interior", "semantic", "scope", "source", "meta", "bridge",
                ] {
                    assert!(
                        synthetic_plan
                            .iter()
                            .any(|detail| detail.starts_with(&format!("SEARCH {alias} "))),
                        "synthetic Java type bodies must seek {alias} with {statistics}: {synthetic_plan:#?}"
                    );
                }
                // The only permitted scan is the bounded json_each request
                // array (#6594).
                assert!(
                    synthetic_plan
                        .iter()
                        .all(|detail| !detail.contains("AUTOMATIC")
                            && !detail.contains("TEMP B-TREE")
                            && !detail.contains("CO-ROUTINE")
                            && (!detail.starts_with("SCAN ")
                                || detail.starts_with("SCAN request VIRTUAL TABLE"))),
                    "{statistics}: {synthetic_plan:#?}"
                );
                // The canonical metadata view checks agreement of source
                // visibility values for one indexed unit. Its DISTINCT set is
                // bounded by the visibility enum; it does not sort workspace rows.
                assert!(
                    plan.iter().all(|detail| !detail.contains("AUTOMATIC")
                        && (!detail.contains("TEMP B-TREE")
                            || detail == "USE TEMP B-TREE FOR count(DISTINCT)")
                        && !detail.contains("CO-ROUTINE")
                        && (!detail.starts_with("SCAN ")
                            || detail.starts_with("SCAN request VIRTUAL TABLE"))),
                    "{statistics}: {plan:#?}"
                );
            }
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            assert!(
                typed
                    .java_inheritance_declarations(&definitions, &cancelled)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                typed
                    .java_inheritance_declarations(&definitions, &cancellation)
                    .unwrap()
                    .unwrap()
                    .len(),
                515
            );
        }
    }
    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "2954b247d759: a reference that sits in no declaration is stored with owner -1, which the JVM access endpoint read rejected as an out-of-range integer (Scala precedence census G4)"
    )]
    fn selected_jvm_access_endpoints_read_a_reference_that_sits_in_no_declaration() {
        let fixture = JavaRootResolutionOperationFixture::new();
        // `resolution_sites.owner` is -1 for a reference in no declaration. Scala
        // stores that for an import selector; no Java construct produces it, so
        // the stored row is set directly.
        fixture.store.conn.execute(|connection| {
            connection
                .execute("UPDATE resolution_sites SET owner=-1 WHERE role=0", [])
                .unwrap()
        });
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let mount = operation
            .mount_table()
            .mount_for_path("java", JAVA_ROOT_CONSUMER_PATH)
            .unwrap()
            .unwrap();
        let lowered =
            brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                mount.fragment(),
                &operation.ready.shared_names(),
                Language::Java,
                &fixture.consumer_facts,
            );
        let references = lowered
            .lexical()
            .semantics()
            .iter()
            .filter(|row| row.role() == LoweredSemanticRole::Reference)
            .map(|row| row.semantic())
            .collect::<Vec<_>>();
        assert!(!references.is_empty());
        let endpoints = operation
            .ready
            .typed_source()
            .jvm_access_endpoints(&references, &cancellation)
            .unwrap()
            .expect("live JVM access metadata");
        assert_eq!(endpoints.len(), references.len());
        for endpoint in endpoints {
            assert_eq!(endpoint.enclosing_templates, Vec::new(), "{endpoint:?}");
            assert_eq!(endpoint.outermost_type, None, "{endpoint:?}");
        }
    }
    #[test]
    fn selected_java_same_package_access_keeps_exact_main_test_direction() {
        let pom =
            "<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>";
        for (consumer_path, provider_path, visible) in [
            (
                "src/main/java/use/Use.java",
                "src/test/java/use/Target.java",
                false,
            ),
            (
                "src/test/java/use/Use.java",
                "src/main/java/use/Target.java",
                true,
            ),
        ] {
            let fixture = JavaRootResolutionOperationFixture::with_source_texts(
                [
                    "package use; class Use { Target field; }",
                    "package use; class Target {}",
                    JAVA_ROOT_SOURCES[2].1,
                ],
                [consumer_path, provider_path, JAVA_ROOT_DECOY_PATH],
                &[("pom.xml", pom)],
            );
            assert_java_provider_visibility(&fixture, visible);
        }
    }
    #[test]
    fn selected_java_same_package_parity_reopens_and_keeps_lexical_shadowing() {
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                "package use; class Use { Target field; }",
                "package use; class Target {}",
                JAVA_ROOT_SOURCES[2].1,
            ],
            [
                JAVA_ROOT_CONSUMER_PATH,
                JAVA_ROOT_PROVIDER_PATH,
                JAVA_ROOT_DECOY_PATH,
            ],
            &[],
        );
        assert_java_root_parity(&fixture);
        assert_java_root_parity(&fixture.reopen());
        let fixture = JavaRootResolutionOperationFixture::with_source_texts(
            [
                "package use; class Use { class Target {} Target field; }",
                "package use; class Target {}",
                JAVA_ROOT_SOURCES[2].1,
            ],
            [
                JAVA_ROOT_CONSUMER_PATH,
                JAVA_ROOT_PROVIDER_PATH,
                JAVA_ROOT_DECOY_PATH,
            ],
            &[],
        );
        assert_java_provider_visibility(&fixture, false);
        assert_eq!(
            assert_java_definition_visibility(
                &fixture,
                &fixture.consumer_facts,
                &fixture.consumer_path,
                true,
            ),
            ResolutionCompletion::Complete,
            "lexical nested type plus proven same-package access closes this lookup"
        );
        let default = JavaRootResolutionOperationFixture::with_source_texts(
            [
                "class Use { Target field; }",
                "class Target {}",
                JAVA_ROOT_SOURCES[2].1,
            ],
            [
                JAVA_ROOT_CONSUMER_PATH,
                JAVA_ROOT_PROVIDER_PATH,
                JAVA_ROOT_DECOY_PATH,
            ],
            &[],
        );
        assert_java_provider_visibility(&default, true);
    }
    #[doc(hidden)]
    pub struct JavaRootResolutionOperationFixture {
        store: AnalyzerStore,
        #[doc(hidden)]
        pub project_root: tempfile::TempDir,
        project: MutableGenerationProject,
        workspace_id: WorkspaceId,
        snapshots: WorkspaceSnapshots,
        languages: Vec<SelectedResolutionLanguage>,
        source_rows: Vec<WorkspaceFileRow>,
        package_rows: Vec<brokk_bifrost_analysis::analyzer::store::WorkspacePackageFileRow>,
        configuration: Vec<
            brokk_bifrost_analysis::analyzer::store::workspace_inputs::WorkspaceConfigurationInput,
        >,
        consumer_path: String,
        consumer_source: String,
        consumer_facts: FileResolutionFacts,
        provider_facts: FileResolutionFacts,
        decoy_facts: FileResolutionFacts,
    }
    impl JavaRootResolutionOperationFixture {
        #[doc(hidden)]
        pub fn new() -> Self {
            Self::with_consumer(JAVA_ROOT_SOURCES[0].1)
        }

        fn with_consumer(consumer: &str) -> Self {
            Self::with_layout(
                consumer,
                [
                    JAVA_ROOT_CONSUMER_PATH,
                    JAVA_ROOT_PROVIDER_PATH,
                    JAVA_ROOT_DECOY_PATH,
                ],
                &[],
            )
        }

        fn with_layout(consumer: &str, paths: [&str; 3], configuration: &[(&str, &str)]) -> Self {
            Self::with_source_texts(
                [consumer, JAVA_ROOT_SOURCES[1].1, JAVA_ROOT_SOURCES[2].1],
                paths,
                configuration,
            )
        }

        fn with_source_texts(
            sources: [&str; 3],
            paths: [&str; 3],
            configuration: &[(&str, &str)],
        ) -> Self {
            let configuration = configuration
            .iter()
            .map(|(path, source)| {
                brokk_bifrost_analysis::analyzer::store::workspace_inputs::WorkspaceConfigurationInput::new(
                    (*path).to_owned(),
                    source.as_bytes().to_vec().into_boxed_slice(),
                )
            })
            .collect::<Vec<_>>();
            // A mutable-generation project and a persistent store share this root
            // so the fixture can exercise selected publication and database reopen.
            let project_root = tempfile::tempdir().unwrap();
            let project = MutableGenerationProject::new(project_root.path(), Language::Java);
            let store =
                AnalyzerStore::open_persistent(&project_root.path().join("store.db")).unwrap();
            let generation = store
                .ensure_language_epoch_value("java", "java-root-operation-v1")
                .unwrap();
            store
                .ensure_resolution_producer_epoch("java", Language::Java)
                .unwrap();
            let mut source_rows = Vec::new();
            let mut package_rows = Vec::new();
            let mut facts = Vec::new();
            let mut prepared = Vec::new();
            for (path, source) in paths.into_iter().zip(sources) {
                let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
                let (state, file_facts) =
                    parsed_operation_state(project_root.path(), path, source, &JavaAdapter);
                package_rows.push(
                    brokk_bifrost_analysis::analyzer::store::WorkspacePackageFileRow {
                        package_name: state.package_name.clone(),
                        rel_path: path.to_owned(),
                    },
                );
                prepared.push(
                    AnalyzerStore::prepare_parsed_blob(
                        oid,
                        "java",
                        generation,
                        &JavaAdapter,
                        state,
                    )
                    .unwrap(),
                );
                source_rows.push(WorkspaceFileRow {
                    rel_path: path.to_owned(),
                    blob_oid: oid,
                });
                facts.push(file_facts);
            }
            let (outcomes, _) =
                store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
            assert_eq!(outcomes.len(), 3);
            assert!(
                outcomes.iter().all(|outcome| outcome.error.is_none()),
                "{outcomes:?}"
            );
            let workspace_id = WorkspaceId(
                "7575757575757575757575757575757575757575757575757575757575757575".to_owned(),
            );
            let snapshot = store
                .sync_workspace_inputs_for_workspace(
                    &workspace_id,
                    "java",
                    generation,
                    &source_rows,
                    &[],
                    &[],
                    &package_rows,
                    &[],
                    &[],
                    &configuration,
                    &[],
                    &[],
                )
                .unwrap();
            store.reconcile_jvm_package_context(&snapshot).unwrap();
            let mut snapshots = WorkspaceSnapshots::default();
            snapshots.insert("java".to_owned(), snapshot);
            let [consumer_facts, provider_facts, decoy_facts]: [FileResolutionFacts; 3] =
                facts.try_into().unwrap();
            Self {
                store,
                project_root,
                project,
                workspace_id,
                snapshots,
                languages: vec![SelectedResolutionLanguage::new("java", Language::Java)],
                source_rows,
                package_rows,
                configuration,
                consumer_path: paths[0].to_owned(),
                consumer_source: sources[0].to_owned(),
                consumer_facts,
                provider_facts,
                decoy_facts,
            }
        }

        fn reopen(mut self) -> Self {
            let database = self.project_root.path().join("store.db");
            drop(self.store);
            self.store = AnalyzerStore::open_persistent(&database).unwrap();
            self
        }

        fn open(
            &self,
            cancellation: &CancellationToken,
        ) -> SelectedResolutionOperationOpenOutcome<'_, '_> {
            self.store
                .open_selected_resolution_operation(
                    SelectedResolutionOperationInput::new(
                        &self.project,
                        &self.workspace_id,
                        &self.snapshots,
                        &self.languages,
                        &[],
                    ),
                    cancellation,
                )
                .unwrap()
        }

        #[doc(hidden)]
        pub fn open_ready(
            &self,
            cancellation: &CancellationToken,
        ) -> SelectedResolutionOperation<'_, '_> {
            match self.open(cancellation) {
                SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
                _ => panic!("complete Java operation must open Ready"),
            }
        }

        fn target_field_reference(&self) -> ResolutionSiteId {
            let start = self
                .consumer_source
                .find("Target field")
                .expect("fixture field-type occurrence");
            self.consumer_facts
                .identifiers_named(
                    "Target",
                    ResolutionIdentifierRole::Reference,
                    ResolutionNamespace::Type,
                )
                .into_iter()
                .find(|identifier| {
                    self.consumer_facts.sites[identifier.site.index()].start_byte == start
                })
                .expect("field-type reference at its source range")
                .site
        }

        fn contexts_for(
            &self,
            operation: &SelectedResolutionOperation<'_, '_>,
        ) -> SelectedResolutionContextSet {
            match operation
            .jvm_import_context(
                Language::Java,
                &self.consumer_path,
                &CancellationToken::new(),
            )
            .unwrap()
        {
            brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_context::JavaImportContext::Ready { context, .. } => *context,
            _ => panic!("published Java selected source context must be ready"),
        }
        }
    }
    fn assert_java_root_parity(fixture: &JavaRootResolutionOperationFixture) -> bool {
        let cancellation = CancellationToken::default();
        let mounted = fixture.open_ready(&cancellation);
        assert_eq!(mounted.mounts().unwrap().len(), 3);
        let mounts = mounted.mounts().unwrap().to_vec();
        let preload_context = fixture.contexts_for(&mounted);

        let artifact_for = |path: &str, facts: &FileResolutionFacts| {
            let mount = mounts
                .iter()
                .find(|mount| mount.persisted_relative_path() == path)
                .unwrap_or_else(|| panic!("missing selected Java mount {path:?}"));
            let artifact =
                brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                    mount.fragment(),
                    &mounted.ready.shared_names(),
                    Language::Java,
                    facts,
                );
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::fixture_names::record_selected(
            artifact.identities(),
            mounted
                .ready
                .inventory
                .mount_record_by_ordinal(mount.ordinal())
                .unwrap()
                .fragment_digest()
                .as_bytes(),
        );
            artifact
        };
        let consumer = artifact_for(JAVA_ROOT_CONSUMER_PATH, &fixture.consumer_facts);
        let provider = artifact_for(JAVA_ROOT_PROVIDER_PATH, &fixture.provider_facts);
        let decoy = artifact_for(JAVA_ROOT_DECOY_PATH, &fixture.decoy_facts);
        let reference_site = fixture.target_field_reference();
        let provider_site = site_for_identifier(
            &fixture.provider_facts,
            "Target",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        );
        let decoy_site = site_for_identifier(
            &fixture.decoy_facts,
            "Target",
            ResolutionIdentifierRole::Declaration,
            ResolutionNamespace::Type,
        );
        let reference = semantic_at(&consumer, reference_site, LoweredSemanticRole::Reference);
        let provider_definition =
            semantic_at(&provider, provider_site, LoweredSemanticRole::Definition);
        let decoy_definition = semantic_at(&decoy, decoy_site, LoweredSemanticRole::Definition);

        let mut preload = PreloadedFactResolutionService::from_lowered_fragments(
            [
                consumer.lexical().clone(),
                provider.lexical().clone(),
                decoy.lexical().clone(),
            ],
            [
                consumer.typed().clone(),
                provider.typed().clone(),
                decoy.typed().clone(),
            ],
        );
        // Independent in-memory ownership oracle from lowered AST facts. Package
        // identity comes from this fixture's authored package rows, not access SQL.
        let mut endpoints = Vec::new();
        let mut declarations = Vec::new();
        for (index, (path, artifact)) in [
            (JAVA_ROOT_CONSUMER_PATH, &consumer),
            (JAVA_ROOT_PROVIDER_PATH, &provider),
            (JAVA_ROOT_DECOY_PATH, &decoy),
        ]
        .into_iter()
        .enumerate()
        {
            let package = fixture
                .package_rows
                .iter()
                .find(|row| row.rel_path == path)
                .map(|row| row.package_name.clone());
            // These oracle fixtures author classes only; an interface would need
            // its own flag before this oracle could describe it.
            let source_path = &fixture.source_rows[index].rel_path;
            let text = std::fs::read_to_string(fixture.project_root.path().join(source_path))
                .expect("read Java oracle fixture source");
            assert!(!text.contains("interface"), "{source_path}: {text}");
            declarations.extend(
            artifact
                .typed()
                .member_scopes()
                .iter()
                .filter(|row| row.is_type_body())
                .map(
                    |row| brokk_bifrost_analysis::analyzer::resolution::fact_source::JavaInheritanceDeclaration {
                        definition: row.definition(),
                        name: String::new(),
                        package: brokk_bifrost_analysis::analyzer::resolution::fact_source::JvmDeclarationPackage::Known(package.clone()),
                        kind: brokk_bifrost_analysis::analyzer::resolution::fact_source::JavaInheritanceDeclarationKind::Type {
                            is_interface: false,
                            is_singleton: false,
                        },
                    },
                ),
        );
            let parents = artifact
                .typed()
                .member_owners()
                .iter()
                .map(|row| (row.definition(), row.owner_definition()))
                .collect::<HashMap<_, _>>();
            let types = artifact
                .typed()
                .member_scopes()
                .iter()
                .filter(|row| row.is_type_body())
                .map(|row| row.definition())
                .collect::<HashSet<_>>();
            for row in artifact.lexical().semantics() {
                let mut owner = if row.role() == LoweredSemanticRole::Definition {
                    Some(row.semantic())
                } else {
                    row.reference_owner().flatten()
                };
                let mut seen = HashSet::default();
                while let Some(current) = owner {
                    assert!(seen.insert(current), "fixture ownership is acyclic");
                    let Some(parent) = parents.get(&current) else {
                        break;
                    };
                    owner = Some(*parent);
                }
                endpoints.push(
                    brokk_bifrost_analysis::analyzer::resolution::fact_source::JavaAccessEndpoint {
                        semantic: row.semantic(),
                        package: package.clone(),
                        outermost_type: owner.filter(|owner| types.contains(owner)),
                    },
                );
            }
        }
        preload.set_java_access_endpoints(endpoints);
        preload.set_java_inheritance_metadata(declarations);
        let SelectedResolutionContextValidationOutcome::Ready(preload_context) = preload_context
            .validate_exact_mounts(mounts.len(), &mount_lookup(&mounts), &cancellation)
            .expect("validate preloaded Java root context")
        else {
            panic!("uncancelled preloaded Java root context must validate")
        };
        let preload_blueprint =
        brokk_bifrost_analysis::analyzer::resolution::fact_resolution::SelectedContextTestOracle::collect_context(
            preload_context,
            &mounted.ready.shared_names(),
            &cancellation,
        )
        .expect("compile independent preloaded Java root context oracle");
        drop(mounted);
        let expected_point = preload_blueprint
            .resolve_reference(&preload, &preload, reference, &cancellation)
            .expect("preloaded cross-package Java point resolution");
        assert!(
            expected_point
                .binding()
                .targets()
                .contains(&provider_definition)
        );
        assert!(
            !expected_point
                .binding()
                .targets()
                .contains(&decoy_definition)
        );
        assert!(matches!(
            expected_point.completion(),
            ResolutionCompletion::Incomplete(_)
        ));

        let point_locator = SelectedSemanticLocator::new(
            "java",
            JAVA_ROOT_CONSUMER_PATH,
            reference_site,
            LoweredSemanticRole::Reference,
        );
        let point_operation = fixture.open_ready(&cancellation);
        let point_context = fixture.contexts_for(&point_operation);
        let mut point_metrics = SelectedResolutionContextMetrics;
        let point = point_operation
            .resolve_reference(
                point_context,
                &point_locator,
                &cancellation,
                &mut point_metrics,
            )
            .expect("persisted cross-package Java point resolution");
        assert_empty_context_metrics(&point_metrics);
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(point)) =
            point
        else {
            panic!("persisted cross-package Java point must return a native found answer")
        };
        assert_eq!(point.site_metadata(), expected_point.site_metadata());
        assert_eq!(point.reference_owner(), expected_point.reference_owner());
        assert_eq!(
            point.callable_receiver_origin(),
            expected_point.callable_receiver_origin()
        );
        assert_eq!(
            point.callable_receiver_dispositions(),
            expected_point.callable_receiver_dispositions()
        );
        assert_eq!(
            point.callable_candidate_applicability(),
            expected_point.callable_candidate_applicability()
        );
        assert_eq!(point.member_owners(), expected_point.member_owners());
        assert_eq!(
            point.observed_type_identity(),
            expected_point.observed_type_identity()
        );
        assert_eq!(
            point.type_bound_receiver(),
            expected_point.type_bound_receiver()
        );
        assert_eq!(
            point.binding().targets(),
            expected_point.binding().targets()
        );
        assert_eq!(
            point.binding().witnesses(),
            expected_point.binding().witnesses()
        );
        let implicit_project = fixture.configuration.is_empty();
        let mut completion_improved = false;
        completion_improved |= assert_java_import_route_proof_delta(
            point.binding().completion(),
            expected_point.binding().completion(),
            reference,
            implicit_project,
        );
        assert_eq!(point.projections(), expected_point.projections());
        assert_eq!(
            point.projected_frontiers().len(),
            expected_point.projected_frontiers().len()
        );
        for (actual, expected) in point
            .projected_frontiers()
            .iter()
            .zip(expected_point.projected_frontiers())
        {
            assert_eq!(actual.slot(), expected.slot());
            assert_eq!(actual.possible_values(), expected.possible_values());
            completion_improved |= assert_java_import_route_proof_delta(
                actual.completion(),
                expected.completion(),
                reference,
                implicit_project,
            );
        }
        completion_improved |= assert_java_import_route_proof_delta(
            point.completion(),
            expected_point.completion(),
            reference,
            implicit_project,
        );

        let expected_reverse = preload_blueprint
            .references_to(
                &preload,
                &preload,
                2,
                provider_definition,
                &cancellation,
                &mut FactReverseResolutionMetrics::default(),
            )
            .expect("preloaded cross-package Java reverse resolution");
        assert!(expected_reverse.references().contains(&reference));
        assert!(matches!(
            expected_reverse.completion(),
            ResolutionCompletion::Incomplete(_)
        ));
        let definition_locator = SelectedSemanticLocator::new(
            "java",
            JAVA_ROOT_PROVIDER_PATH,
            provider_site,
            LoweredSemanticRole::Definition,
        );
        let reverse_operation = fixture.open_ready(&cancellation);
        let reverse_context = fixture.contexts_for(&reverse_operation);
        let mut context_metrics = SelectedResolutionContextMetrics;
        let mut reverse_metrics = FactReverseResolutionMetrics::default();
        let reverse = reverse_operation
            .references_to_selected_definition(
                reverse_context,
                2,
                &definition_locator,
                &cancellation,
                &mut context_metrics,
                &mut reverse_metrics,
            )
            .expect("persisted cross-package Java reverse resolution");
        assert_empty_context_metrics(&context_metrics);
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(reverse)) =
            reverse
        else {
            panic!("persisted cross-package Java reverse must return a native found answer")
        };
        assert_eq!(reverse.references(), expected_reverse.references());
        assert_eq!(reverse.answer().witnesses(), expected_reverse.witnesses());
        completion_improved |= assert_java_import_route_proof_delta(
            reverse.completion(),
            expected_reverse.completion(),
            reference,
            implicit_project,
        );
        assert!(reverse.references().contains(&reference));
        completion_improved
    }
    fn assert_java_provider_visibility(
        fixture: &JavaRootResolutionOperationFixture,
        visible: bool,
    ) {
        assert_java_definition_visibility(
            fixture,
            &fixture.provider_facts,
            &fixture.source_rows[1].rel_path,
            visible,
        );
    }
    fn assert_java_definition_visibility(
        fixture: &JavaRootResolutionOperationFixture,
        facts: &FileResolutionFacts,
        path: &str,
        visible: bool,
    ) -> ResolutionCompletion {
        assert_java_named_definition_visibility(
            fixture,
            facts,
            path,
            "Target",
            ResolutionNamespace::Type,
            visible,
        )
    }
    fn assert_java_named_definition_visibility(
        fixture: &JavaRootResolutionOperationFixture,
        facts: &FileResolutionFacts,
        path: &str,
        name: &str,
        namespace: ResolutionNamespace,
        visible: bool,
    ) -> ResolutionCompletion {
        let cancellation = CancellationToken::new();
        let operation = fixture.open_ready(&cancellation);
        let context = fixture.contexts_for(&operation);
        let provider = operation
            .mount_table()
            .mount_for_path("java", path)
            .unwrap()
            .unwrap();
        let lowered =
            brokk_bifrost_analysis::analyzer::resolution::lower_resolution_facts_for_selection(
                provider.fragment(),
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
                Language::Java,
                facts,
            );
        let definition = semantic_at(
            &lowered,
            site_for_identifier(
                facts,
                name,
                ResolutionIdentifierRole::Declaration,
                namespace,
            ),
            LoweredSemanticRole::Definition,
        );
        let reference = try_site_for_identifier(
            &fixture.consumer_facts,
            name,
            ResolutionIdentifierRole::Reference,
            namespace,
        )
        .or_else(|| {
            (namespace == ResolutionNamespace::Value)
                .then(|| {
                    try_site_for_identifier(
                        &fixture.consumer_facts,
                        name,
                        ResolutionIdentifierRole::Reference,
                        ResolutionNamespace::TypeOrValue,
                    )
                })
                .flatten()
        })
        .unwrap_or_else(|| panic!("fixture identifier Reference {namespace:?} {name:?}"));
        let answer = operation
            .resolve_reference(
                context,
                &SelectedSemanticLocator::new(
                    "java",
                    &fixture.consumer_path,
                    reference,
                    LoweredSemanticRole::Reference,
                ),
                &cancellation,
                &mut SelectedResolutionContextMetrics,
            )
            .unwrap();
        let SelectedResolutionOperationOutcome::Native(SelectedResolutionLocated::Found(answer)) =
            answer
        else {
            panic!("source-owned Java type reference must remain located");
        };
        assert_eq!(
            answer.binding().targets().contains(&definition),
            visible,
            "{answer:?}"
        );
        answer.completion().clone()
    }

    use rusqlite::params;
}
