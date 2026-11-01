#[cfg(test)]
mod csharp_extraction_tests {
    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use std::sync::Arc;

    use brokk_bifrost_analysis::analyzer::store::GenerationId;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    use brokk_bifrost_analysis::analyzer::store::epoch;

    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_prior_parsed_blob_invalidated;

    use brokk_bifrost_core::test_support::write_file;
    use brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAdapter;

    #[test]
    fn csharp_extent_publication_tracks_edits_and_overlay_inventory() {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
        use brokk_bifrost_analysis::analyzer::store::{WorkspaceId,workspace_inputs::WorkspaceConfigurationInput};
        use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{SelectedResolutionContentMountRequest,SelectedResolutionLanguage,SelectedResolutionMountInventoryOutcome,SelectedResolutionOverlayMask};
        use brokk_bifrost_analysis::analyzer::store_support::test_support::operation_fixture_support::parsed_operation_source_state;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test;
        use brokk_bifrost_core::{analyzer::Language,cancellation::CancellationToken,gitblob::BlobKey,hash::HashMap};
        if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","engine_tests::csharp_store::csharp_extraction_tests::csharp_extent_publication_tracks_edits_and_overlay_inventory","--nocapture"])
                .env("BIFROST_TRIAL_NATIVE_CSHARP","1").output().unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                "{output:?}"
            );
            return;
        }
        let config = "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"../Shared.cs\"/><Compile Remove=\"Removed.cs\"/></ItemGroup></Project>";
        let mut builder = InlineTestProject::with_language(Language::CSharp)
            .file("A/A.csproj", config)
            .file("B/B.csproj", config)
            .file("Shared.cs", "global using SharedAlias=N.W; class Shared {}")
            .file(
                "A/Global.cs",
                "global using AType=N.W; namespace N { public class W {} }",
            )
            .file("A/Removed.cs", "class Removed {}")
            .file("A/Identical.cs", "class F1 {}")
            .file("B/Peer.cs", "namespace N { public class W {} }");
        for i in 0..128 {
            builder = builder.file(format!("A/F{i:03}.cs"), format!("class F{i} {{}}"));
        }
        let fixture = builder.build();
        let context =
            single_connection_store_context_for_test(fixture.project_dyn().as_ref()).unwrap();
        let store = Arc::clone(&context.store);
        let workspace = context.workspace_id.clone();
        let _analyzer = WorkspaceAnalyzer::build_with_store_context_for_test(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
            context,
        )
        .unwrap();
        let mut snapshots = store
            .workspace_snapshots_for_current_languages(&workspace, &["csharp".into()])
            .unwrap();
        let first = snapshots["csharp"].revision;
        let inspect = |sql: &str| -> i64 {
            let conn = store.conn.lock().unwrap();
            brokk_bifrost_analysis::analyzer::store::csharp_compilation::verify_using_counts_for_test(&conn);
            conn.query_row(sql, [workspace.as_str()], |r| r.get(0))
                .unwrap()
        };
        let members = "SELECT count(*) FROM csharp_compilation_members WHERE workspace_id=?1 AND valid_until IS NULL";
        let complete = "SELECT count(*) FROM csharp_compilation_using_coverage WHERE workspace_id=?1 AND valid_until IS NULL AND membership_complete=1 AND metadata_complete=1 AND publications_installed=publications_expected";
        assert_eq!(inspect(members), 133, "populated publisher ran");
        assert_eq!(inspect(complete), 2, "both certificates installed");
        assert_eq!(
            inspect(
                "SELECT count(*) FROM csharp_compilation_members WHERE workspace_id=?1 AND rel_path='Shared.cs' AND valid_until IS NULL"
            ),
            2
        );
        assert_eq!(
            inspect(
                "SELECT count(*) FROM csharp_compilation_members WHERE workspace_id=?1 AND rel_path='A/Removed.cs'"
            ),
            0
        );
        let peer = inspect(
            "SELECT file_version_id FROM csharp_compilation_members WHERE workspace_id=?1 AND rel_path='B/Peer.cs' AND valid_until IS NULL",
        );
        let before =
            inspect("SELECT count(*) FROM csharp_compilation_members WHERE workspace_id=?1");
        let source =
            "global using AType=N.Other; namespace N { public class W {} public class Other {} }";
        let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        let langs = vec!["csharp".to_owned()];
        let generations = snapshots
            .iter()
            .map(|(k, v)| (k.clone(), v.generation))
            .collect::<HashMap<_, _>>();
        snapshots = store
            .replace_path_symbol_unit(
                &workspace,
                &snapshots,
                &langs,
                &generations,
                "A/Global.cs",
                Some(("csharp", oid, None)),
                None,
                &[],
                &[],
                &[],
                &[],
                None,
            )
            .unwrap();
        let second = snapshots["csharp"].revision;
        // A building publication for the selected new OID contributes no installed count.
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO blobs(blob_oid,lang,generation) VALUES(?1,'csharp',?2)",
                (oid.to_string(), snapshots["csharp"].generation.0),
            )
            .unwrap();
            conn.execute("INSERT OR IGNORE INTO resolution_fragment_interiors(blob_id,lang,semantic_language,producer_epoch,interior_digest,expected_semantic_site_count,logical_rows,payload_bytes,publication_state)
                SELECT id,'csharp','csharp','incomplete-oracle',zeroblob(32),0,0,0,'building' FROM blobs WHERE blob_oid=?1 AND lang='csharp' AND parse_variant=x''",[oid.to_string()]).unwrap();
        }

        assert!(second > first);
        assert_eq!(inspect(members), 133);
        assert_eq!(
            inspect(
                "SELECT sum(publications_expected-publications_installed) FROM csharp_compilation_using_coverage WHERE workspace_id=?1 AND valid_until IS NULL"
            ),
            1
        );
        assert_eq!(
            inspect(
                "SELECT file_version_id FROM csharp_compilation_members WHERE workspace_id=?1 AND rel_path='B/Peer.cs' AND valid_until IS NULL"
            ),
            peer
        );
        assert_eq!(
            inspect("SELECT count(*) FROM csharp_compilation_members WHERE workspace_id=?1"),
            before + 1,
            "only edited path got another interval"
        );
        let cancellation = CancellationToken::new();
        let (state, _) =
            parsed_operation_source_state(fixture.root(), "A/Global.cs", source, &CSharpAdapter);
        let prepared = AnalyzerStore::prepare_parsed_blob(
            &BlobKey::unvaried(oid, "csharp"),
            snapshots["csharp"].generation,
            &CSharpAdapter,
            state,
        )
        .unwrap();
        assert!(matches!(
            store
                .publish_selected_parsed_content(
                    &snapshots["csharp"],
                    "A/Global.cs",
                    prepared,
                    &cancellation
                )
                .unwrap(),
            ResolutionContentPublicationOutcome::Ready(_)
        ));
        assert_eq!(
            inspect(complete),
            2,
            "late publication filled the missing source"
        );
        assert_eq!(
            inspect("SELECT count(*) FROM csharp_compilation_members WHERE workspace_id=?1"),
            before + 1,
            "late publication preserves membership intervals"
        );
        // An unchanged source publication retains all intervals and certificates.
        snapshots = store
            .replace_path_symbol_unit(
                &workspace,
                &snapshots,
                &langs,
                &generations,
                "A/Global.cs",
                Some(("csharp", oid, None)),
                None,
                &[],
                &[],
                &[],
                &[],
                None,
            )
            .unwrap();
        assert_eq!(snapshots["csharp"].revision, second);
        assert_eq!(
            inspect("SELECT count(*) FROM csharp_compilation_members WHERE workspace_id=?1"),
            before + 1
        );
        let config2 = config.replace("</ItemGroup>", "<Compile Remove=\"F000.cs\"/></ItemGroup>");
        (snapshots, _) = store
            .replace_configuration_input(
                &workspace,
                &snapshots,
                &langs,
                &generations,
                WorkspaceConfigurationInput::new("A/A.csproj".into(), config2.into_bytes().into()),
            )
            .unwrap();
        let third = snapshots["csharp"].revision;
        assert!(third > second);
        assert_eq!(inspect(members), 132, "one removed member, whole new set");
        assert_eq!(inspect(complete), 2);
        assert_eq!(
            inspect(
                "SELECT count(*) FROM csharp_compilation_members WHERE workspace_id=?1 AND valid_until IS NULL AND rel_path='A/F000.cs'"
            ),
            0
        );
        assert_eq!(
            inspect(&format!(
                "SELECT count(*) FROM csharp_compilation_members WHERE workspace_id=?1 AND valid_until IS NULL AND rel_path='B/Peer.cs' AND file_version_id={peer}"
            )),
            1
        );
        assert_eq!(
            inspect(
                "SELECT count(DISTINCT valid_from) FROM csharp_compilation_members WHERE workspace_id=?1 AND valid_until IS NULL"
            ),
            1
        );
        assert_eq!(
            inspect(
                "SELECT min(valid_from) FROM csharp_compilation_members WHERE workspace_id=?1 AND valid_until IS NULL"
            ),
            third
        );
        assert_eq!(
            inspect(
                "SELECT count(*) FROM csharp_compilation_using_coverage WHERE workspace_id=?1 AND valid_until IS NULL"
            ),
            2
        );
        // Equal counts do not merge distinct source states into one certificate interval.
        let prepublished = format!("{source} ");
        let fresh_oid =
            git2::Oid::hash_object(git2::ObjectType::Blob, prepublished.as_bytes()).unwrap();
        let (state, _) = parsed_operation_source_state(
            fixture.root(),
            "A/Global.cs",
            &prepublished,
            &CSharpAdapter,
        );
        let prepared = AnalyzerStore::prepare_parsed_blob(
            &BlobKey::unvaried(fresh_oid, "csharp"),
            snapshots["csharp"].generation,
            &CSharpAdapter,
            state,
        )
        .unwrap();
        assert!(matches!(
            store
                .publish_selected_parsed_content(
                    &snapshots["csharp"],
                    "A/Global.cs",
                    prepared,
                    &cancellation
                )
                .unwrap(),
            ResolutionContentPublicationOutcome::Ready(_)
        ));
        snapshots = store
            .replace_path_symbol_unit(
                &workspace,
                &snapshots,
                &langs,
                &generations,
                "A/Global.cs",
                Some(("csharp", fresh_oid, None)),
                None,
                &[],
                &[],
                &[],
                &[],
                None,
            )
            .unwrap();
        assert_eq!(
            inspect(
                "SELECT v.valid_from FROM csharp_compilation_using_coverage v JOIN csharp_compilations c ON c.compilation_id=v.compilation_id WHERE v.workspace_id=?1 AND v.valid_until IS NULL AND c.project_path='A/A.csproj'"
            ),
            snapshots["csharp"].revision
        );
        let (state, _) =
            parsed_operation_source_state(fixture.root(), "A/Global.cs", source, &CSharpAdapter);
        let prepared = AnalyzerStore::prepare_parsed_blob(
            &BlobKey::unvaried(oid, "csharp"),
            snapshots["csharp"].generation,
            &CSharpAdapter,
            state,
        )
        .unwrap();
        store.repair_prepared_blob(prepared).unwrap();
        assert_eq!(
            inspect(complete),
            2,
            "repairing retained old content preserves the current certificate"
        );
        assert_eq!(
            inspect(
                "SELECT count(*) FROM csharp_compilation_using_coverage WHERE workspace_id=?1 AND publications_installed<>publications_expected"
            ),
            0,
            "retained certificates were restored too"
        );
        let overlay = "global using Replacement=N.W; class Overlay {}";
        let overlay_oid =
            git2::Oid::hash_object(git2::ObjectType::Blob, overlay.as_bytes()).unwrap();
        let (state, _) =
            parsed_operation_source_state(fixture.root(), "A/Global.cs", overlay, &CSharpAdapter);
        let prepared = AnalyzerStore::prepare_parsed_blob(
            &BlobKey::unvaried(overlay_oid, "csharp"),
            snapshots["csharp"].generation,
            &CSharpAdapter,
            state,
        )
        .unwrap();
        let ResolutionContentPublicationOutcome::Ready(content) = store
            .publish_selected_parsed_content(
                &snapshots["csharp"],
                "A/Global.cs",
                prepared,
                &cancellation,
            )
            .unwrap()
        else {
            panic!("overlay publication");
        };
        let requests = [SelectedResolutionContentMountRequest::new(
            content.into_parts().0,
            WorkspaceFileRow {
                decision: None,
                rel_path: "A/Global.cs".into(),
                blob_oid: overlay_oid,
            },
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .with_live_overlay_content_digest(
            brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(overlay.as_bytes()),
        )];
        let languages = [SelectedResolutionLanguage::new("csharp", Language::CSharp)];
        {
            let masks = [SelectedResolutionOverlayMask::replacement(
                "csharp",
                "A/Global.cs",
            )];
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory_with_content_mounts(
                    &workspace,
                    &snapshots,
                    &languages,
                    &masks,
                    &requests,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("replacement selection");
            };
            let conn = selection.connection();
            assert_eq!(conn.query_row("SELECT count(*) FROM temp.selected_csharp_global_using_extent e JOIN blobs b ON b.id=e.blob_id WHERE e.rel_path='A/Global.cs' AND b.blob_oid=?1",[overlay_oid.to_string()],|r|r.get::<_,i64>(0)).unwrap(),1,"replacement replaces predecessor");
            assert_eq!(conn.query_row("SELECT count(*) FROM temp.selected_csharp_compilation_using_coverage WHERE publications_expected=publications_installed AND membership_complete=1 AND metadata_complete=1",[],|r|r.get::<_,i64>(0)).unwrap(),2);
        }
        {
            let masks = [SelectedResolutionOverlayMask::removal(
                "csharp",
                "A/Global.cs",
            )];
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory(
                    &workspace,
                    &snapshots,
                    &languages,
                    &masks,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("deletion selection");
            };
            let conn = selection.connection();
            assert_eq!(conn.query_row("SELECT count(*) FROM temp.selected_csharp_global_using_extent WHERE rel_path='A/Global.cs'",[],|r|r.get::<_,i64>(0)).unwrap(),0);
            assert_eq!(conn.query_row("SELECT sum(publications_expected) FROM temp.selected_csharp_compilation_using_coverage",[],|r|r.get::<_,i64>(0)).unwrap(),131);
            assert_eq!(conn.query_row("SELECT sum(publications_expected-publications_installed) FROM temp.selected_csharp_compilation_using_coverage",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        }
        {
            let masks = [SelectedResolutionOverlayMask::replacement(
                "csharp",
                "A/Global.cs",
            )];
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory(
                    &workspace,
                    &snapshots,
                    &languages,
                    &masks,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("unpublished replacement selection");
            };
            assert_eq!(selection.connection().query_row("SELECT sum(publications_expected-publications_installed) FROM temp.selected_csharp_compilation_using_coverage",[],|r|r.get::<_,i64>(0)).unwrap(),1,"missing replacement remains a publication obligation");
        }
        {
            let masks = [SelectedResolutionOverlayMask::removal(
                "csharp",
                "A/A.csproj",
            )];
            let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
                .open_selected_resolution_mount_inventory(
                    &workspace,
                    &snapshots,
                    &languages,
                    &masks,
                    &cancellation,
                )
                .unwrap()
            else {
                panic!("configuration overlay selection");
            };
            assert_eq!(selection.connection().query_row("SELECT count(*) FROM temp.selected_csharp_compilation_using_coverage WHERE membership_complete=0 AND metadata_complete=0",[],|r|r.get::<_,i64>(0)).unwrap(),2);
            assert_eq!(
                selection
                    .connection()
                    .query_row(
                        "SELECT count(*) FROM temp.selected_csharp_global_using_extent",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                0,
                "changed configuration cannot borrow disk membership"
            );
        }
        // Both directive-bearing and zero-directive publication repairs update certificates.
        for (path, text) in [
            ("Shared.cs", "global using SharedAlias=N.W; class Shared {}"),
            ("A/F001.cs", "class F1 {}"),
        ] {
            let oid = git2::Oid::hash_object(git2::ObjectType::Blob, text.as_bytes()).unwrap();
            let (state, _) =
                parsed_operation_source_state(fixture.root(), path, text, &CSharpAdapter);
            let prepared = AnalyzerStore::prepare_parsed_blob(
                &BlobKey::unvaried(oid, "csharp"),
                snapshots["csharp"].generation,
                &CSharpAdapter,
                state,
            )
            .unwrap();
            store.repair_prepared_blob(prepared).unwrap();
            assert_eq!(
                inspect(complete),
                2,
                "publication repair restored coverage for {path}"
            );
        }
        // Re-publishing an already complete source preserves its installed contribution.
        for _ in 0..2 {
            let text = "global using SharedAlias=N.W; class Shared {}";
            let oid = git2::Oid::hash_object(git2::ObjectType::Blob, text.as_bytes()).unwrap();
            let (state, _) =
                parsed_operation_source_state(fixture.root(), "Shared.cs", text, &CSharpAdapter);
            let prepared = AnalyzerStore::prepare_parsed_blob(
                &BlobKey::unvaried(oid, "csharp"),
                snapshots["csharp"].generation,
                &CSharpAdapter,
                state,
            )
            .unwrap();
            assert!(matches!(
                store
                    .publish_selected_parsed_content(
                        &snapshots["csharp"],
                        "Shared.cs",
                        prepared,
                        &cancellation
                    )
                    .unwrap(),
                ResolutionContentPublicationOutcome::Ready(_)
            ));
            assert_eq!(inspect(complete), 2);
        }
        {
            // The engine fixture uses one in-memory connection. Reclaim a persisted copy
            // of that exact publication history through the real core collector.
            let scratch = tempfile::tempdir().unwrap();
            let db = scratch.path().join("gc.db");
            store
                .conn
                .lock()
                .unwrap()
                .execute("VACUUM main INTO ?1", [db.to_str().unwrap()])
                .unwrap();
            // An unrelated unmarked blob must actually be reclaimed by this sweep.
            {
                let copy = brokk_bifrost_core::cache_db::open_unified_connection(&db).unwrap();
                copy.execute("INSERT INTO blobs(blob_oid,lang,generation) VALUES('ffffffffffffffffffffffffffffffffffffffff','csharp',?1)",[snapshots["csharp"].generation.0]).unwrap();
            }
            let repo = git2::Repository::init(fixture.root()).unwrap();
            brokk_bifrost_core::cache_gc::force_gc(&db, &repo, fixture.root()).unwrap();
            let copy = brokk_bifrost_core::cache_db::open_unified_connection(&db).unwrap();
            assert_eq!(copy.query_row("SELECT count(*) FROM blobs WHERE blob_oid='ffffffffffffffffffffffffffffffffffffffff'",[],|r|r.get::<_,i64>(0)).unwrap(),0,"real GC reclaimed the unaccounted candidate");
            brokk_bifrost_analysis::analyzer::store::csharp_compilation::verify_using_counts_for_test(&copy);
            assert_eq!(
                copy.query_row(complete, [workspace.as_str()], |r| r.get::<_, i64>(0))
                    .unwrap(),
                2,
                "real GC retained accounted publications"
            );
        }
        let loose = WorkspaceId::for_session();
        let loose_snapshot = store
            .sync_workspace_inputs_for_workspace(
                &loose,
                "csharp",
                generations["csharp"],
                &[WorkspaceFileRow {
                    decision: None,
                    rel_path: "Loose.cs".into(),
                    blob_oid: oid,
                }],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        assert_eq!(store.conn.lock().unwrap().query_row("SELECT count(*) FROM csharp_compilation_members m JOIN csharp_compilations c ON c.compilation_id=m.compilation_id WHERE m.workspace_id=?1 AND c.project_path IS NULL AND m.valid_until IS NULL",[loose_snapshot.workspace_id.as_str()],|r|r.get::<_,i64>(0)).unwrap(),1,"implicit compilation published");
    }

    #[test]
    fn csharp_new_selected_source_has_placement_without_persisted_version() {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedContextIdentities;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_units::CSharpUnitReader;
        use brokk_bifrost_analysis::analyzer::store::resolution_publication::ResolutionContentPublicationOutcome;
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{SelectedResolutionContentMountRequest, SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome, SelectedResolutionOverlayMask};
        use brokk_bifrost_analysis::analyzer::store_support::test_support::operation_fixture_support::parsed_operation_source_state;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test;
        use brokk_bifrost_core::{analyzer::Language, cancellation::CancellationToken, gitblob::BlobKey};
        if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "engine_tests::csharp_store::csharp_extraction_tests::csharp_new_selected_source_has_placement_without_persisted_version", "--nocapture"])
                .env("BIFROST_TRIAL_NATIVE_CSHARP", "1").output().unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                "{output:?}"
            );
            return;
        }
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
            .file(
                "App/Peer.cs",
                "global using X = N.W; namespace N { public class W {} }",
            )
            .build();
        let context =
            single_connection_store_context_for_test(fixture.project_dyn().as_ref()).unwrap();
        let store = Arc::clone(&context.store);
        let workspace_id = context.workspace_id.clone();
        let _workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
            context,
        )
        .unwrap();
        let snapshots = store
            .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".into()])
            .unwrap();
        let path = "App/New.cs";
        let source = "class New { X field; }";
        let (state, _) =
            parsed_operation_source_state(fixture.root(), path, source, &CSharpAdapter);
        let oid = git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes()).unwrap();
        let cancellation = CancellationToken::new();
        let prepared = AnalyzerStore::prepare_parsed_blob(
            &BlobKey::unvaried(oid, "csharp"),
            snapshots["csharp"].generation,
            &CSharpAdapter,
            state,
        )
        .unwrap();
        let ResolutionContentPublicationOutcome::Ready(content) = store
            .publish_selected_parsed_content(&snapshots["csharp"], path, prepared, &cancellation)
            .unwrap()
        else {
            panic!("new source publication");
        };
        let content_mounts = [SelectedResolutionContentMountRequest::new(
            content.into_parts().0,
            WorkspaceFileRow {
                rel_path: path.into(),
                blob_oid: oid,
                // This transient mount deliberately has no persisted source version.
                decision: None,
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .with_live_overlay_content_digest(
            brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(source.as_bytes()),
        )];
        let languages = [SelectedResolutionLanguage::new("csharp", Language::CSharp)];
        let masks = [SelectedResolutionOverlayMask::replacement("csharp", path)];
        let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
            .open_selected_resolution_mount_inventory_with_content_mounts(
                &workspace_id,
                &snapshots,
                &languages,
                &masks,
                &content_mounts,
                &cancellation,
            )
            .unwrap()
        else {
            panic!("new selected source");
        };
        assert_eq!(selection.connection().query_row("SELECT count(*) FROM workspace_file_versions WHERE workspace_id=?1 AND lang='csharp' AND rel_path=?2", rusqlite::params![workspace_id.as_str(), path], |row| row.get::<_, i64>(0)).unwrap(), 0);
        let mount = selection
            .mount_record_for_path("csharp", path)
            .unwrap()
            .unwrap();
        assert!(mount.file_version_id().is_none(), "transient source ran");
        let identities = SelectedContextIdentities::new();
        let mut reader =
            CSharpUnitReader::new(&selection, &snapshots["csharp"], &identities).unwrap();
        let placements = reader.placements(path).unwrap().unwrap();
        assert_eq!(placements.len(), 1, "{placements:?}");
        assert_eq!(
            placements[0].project_path.as_deref(),
            Some("App/App.csproj")
        );
        assert!(reader.placements("App/NotSelected.cs").unwrap().is_none());
        drop(reader);
        drop(selection);
        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedSemanticLocator;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
            SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
        };
        use brokk_bifrost_core::analyzer::project::OverlayProject;
        let overlay = OverlayProject::new(fixture.project_dyn());
        assert!(overlay.set(fixture.root().join(path), source.into()));
        let input = SelectedResolutionOperationInput::new(
            &overlay,
            &workspace_id,
            &snapshots,
            &languages,
            &masks,
        )
        .with_content_mounts(content_mounts.to_vec());
        let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
            .open_selected_resolution_operation(input, &cancellation)
            .unwrap()
        else {
            panic!("selected overlay caller operation");
        };
        let start = source.find("X field").unwrap();
        let locator =
            SelectedSemanticLocator::for_reference_range("csharp", path, start, start + 1);
        let answer = brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_demand::probe_type(&operation, &snapshots["csharp"], &locator, &cancellation).unwrap().unwrap();
        assert_eq!(
            answer.targets,
            vec![("App/Peer.cs".into(), "N.W".into())],
            "overlay-only caller must select the other file's global alias"
        );
    }

    #[test]
    fn csharp_linked_file_access_agrees_per_caller_compilation() {
        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_analysis::analyzer::read_ledger::{DerivationExecutionCause, reason};
        use brokk_bifrost_analysis::analyzer::resolution::selected_context::SelectedContextIdentities;
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::csharp_units::{
            ACCESS_UNKNOWN, CSharpUnitAccess, CSharpUnitReader, PLACEMENT_SQL,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection,
            finish_production_selected_sql_trace_on_connection,
        };
        use brokk_bifrost_analysis::analyzer::store::resolution_selection::{
            SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
        };
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test;
        use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
        use brokk_bifrost_core::{analyzer::Language, cancellation::CancellationToken};
        if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "engine_tests::csharp_store::csharp_extraction_tests::csharp_linked_file_access_agrees_per_caller_compilation", "--nocapture"])
                .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
                .output().unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                "the child must run: {output:?}"
            );
            return;
        }
        let project = "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"../Linked.cs\" /></ItemGroup></Project>";
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file("A/A.csproj", project)
            .file("B/B.csproj", project)
            .file("Linked.cs", "class Linked {}")
            .file("A/Caller.cs", "class Caller {}")
            .file("A/Target.cs", "class Target {}")
            .file("B/Hidden.cs", "class Hidden {}")
            .file("Outside.cs", "class Outside {}")
            .build();
        let context =
            single_connection_store_context_for_test(fixture.project_dyn().as_ref()).unwrap();
        let workspace_id = context.workspace_id.clone();
        let store = Arc::clone(&context.store);
        let _workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
            context,
        )
        .unwrap();
        let snapshots = store
            .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".to_owned()])
            .unwrap();
        let cancellation = CancellationToken::new();
        let languages = [SelectedResolutionLanguage::new("csharp", Language::CSharp)];
        let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
            .open_selected_resolution_mount_inventory(
                &workspace_id,
                &snapshots,
                &languages,
                &[],
                &cancellation,
            )
            .unwrap()
        else {
            panic!("selected C# inventory");
        };
        let identities = SelectedContextIdentities::new();
        let mut reader =
            CSharpUnitReader::new(&selection, &snapshots["csharp"], &identities).unwrap();
        begin_production_selected_sql_trace_on_connection(selection.connection());
        let linked = reader.placements("Linked.cs").unwrap().unwrap();
        let cost = finish_production_selected_sql_trace_on_connection(selection.connection());
        assert_eq!(
            linked
                .iter()
                .map(|p| p.project_path.as_deref())
                .collect::<Vec<_>>(),
            [Some("A/A.csproj"), Some("B/B.csproj")]
        );
        assert_eq!(
            cost.statements
                .iter()
                .filter(|sql| sql.as_str() == PLACEMENT_SQL)
                .count(),
            2,
            "{cost:?}"
        );
        assert_eq!(
            cost.rows_by_shape()
                .iter()
                .find(|(_, _, sql)| *sql == PLACEMENT_SQL)
                .map(|(rows, _, _)| *rows),
            Some(2),
            "{cost:?}"
        );
        let caller = reader.placements("A/Caller.cs").unwrap().unwrap();
        let target = reader.placements("A/Target.cs").unwrap().unwrap();
        let hidden = reader.placements("B/Hidden.cs").unwrap().unwrap();
        begin_production_selected_sql_trace_on_connection(selection.connection());
        assert_eq!(
            reader.access(Some(&caller), Some(&target)).unwrap(),
            CSharpUnitAccess::Visible
        );
        assert_eq!(
            reader.access(Some(&caller), Some(&hidden)).unwrap(),
            CSharpUnitAccess::NotVisible
        );
        let CSharpUnitAccess::Unknown { kind, evidence } =
            reader.access(Some(&linked), Some(&target)).unwrap()
        else {
            panic!("linked callers disagree");
        };
        assert_eq!(kind, ACCESS_UNKNOWN);
        assert_eq!(
            reason::classify_known(kind),
            Some(Some(DerivationExecutionCause::Provider))
        );
        assert!(
            evidence.contains("A/A.csproj") && evidence.contains("B/B.csproj"),
            "{evidence}"
        );
        // A target linked into both projects is visible to A even though B is not.
        assert_eq!(
            reader.access(Some(&caller), Some(&linked)).unwrap(),
            CSharpUnitAccess::Visible
        );
        let outside = reader.placements("Outside.cs").unwrap().unwrap();
        assert!(outside.is_empty());
        assert!(matches!(
            reader.access(Some(&caller), Some(&outside)).unwrap(),
            CSharpUnitAccess::Unknown { .. }
        ));
        let unselected = reader.placements("NotSelected.cs").unwrap();
        assert!(unselected.is_none());
        assert!(matches!(
            reader.access(unselected.as_deref(), Some(&target)).unwrap(),
            CSharpUnitAccess::Unknown { .. }
        ));
        let cost = finish_production_selected_sql_trace_on_connection(selection.connection());
        // These are M2's real closure statements on the held connection, not
        // constructed pair answers or a memo that was never populated.
        let closures: Vec<_> = cost
            .statements
            .iter()
            .filter(|sql| sql.contains("WITH RECURSIVE reach"))
            .collect();
        assert!(
            closures
                .iter()
                .any(|sql| sql.contains("references_complete")),
            "{cost:?}"
        );
        assert!(
            closures.iter().any(|sql| sql.contains("expand")),
            "{cost:?}"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "5304870f83d5: production C# test-like calls were misclassified by runner-name matching"
    )]
    #[test]
    fn csharp_structured_test_classification_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "Http3RequestTests.cs",
            "public class Http3RequestTests {\n\
             [ConditionalTheory]\n\
             public void RequestAbortRaised() { }\n\
             }\n",
        );
        let mut state = parse_state(&CSharpAdapter, &file);
        assert!(state.contains_tests);
        // The direct-name classifier used before this epoch did not recognize
        // custom xUnit attributes and persisted this runnable test as false.
        state.contains_tests = false;
        let state = Arc::new(state);
        let prior_epoch = epoch::csharp_epoch_before_structured_runnable_test_classification();
        assert_prior_parsed_blob_invalidated(&CSharpAdapter, state.as_ref(), &prior_epoch);
    }
    #[brokk_bifrost_test_macros::hardwon(
        "1396a5373c5b: inherited C# test methods were missing from derived-class blast radius"
    )]
    #[test]
    fn csharp_inherited_test_classification_epoch_invalidates_prior_owner_facts() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "BaseSpec.cs",
            "public abstract class BaseSpec {\n\
             [Fact]\n\
             public virtual void Inherited() { }\n\
             }\n",
        );
        let mut state = parse_state(&CSharpAdapter, &file);
        assert!(state.contains_tests);
        assert_eq!(1, state.test_region_units.len());
        // The immediately preceding C# epoch retained only the file-level
        // boolean. It did not identify which declaring type owns the runner
        // method, so a hierarchy walk could not classify derived files.
        state.test_region_units.clear();
        let state = Arc::new(state);
        let prior_epoch = epoch::csharp_epoch_before_inherited_test_classification();
        assert_prior_parsed_blob_invalidated(&CSharpAdapter, state.as_ref(), &prior_epoch);
    }
    #[test]
    fn csharp_nested_type_persists_structural_and_namespace_visibility() {
        let temp = tempfile::TempDir::new().unwrap();
        let content = "namespace Demo { class Outer { public class Nested<T> {} } }\n";
        let file = write_file(temp.path(), "Nested.cs", content);
        let oid = oid_for(content.as_bytes());
        let adapter = CSharpAdapter;
        let state = parse_state(&adapter, &file);
        let nested = state
            .declarations
            .iter()
            .find(|unit| unit.is_class() && unit.identifier().starts_with("Nested"))
            .expect("fixture declares a nested type");
        assert_eq!(nested.package_name(), "Demo");

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, "csharp"),
                &adapter,
                &state,
            )
            .unwrap();
        let workspace_file = WorkspaceFileRow {
            decision: None,
            rel_path: brokk_bifrost_core::path_utils::rel_path_string(&file),
            blob_oid: oid,
        };
        store
            .sync_workspace_snapshot(
                "csharp",
                GenerationId::BOOTSTRAP,
                &[workspace_file],
                &[],
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();

        let conn = store.conn.lock().expect("store mutex");
        let containers = conn
            .prepare(
                "SELECT exact_parent_tail
                 FROM live_visible_members
                 WHERE lang = 'csharp' AND identifier LIKE 'Nested%'
                 ORDER BY exact_parent_tail",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(containers, ["Demo", "Demo.Outer"]);

        let (simple_name, normalized_tail, segment_count): (String, String, i64) = conn
            .query_row(
                "SELECT units.simple_type_name, units.normalized_fqn_tail,
                        COUNT(segments.seg_ordinal)
                 FROM code_units AS units
                 JOIN code_unit_fq_segments AS segments
                   ON segments.blob_id = units.blob_id
                  AND segments.unit_key = units.unit_key
                 WHERE units.blob_id = (
                         SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'csharp'
                       )
                   AND units.identifier LIKE 'Nested%'
                 GROUP BY units.blob_id, units.unit_key",
                [oid.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(simple_name, "Nested");
        assert_eq!(normalized_tail, "Demo.Outer.Nested");
        assert_eq!(segment_count, nested.fq().len() as i64);
    }
}

#[test]
#[brokk_bifrost_test_macros::hardwon(
    "#8155: incomplete C# descendant cache fills panicked during member-family inversion"
)]
fn csharp_incomplete_descendant_fill_leaves_member_family_open() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete;
    use brokk_bifrost_analysis::analyzer::multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
    use brokk_bifrost_analysis::analyzer::usages::member_family::csharp_member_family;
    use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, IAnalyzer, capture_query_reads};
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::structural::resolution::MemberFamilyOutcome;
    use brokk_bifrost_csharp_analysis::CSharpAnalyzer;
    use std::collections::BTreeMap;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "Base.cs",
            "public class Base { public virtual void Run() {} }",
        )
        .file(
            "Child.cs",
            "public class Child : Base { public override void Run() {} }",
        )
        .build();
    let analyzer = MultiAnalyzer::new(BTreeMap::from([(
        Language::CSharp,
        AnalyzerDelegate::new(CSharpAnalyzer::new(project.project_dyn())),
    )]));
    let member = analyzer
        .declarations(&project.file("Base.cs"))
        .into_iter()
        .find(|unit| unit.is_function() && unit.identifier() == "Run")
        .unwrap();
    let owner = analyzer.parent_of(&member).unwrap();
    let gap = QueryReadIncomplete::SemanticEvidenceGap("refused hierarchy input".into());
    let (_, reads) = capture_query_reads(&analyzer, || {
        let scope = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
        analyzer.record_query_incomplete(gap.clone());
        let answer = csharp_member_family(&analyzer, &analyzer, &member, None);
        assert_eq!(
            answer.descendants.outcome,
            MemberFamilyOutcome::Incomplete,
            "{answer:?}"
        );
        assert_eq!(scope.captured_read_incompleteness(), vec![gap]);
    });
    assert_eq!(reads.execution_dependences(), 0, "{reads:?}");
    assert!(reads.unattributed_reads() > 0, "{reads:?}");
    let descendants = analyzer.get_direct_descendants(&owner);
    assert!(
        descendants.is_complete()
            && descendants
                .edges
                .iter()
                .any(|unit| unit.identifier() == "Child"),
        "{descendants:?}"
    );
}

#[test]
fn csharp_membership_descendants_preserve_refused_fill() {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, IAnalyzer, QueryReadIncomplete};
    use brokk_bifrost_core::analyzer::capabilities::{
        DescendantIndexScope, HierarchyOpenReason, TypeHierarchyProvider,
    };
    use brokk_bifrost_core::analyzer::{CodeUnitIndex, Language};
    use brokk_bifrost_core::cancellation::CancellationToken;
    use brokk_bifrost_csharp::graph::membership_scope::MembershipScopedSource;
    use brokk_bifrost_csharp_analysis::CSharpAnalyzer;
    let project = InlineTestProject::with_language(Language::CSharp)
        .file("Base.cs", "public partial class Base {}")
        .file(
            "Part.cs",
            "public partial class Base {} public class Child : Base {}",
        )
        .build();
    let analyzer = CSharpAnalyzer::new(project.project_dyn());
    let owner = analyzer
        .declarations(&project.file("Base.cs"))
        .into_iter()
        .find(|unit| unit.identifier() == "Base")
        .unwrap();
    let view = MembershipScopedSource::new(&analyzer, &project.file("Base.cs"));
    let _query = AnalyzerQueryScope::capturing_read_incompleteness(&analyzer);
    analyzer.record_query_incomplete(QueryReadIncomplete::SemanticEvidenceGap(
        "refused physical part".into(),
    ));
    let answer = view.get_direct_descendants(&owner);
    assert!(!answer.is_complete(), "{answer:?}");
    assert!(
        answer
            .open
            .iter()
            .any(|reason| matches!(reason, HierarchyOpenReason::DescendantIndexUnavailable)),
        "{answer:?}"
    );
    let token = CancellationToken::default();
    let scoped = view
        .get_direct_descendants_within(&owner, &DescendantIndexScope::whole_workspace(&token))
        .unwrap();
    assert!(!scoped.is_complete(), "{scoped:?}");
    assert!(
        scoped
            .open
            .iter()
            .any(|reason| matches!(reason, HierarchyOpenReason::DescendantIndexUnavailable)),
        "{scoped:?}"
    );
}
