#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    include!("rust_forwarded_surface_tests.rs");
    include!("rust_summary_equality_tests.rs");

    #[test]
    #[hardwon(
        "#13047: a carried detached unit recorded ancestor Cargo config inputs, so a scoped update re-keyed it"
    )]
    fn detached_configuration_inputs_match_fresh_after_scoped_update() {
        fn rows(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, (i64, String, String)> {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.prepare("SELECT t.crate_name,s.summary_id,hex(s.lookup_digest),
                (SELECT json_group_array(json_array(source_role,rel_path)) FROM
                 (SELECT source_role,rel_path FROM resolution_unit_summary_input_files
                  WHERE summary_id=s.summary_id ORDER BY source_role,rel_path))
                FROM resolution_unit_summary_versions v
                JOIN resolution_unit_summaries s USING(summary_id)
                JOIN rust_crate_versions c ON c.workspace_id=v.workspace_id AND c.generation=v.generation
                  AND c.crate_key=v.unit_key AND c.valid_until IS NULL
                JOIN rust_crate_topologies t USING(topology_id)
                WHERE v.lang='rust' AND v.valid_until IS NULL AND t.target_kind='detached'")
                .unwrap().query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?, r.get(3)?))))
                .unwrap().collect::<rusqlite::Result<_>>().unwrap()
        }
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub fn app() {}\n")
            .file("nested/a.rs", "pub struct A;\n")
            .file("nested/deeper/b.rs", "pub struct B;\n")
            .file(
                "nested/.cargo/config.toml",
                "[build]\nrustflags=['--cfg', 'nested']\n",
            )
            .build();
        let workspace = project.certified_workspace_analyzer(AnalyzerConfig::default());
        let before = rows(&workspace);
        assert_eq!(before.len(), 2);
        let source = project.file("src/lib.rs");
        std::fs::write(source.abs_path(), "pub fn app() { let _value = 1; }\n").unwrap();
        let updated = workspace.update(&BTreeSet::from([source]));
        let after = rows(&updated);
        let fresh = project.certified_workspace_analyzer(AnalyzerConfig::default());
        let expected = rows(&fresh);
        for (name, (id, lookup, inputs)) in &after {
            eprintln!(
                "{name}: initial={:?}; updated={:?}; fresh={:?}",
                before[name], after[name], expected[name]
            );
            assert_eq!(inputs, &expected[name].2, "{name}: declared inputs");
            assert_eq!(lookup, &expected[name].1, "{name}: lookup digest");
            // IDs are store-local: compare with this store's fresh discovery.
            assert_eq!(*id, before[name].0, "{name}: detached unit was re-derived");
        }
        assert_eq!(after.len(), expected.len());
    }

    #[test]
    #[hardwon(
        "#12447: deleting rust-toolchain.toml failed workspace configuration capture instead of recording absence"
    )]
    fn deleted_workspace_configuration_matches_fresh_analysis() {
        // A listing whose ignore inputs are inside the capture race window is
        // deliberately uncertified, so its next update re-lists. Keep the
        // fixture under a parent this test owns, then age the Git exclude and
        // repository directories so the deletion update exercises the cached
        // membership patch rather than the fail-closed refresh.
        let temp = tempfile::tempdir().unwrap();
        let _env = brokk_bifrost_core::analyzer::project::IgnoreTestEnvironment::new(
            &temp.path().join("home"),
        );
        let root = temp.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        for (rel_path, contents) in [
            (
                "Cargo.toml",
                "[package]\nname='config_deletion'\nversion='0.1.0'\nedition='2021'\n",
            ),
            ("src/lib.rs", "pub fn probe() {}\n"),
            ("rust-toolchain.toml", "[toolchain]\nchannel='1.81.0'\n"),
            (
                ".cargo/config.toml",
                "[build]\nrustflags=['--cfg', 'configured']\n",
            ),
            (".cargo/config", "[build]\nrustflags=['--cfg', 'legacy']\n"),
            ("removed/a.rs", "pub struct A;\n"),
            ("removed/b.rs", "pub struct B;\n"),
            ("removed/c.rs", "pub struct C;\n"),
        ] {
            brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), rel_path)
                .write(contents)
                .unwrap();
        }
        crate::inline_project::init_git_repo_with_identity(&root);
        crate::inline_project::run_git(&root, &["add", "-A"]);
        crate::inline_project::run_git(&root, &["commit", "-m", "initial commit"]);
        // Every ignore input is under this private parent, so a quiet window
        // certifies them without depending on the shared temporary directory.
        std::thread::sleep(std::time::Duration::from_millis(2100));
        let cache = std::sync::Arc::new(
            brokk_bifrost_core::analyzer::project::WorkspaceFileListingCache::new(root.clone()),
        );
        let project = std::sync::Arc::new(
            brokk_bifrost_core::analyzer::project::FilesystemProject::with_cached_listing(
                &root,
                std::sync::Arc::clone(&cache),
            )
            .unwrap(),
        );
        let workspace =
            WorkspaceAnalyzer::build_persisted(project.clone(), AnalyzerConfig::default()).unwrap();
        let walks = cache.walk_count();
        let deleted = BTreeSet::from([
            brokk_bifrost_core::analyzer::model::ProjectFile::new(
                root.clone(),
                "rust-toolchain.toml",
            ),
            brokk_bifrost_core::analyzer::model::ProjectFile::new(
                root.clone(),
                ".cargo/config.toml",
            ),
            brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), ".cargo/config"),
            brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), "removed/a.rs"),
            brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), "removed/b.rs"),
            brokk_bifrost_core::analyzer::model::ProjectFile::new(root.clone(), "removed/c.rs"),
        ]);
        for file in &deleted {
            std::fs::remove_file(file.abs_path()).unwrap();
        }
        std::fs::remove_dir(root.join("removed")).unwrap();
        let updated = workspace.update(&deleted);
        assert_eq!(
            cache.walk_count(),
            walks,
            "deletions must patch the listing"
        );
        let listing =
            brokk_bifrost_core::analyzer::project::Project::all_files_shared(project.as_ref())
                .unwrap();
        assert!(deleted.iter().all(|file| !listing.contains(file)));
        let context = std::sync::Arc::new(
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
        );
        let attribution = context.enter();
        updated.analyzer().begin_query(&context);
        let mut actual = updated
            .analyzer()
            .get_all_declarations()
            .into_iter()
            .map(|unit| unit.identifier().to_string())
            .collect::<Vec<_>>();
        let error = context.store_error();
        updated.analyzer().end_query(&context);
        drop(attribution);
        assert!(error.is_none(), "{error:?}");
        assert!(!actual.is_empty());
        let fresh = WorkspaceAnalyzer::build_ephemeral_footgun(
            std::sync::Arc::new(
                brokk_bifrost_analysis::TestProject::from_root_with_inferred_languages(
                    root.clone(),
                )
                .unwrap(),
            ),
            AnalyzerConfig::default(),
        )
        .unwrap();
        let mut expected = fresh
            .analyzer()
            .get_all_declarations()
            .into_iter()
            .map(|unit| unit.identifier().to_string())
            .collect::<Vec<_>>();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected);
    }

    #[test]
    #[hardwon("#10381: any Cargo.toml edit invalidated every Rust unit summary")]
    fn rust_feature_projection_tracks_consumers_and_config_candidates() {
        fn fixture(
            sibling: &str,
            member: Option<&str>,
        ) -> crate::inline_project::BuiltInlineTestProject {
            let mut project = InlineTestProject::new()
                .file("Cargo.toml", "[workspace]\nmembers=['a','consumer','sibling','unrelated','members/*']\nexclude=['shared']\nresolver='2'\n")
                .file("a/Cargo.toml", "[package]\nname='a'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nshared={path='../shared',default-features=false}\n[features]\nmember_only=[]\n")
                .file("a/src/lib.rs", "pub use shared::Always;\n")
                .file("consumer/Cargo.toml", "[package]\nname='consumer'\nversion='0.1.0'\nedition='2021'\n[dependencies]\na={path='../a'}\n")
                .file("consumer/src/lib.rs", "pub use a::Always;\n")
                .file("sibling/Cargo.toml", sibling)
                .file("sibling/src/lib.rs", "pub fn sibling() {}\n")
                .file("unrelated/Cargo.toml", "[package]\nname='unrelated'\nversion='0.1.0'\nedition='2021'\n")
                .file("unrelated/src/lib.rs", "pub use std::vec::Vec; pub fn unrelated() {}\n")
                .file("shared/Cargo.toml", "[package]\nname='shared'\nversion='0.1.0'\nedition='2021'\n[features]\nx=[]\n")
                .file("shared/src/lib.rs", "pub struct Always;\n")
                .file("island/Cargo.toml", "[package]\nname='island'\nversion='0.1.0'\nedition='2021'\n[workspace]\n")
                .file("island/src/lib.rs", "pub fn island() {}\n")
                .file("orphan.rs", "pub fn detached() {}\n");
            if let Some(member) = member {
                project = project
                    .file("members/new/Cargo.toml", member)
                    .file("members/new/src/lib.rs", "pub fn added() {}\n");
            }
            project.build()
        }
        fn assert_ready(workspace: &WorkspaceAnalyzer) {
            let context = std::sync::Arc::new(
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
            );
            let attribution = context.enter();
            workspace.analyzer().begin_query(&context);
            let update_error = context.store_error();
            workspace.analyzer().end_query(&context);
            drop(attribution);
            assert!(
                workspace.test_pending_update_paths().is_empty(),
                "update did not apply: {update_error:?}; pending={:?}",
                workspace.test_pending_update_paths()
            );
        }
        fn projections(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, (Vec<u8>, bool)> {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.prepare("SELECT t.crate_name,p.projection_digest,p.complete FROM rust_feature_projections p
                JOIN rust_crate_versions v ON v.workspace_id=p.workspace_id AND v.generation=p.generation AND v.crate_key=p.unit_key
                JOIN rust_crate_topologies t USING(topology_id) WHERE v.valid_until IS NULL AND t.target_kind='lib' ORDER BY t.crate_name")
                .unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, (row.get(1)?, row.get(2)?))))
                .unwrap().collect::<rusqlite::Result<_>>().unwrap()
        }
        fn unit_rows(workspace: &WorkspaceAnalyzer) -> Vec<(String, String)> {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.prepare("SELECT t.crate_name,json_array(hex(s.lookup_digest),hex(s.output_digest),s.complete,
                (SELECT json_group_array(json_array(input_ordinal,rel_path,source_role)) FROM
                    (SELECT input_ordinal,rel_path,source_role FROM resolution_unit_summary_input_files WHERE summary_id=s.summary_id ORDER BY input_ordinal)))
                FROM resolution_unit_summary_versions v JOIN resolution_unit_summaries s USING(summary_id)
                JOIN rust_crate_versions c ON c.workspace_id=v.workspace_id AND c.generation=v.generation AND c.crate_key=v.unit_key AND c.valid_until IS NULL
                JOIN rust_crate_topologies t USING(topology_id)
                WHERE v.lang='rust' AND v.valid_until IS NULL AND t.target_kind='lib' ORDER BY t.crate_name")
                .unwrap().query_map([], |row| Ok((row.get(0)?,row.get(1)?)))
                .unwrap().collect::<rusqlite::Result<_>>().unwrap()
        }
        let sibling = "[package]\nname='sibling'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nshared={path='../shared',default-features=false}\n";
        let project = fixture(sibling, None);
        let mut workspace = project.certified_workspace_analyzer(AnalyzerConfig::default());
        // Members already activate every declared feature, even without this request.
        let before_member_request = projections(&workspace);
        let before_member_rows = live_summaries(&workspace);
        let consumer_manifest = project.file("consumer/Cargo.toml");
        let original_consumer = std::fs::read_to_string(consumer_manifest.abs_path()).unwrap();
        std::fs::write(
            consumer_manifest.abs_path(),
            original_consumer.replace(
                "a={path='../a'}",
                "a={path='../a',features=['member_only']}",
            ),
        )
        .unwrap();
        workspace = workspace.update(&BTreeSet::from([consumer_manifest.clone()]));
        assert_eq!(before_member_request, projections(&workspace));
        assert_eq!(before_member_rows["a"], live_summaries(&workspace)["a"]);
        std::fs::write(consumer_manifest.abs_path(), original_consumer).unwrap();
        workspace = workspace.update(&BTreeSet::from([consumer_manifest]));
        let detached_summary = |workspace: &WorkspaceAnalyzer| -> i64 {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            conn.query_row("SELECT s.summary_id FROM resolution_unit_summary_versions s
                JOIN rust_crate_versions v ON v.workspace_id=s.workspace_id AND v.generation=s.generation AND v.crate_key=s.unit_key
                JOIN rust_crate_topologies t USING(topology_id)
                WHERE s.lang='rust' AND s.valid_until IS NULL AND v.valid_until IS NULL
                  AND t.target_kind='detached' AND t.crate_name='orphan.rs'", [], |row| row.get(0)).unwrap()
        };
        let carried = detached_summary(&workspace);
        let source = project.file("a/src/lib.rs");
        std::fs::write(
            source.abs_path(),
            "pub use shared::Always;\n// scoped body change\n",
        )
        .unwrap();
        workspace = workspace.update(&BTreeSet::from([source.clone()]));
        assert_ready(&workspace);
        assert_eq!(
            carried,
            detached_summary(&workspace),
            "a scoped pass must retain an unreached detached summary"
        );
        std::fs::write(source.abs_path(), "pub use shared::Always;\n").unwrap();
        workspace = workspace.update(&BTreeSet::from([source]));
        assert_ready(&workspace);
        let initial = live_summaries(&workspace);
        let initial_features = projections(&workspace);
        let toolchain = project.file("rust-toolchain.toml");
        for channel in ["1.80.0", "1.81.0"] {
            std::fs::write(
                toolchain.abs_path(),
                format!("[toolchain]\nchannel='{channel}'\n"),
            )
            .unwrap();
            workspace = workspace.update(&BTreeSet::from([toolchain.clone()]));
            assert_eq!(
                initial,
                live_summaries(&workspace),
                "stdlib pack selection is not a crate summary input"
            );
        }
        let manifest = project.file("sibling/Cargo.toml");
        std::fs::write(manifest.abs_path(), format!("{sibling}# unrelated edit\n")).unwrap();
        workspace = workspace.update(&BTreeSet::from([manifest.clone()]));
        let unchanged = live_summaries(&workspace);
        assert_eq!(initial_features, projections(&workspace));
        for name in ["a", "shared", "unrelated", "island"] {
            assert_eq!(
                initial[name], unchanged[name],
                "{name}: sibling comment invalidated a summary"
            );
        }
        let changed = sibling.replace(
            "default-features=false",
            "default-features=false,features=['x']",
        );
        std::fs::write(manifest.abs_path(), &changed).unwrap();
        workspace = workspace.update(&BTreeSet::from([manifest.clone()]));
        assert_ready(&workspace);
        let unified = projections(&workspace);
        let feature_rows: Vec<String> = workspace.store().unwrap().read_conn().unwrap()
            .prepare("SELECT json_array(manifest_path,json(features),complete) FROM rust_feature_projection_packages ORDER BY unit_key,manifest_path").unwrap()
            .query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        let summaries = live_summaries(&workspace);
        for name in ["a", "shared"] {
            assert_ne!(
                initial_features[name].0, unified[name].0,
                "{name}: shared features must move the projection: initial={initial_features:?}; final={unified:?}; rows={feature_rows:?}"
            );
            assert_ne!(
                unchanged[name].0, summaries[name].0,
                "{name}: changed projection must invalidate the summary"
            );
        }
        assert_eq!(
            unchanged["a"].1, summaries["a"].1,
            "direct dependent output remains equal"
        );
        assert_eq!(initial_features["consumer"], unified["consumer"]);
        assert_eq!(
            unchanged["consumer"], summaries["consumer"],
            "indirect feature changes stop at equal direct output"
        );
        assert_eq!(initial_features["unrelated"], unified["unrelated"]);
        assert_eq!(unchanged["unrelated"], summaries["unrelated"]);
        let fresh = fixture(&changed, None);
        let fresh_workspace = fresh.certified_workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(unified, projections(&fresh_workspace));
        assert_eq!(unit_rows(&workspace), unit_rows(&fresh_workspace));
        assert_eq!(
            summaries
                .into_iter()
                .map(|(name, (_, digest))| (name, digest))
                .collect::<BTreeMap<_, _>>(),
            live_summaries(&fresh_workspace)
                .into_iter()
                .map(|(name, (_, digest))| (name, digest))
                .collect()
        );

        // Admission through an existing glob must refresh discovery before lookup.
        std::fs::write(manifest.abs_path(), sibling).unwrap();
        workspace = workspace.update(&BTreeSet::from([manifest]));
        let before_glob = projections(&workspace);
        let new_fixture = fixture(
            sibling,
            Some(
                "[package]\nname='new_member'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nshared={path='../../shared',features=['x']}\n",
            ),
        );
        for path in ["members/new/Cargo.toml", "members/new/src/lib.rs"] {
            let destination = project.root().join(path);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            std::fs::copy(new_fixture.root().join(path), &destination).unwrap();
        }
        workspace = workspace.update(&BTreeSet::from([
            project.file("members/new/Cargo.toml"),
            project.file("members/new/src/lib.rs"),
        ]));
        assert_ne!(before_glob["a"].0, projections(&workspace)["a"].0);
        let fresh_workspace = new_fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(projections(&workspace), projections(&fresh_workspace));
        assert_eq!(unit_rows(&workspace), unit_rows(&fresh_workspace));
        let before_redundant = live_summaries(&workspace);
        let before_redundant_features = projections(&workspace);
        let sibling_file = project.file("sibling/Cargo.toml");
        std::fs::write(sibling_file.abs_path(), &changed).unwrap();
        workspace = workspace.update(&BTreeSet::from([sibling_file]));
        assert_eq!(
            before_redundant_features,
            projections(&workspace),
            "the glob member already enabled x"
        );
        assert_eq!(before_redundant["a"], live_summaries(&workspace)["a"]);

        // Config candidates are scoped to the build root; legacy wins at its level.
        let island_before = live_summaries(&workspace);
        let before_config_rows = unit_rows(&workspace);
        let modern = project.file("island/.cargo/config.toml");
        std::fs::create_dir_all(modern.abs_path().parent().unwrap()).unwrap();
        std::fs::write(
            modern.abs_path(),
            "[build]\nrustflags=['--cfg','island_flag']\n",
        )
        .unwrap();
        workspace = workspace.update(&BTreeSet::from([modern.clone()]));
        let modern_rows = live_summaries(&workspace);
        assert_ne!(island_before["island"].0, modern_rows["island"].0);
        assert_eq!(island_before["a"], modern_rows["a"]);
        let legacy = project.file("island/.cargo/config");
        std::fs::write(
            legacy.abs_path(),
            "[build]\nrustflags=['--cfg','legacy_flag']\n",
        )
        .unwrap();
        workspace = workspace.update(&BTreeSet::from([legacy.clone()]));
        let legacy_rows = live_summaries(&workspace);
        std::fs::write(
            modern.abs_path(),
            "[build]\nrustflags=['--cfg','ignored_flag']\n",
        )
        .unwrap();
        workspace = workspace.update(&BTreeSet::from([modern.clone()]));
        assert_eq!(legacy_rows["island"], live_summaries(&workspace)["island"]);
        // Keep this full refresh focused on feature projections; incremental
        // configuration deletion is covered by
        // deleted_workspace_configuration_matches_fresh_analysis.
        std::fs::remove_file(legacy.abs_path()).unwrap();
        workspace = workspace.update_all();
        assert_ready(&workspace);
        assert_ne!(
            legacy_rows["island"].0,
            live_summaries(&workspace)["island"].0
        );
        assert_eq!(island_before["a"], live_summaries(&workspace)["a"]);
        std::fs::remove_file(modern.abs_path()).unwrap();
        workspace = workspace.update_all();
        assert_ready(&workspace);
        assert_eq!(before_config_rows, unit_rows(&workspace));
        assert_eq!(
            island_before["island"].1,
            live_summaries(&workspace)["island"].1
        );
        assert_eq!(island_before["a"], live_summaries(&workspace)["a"]);

        let opaque = fixture(
            &changed,
            Some(
                "[package]\nname='new_member'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nmissing={path='../../missing'}\n",
            ),
        );
        let opaque_manifest = project.file("members/new/Cargo.toml");
        std::fs::copy(
            opaque.root().join("members/new/Cargo.toml"),
            opaque_manifest.abs_path(),
        )
        .unwrap();
        workspace = workspace.update(&BTreeSet::from([opaque_manifest]));
        let opaque_workspace = opaque.certified_workspace_analyzer(AnalyzerConfig::default());
        assert!(!projections(&opaque_workspace)["shared"].1);
        assert!(!projections(&workspace)["shared"].1);
        assert_eq!(projections(&workspace), projections(&opaque_workspace));
        assert_eq!(unit_rows(&workspace), unit_rows(&opaque_workspace));
        let conn = opaque_workspace.store().unwrap().read_conn().unwrap();
        let reasons: Vec<String> = conn
            .prepare("SELECT DISTINCT reason FROM rust_feature_projections WHERE complete=0")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(reasons, ["activation_not_established"]);
    }

    fn select_export_endpoints(conn: &rusqlite::Connection) {
        conn.execute_batch("DROP TABLE IF EXISTS selected_workspace_revisions;
CREATE TEMP TABLE selected_workspace_revisions AS SELECT DISTINCT workspace_id,lang,generation,revision FROM workspace_heads;
DROP VIEW IF EXISTS selected_workspace_file_versions;
CREATE TEMP VIEW selected_workspace_file_versions AS SELECT f.*,b.parse_variant FROM workspace_file_versions f JOIN blobs b ON b.blob_oid=f.blob_oid AND b.lang=f.lang AND b.generation=f.generation WHERE f.valid_until IS NULL;
CREATE TEMP VIEW IF NOT EXISTS test_export_endpoints AS SELECT e.*, a.blob_id AS endpoint_blob, d.dense_id AS endpoint_site
                   FROM resolution_unit_summary_exports e
                   JOIN selected_unit_member_blobs a ON a.summary_id=e.summary_id AND a.member_ordinal=e.declaration_member_ordinal
                   JOIN surface_dense d ON d.blob_id=a.blob_id AND d.id_space=0 AND d.surface_ordinal=e.site_surface_ordinal
                   WHERE e.target_kind='own'
                   UNION ALL
                   SELECT e.*, r.blob_id, target.declaration_site
                   FROM resolution_unit_summary_exports e
                   JOIN resolution_unit_summary_versions v ON v.valid_until IS NULL
                   JOIN rust_resolution_unit_summary_exports target ON target.summary_id=v.summary_id
                     AND target.namespace=e.namespace AND target.origin='declaration'
                     AND EXISTS (SELECT 1 FROM rust_resolution_unit_summary_exports child
                       WHERE child.summary_id=e.summary_id AND child.identity_id=e.identity_id
                         AND child.namespace=e.namespace AND child.alias_dependency_ordinal=e.alias_dependency_ordinal
                         AND child.origin<>'declaration' AND child.target_unit_key=v.unit_key
                         AND child.target_module_path=target.module_path AND child.target_name=target.name)
                   /* Rust-only derived-from blob until #11183 M3 converts Rust child rows */
                   JOIN resolution_unit_summary_members r ON r.summary_id=target.summary_id AND r.member_ordinal=target.declaration_member_ordinal
                   WHERE e.target_kind='foreign';").unwrap();
    }

    #[test]
    fn manifest_feature_toggle_local_import_matches_cold() {
        let manifest = "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\ndep={path=\"dep\"}\n";
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", manifest)
            .file(
                "src/lib.rs",
                "pub fn run() { #[cfg(feature = \"f\")] use dep::thing; thing(); }\n",
            )
            .file(
                "dep/Cargo.toml",
                "[package]\nname=\"dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            )
            .file("dep/src/lib.rs", "pub fn thing() {}\n")
            .build();
        let state = |workspace: &WorkspaceAnalyzer| {
            let answer = crate::searchtools::get_definitions_by_reference(
                workspace.analyzer(),
                crate::searchtools::GetDefinitionByReferenceParams {
                    references: vec![crate::searchtools::DefinitionContextReferenceQuery {
                        symbol: "app.run".into(),
                        context: "thing();".into(),
                        target: "thing".into(),
                    }],
                },
            );
            let conn = workspace.store().unwrap().read_conn().unwrap();
            let routes = conn
                .prepare(
                    "SELECT route.module_path, route.bound_name, route.target_module_path,
                        route.target_name, json(context.cfg_atoms)
                 FROM rust_resolution_unit_summary_import_routes route
                 JOIN rust_resolution_unit_summary_contexts context USING(summary_id)
                 JOIN resolution_unit_summary_versions version USING(summary_id)
                 WHERE version.valid_until IS NULL AND context.crate_name='app'
                   AND context.target_kind='lib' AND route.bound_name='thing'
                 ORDER BY route.module_path, route.binder_scope, route.route_ordinal",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (routes, serde_json::to_value(answer).unwrap())
        };
        let mut warm = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = state(&warm);
        assert!(
            initial.1["results"][0]["definitions"]
                .as_array()
                .is_none_or(Vec::is_empty),
            "{initial:#?}"
        );
        for enabled in [true, false, true] {
            let declaration = if enabled { "[features]\nf=[]\n" } else { "" };
            let file = fixture.file("Cargo.toml");
            file.write(format!("{manifest}{declaration}")).unwrap();
            warm = warm.update(&BTreeSet::from([file]));
            let actual = state(&warm);
            let cold = state(&fixture.workspace_analyzer(AnalyzerConfig::default()));
            assert_eq!(
                actual, cold,
                "manifest-only f={enabled}: warm import routes/context and dependent answer must equal cold"
            );
            assert_eq!(
                !actual.0.is_empty(),
                enabled,
                "local import route activation f={enabled}: {actual:#?}"
            );
            eprintln!("manifest-only feature f={enabled}: routes and dependent answer {actual:#?}");
            for route in &actual.0 {
                let atoms: Vec<String> = serde_json::from_str(&route.4).unwrap();
                assert_eq!(
                    atoms.iter().any(|atom| atom == "feature = \"f\""),
                    enabled,
                    "{actual:#?}"
                );
            }
            let definitions = actual.1["results"][0]["definitions"].as_array();
            assert_eq!(
                definitions
                    .is_some_and(|definitions| definitions.iter().any(|d| d["fqn"] == "dep.thing")),
                enabled,
                "{actual:#?}"
            );
        }
    }

    #[test]
    fn previous_summary_version_rederives_summary_representations() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"summary_upgrade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "#[cfg(any())] mod inactive;\n#[cfg(any())] mod absent;\npub use missing::Thing;\n",
            )
            .file("src/inactive.rs", "pub struct Inactive;")
            .build();
        let build = || {
            WorkspaceAnalyzer::build_persisted(fixture.project_dyn(), AnalyzerConfig::default())
                .unwrap()
        };
        let workspace = build();
        {
            let store = workspace.store().unwrap();
            store
                .conn
                .execute(|conn| {
                    let _fixture =
                        brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(
                            conn,
                        );
                    conn.execute("UPDATE resolution_unit_summaries SET derivation_identity=?1 WHERE lang='rust'", [brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_unit_summary_derivation_identity_before_last_token()])?;
                    conn.execute_batch("UPDATE resolution_unit_summaries SET
                     summary_digest=CAST(printf('%032x', summary_id) AS BLOB),
                     lookup_digest=CAST(printf('%032x', summary_id) AS BLOB)
                 WHERE lang='rust';
                DELETE FROM rust_resolution_unit_summary_inactive_placements;
                DELETE FROM resolution_unit_summary_input_files;
                DELETE FROM rust_resolution_unit_summary_public_surface_gaps;
                UPDATE rust_resolution_unit_summary_contexts SET broad_complete=0;",
                    )
                })
                .unwrap();
        }
        drop(workspace);
        let workspace = build();
        let store = workspace.store().unwrap();
        store.assert_rust_summary_differential_for_test();
        let conn = store.read_conn().unwrap();
        let versions = conn.prepare("SELECT summaries.summary_id,summaries.derivation_identity FROM resolution_unit_summary_versions versions JOIN resolution_unit_summaries summaries USING(summary_id) WHERE versions.valid_until IS NULL AND summaries.lang='rust'")
            .unwrap().query_map([], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,[u8;32]>(1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert!(!versions.is_empty());
        assert!(
            versions.iter().all(|(_, version)| *version
                == brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_unit_summary_derivation_identity()),
            "live summaries: {versions:?}"
        );
        let inputs = conn
            .prepare("SELECT rel_path FROM resolution_unit_summary_input_files WHERE source_role='inactive_source' ORDER BY rel_path")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(inputs, ["src/inactive.rs"]);
    }

    #[test]
    fn persisted_input_files_are_the_declared_list_that_placements_reference() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"declared\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "#[cfg(any())] mod zeta;\n#[cfg(any())] mod alpha;\n",
            )
            .file("src/alpha.rs", "pub struct Alpha;")
            .file("src/zeta.rs", "pub struct Zeta;")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().unwrap();
        store.assert_rust_summary_differential_for_test();
        let conn = store.read_conn().unwrap();
        let files = conn
            .prepare("SELECT input_ordinal, source_role, rel_path FROM resolution_unit_summary_input_files WHERE source_role='inactive_source' ORDER BY summary_id, input_ordinal")
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            files,
            [
                // Canonical cargo_config roles precede the inactive sources.
                (2, "inactive_source".to_owned(), "src/alpha.rs".to_owned()),
                (3, "inactive_source".to_owned(), "src/zeta.rs".to_owned()),
            ]
        );
        let placed = conn
            .prepare("SELECT placements.module_path, files.rel_path FROM rust_resolution_unit_summary_inactive_placements placements JOIN resolution_unit_summary_input_files files ON files.summary_id = placements.summary_id AND files.input_ordinal = placements.input_file_ordinal ORDER BY placements.module_path")
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            placed,
            [
                ("crate::alpha".to_owned(), "src/alpha.rs".to_owned()),
                ("crate::zeta".to_owned(), "src/zeta.rs".to_owned()),
            ]
        );
    }

    #[test]
    fn previous_summary_version_rederives_binding_authority() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"binding_upgrade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub mod inner { pub fn run() {} pub struct Item; }\nuse inner::*;\npub use inner::run as again;\nmod missing_file;\n",
            )
            .build();
        let build = || {
            WorkspaceAnalyzer::build_persisted(fixture.project_dyn(), AnalyzerConfig::default())
                .unwrap()
        };
        let workspace = build();
        {
            let store = workspace.store().unwrap();
            store
                .conn
                .execute(|conn| {
                    let _fixture =
                        brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(
                            conn,
                        );
                    conn.execute("UPDATE resolution_unit_summaries SET derivation_identity=?1 WHERE lang='rust'", [brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_unit_summary_derivation_identity_before_last_token()])?;
                    conn.execute_batch("UPDATE resolution_unit_summaries SET
                     lookup_digest=CAST(printf('%032x', summary_id) AS BLOB),
                     summary_digest=CAST(printf('%032x', summary_id) AS BLOB)
                 WHERE lang='rust';
                DELETE FROM rust_resolution_unit_summary_binding_blockers;
                DELETE FROM rust_resolution_unit_summary_binding_alternatives;
                DELETE FROM rust_resolution_unit_summary_binding_names;
                DELETE FROM rust_resolution_unit_summary_binding_owners;",
                    )
                })
                .unwrap();
        }
        drop(workspace);
        let workspace = build();
        let store = workspace.store().unwrap();
        // The differential compares every copied row with its topology row.
        store.assert_rust_summary_differential_for_test();
        let conn = store.read_conn().unwrap();
        let live = conn.prepare("SELECT summaries.summary_id, summaries.derivation_identity,
                    (SELECT count(*) FROM rust_resolution_unit_summary_binding_owners o WHERE o.summary_id=summaries.summary_id),
                    (SELECT count(*) FROM rust_resolution_unit_summary_binding_names n WHERE n.summary_id=summaries.summary_id),
                    (SELECT count(*) FROM rust_resolution_unit_summary_binding_alternatives a WHERE a.summary_id=summaries.summary_id)
             FROM resolution_unit_summary_versions versions JOIN resolution_unit_summaries summaries USING(summary_id)
             WHERE versions.valid_until IS NULL AND summaries.lang='rust'")
            .unwrap().query_map([], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,[u8;32]>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert!(!live.is_empty());
        assert!(
            live.iter()
                .all(|(_, version, owners, names, alternatives)| {
                    *version
                        == brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_unit_summary_derivation_identity()
                        && *owners > 0
                        && *names > 0
                        && *alternatives > 0
                }),
            "every live summary re-derives its binding authority: {live:?}"
        );
    }

    #[test]
    fn cfg_alternative_declarations_keep_every_binding_row() {
        // Two statically active cfg alternatives of one module each declare `g1`, and
        // one glob import reaches both. Same-module duplicates collapse in the
        // topology itself, so the alternatives differ by module.
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"dep\", \"app\"]\nresolver = \"2\"\n")
            .file(
                "dep/Cargo.toml",
                "[package]\nname = \"cfg_dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "dep/src/lib.rs",
                "#[cfg(all())]\nmod left { pub fn g1() {} }\n#[cfg(not(any()))]\nmod right { pub fn g1() {} }\npub use left::*;\npub use right::*;\n",
            )
            .file(
                "app/Cargo.toml",
                "[package]\nname = \"cfg_app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncfg_dep = { path = \"../dep\" }\n",
            )
            .file("app/src/lib.rs", "pub use cfg_dep::g1;\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().unwrap();
        // The differential proves the mirror equals the topology rows, multiplicity included.
        store.assert_rust_summary_differential_for_test();
        let conn = store.read_conn().unwrap();
        let rows = |crate_name: &str, origin: &str| {
            conn.prepare(
                "SELECT a.target_form, a.target_module_path, a.target_site, a.target_form='foreign'
                 FROM rust_resolution_unit_summary_binding_alternatives a
                 JOIN resolution_unit_summary_versions v ON v.summary_id=a.summary_id AND v.valid_until IS NULL
                 JOIN rust_resolution_unit_summary_contexts c ON c.summary_id=a.summary_id
                 JOIN rust_resolution_unit_summary_binding_owners o ON o.summary_id=a.summary_id AND o.owner_handle=a.owner_handle
                 WHERE c.crate_name=?1 AND c.target_kind='lib' AND o.module_path='crate' AND o.kind='module'
                   AND a.name='g1' AND a.namespace='value' AND a.origin=?2
                 ORDER BY a.target_module_path",
            )
            .unwrap()
            .query_map([crate_name, origin], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        };
        let own = rows("cfg_dep", "glob");
        assert_eq!(own.len(), 2, "cfg_dep glob alternatives: {own:?}");
        assert!(
            own.iter().all(|row| row.0 == "local_site" && !row.3),
            "{own:?}"
        );
        assert_eq!(
            own.iter().map(|row| row.1.as_str()).collect::<Vec<_>>(),
            ["crate::left", "crate::right"]
        );
        assert_ne!(own[0].2, own[1].2, "distinct dense sites: {own:?}");
        // The importing crate names them by unit key and module path; both stay,
        // and a consumer of the name `g1` must treat it as ambiguous.
        let foreign = rows("cfg_app", "named_import");
        assert_eq!(foreign.len(), 2, "cfg_app alternatives: {foreign:?}");
        assert!(
            foreign
                .iter()
                .all(|row| row.0 == "foreign" && row.3 && row.2.is_none())
        );
    }

    #[hardwon(
        "#11173: a binding-authority mirror attached a declaration to an identical file in another module"
    )]
    #[test]
    fn binding_authority_mirror_places_identical_files_in_their_own_module() {
        // `a.rs` and `b.rs` are byte-identical, so they share one blob, yet they are
        // distinct members placed in distinct modules. A declaration is attached to
        // the member its module path places, never to the first member of its blob.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"twins\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "mod a;\nmod b;\npub use a::Item as AItem;\npub use b::Item as BItem;\n",
            )
            .file("src/a.rs", "pub struct Item;\n")
            .file("src/b.rs", "pub struct Item;\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().unwrap();
        store.assert_rust_summary_differential_for_test();
        let conn = store.read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT a.name, a.target_module_path, tm.rel_path
                 FROM rust_resolution_unit_summary_binding_alternatives a
                 JOIN resolution_unit_summary_versions v ON v.summary_id=a.summary_id AND v.valid_until IS NULL
                 JOIN rust_resolution_unit_summary_contexts c ON c.summary_id=a.summary_id
                 LEFT JOIN resolution_unit_summary_members tm ON tm.summary_id=a.summary_id AND tm.member_ordinal=a.target_member_ordinal
                 WHERE c.crate_name='twins' AND a.name IN ('AItem', 'BItem')
                 ORDER BY a.name, a.target_module_path, tm.rel_path",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<BTreeSet<_>>>()
            .unwrap();
        let expected = BTreeSet::from([
            (
                "AItem".to_owned(),
                "crate::a".to_owned(),
                Some("src/a.rs".to_owned()),
            ),
            (
                "BItem".to_owned(),
                "crate::b".to_owned(),
                Some("src/b.rs".to_owned()),
            ),
        ]);
        assert_eq!(rows, expected);
    }

    #[hardwon(
        "#11173: identical macro_export twins in two modules must be analyzed and named deterministically"
    )]
    #[test]
    fn binding_authority_mirror_names_identical_macro_export_twins_by_lowest_path() {
        // A `#[macro_export]` macro is re-homed to the crate root, so its topology
        // row names no declaring module. `a.rs` and `b.rs` are byte-identical and
        // both declare `m` in the crate root: one blob, one dense site, two members
        // placed in two modules. They are twins in ONE module (the crate root), so
        // the same-bytes-declare-once rule names the lowest rel_path, and the
        // choice changes only provenance. rustc rejects the duplicate (E0428), but
        // an invalid crate is analyzed, not refused: the build must succeed, the
        // differential must agree, and the choice must be deterministic.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"macro_twins\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("src/lib.rs", "mod a;\nmod b;\npub use crate::m as mm;\n")
            .file(
                "src/a.rs",
                "#[macro_export]\nmacro_rules! m { () => {}; }\n",
            )
            .file(
                "src/b.rs",
                "#[macro_export]\nmacro_rules! m { () => {}; }\n",
            )
            .build();
        let workspace = WorkspaceAnalyzer::build_ephemeral_footgun(
            fixture.project_dyn(),
            AnalyzerConfig::default(),
        )
        .expect("an invalid crate with identical macro_export twins is still analyzed");
        let store = workspace.store().unwrap();
        store.assert_rust_summary_differential_for_test();
        let conn = store.read_conn().unwrap();
        let paths = conn
            .prepare(
                "SELECT DISTINCT tm.rel_path
                 FROM rust_resolution_unit_summary_binding_alternatives a
                 JOIN resolution_unit_summary_versions v ON v.summary_id=a.summary_id AND v.valid_until IS NULL
                 JOIN rust_resolution_unit_summary_contexts c ON c.summary_id=a.summary_id
                 JOIN resolution_unit_summary_members tm ON tm.summary_id=a.summary_id AND tm.member_ordinal=a.target_member_ordinal
                 WHERE c.crate_name='macro_twins' AND a.name IN ('m', 'mm') AND a.namespace='macro'",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<BTreeSet<_>>>()
            .unwrap();
        assert_eq!(paths, BTreeSet::from(["src/a.rs".to_owned()]));
    }

    #[test]
    fn previous_summary_version_rederives_inherent_impls() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"dep\", \"app\"]\nresolver = \"2\"\n")
            .file(
                "dep/Cargo.toml",
                "[package]\nname = \"impl_dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("dep/src/lib.rs", "pub struct Exposed;\n")
            .file(
                "app/Cargo.toml",
                "[package]\nname = \"impl_app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nimpl_dep = { path = \"../dep\" }\n",
            )
            .file(
                "app/src/lib.rs",
                "pub struct Local;\nimpl Local { pub fn go(&self) {} }\nimpl impl_dep::Exposed { pub fn extra(&self) {} }\nimpl Missing { pub fn nope(&self) {} }\n",
            )
            .build();
        let build = || {
            WorkspaceAnalyzer::build_persisted(fixture.project_dyn(), AnalyzerConfig::default())
                .unwrap()
        };
        let workspace = build();
        {
            let store = workspace.store().unwrap();
            store
                .conn
                .execute(|conn| {
                    let _fixture =
                        brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(
                            conn,
                        );
                    conn.execute("UPDATE resolution_unit_summaries SET derivation_identity=?1 WHERE lang='rust'", [brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_unit_summary_derivation_identity_before_last_token()])?;
                    conn.execute_batch("UPDATE resolution_unit_summaries SET
                     lookup_digest=CAST(printf('%032x', summary_id) AS BLOB),
                     summary_digest=CAST(printf('%032x', summary_id) AS BLOB)
                 WHERE lang='rust';
                DELETE FROM rust_resolution_unit_summary_unresolved_inherent_impls;
                DELETE FROM rust_resolution_unit_summary_inherent_impls;",
                    )
                })
                .unwrap();
        }
        drop(workspace);
        let workspace = build();
        let store = workspace.store().unwrap();
        // The differential compares every copied row with its topology row.
        store.assert_rust_summary_differential_for_test();
        let conn = store.read_conn().unwrap();
        let live = conn
            .prepare(
                "SELECT summaries.derivation_identity, c.crate_name,
                        (SELECT group_concat(subject_form, ',') FROM (SELECT subject_form FROM rust_resolution_unit_summary_inherent_impls i WHERE i.summary_id=summaries.summary_id ORDER BY subject_form)),
                        (SELECT group_concat(reason, ',') FROM rust_resolution_unit_summary_unresolved_inherent_impls u WHERE u.summary_id=summaries.summary_id)
                 FROM resolution_unit_summary_versions versions
                 JOIN resolution_unit_summaries summaries USING(summary_id)
                 JOIN rust_resolution_unit_summary_contexts c ON c.summary_id=summaries.summary_id
                 WHERE versions.valid_until IS NULL AND summaries.lang='rust' AND c.target_kind='lib'
                 ORDER BY c.crate_name",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, [u8;32]>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            live,
            [
                (
                    brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_unit_summary_derivation_identity(),
                    "impl_app".to_owned(),
                    Some("foreign,local_site".to_owned()),
                    Some("unbound".to_owned())
                ),
                (
                    brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::rust_unit_summary_derivation_identity(),
                    "impl_dep".to_owned(),
                    None,
                    None,
                ),
            ],
            "every live summary re-derives its inherent impls"
        );
    }

    #[test]
    fn cfg_alternative_impl_subjects_of_one_name_stay_distinct_or_unresolved() {
        // Two statically active cfg alternatives each declare `S` and implement it in
        // their own module, and the crate root re-exports both by glob. Inside the
        // declaring crate each impl keeps its own subject. A dependent that writes
        // `dep::S` names both declarations: the binding is ambiguous, so the impl is
        // recorded as unresolved and never attached to the first match.
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"dep\", \"app\"]\nresolver = \"2\"\n")
            .file(
                "dep/Cargo.toml",
                "[package]\nname = \"alt_dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "dep/src/lib.rs",
                "#[cfg(all())]\nmod left { pub struct S; impl S { pub fn l(&self) {} } }\n#[cfg(not(any()))]\nmod right { pub struct S; impl S { pub fn r(&self) {} } }\npub use left::*;\npub use right::*;\n",
            )
            .file(
                "app/Cargo.toml",
                "[package]\nname = \"alt_app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nalt_dep = { path = \"../dep\" }\n",
            )
            .file("app/src/lib.rs", "impl alt_dep::S { pub fn x(&self) {} }\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().unwrap();
        store.assert_rust_summary_differential_for_test();
        let conn = store.read_conn().unwrap();
        let local = |crate_name: &str| {
            conn.prepare(
                "SELECT h.subject_form, h.subject_site, m.rel_path
                 FROM rust_resolution_unit_summary_inherent_impls h
                 JOIN resolution_unit_summary_versions v ON v.summary_id=h.summary_id AND v.valid_until IS NULL
                 JOIN rust_resolution_unit_summary_contexts c ON c.summary_id=h.summary_id
                 JOIN resolution_unit_summary_members m ON m.summary_id=h.summary_id AND m.member_ordinal=h.subject_member_ordinal
                 WHERE c.crate_name=?1 AND c.target_kind='lib'
                 ORDER BY h.subject_site",
            )
            .unwrap()
            .query_map([crate_name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        };
        let own = local("alt_dep");
        assert_eq!(own.len(), 2, "alt_dep inherent impls: {own:?}");
        assert!(
            own.iter()
                .all(|row| row.0 == "local_site" && row.2 == "dep/src/lib.rs")
        );
        assert_ne!(own[0].1, own[1].1, "distinct dense subject sites: {own:?}");
        assert!(local("alt_app").is_empty());
        let unresolved = conn
            .prepare(
                "SELECT u.reason, u.spelling
                 FROM rust_resolution_unit_summary_unresolved_inherent_impls u
                 JOIN resolution_unit_summary_versions v ON v.summary_id=u.summary_id AND v.valid_until IS NULL
                 JOIN rust_resolution_unit_summary_contexts c ON c.summary_id=u.summary_id
                 WHERE c.crate_name='alt_app' AND c.target_kind='lib'",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            unresolved.len(),
            1,
            "alt_app unresolved impls: {unresolved:?}"
        );
    }

    #[test]
    fn source_members_cover_mixed_crate_placements() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"placements\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                r#"
mod ordinary;
mod inline { pub enum Item { Value } }
#[path = "mapped.rs"] mod relocated;
include!("splice.rs");
macro_rules! replay { ($($item:item)*) => { $($item)* }; }
replay! { mod replayed; }
#[cfg(any())] mod inactive;
"#,
            )
            .file("src/main.rs", "mod ordinary; fn main() {}")
            .file("src/ordinary.rs", "pub struct Ordinary;")
            .file("src/mapped.rs", "pub struct Mapped;")
            .file("src/splice.rs", "pub struct Spliced;")
            .file("src/replayed.rs", "pub struct Replayed;")
            .file("src/inactive.rs", "pub struct Inactive;")
            .file("src/detached.rs", "pub struct Detached;")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().unwrap();
        store.assert_rust_summary_differential_for_test();
        let conn = store.conn.lock().unwrap();
        // Guard against vacuous coverage: both publishers must actually see
        // each source kind, including one file placed in multiple targets.
        let kinds = conn.prepare("SELECT DISTINCT source_kind FROM rust_crate_container_sources ORDER BY source_kind")
            .unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap()
            .collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(kinds, ["declared", "include"]);
        let targets: i64 = conn.query_row("SELECT count(DISTINCT topology_id) FROM rust_crate_container_sources WHERE rel_path = 'src/ordinary.rs'", [], |row| row.get(0)).unwrap();
        assert!(
            targets >= 2,
            "ordinary.rs must be owned by two targets: {targets}"
        );
        drop(conn);
        // Mutate the published member key, leaving placements intact. This
        // simulates an omitted member without cascading away the evidence.
        for kind in ["declared", "include"] {
            let (summary, ordinal, path): (i64, i64, String) = {
                let conn = store.conn.lock().unwrap();
                let _fixture =
                    brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(&conn);
                let member = conn
                    .query_row(
                        "SELECT summary_id, member_ordinal, rel_path
                     FROM resolution_unit_summary_members WHERE source_role = ?1
                     ORDER BY summary_id, member_ordinal LIMIT 1",
                        [kind],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .unwrap();
                conn.execute(
                    "UPDATE resolution_unit_summary_members SET rel_path = 'omitted.rs'
                              WHERE summary_id = ?1 AND member_ordinal = ?2",
                    rusqlite::params![member.0, member.1],
                )
                .unwrap();
                member
            };
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                store.assert_rust_summary_differential_for_test();
            }));
            {
                let conn = store.conn.lock().unwrap();
                let _fixture =
                    brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(&conn);
                conn.execute(
                    "UPDATE resolution_unit_summary_members SET rel_path = ?3
                     WHERE summary_id = ?1 AND member_ordinal = ?2",
                    rusqlite::params![summary, ordinal, path],
                )
                .unwrap();
            }
            let failure = failure.expect_err("omitting a published member key must fail");
            let message = failure.downcast_ref::<String>().unwrap();
            assert!(
                message.contains("sources missing members"),
                "{kind}: {message}"
            );
            store.assert_rust_summary_differential_for_test();
        }
    }

    #[test]
    fn unindexed_trait_impl_subject_is_found_by_identity_through_renamed_imports() {
        let mut results = Vec::new();
        for subject in ["W", "Alias"] {
            let project = InlineTestProject::new()
                .file(
                    "Cargo.toml",
                    "[package]\nname = \"trait_subject\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                )
                .file(
                    "src/lib.rs",
                    format!(
                        "pub struct Item;\npub struct W(Item);\nuse W as Alias;\n\
                         impl std::ops::Deref for {subject} {{\n\
                             type Target = Item;\n\
                             fn deref(&self) -> &Self::Target {{ &self.0 }}\n\
                         }}\n"
                    ),
                )
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let store = workspace.store().unwrap();
            let conn = store.conn.lock().unwrap();
            brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn)
                .unwrap();
            brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
            conn.execute("INSERT OR REPLACE INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
            let (unit_key, module_path, identity): (Vec<u8>, String, i64) = conn
                .query_row(
                    "SELECT units.unit_key, exports.module_path, exports.identity_id
                     FROM selected_rust_unit_summaries AS units
                     JOIN rust_resolution_unit_summary_exports AS exports
                       ON exports.summary_id=units.summary_id
                     WHERE exports.name='W' AND exports.namespace='type'
                       AND exports.origin='declaration'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            const PROBE: &str = "SELECT trait.endpoint_state, trait.unresolved_spelling
                FROM rust_resolution_unit_summary_trait_endpoints AS subject
                  INDEXED BY rust_resolution_unit_summary_trait_endpoints_target
                CROSS JOIN selected_rust_unit_summaries AS owner
                  ON owner.summary_id=subject.summary_id
                CROSS JOIN rust_resolution_unit_summary_trait_endpoints AS trait
                  ON trait.summary_id=subject.summary_id
                 AND trait.member_ordinal=subject.member_ordinal
                 AND trait.owner_module_path=subject.owner_module_path
                 AND trait.source_relation_key=subject.source_relation_key
                 AND trait.endpoint_role='trait'
                WHERE subject.target_unit_key=?1 AND subject.target_module_path=?2
                  AND subject.target_identity_id=?3 AND subject.endpoint_role='subject'
                  AND subject.endpoint_state='resolved'";
            let plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {PROBE}"))
                .unwrap()
                .query_map(rusqlite::params![unit_key, module_path, identity], |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter().any(
                    |step| step.contains("rust_resolution_unit_summary_trait_endpoints_target")
                ),
                "subject identity probe must seek its index: {plan:?}"
            );
            println!("subject={subject}; selected-snapshot QEP: {plan:#?}");
            let endpoints = conn
                .prepare(PROBE)
                .unwrap()
                .query_map(rusqlite::params![unit_key, module_path, identity], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            results.push((subject, endpoints));
        }
        assert_eq!(
            results,
            ["W", "Alias"]
                .map(|subject| (subject, vec![("unresolved".to_owned(), "Deref".to_owned())])),
            "both impl headers must be found by W's identity with an unindexed trait"
        );
    }

    // Shared with the Rust derivation migration's single-input differential.
    // Store-local row IDs are addresses, not cache identity.
    fn single_input_summary_rows(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, Vec<String>> {
        let conn = workspace.store().unwrap().read_conn().unwrap();
        let tables = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND (name LIKE 'resolution_unit_summary_%' OR name LIKE 'rust_resolution_unit_summary_%' OR name='resolution_unit_summaries') AND name NOT LIKE '%_versions' ORDER BY name")
            .unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap()
            .collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let mut result = BTreeMap::new();
        for table in tables {
            let columns = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let expressions = columns.iter().filter(|column| column.as_str() != "summary_id")
                .map(|column| match column.as_str() {
                    "blob_id" => "(SELECT blob_oid FROM blobs WHERE id=child.blob_id)".to_owned(),
                    "consumed_summary_id" => "(SELECT hex(summary_digest) FROM resolution_unit_summaries WHERE summary_id=child.consumed_summary_id)".to_owned(),
                    "identity_id" | "alias_identity_id" | "target_identity_id" => format!("(SELECT hex(identity_digest) FROM resolution_identities WHERE id=child.{column})"),
                    _ => format!("child.{column}"),
                }).collect::<Vec<_>>();
            let sql = format!(
                "SELECT hex(version.unit_key), {} FROM {table} child JOIN resolution_unit_summary_versions version USING(summary_id) WHERE version.lang='rust' AND version.valid_until IS NULL",
                expressions.join(",")
            );
            let mut statement = conn.prepare(&sql).unwrap();
            let mut rows = statement.query([]).unwrap();
            let mut canonical = Vec::new();
            while let Some(row) = rows.next().unwrap() {
                let values = (0..=expressions.len())
                    .map(|index| format!("{:?}", row.get_ref(index).unwrap()))
                    .collect::<Vec<_>>();
                canonical.push(format!("{values:?}"));
            }
            canonical.sort();
            result.insert(table, canonical);
        }
        result
    }

    fn single_input_summary_keys(
        workspace: &WorkspaceAnalyzer,
    ) -> BTreeMap<String, (Vec<u8>, Vec<u8>)> {
        let conn = workspace.store().unwrap().read_conn().unwrap();
        conn.prepare("SELECT hex(version.unit_key), summary.lookup_digest, summary.summary_digest FROM resolution_unit_summary_versions version JOIN resolution_unit_summaries summary USING(summary_id) WHERE version.lang='rust' AND version.valid_until IS NULL ORDER BY version.unit_key")
            .unwrap().query_map([], |row| Ok((row.get(0)?, (row.get(1)?, row.get(2)?))))
            .unwrap().collect::<rusqlite::Result<_>>().unwrap()
    }

    fn assert_single_input_differential(
        category: &str,
        fixture: InlineTestProject,
        edit: impl FnOnce(
            &crate::inline_project::BuiltInlineTestProject,
        ) -> BTreeSet<brokk_bifrost_core::analyzer::model::ProjectFile>,
    ) {
        assert_single_input_differential_with(category, fixture, move |fixture, workspace| {
            let paths = edit(fixture);
            workspace.update(&paths)
        });
    }

    fn assert_single_input_differential_with(
        category: &str,
        fixture: InlineTestProject,
        update: impl FnOnce(
            &crate::inline_project::BuiltInlineTestProject,
            &WorkspaceAnalyzer,
        ) -> WorkspaceAnalyzer,
    ) {
        let fixture = fixture.build();
        let workspace = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        let before = single_input_summary_keys(&workspace);
        assert!(!before.is_empty(), "{category}: no initial summaries");
        let incremental = update(&fixture, &workspace);
        let after = single_input_summary_keys(&incremental);
        assert_ne!(
            before, after,
            "{category}: STOP: input mutation did not move a lookup/summary key"
        );
        for (unit, (lookup, summary)) in &before {
            if let Some((new_lookup, new_summary)) = after.get(unit)
                && (lookup, summary) != (new_lookup, new_summary)
            {
                assert_ne!(
                    lookup, new_lookup,
                    "{category}: {unit} lookup key did not move"
                );
                assert_ne!(
                    summary, new_summary,
                    "{category}: {unit} summary key did not move"
                );
            }
        }
        let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        assert!(!std::ptr::eq(
            incremental.store().unwrap().as_ref(),
            fresh.store().unwrap().as_ref()
        ));
        let incremental_rows = single_input_summary_rows(&incremental);
        let fresh_rows = single_input_summary_rows(&fresh);
        for (table, rows) in &incremental_rows {
            if fresh_rows.get(table) != Some(rows) {
                eprintln!(
                    "{category}: differing relation {table}: incremental={rows:?}; fresh={:?}",
                    fresh_rows.get(table)
                );
            }
        }
        assert_eq!(
            after,
            single_input_summary_keys(&fresh),
            "{category}: incremental/fresh keys"
        );
        assert_eq!(
            incremental_rows, fresh_rows,
            "{category}: incremental/fresh rows"
        );
    }

    #[test]
    fn rust_single_input_differential_source_body() {
        assert_single_input_differential("private source body", readiness_fixture(), |fixture| {
            let file = fixture.file("src/lib.rs");
            file.write("pub struct Item; fn private() -> u32 { 2 }\n")
                .unwrap();
            BTreeSet::from([file])
        });
    }

    #[test]
    fn rust_single_input_differential_manifest_edition() {
        assert_single_input_differential("manifest edition", readiness_fixture(), |fixture| {
            let file = fixture.file("Cargo.toml");
            let source = std::fs::read_to_string(file.abs_path()).unwrap();
            file.write(source.replace("edition='2021'", "edition='2024'"))
                .unwrap();
            BTreeSet::from([file])
        });
    }

    #[test]
    fn rust_single_input_differential_features() {
        assert_single_input_differential("declared features", readiness_fixture(), |fixture| {
            let file = fixture.file("Cargo.toml");
            let source = std::fs::read_to_string(file.abs_path()).unwrap();
            file.write(format!("{source}second=[]\n")).unwrap();
            BTreeSet::from([file])
        });
    }

    #[test]
    fn rust_single_input_differential_cargo_configuration() {
        assert_single_input_differential(
            "Cargo cfg atoms",
            readiness_fixture().file(
                ".cargo/config.toml",
                "[build]\nrustflags=['--cfg', 'first']\n",
            ),
            |fixture| {
                let file = fixture.file(".cargo/config.toml");
                file.write("[build]\nrustflags=['--cfg', 'second']\n")
                    .unwrap();
                BTreeSet::from([file])
            },
        );
    }

    #[test]
    fn rust_single_input_differential_source_membership() {
        assert_single_input_differential(
            "previously absent module",
            readiness_fixture().file("src/lib.rs", "pub mod extra;\npub struct Item;\n"),
            |fixture| {
                let file = fixture.file("src/extra.rs");
                file.write("pub struct Added;\n").unwrap();
                BTreeSet::from([file])
            },
        );
    }

    #[test]
    fn rust_single_input_differential_target_membership() {
        assert_single_input_differential(
            "automatic target membership",
            readiness_fixture(),
            |fixture| {
                let file = fixture.file("src/main.rs");
                file.write("fn main() {}\n").unwrap();
                BTreeSet::from([file])
            },
        );
    }

    #[test]
    fn rust_single_input_differential_consumed_surface() {
        assert_single_input_differential("dependency export surface", readiness_fixture()
            .file("Cargo.toml", "[package]\nname='readiness'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nprovider={path='provider'}\n")
            .file("src/lib.rs", "pub use provider::*;\n")
            .file("provider/Cargo.toml", "[package]\nname='provider'\nversion='0.1.0'\nedition='2021'\n")
            .file("provider/src/lib.rs", "pub struct Item;\n"), |fixture| {
            let file = fixture.file("provider/src/lib.rs");
            file.write("pub struct Renamed;\n").unwrap();
            BTreeSet::from([file])
        });
    }

    #[test]
    fn rust_single_input_differential_external_cargo_configuration() {
        const CHILD: &str = "BIFROST_12998_EXTERNAL_CONFIG_CHILD";
        if std::env::var_os(CHILD).is_some() {
            eprintln!("EXTERNAL_CONFIG_CHILD_RAN");
            assert_single_input_differential(
                "external Cargo cfg",
                readiness_fixture(),
                |fixture| {
                    let home = std::path::PathBuf::from(std::env::var_os("CARGO_HOME").unwrap());
                    std::fs::write(
                        home.join("config.toml"),
                        "[build]\nrustflags=['--cfg', 'second']\n",
                    )
                    .unwrap();
                    // Notify through an unchanged configuration path. Only the external
                    // configuration bytes changed; no workspace file or revision moved.
                    BTreeSet::from([fixture.file("Cargo.toml")])
                },
            );
            return;
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::write(
            home.path().join("config.toml"),
            "[build]\nrustflags=['--cfg', 'first']\n",
        )
        .unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "engine_tests::rust_unit_summaries::tests::rust_single_input_differential_external_cargo_configuration", "--nocapture"])
            .env(CHILD, "1").env("CARGO_HOME", home.path())
            .env_remove("RUSTFLAGS").env_remove("CARGO_ENCODED_RUSTFLAGS")
            .output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(
            stderr.contains("EXTERNAL_CONFIG_CHILD_RAN"),
            "child test body did not run:\n{stdout}\n{stderr}"
        );
    }

    #[test]
    fn rust_single_input_differential_derivation_identity() {
        const CHILD: &str = "BIFROST_12998_DERIVATION_CHILD";
        if std::env::var_os(CHILD).is_some() {
            eprintln!("DERIVATION_CHILD_RAN");
            use brokk_bifrost_analysis::analyzer::store::rust_crates::{
                derivation_identity_before_last_token, set_derivation_identity,
            };
            set_derivation_identity(Some(derivation_identity_before_last_token()));
            assert_single_input_differential_with(
                "crate producer identity",
                readiness_fixture(),
                |_, workspace| {
                    set_derivation_identity(None);
                    workspace.update_all()
                },
            );
            return;
        }
        // The override is process-global. A child keeps the one-input mutation
        // isolated from other tests, including if an assertion panics.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "engine_tests::rust_unit_summaries::tests::rust_single_input_differential_derivation_identity", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(
            stderr.contains("DERIVATION_CHILD_RAN"),
            "child test body did not run:\n{stdout}\n{stderr}"
        );
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#12998: a directory omission made incremental Cargo cfg differ from fresh analysis")]
    fn rust_single_input_differential_listing_certificate() {
        assert_single_input_differential(
            "directory omission certificate",
            readiness_fixture()
                .with_git()
                .file("src/data.txt", "data\n")
                .file("shared/data.txt", "shared\n"),
            |fixture| {
                std::os::unix::fs::symlink("../shared", fixture.root().join("src/bin")).unwrap();
                BTreeSet::from([fixture.file("src/bin")])
            },
        );
    }

    #[cfg(unix)]
    #[test]
    #[hardwon("#12998: listing-only publication must reacquire a changed Cargo include")]
    fn listing_only_update_reacquires_unnotified_cargo_include() {
        let fixture = readiness_fixture()
            .with_git()
            .file(".cargo/config.toml", "include='flags.toml'\n")
            .file(
                ".cargo/flags.toml",
                "[build]\nrustflags=['--cfg', 'first']\n",
            )
            .file("shared/data.txt", "shared\n")
            .build();
        let workspace = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        let before = single_input_summary_keys(&workspace);
        // The notification names only the listing change. The recorded include
        // also changed before admission, so carrying its old acquisition is stale.
        fixture
            .file(".cargo/flags.toml")
            .write("[build]\nrustflags=['--cfg', 'second']\n")
            .unwrap();
        std::os::unix::fs::symlink("../shared", fixture.root().join("src/bin")).unwrap();
        let incremental = workspace.update(&BTreeSet::from([fixture.file("src/bin")]));
        assert_ne!(before, single_input_summary_keys(&incremental));
        let fresh = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            single_input_summary_keys(&incremental),
            single_input_summary_keys(&fresh)
        );
        assert_eq!(
            single_input_summary_rows(&incremental),
            single_input_summary_rows(&fresh)
        );
    }

    #[test]
    #[hardwon("#12998: a settled private edit incurred a second Everything traversal on readiness")]
    fn settled_private_edit_readiness_retry_skips_everything() {
        const CHILD: &str = "BIFROST_12998_READINESS_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let fixture = readiness_fixture().build();
            let workspace = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
            let file = fixture.file("src/lib.rs");
            file.write("pub struct Item; fn private() -> u32 { 2 }\n")
                .unwrap();
            let workspace = workspace.update(&BTreeSet::from([file]));
            let before = single_input_summary_rows(&workspace);
            eprintln!("READINESS_RETRY_BEGIN");
            let workspace = workspace.update_all();
            let workspace = workspace.update_all();
            assert_eq!(before, single_input_summary_rows(&workspace));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "engine_tests::rust_unit_summaries::tests::settled_private_edit_readiness_retry_skips_everything", "--nocapture"])
            .env(CHILD, "1").env("BIFROST_TIMING", "1")
            .output().unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{stderr}");
        assert!(
            stderr.contains("READINESS_RETRY_BEGIN"),
            "child test body did not run:\n{stderr}"
        );
        let (_, retry) = stderr
            .split_once("READINESS_RETRY_BEGIN")
            .expect("child reached settled readiness retry");
        assert!(
            !retry.contains("scope Everything"),
            "readiness repeated Everything: {retry}"
        );
    }

    fn readiness_fixture() -> InlineTestProject {
        InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='readiness'\nversion='0.1.0'\nedition='2021'\n[features]\nextra=[]\n")
            .file("src/lib.rs", "pub struct Item; fn private() -> u32 { 1 }\n")
    }

    fn live_summaries(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, (i64, Vec<u8>)> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT topology.crate_name, summaries.summary_id, summaries.output_digest
                 FROM rust_crate_versions AS topology_versions
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN resolution_unit_summary_versions AS summary_versions
                   ON summary_versions.workspace_id = topology_versions.workspace_id
                  AND summary_versions.lang = topology_versions.lang
                  AND summary_versions.generation = topology_versions.generation
                  AND summary_versions.unit_key = topology_versions.crate_key
                  AND summary_versions.valid_until IS NULL
                 JOIN resolution_unit_summaries AS summaries
                   ON summaries.summary_id = summary_versions.summary_id
                 WHERE topology_versions.lang = 'rust'
                   AND topology_versions.valid_until IS NULL
                   AND topology.target_kind = 'lib'
                   AND summaries.publication_state = 'complete'
                 ORDER BY topology.crate_name",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap()
            .map(|row| {
                let (name, summary_id, output_digest) = row.unwrap();
                (name, (summary_id, output_digest))
            })
            .collect()
    }

    fn changed_summaries(
        before: &BTreeMap<String, (i64, Vec<u8>)>,
        after: &BTreeMap<String, (i64, Vec<u8>)>,
    ) -> BTreeSet<String> {
        assert_eq!(
            before.keys().collect::<Vec<_>>(),
            after.keys().collect::<Vec<_>>()
        );
        before
            .iter()
            .filter(|(name, (summary_id, _))| after[*name].0 != *summary_id)
            .map(|(name, _)| name.clone())
            .collect()
    }

    type SummaryRootRoute = (i64, String, i64, i64, Vec<u8>, String, String);

    fn summary_root_routes(
        workspace: &WorkspaceAnalyzer,
        summary_id: i64,
    ) -> Vec<SummaryRootRoute> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT member_ordinal, module_path, route_key, reference_source_site,
                    target_unit_key, target_module_path, target_name
             FROM rust_resolution_unit_summary_root_routes
             WHERE summary_id = ?1
             ORDER BY member_ordinal, module_path, route_key",
        )
        .unwrap()
        .query_map([summary_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    #[test]
    #[hardwon("ae10707fd23b: Rust topology ids and multi-namespace declarations were misread")]
    fn summary_detail_rows_crosswalk_the_selected_topology() {
        let names = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];
        let members = names
            .iter()
            .map(|name| format!("\"pkg_{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut fixture = InlineTestProject::new().file(
            "Cargo.toml",
            format!("[workspace]\nmembers = [{members}]\nresolver = \"2\"\n"),
        );
        for name in names {
            fixture = fixture
                .file(
                    format!("pkg_{name}/Cargo.toml"),
                    format!(
                        "[package]\nname = \"unit_{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    ),
                )
                .file(
                    format!("pkg_{name}/src/lib.rs"),
                    format!("pub struct {name}Item;\npub fn {name}() {{}}\n"),
                );
        }
        let fixture = fixture.build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let rows = conn
            .prepare(
                "SELECT topology.crate_name, contexts.crate_name
                 FROM rust_crate_versions AS topology_versions
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN resolution_unit_summary_versions AS summary_versions
                   ON summary_versions.workspace_id = topology_versions.workspace_id
                  AND summary_versions.lang = topology_versions.lang
                  AND summary_versions.generation = topology_versions.generation
                  AND summary_versions.unit_key = topology_versions.crate_key
                  AND summary_versions.valid_until IS NULL
                 JOIN rust_resolution_unit_summary_versions AS rust_versions
                   ON rust_versions.summary_id = summary_versions.summary_id
                 JOIN rust_resolution_unit_summary_contexts AS contexts
                   ON contexts.summary_id = rust_versions.summary_id
                 WHERE topology_versions.lang = 'rust'
                   AND topology_versions.valid_until IS NULL
                   AND topology.target_kind = 'lib'
                 ORDER BY topology.crate_name",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(rows.len(), names.len(), "published Rust contexts: {rows:?}");
        assert!(
            rows.iter()
                .all(|(topology_name, summary_name)| topology_name == summary_name),
            "summary detail rows must join their selected topology: {rows:?}"
        );
    }

    #[test]
    fn rust_summary_binding_surface_reader_seeks_in_both_statistics_states() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::types::Value;

        let fixture = InlineTestProject::with_language(
            brokk_bifrost_core::analyzer::model::Language::Rust,
        )
        .file(
            "Cargo.toml",
            "[package]\nname = \"binding_surface_plan\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .file("src/lib.rs", "pub struct Item; pub fn run() {}\n")
        .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().expect("fixture store");
        let conn = store.conn.lock().expect("fixture store connection");
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn)
            .expect("revisioned workspace views");
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .expect("clear workspace selections");
        conn.execute(
            "INSERT INTO selected_workspace_revisions
             SELECT workspace_id, lang, generation, revision FROM workspace_heads
             WHERE lang = 'rust'",
            [],
        )
        .expect("select fixture Rust workspace");
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        prepare_pin_context(&conn);
        let mut pin = pinned("rust_unit_summary_import_graph_binding_surfaces");
        pin.params = vec![Value::Text(serde_json::json!(["src/lib.rs"]).to_string())];

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pin);
            for index in [
                "rust_resolution_unit_summary_effective_bindings_member_name",
                "rust_resolution_unit_summary_import_route_provenance_binding",
                "rust_resolution_unit_summary_effective_bindings_module_name",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(index)),
                    "{state:?}: binding surface reader must seek {index}: {plan:?}"
                );
            }
            assert!(
                plan.iter()
                    .all(|row| !row.contains("AUTOMATIC") && !row.contains("TEMP B-TREE")),
                "{state:?}: binding surface reader builds no transient index or sort: {plan:?}"
            );
        }
    }

    #[test]
    fn rust_summary_binding_completeness_reader_seeks_in_both_statistics_states() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::types::Value;

        let fixture = InlineTestProject::with_language(brokk_bifrost_core::analyzer::model::Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"binding_completeness_plan\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file("src/lib.rs", "pub struct Item; pub fn run() {}\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().expect("fixture store");
        let conn = store.conn.lock().expect("fixture store connection");
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn)
            .expect("revisioned workspace views");
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .expect("clear workspace selections");
        conn.execute(
            "INSERT INTO selected_workspace_revisions
             SELECT workspace_id, lang, generation, revision FROM workspace_heads
             WHERE lang = 'rust'",
            [],
        )
        .expect("select fixture Rust workspace");
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        prepare_pin_context(&conn);
        let mut pin = pinned("rust_unit_summary_import_graph_binding_completeness");
        pin.params = vec![Value::Text(serde_json::json!(["src/lib.rs"]).to_string())];

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pin);
            assert!(
                plan.iter()
                    .any(|row| row
                        .contains("rust_resolution_unit_summary_binding_completeness_member")),
                "{state:?}: binding completeness reader must seek its member index: {plan:?}"
            );
            assert!(
                plan.iter()
                    .any(|row| row.contains("SEARCH gaps USING PRIMARY KEY (summary_id=?)")),
                "{state:?}: binding completeness reader must seek unit gaps: {plan:?}"
            );
            assert!(
                plan.iter()
                    .all(|row| !row.contains("AUTOMATIC") && !row.contains("TEMP B-TREE")),
                "{state:?}: binding completeness reader builds no transient index or sort: {plan:?}"
            );
        }
    }

    #[test]
    fn rust_summary_module_candidate_reader_seeks_in_both_statistics_states() {
        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

        use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::types::Value;

        let store = AnalyzerStore::open_ephemeral().expect("ephemeral planner store");
        let conn = store.conn.lock().expect("planner store connection");
        prepare_pin_context(&conn);
        let mut pin = pinned("rust_unit_summary_import_graph_module_candidates");
        pin.params = vec![Value::Text(
            serde_json::json!([[0, 1, "crate"]]).to_string(),
        )];

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let plan = explain_pin(&conn, &pin);
            for access in [
                "SEARCH containers USING PRIMARY KEY",
                "SEARCH placements USING PRIMARY KEY",
                "SEARCH members USING PRIMARY KEY",
            ] {
                assert!(
                    plan.iter().any(|row| row.contains(access)),
                    "{state:?}: module candidate reader must seek by primary key at {access}: {plan:?}"
                );
            }
            assert!(
                plan.iter()
                    .all(|row| !row.contains("AUTOMATIC") && !row.contains("TEMP B-TREE")),
                "{state:?}: module candidate reader builds no transient index or sort: {plan:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#4920: one enum reexported through two dependencies failed Rust summary reconciliation"
    )]
    fn reexport_routes_to_one_declaration_keep_the_smallest_dependency_ordinal() {
        // Swap the module paths as well as source order so EXPORTS_SQL visits
        // the direct and indirect dependency routes in both orders.
        for selection_source in [
            "pub mod traits { pub use infer::traits::*; pub mod project { pub use middle::traits::Reveal; } }\n",
            "pub mod traits { pub use middle::traits::Reveal; pub mod project { pub use infer::traits::*; } }\n",
        ] {
            let fixture = InlineTestProject::new()
                .file("Cargo.toml", "[workspace]\nmembers = [\"middle\", \"infer\", \"selection\"]\nresolver = \"2\"\n")
                .file("middle/Cargo.toml", "[package]\nname = \"middle\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
                .file("middle/src/lib.rs", "pub mod traits { pub enum Reveal { UserFacing, All } }\n")
                .file("infer/Cargo.toml", "[package]\nname = \"infer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nmiddle = { path = \"../middle\" }\n")
                .file("infer/src/lib.rs", "pub mod traits { pub mod project { pub use middle::traits::Reveal; } pub use self::project::Reveal; pub use middle::traits::*; }\n")
                .file("selection/Cargo.toml", "[package]\nname = \"selection\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nmiddle = { path = \"../middle\" }\ninfer = { path = \"../infer\" }\n")
                .file("selection/src/lib.rs", selection_source)
                .build();
            let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            // A failed unit publishes nothing; every library must have a live
            // summary after fresh reconciliation (also checked by differential).
            let summaries = live_summaries(&workspace);
            assert_eq!(summaries.len(), 3, "live Rust summaries: {summaries:?}");
            let conn = workspace.store().unwrap().read_conn().unwrap();
            select_export_endpoints(&conn);
            let (count, ordinal, minimum): (i64, i64, i64) = conn
                .query_row(
                    "SELECT count(*), MIN(exports.alias_dependency_ordinal),
                       (SELECT MIN(dependency_ordinal)
                        FROM resolution_unit_summary_dependencies WHERE summary_id = ?1)
                     FROM test_export_endpoints AS exports
                     JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                     JOIN test_export_endpoints AS declaration
                       ON declaration.summary_id = ?2
                      AND declaration.identity_id = exports.identity_id
                      AND declaration.namespace = exports.namespace
                      AND declaration.endpoint_blob = exports.endpoint_blob
                      AND declaration.endpoint_site = exports.endpoint_site
                     WHERE exports.summary_id = ?1 AND identities.spelling = 'Reveal'
                       AND exports.namespace = 'type' AND exports.origin = 'reexport'",
                    rusqlite::params![summaries["selection"].0, summaries["middle"].0],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(count, 1, "one shared export for the enum declaration");
            assert_eq!(ordinal, minimum, "smallest dependency ordinal wins");
        }
    }

    fn vector_reexport_fixture() -> crate::inline_project::BuiltInlineTestProject {
        // Vector's root package depends only on vector-lib. The declaration
        // lives in vector-core, which is deliberately not a direct dependency
        // of vector. Keep this fixture free of external packs and dependencies.
        InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"vector\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [workspace]\nmembers = [\"lib/vector-lib\", \"lib/vector-core\"]\nresolver = \"2\"\n\
                 [dependencies]\nvector-lib = { path = \"lib/vector-lib\" }\n",
            )
            .file("src/lib.rs", "pub use vector_lib::event::Event;\n")
            .file(
                "lib/vector-lib/Cargo.toml",
                "[package]\nname = \"vector-lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\nvector-core = { path = \"../vector-core\" }\n",
            )
            .file("lib/vector-lib/src/lib.rs", "pub use vector_core::event;\n")
            .file(
                "lib/vector-core/Cargo.toml",
                "[package]\nname = \"vector-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("lib/vector-core/src/lib.rs", "pub mod event;\n")
            .file("lib/vector-core/src/event.rs", "pub enum Event { Log, Metric }\n")
            .build()
    }

    #[test]
    #[hardwon("#5133: a public module alias can leave a forwarded module's physical subtree")]
    fn vector_forwarded_module_alias_outside_subtree_publishes_first_hop() {
        let fixture = vector_reexport_fixture();
        fixture
            .file("lib/vector-core/src/lib.rs")
            .write("pub mod event;\npub mod outside;\n")
            .unwrap();
        fixture
            .file("lib/vector-core/src/event.rs")
            .write("pub use crate::outside as alias;\n")
            .unwrap();
        std::fs::write(
            fixture.root().join("lib/vector-core/src/outside.rs"),
            "pub enum Event { Log, Metric }\n",
        )
        .unwrap();
        fixture
            .file("src/lib.rs")
            .write("pub use vector_lib::event::alias::Event;\n")
            .unwrap();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let topologies = vector_topologies(&workspace);
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let targets = conn
            .prepare(brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::NAMED_REEXPORT_TARGETS_SQL)
            .unwrap()
            .query_map(
                rusqlite::params![topologies["vector"], "crate", "type", "Event"],
                |row| Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            targets,
            vec![("crate::outside".to_owned(), "Event".to_owned())],
            "the shared route algorithm must retain the canonical module alias target"
        );
        let topology_has_event: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM rust_crate_exports
                 WHERE topology_id = ?1 AND module_path = 'crate'
                   AND namespace = 'type' AND name = 'Event' AND visibility = 'public')",
                [topologies["vector"]],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            topology_has_event,
            "the legal alias must exist in the topology oracle"
        );
        drop(conn);
        assert_vector_event_export(
            &workspace,
            "vector",
            "lib/vector-core/src/outside.rs",
            "vector_lib",
        );
    }

    #[test]
    #[hardwon("#5133: a transitive reexport disappeared from the shared Rust summary")]
    fn vector_transitive_reexport_publishes_the_direct_dependency_and_complete_header() {
        let fixture = vector_reexport_fixture();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(summaries.len(), 3, "live Rust summaries: {summaries:?}");
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        select_export_endpoints(&conn);
        let rows = conn
            .prepare(
                "SELECT identities.spelling, exports.namespace, exports.origin,
                        dependency_names.extern_name, declaration_members.rel_path,
                        summaries.complete, summaries.publication_state,
                        rust_exports.target_unit_key = leaf.unit_key,
                        rust_exports.target_module_path, rust_exports.target_name,
                        rust_exports.alias_identity_id = declaration.identity_id
                 FROM test_export_endpoints AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 JOIN resolution_unit_summaries AS summaries USING(summary_id)
                 JOIN rust_unit_summary_dependency_names AS dependency_names
                   ON dependency_names.summary_id = exports.summary_id
                  AND dependency_names.dependency_ordinal = exports.alias_dependency_ordinal
                 JOIN test_export_endpoints AS declaration
                   ON declaration.summary_id = ?2
                  AND declaration.endpoint_blob = exports.endpoint_blob
                  AND declaration.endpoint_site = exports.endpoint_site
                  AND declaration.namespace = exports.namespace
                 JOIN resolution_unit_summary_members AS declaration_members
                   ON declaration_members.summary_id = declaration.summary_id
                  AND declaration_members.blob_id = declaration.endpoint_blob
                 JOIN resolution_unit_summaries AS leaf ON leaf.summary_id = declaration.summary_id
                 JOIN rust_resolution_unit_summary_exports AS rust_exports
                   ON rust_exports.summary_id = exports.summary_id
                  AND rust_exports.module_path = 'crate'
                  AND rust_exports.name = identities.spelling
                  AND rust_exports.namespace = exports.namespace
                 WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                 ORDER BY exports.namespace",
            )
            .unwrap()
            .query_map(
                rusqlite::params![summaries["vector"].0, summaries["vector_core"].0],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, bool>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, bool>(10)?,
                    ))
                },
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(
                "Event".to_owned(),
                "type".to_owned(),
                "reexport".to_owned(),
                "vector_lib".to_owned(),
                "lib/vector-core/src/event.rs".to_owned(),
                true,
                "complete".to_owned(),
                true,
                "crate::event".to_owned(),
                "Event".to_owned(),
                true,
            )],
            "the shared first hop is vector_lib and the Rust target is the canonical vector_core leaf"
        );
    }

    /// A consumed unit's crate name, its read kinds, and whether it was
    /// available when read.
    type ConsumedRow = (String, Vec<&'static str>, bool);

    /// Each live library summary's recorded consumed units, by crate name.
    fn consumed_sets(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, Vec<ConsumedRow>> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT consumer.crate_name, consumed.crate_name, units.read_reexport_hop,
                        units.read_module_hop, units.read_endpoint, units.read_absence,
                        units.read_closure_bindings, units.read_trait_endpoint,
                        units.consumed_summary_id IS NOT NULL
                 FROM rust_crate_versions AS consumer_versions
                 JOIN rust_crate_topologies AS consumer USING(topology_id)
                 JOIN resolution_unit_summary_versions AS versions
                   ON versions.unit_key = consumer_versions.crate_key
                  AND versions.valid_until IS NULL
                 JOIN resolution_unit_summary_consumed_units AS units
                   ON units.summary_id = versions.summary_id
                 JOIN rust_crate_versions AS consumed_versions
                   ON consumed_versions.crate_key = units.consumed_unit_key
                  AND consumed_versions.valid_until IS NULL
                 JOIN rust_crate_topologies AS consumed
                   ON consumed.topology_id = consumed_versions.topology_id
                 WHERE consumer_versions.valid_until IS NULL AND consumer.target_kind = 'lib'
                   AND consumed.target_kind = 'lib'
                 ORDER BY consumer.crate_name, consumed.crate_name",
            )
            .unwrap();
        let rows = statement
            .query_map([], |row| {
                let kinds: Vec<&'static str> = [
                    "reexport_hop",
                    "module_hop",
                    "endpoint",
                    "absence",
                    "closure_bindings",
                    "trait_endpoint",
                ]
                .into_iter()
                .enumerate()
                .filter(|(index, _)| row.get::<_, bool>(2 + index).unwrap())
                .map(|(_, kind)| kind)
                .collect();
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    kinds,
                    row.get::<_, bool>(8)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let mut sets: BTreeMap<String, Vec<_>> = BTreeMap::new();
        for (consumer, consumed, kinds, available) in rows {
            sets.entry(consumer)
                .or_default()
                .push((consumed, kinds, available));
        }
        sets
    }

    #[test]
    fn vector_records_the_transitive_endpoint_with_its_read_kinds() {
        let fixture = vector_reexport_fixture();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        // vector_lib is vector's direct dependency, so the dependencies table
        // holds it; vector_core is reached through it and is recorded. The whole
        // module `pub use vector_core::event;` in vector_lib is a module hop.
        // vector_lib's only dependency is vector_core, also direct there.
        let sets = consumed_sets(&workspace);
        assert_eq!(
            sets.get("vector"),
            Some(&vec![(
                "vector_core".to_owned(),
                vec!["module_hop", "endpoint", "closure_bindings"],
                true
            )]),
            "{sets:?}"
        );
        assert!(!sets.contains_key("vector_lib"), "{sets:?}");
    }

    /// `top` re-exports `Event` through `mid`, which re-exports `kernel` by glob
    /// or by module, depending on `mid_source`; `kernel_source` is kernel's root.
    fn walk_fixture(
        mid_source: &str,
        top_source: &str,
        kernel_source: &str,
    ) -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"top\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [workspace]\nmembers = [\"mid\", \"kernel\"]\nresolver = \"2\"\n\
                 [dependencies]\nmid = { path = \"mid\" }\n",
            )
            .file("src/lib.rs", top_source)
            .file(
                "mid/Cargo.toml",
                "[package]\nname = \"mid\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\nkernel = { path = \"../kernel\" }\n",
            )
            .file("mid/src/lib.rs", mid_source)
            .file(
                "kernel/Cargo.toml",
                "[package]\nname = \"kernel\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("kernel/src/lib.rs", kernel_source)
            .file("kernel/src/event.rs", "pub enum Event { Log, Metric }\n")
            .build()
    }

    #[test]
    #[hardwon("#11173: foreign gap binding evidence retained another unit's blob and site")]
    fn foreign_gap_bindings_use_name_forms_and_keep_conflicts() {
        for (case, mid, top, kernel) in [
            (
                "named",
                "pub use kernel::event; pub use event::*;",
                "pub use mid::event; pub use event::*;",
                "pub mod event { mod left { pub struct Event; } mod right { pub struct Event; } pub use left::*; pub use right::*; }",
            ),
            (
                "glob",
                "pub use kernel::*; pub use event::*;",
                "pub use mid::*; pub use event::*;",
                "pub mod event { mod left { pub struct Event; } mod right { pub struct Event; } pub use left::*; pub use right::*; }",
            ),
            (
                "same_name",
                "pub use kernel::event; pub use kernel::event as second; pub use event::*; pub use second::*;",
                "pub use mid::*;",
                "pub mod event { pub struct Event; pub struct Event; }",
            ),
        ] {
            let fixture = walk_fixture(mid, top, kernel);
            let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            // Scan ALL Rust units and both summary tables, plus the topology
            // source. Macro invocation member_blob/invocation_occurrence are
            // deliberately exempt in phase A; they need dependency resolution.
            let rows = conn
                .prepare(
                    "SELECT 'rust', hex(s.unit_key), c.crate_name, json(g.detail)
                 FROM rust_resolution_unit_summary_gaps g
                 JOIN resolution_unit_summaries s USING(summary_id)
                 JOIN rust_resolution_unit_summary_contexts c USING(summary_id)
                 UNION ALL
                 SELECT 'shared', hex(s.unit_key), c.crate_name, json(g.detail)
                 FROM resolution_unit_summary_gaps g
                 JOIN resolution_unit_summaries s USING(summary_id)
                 JOIN rust_resolution_unit_summary_contexts c USING(summary_id)
                 WHERE s.lang='rust'
                 UNION ALL
                 SELECT 'topology', hex(t.crate_key), t.crate_name, json(g.detail)
                 FROM rust_crate_gaps g JOIN rust_crate_topologies t USING(topology_id)",
                )
                .unwrap()
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let mut foreign = BTreeSet::new();
            let mut conflicts = BTreeSet::new();
            for (table, publishing_unit, crate_name, detail) in &rows {
                let detail: serde_json::Value = serde_json::from_str(detail).unwrap();
                let mut pending = vec![&detail];
                while let Some(item) = pending.pop() {
                    match item {
                        serde_json::Value::Array(items) => pending.extend(items),
                        serde_json::Value::Object(fields) => {
                            if item["reason"] == "InconsistentPrecedence" {
                                conflicts.insert((table.as_str(), crate_name.as_str()));
                            }
                            if let (Some(target_unit), Some(binding)) =
                                (item["crate"].as_str(), fields.get("binding"))
                                && target_unit != publishing_unit
                                && !binding.is_null()
                            {
                                assert!(
                                    binding.get("blob").is_none() && binding.get("site").is_none(),
                                    "{case}/{table}/{crate_name}: {item}"
                                );
                                assert_eq!(binding["unit_key"], target_unit);
                                assert_eq!(binding["module_path"], item["module"]);
                                assert_eq!(binding["name"], item["name"]);
                                assert_eq!(binding["origin"], "declaration");
                                assert!(
                                    binding["kind"].is_string() && binding["namespace"].is_string()
                                );
                                foreign.insert((table.as_str(), crate_name.as_str()));
                            }
                            pending.extend(fields.values());
                        }
                        _ => {}
                    }
                }
            }
            for table in ["rust", "shared", "topology"] {
                for unit in ["mid", "top"] {
                    assert!(
                        conflicts.contains(&(table, unit)),
                        "{case}: missing conflict {table}/{unit}: {rows:?}"
                    );
                    assert!(
                        foreign.contains(&(table, unit)),
                        "{case}: missing foreign evidence {table}/{unit}: {rows:?}"
                    );
                }
            }
        }
    }

    #[test]
    #[hardwon(
        "#11173: a function-body invocation of the same macro suppressed a covered generated definition"
    )]
    fn forwarded_macro_gap_requires_every_matching_invocation_anchor() {
        use brokk_bifrost_analysis::analyzer::semantic_model::*;
        use brokk_bifrost_analysis::analyzer::usages::get_definition::{
            DefinitionLookupRequest, trace::resolve_definition_batch_with_trace,
        };
        // Original test-only generator. An empty invocation emits no anchor.
        const MODEL: &str = r#"
schema_version: 2
pack_id: bifrost.fixture.11173
version: 1.0.0
producer: { name: engine-test-fixture, version: 1.0.0 }
language: rust
ecosystem: cargo
compatibility: { bifrost: ">=0.8.21, <1.0.0", toolchains: [] }
provenance: { source: "Original test-only model for issue 11173 invocation coverage", revision: fixture-1 }
license: Apache-2.0
completeness: partial
safety: { generated_code_only: true, review_required: false }
shards:
  - id: functions
    activation:
      - configurations: [bifrost.fixture.11173]
    payload:
      kind: generator_rules
      rules:
        - id: fixture-functions
          trigger: { kind: macro_invocation, name: unknown }
          captures:
            - name: function_name
              binding: { source: { kind: arguments, from: 0 }, projection: name }
              value_kind: identifier
              cardinality: many
            - name: function_id
              binding: { source: { kind: arguments, from: 0 }, projection: stable_id }
              value_kind: stable_id
              cardinality: many
          emissions:
            - kind: declaration
              id: { op: concat, values: [{ op: capture, name: function_id }, { op: literal, value: .function }] }
              name: { op: capture, name: function_name }
              anchor: { op: capture, name: function_id }
              declaration: { kind: member, member_kind: function, visibility: public }
"#;
        for (tail, expected) in [
            ("unknown!();", 0),
            ("unknown!(missing);", 2),
            ("fn f() { unknown!(); }", 1),
        ] {
            let source = "use kernel::event::missing; fn caller() { missing(); }";
            let fixture = walk_fixture(
                "pub use kernel::event;",
                source,
                &format!("pub mod event {{ unknown!(missing); {tail} }}"),
            );
            // Generated-function spelling resolution already supports direct
            // Cargo imports; transitive re-export routing is a separate surface.
            let manifest = fixture.file("Cargo.toml");
            manifest
                .write(format!(
                    "{}kernel = {{ path = \"kernel\" }}\n",
                    manifest.read_to_string().unwrap()
                ))
                .unwrap();
            fixture
                .file(".bifrost/semantic-models/invocation.yaml")
                .write(MODEL)
                .unwrap();
            let workspace = fixture.certified_workspace_analyzer(AnalyzerConfig::default());
            let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
            let registration = register_workspace_semantic_models(
                fixture.root(),
                &catalog,
                WorkspaceSemanticModelOptions::default(),
            )
            .unwrap();
            let request = SemanticModelActivationRequest {
                approximate_standard_libraries: Vec::new(),
                bifrost_version: semver::Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
                evidence: registration.evidence,
                controls: Vec::new(),
                limits: SemanticModelRuntimeLimits::default(),
            };
            let activation = acquire_active_semantic_models(
                workspace.analyzer(),
                &catalog,
                None,
                &request,
                &brokk_bifrost_core::cancellation::CancellationToken::new(),
            );
            assert!(
                matches!(activation, SemanticModelRuntimeOutcome::Ready { .. }),
                "{activation:?}"
            );
            let file = fixture.file("src/lib.rs");
            let start = source.rfind("missing()").unwrap();
            let answer = resolve_definition_batch_with_trace(
                workspace.analyzer(),
                vec![DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start),
                    end_byte: Some(start + 7),
                }],
                file,
                std::sync::Arc::<str>::from(source),
                &brokk_bifrost_core::cancellation::CancellationToken::new(),
            );
            assert_eq!(
                answer[0].0.modeled_definitions.len(),
                expected,
                "{tail}: {answer:#?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#11173: foreign invocation gaps retained local coordinates and missed live module membership"
    )]
    fn foreign_macro_invocation_reads_track_module_members_independently_of_output() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::{
            AnalyzerQueryScope, capture_query_reads,
        };
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, ReadKey};
        use brokk_bifrost_analysis::analyzer::read_verification::{
            LookupReplayLimits, NoSummaryAnswers, replay_lookup,
        };
        use brokk_bifrost_analysis::analyzer::usages::get_definition::{
            DefinitionLookupRequest, trace::resolve_definition_batch_with_trace,
        };
        let source = "use mid::event::missing; fn caller() { missing(); }";
        let fixture = walk_fixture(
            "pub use kernel::event;",
            source,
            "pub mod event { unknown!(); unknown!(); mod child { unknown!(); } } pub mod other;",
        );
        fixture
            .file("kernel/src/other.rs")
            .write("unknown!();")
            .unwrap();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let file = fixture.file("src/lib.rs");
        let start = source.rfind("missing()").unwrap();
        let (outcomes, captured) = {
            let _scope = AnalyzerQueryScope::new(workspace.analyzer());
            capture_query_reads(workspace.analyzer(), || {
                resolve_definition_batch_with_trace(
                    workspace.analyzer(),
                    vec![DefinitionLookupRequest {
                        file: file.clone(),
                        line: None,
                        column: None,
                        start_byte: Some(start),
                        end_byte: Some(start + 7),
                    }],
                    file,
                    std::sync::Arc::<str>::from(source),
                    &brokk_bifrost_core::cancellation::CancellationToken::new(),
                )
            })
        };
        let keys = captured.keys();
        let (question, before) = keys
            .iter()
            .find_map(|key| match key {
                ReadKey::Lookup {
                    kind: LookupKind::RustMacroInvocations,
                    question,
                    digest,
                } => Some((question.clone(), *digest)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("the consumer must record the dependency module invocation lookup: keys={keys:?}, outcomes={outcomes:?}"));
        let replay = |head: &WorkspaceAnalyzer| {
            replay_lookup(
                head,
                LookupKind::RustMacroInvocations,
                &question,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
            )
            .unwrap()
        };
        assert_eq!(replay(&workspace), before);
        let snapshots = workspace
            .analyzer()
            .selected_workspace_snapshots_for_reads()
            .unwrap();
        let answer = workspace
            .store()
            .unwrap()
            .rust_macro_invocations_answer(
                snapshots.as_ref(),
                &question,
                &brokk_bifrost_core::cancellation::CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            answer.invocations.len(),
            2,
            "child module invocations cannot cover the parent"
        );
        assert!(
            answer
                .invocations
                .iter()
                .all(|row| row.relative_path == "kernel/src/lib.rs")
        );
        let store = workspace.store().unwrap();
        {
            let conn = store.read_conn().unwrap();
            let rows=conn.prepare("SELECT hex(s.unit_key),json(g.detail) FROM rust_resolution_unit_summary_gaps g JOIN resolution_unit_summaries s USING(summary_id) UNION ALL SELECT hex(s.unit_key),json(g.detail) FROM resolution_unit_summary_gaps g JOIN resolution_unit_summaries s USING(summary_id) WHERE s.lang='rust' UNION ALL SELECT hex(t.crate_key),json(g.detail) FROM rust_crate_gaps g JOIN rust_crate_topologies t USING(topology_id)").unwrap().query_map([], |row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let mut foreign = 0;
            for (owner, detail) in rows {
                let value: serde_json::Value = serde_json::from_str(&detail).unwrap();
                let mut pending = vec![&value];
                while let Some(item) = pending.pop() {
                    match item {
                        serde_json::Value::Array(items) => pending.extend(items),
                        serde_json::Value::Object(fields) => {
                            if item["reason"] == "UnsupportedMacroGeneratedModule" {
                                assert_eq!(item["kind"], "macro_invocation");
                                assert!(item["unit_key"].is_string(), "{item}");
                            }
                            if item["kind"] == "macro_invocation"
                                && item["unit_key"].as_str() != Some(owner.as_str())
                            {
                                assert!(
                                    !fields.contains_key("member_blob")
                                        && !fields.contains_key("invocation_occurrence"),
                                    "foreign coordinates: {item}"
                                );
                                foreign += 1;
                            }
                            pending.extend(fields.values());
                        }
                        _ => {}
                    }
                }
            }
            assert!(foreign > 0);
        }
        // A placement without a producer gap does not add an invocation
        // obligation. The producer alone decides which invocations open inventory.
        let changed=store.conn.execute(|conn| {
            let _fixture=brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            conn.execute_batch("INSERT INTO resolution_unit_summary_placements SELECT summary_id,'crate::event',member_ordinal,scope_surface_ordinal FROM resolution_unit_summary_placements WHERE container_path='crate::other';
INSERT INTO rust_resolution_unit_summary_placement_attributes(summary_id,container_path,member_ordinal,placement,source_kind,enum_scope_node_key) SELECT summary_id,'crate::event',member_ordinal,placement,source_kind,enum_scope_node_key FROM rust_resolution_unit_summary_placement_attributes WHERE container_path='crate::other';")?;
            Ok::<_,rusqlite::Error>(conn.changes())
        }).unwrap();
        assert!(changed > 0);
        assert_eq!(
            replay(&workspace),
            before,
            "a placement without producer evidence adds no invocation obligation"
        );
        store.conn.execute(|conn| {
            let _fixture=brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
            conn.execute("DELETE FROM resolution_unit_summary_placements WHERE container_path='crate::event' AND member_ordinal IN (SELECT member_ordinal FROM resolution_unit_summary_placements p WHERE p.summary_id=resolution_unit_summary_placements.summary_id AND p.container_path='crate::other')", [])
        }).unwrap();
        assert_eq!(
            replay(&workspace),
            before,
            "removing the added placement restores the original relation"
        );
        store
            .conn
            .execute(|conn| {
                let _fixture =
                    brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
                conn.execute(
                    "UPDATE resolution_unit_summary_members SET rel_path=rel_path",
                    [],
                )
            })
            .unwrap();
        assert_eq!(
            replay(&workspace),
            before,
            "identical member republication cannot invalidate"
        );
        drop(snapshots);
        let old_summary = live_summaries(&workspace)["kernel"].0;
        let other = fixture.file("kernel/src/other.rs");
        other.write("unknown!(); pub struct Unrelated;\n").unwrap();
        let republished = workspace.update(&BTreeSet::from([other]));
        assert_ne!(live_summaries(&republished)["kernel"].0, old_summary);
        assert_eq!(
            replay(&republished),
            before,
            "a new publication with identical queried module members must stay reusable"
        );
        let event = fixture.file("kernel/src/lib.rs");
        event
            .write("pub mod event { unknown!(); unknown!(); mod child { unknown!(); } } pub mod other; // changed content\n")
            .unwrap();
        let updated = republished.update(&BTreeSet::from([event]));
        assert_ne!(
            replay(&updated),
            before,
            "member content changes invalidate even with identical invocation ranges"
        );
    }

    #[test]
    #[hardwon("#11974: worker-reopened prefetch dropped the RustMacroInvocations read")]
    fn worker_prefetch_macro_invocation_reads_track_dependency_edits() {
        use brokk_bifrost_analysis::analyzer::i_analyzer::{
            AnalyzerQueryScope, capture_query_reads,
        };
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, ReadKey};
        use brokk_bifrost_analysis::analyzer::read_verification::{
            LookupReplayLimits, NoSummaryAnswers, replay_lookup,
        };
        let source = "use mid::event::missing; fn caller() { missing(); }";
        let fixture = walk_fixture(
            "pub use kernel::event;",
            source,
            "pub mod event { unknown!(); unknown!(); mod child { unknown!(); } } pub mod other;",
        );
        fixture
            .file("kernel/src/other.rs")
            .write("unknown!();")
            .unwrap();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let file = fixture.file("src/lib.rs");
        let start = source.rfind("missing()").unwrap();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let range = brokk_bifrost_core::analyzer::model::Range {
            start_byte: start,
            end_byte: start + 7,
            start_line: 0,
            end_line: 0,
        };
        let (outcomes, captured) = pool.install(|| {
            let _scope = AnalyzerQueryScope::new(workspace.analyzer());
            capture_query_reads(workspace.analyzer(), || {
                let mut cache = brokk_bifrost_analysis::analyzer::usages::call_relations::CallBindingCache::default();
                cache.prefetch_selected_call_targets(&workspace, [(file.clone(), range)], None).unwrap();
                cache.resolved_call_target(workspace.analyzer(), &file, range, None)
            })
        });
        let keys = captured.keys();
        let (question, before) = keys
            .iter()
            .find_map(|key| match key {
                ReadKey::Lookup {
                    kind: LookupKind::RustMacroInvocations,
                    question,
                    digest,
                } => Some((question.clone(), *digest)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("the consumer must record the dependency module invocation lookup: keys={keys:?}, outcomes={outcomes:?}"));
        let replay = |head: &WorkspaceAnalyzer| {
            replay_lookup(
                head,
                LookupKind::RustMacroInvocations,
                &question,
                LookupReplayLimits::default(),
                &NoSummaryAnswers,
            )
            .unwrap()
        };
        assert_eq!(replay(&workspace), before);
        let event = fixture.file("kernel/src/lib.rs");
        event.write("pub mod event { unknown!(); unknown!(); unknown!(); mod child { unknown!(); } } pub mod other;\n").unwrap();
        let updated = workspace.update(&BTreeSet::from([event]));
        assert_ne!(
            replay(&updated),
            before,
            "dependency invocation edits invalidate the worker receipt"
        );
        let fresh = fixture.workspace_analyzer(AnalyzerConfig::default());
        pool.install(|| {
            let mut cache =
                brokk_bifrost_analysis::analyzer::usages::call_relations::CallBindingCache::default(
                );
            cache
                .prefetch_selected_call_targets(&fresh, [(file.clone(), range)], None)
                .unwrap();
        });
        let invocations = |head: &WorkspaceAnalyzer| {
            let snapshots = head
                .analyzer()
                .selected_workspace_snapshots_for_reads()
                .unwrap();
            head.store()
                .unwrap()
                .rust_macro_invocations_answer(
                    snapshots.as_ref(),
                    &question,
                    &brokk_bifrost_core::cancellation::CancellationToken::new(),
                )
                .unwrap()
                .invocations
                .into_iter()
                .map(|row| {
                    (
                        row.relative_path,
                        row.macro_name,
                        row.start_byte,
                        row.end_byte,
                        row.private_module_route,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            invocations(&updated),
            invocations(&fresh),
            "incremental and fresh invocation answers agree"
        );
    }

    #[test]
    #[hardwon(
        "#11173+#11994: a forwarded name form without a name must refuse; an unmatched one must stay incomplete"
    )]
    fn forwarded_macro_inventory_name_forms_refuse_malformed_and_keep_unmatched_incomplete() {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::{
            DefinitionLookupRequest, DefinitionLookupStatus,
            trace::resolve_definition_batch_with_trace,
        };

        for missing in [true, false] {
            let source = "use mid::event::missing; fn caller() { missing(); }";
            let fixture = walk_fixture(
                "pub use kernel::event;",
                source,
                "pub mod event { unknown!(); }",
            );
            let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = workspace.store().unwrap();
            let changed = store
                .conn
                .execute(move |conn| {
                    let _fixture =
                        brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(
                            conn,
                        );
                    let rows = conn
                        .prepare(
                            "SELECT g.summary_id,g.gap_kind,g.subject,json(g.detail)
                     FROM rust_resolution_unit_summary_gaps g
                     JOIN rust_resolution_unit_summary_contexts c USING(summary_id)
                     WHERE c.crate_name='top' AND c.target_kind='lib'",
                        )?
                        .query_map([], |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                            ))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    let mut changed = 0;
                    for (summary, kind, subject, detail) in rows {
                        let mut detail: serde_json::Value = serde_json::from_str(&detail).unwrap();
                        let mut pending = vec![&mut detail];
                        let mut mutated = false;
                        while let Some(item) = pending.pop() {
                            match item {
                                serde_json::Value::Array(items) => pending.extend(items),
                                serde_json::Value::Object(fields) => {
                                    if fields.get("reason").and_then(serde_json::Value::as_str)
                                        == Some("UnsupportedMacroGeneratedModule")
                                    {
                                        // The fixture must contain an actual forwarded invocation.
                                        assert_eq!(fields["kind"], "macro_invocation");
                                        assert!(!fields.contains_key("member_blob"));
                                        if missing {
                                            fields.remove("name");
                                        } else {
                                            fields.insert(
                                                "name".into(),
                                                serde_json::json!("not_an_invoked_macro"),
                                            );
                                        }
                                        mutated = true;
                                    }
                                    pending.extend(fields.values_mut());
                                }
                                _ => {}
                            }
                        }
                        if mutated {
                            changed += conn.execute(
                                "UPDATE rust_resolution_unit_summary_gaps SET detail=jsonb(?4)
                             WHERE summary_id=?1 AND gap_kind=?2 AND subject=?3",
                                rusqlite::params![summary, kind, subject, detail.to_string()],
                            )?;
                        }
                    }
                    Ok::<_, rusqlite::Error>(changed)
                })
                .unwrap();
            assert!(changed > 0, "fixture must forward a macro inventory to top");
            let file = fixture.file("src/lib.rs");
            let start = source.rfind("missing()").unwrap();
            let results = resolve_definition_batch_with_trace(
                workspace.analyzer(),
                vec![DefinitionLookupRequest {
                    file: file.clone(),
                    line: None,
                    column: None,
                    start_byte: Some(start),
                    end_byte: Some(start + "missing".len()),
                }],
                file,
                std::sync::Arc::<str>::from(source),
                &brokk_bifrost_core::cancellation::CancellationToken::new(),
            );
            if missing {
                // A name form without a name is malformed evidence: refused.
                assert_eq!(
                    results[0].0.status,
                    DefinitionLookupStatus::Unavailable,
                    "{results:#?}"
                );
                assert!(
                    results[0].0.diagnostics.iter().any(|diagnostic| {
                        diagnostic.kind == "native_store_error"
                            && diagnostic
                                .message
                                .contains("Rust macro inventory invocation cannot be resolved")
                    }),
                    "{results:#?}"
                );
            } else {
                // A name form no producer verdict matches stays an unanchored
                // obligation: incomplete, never covered.
                assert_eq!(
                    results[0].0.status,
                    DefinitionLookupStatus::UnresolvableImportBoundary,
                    "{results:#?}"
                );
                assert!(
                    results[0].0.diagnostics.iter().any(|diagnostic| {
                        diagnostic.kind == "UnsupportedMacroGeneratedSurface"
                            && diagnostic.message.contains("\"rel_path\":null")
                    }),
                    "{results:#?}"
                );
            }
        }
    }

    /// The crate names `top` published a re-export of `name` through, with the
    /// extern name of the first-hop dependency.
    fn first_hops(workspace: &WorkspaceAnalyzer, name: &str) -> Vec<(String, String)> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT topology.crate_name, names.extern_name
             FROM rust_crate_versions AS crate_versions
             JOIN rust_crate_topologies AS topology USING(topology_id)
             JOIN resolution_unit_summary_versions AS versions
               ON versions.unit_key = crate_versions.crate_key AND versions.valid_until IS NULL
             JOIN rust_resolution_unit_summary_exports AS exports
               ON exports.summary_id = versions.summary_id
             JOIN rust_unit_summary_dependency_names AS names
               ON names.summary_id = exports.summary_id
              AND names.dependency_ordinal = exports.alias_dependency_ordinal
             WHERE crate_versions.valid_until IS NULL AND topology.target_kind = 'lib'
               AND exports.origin <> 'declaration' AND exports.name = ?1
             ORDER BY topology.crate_name, names.extern_name",
        )
        .unwrap()
        .query_map([name], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
    }

    #[test]
    fn a_glob_reexport_of_a_module_is_found_through_the_glob_and_records_the_absence() {
        // `mid` re-exports kernel's items by glob, so `event` is a module hop
        // that lands in kernel and `Item` is a name that lands on no module. Both
        // reads are kernel's, and neither is a direct dependency of `top`.
        let fixture = walk_fixture(
            "pub use kernel::*;\n",
            "pub use mid::event::Event;\n",
            "pub mod event;\npub struct Item;\n",
        );
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let sets = consumed_sets(&workspace);
        let kernel = sets
            .get("top")
            .and_then(|rows| rows.iter().find(|row| row.0 == "kernel"))
            .unwrap_or_else(|| panic!("top consumed kernel: {sets:?}"));
        for kind in ["module_hop", "endpoint", "absence"] {
            assert!(kernel.1.contains(&kind), "{kind} in {kernel:?}");
        }
        assert!(kernel.2, "kernel was available: {kernel:?}");
        assert_eq!(
            first_hops(&workspace, "Event"),
            vec![("top".to_owned(), "mid".to_owned())],
            "the first hop is the dependency that exposes the module"
        );
    }

    #[test]
    fn a_module_reexport_cycle_terminates_and_records_the_unit() {
        let fixture = walk_fixture(
            "pub use kernel::a;\n",
            "pub use mid::a::b::Event;\n",
            "pub mod a { pub use super::b; }\npub mod b { pub use super::a; pub use crate::event::Event; }\npub mod event;\n",
        );
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let sets = consumed_sets(&workspace);
        let kernel = sets
            .get("top")
            .and_then(|rows| rows.iter().find(|row| row.0 == "kernel"))
            .unwrap_or_else(|| panic!("top consumed kernel: {sets:?}"));
        assert!(kernel.1.contains(&"module_hop"), "{kernel:?}");
        assert_eq!(
            first_hops(&workspace, "Event"),
            vec![("top".to_owned(), "mid".to_owned())]
        );
    }

    /// The kernel of the perturbation table. `top` reaches `Event` through `mid`, so kernel is a
    /// unit `top` consumes without depending on it directly. Each part of the source is the
    /// subject of a perturbation below.
    const KERNEL_BASELINE: &str = "\
pub mod event;
pub mod event2 { pub enum Event { Log } }
pub trait Marker {}
pub struct Item;
pub struct Other;
pub(crate) struct Hidden;
use event::Event;
impl Marker for Item {}
pub use event::Event as Facade;
pub fn run() -> u32 { 1 }
";

    #[test]
    fn each_child_column_a_consumer_reads_moves_the_output_and_no_dense_edit_does() {
        // (what the edit changes, the replacements it makes, whether the output must move).
        // Name-level edits change a column that a foreign reader reads; dense edits move
        // only declaration sites, byte offsets and ordinals, which no reader may depend on.
        // Reordering declarations is not a row: it moves a position-derived declaration digest in
        // the topology's binding-authority alternatives, which the output still hashes (slice report).
        type Edit = (&'static str, &'static str);
        let table: [(&str, &[Edit], bool); 11] = [
            (
                "exports.visibility (a non-public declaration)",
                &[("pub(crate) struct Hidden;", "struct Hidden;")],
                true,
            ),
            (
                "exports.name (a non-public declaration)",
                &[("pub(crate) struct Hidden;", "pub(crate) struct Hidden2;")],
                true,
            ),
            (
                "container_attributes.module_path (module presence)",
                &[("pub struct Other;", "pub struct Other;\nmod ghost {}")],
                true,
            ),
            (
                "exports.target_module_path (a facade retargeted to an equal name)",
                &[(
                    "pub use event::Event as Facade;",
                    "pub use event2::Event as Facade;",
                )],
                true,
            ),
            (
                "effective_bindings.visibility_kind",
                &[("use event::Event;", "pub(crate) use event::Event;")],
                true,
            ),
            (
                "effective_bindings.name",
                &[("use event::Event;", "use event::Event as Evt;")],
                true,
            ),
            (
                "trait_endpoints.target_identity_id (an impl moved to another subject)",
                &[("impl Marker for Item {}", "impl Marker for Other {}")],
                true,
            ),
            (
                "effective_bindings.target_module_path (a private import retargeted to an equal name)",
                &[("use event::Event;", "use event2::Event;")],
                true,
            ),
            (
                "trait_endpoints (a second impl)",
                &[(
                    "impl Marker for Item {}",
                    "impl Marker for Item {}\nimpl Marker for Other {}",
                )],
                true,
            ),
            (
                "dense: a body edit",
                &[("pub fn run() -> u32 { 1 }", "pub fn run() -> u32 { 2 + 3 }")],
                false,
            ),
            (
                "dense: comment lines move every site and byte offset",
                &[("pub mod event;\n", "// moved\n// moved\npub mod event;\n")],
                false,
            ),
        ];
        let mut failures = Vec::new();
        for (column, edits, moves) in table {
            let mut to = KERNEL_BASELINE.to_owned();
            for (from, replacement) in edits {
                assert!(to.contains(from), "{column}: {from:?} is in the kernel");
                to = to.replacen(from, replacement, 1);
            }
            let fixture = walk_fixture(
                "pub use kernel::event;\n",
                "pub use mid::event::Event;\n",
                KERNEL_BASELINE,
            );
            let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            let consumed = consumed_sets(&workspace);
            assert!(
                consumed
                    .get("top")
                    .is_some_and(|rows| rows.iter().any(|row| row.0 == "kernel")),
                "{column}: top consumes kernel without depending on it: {consumed:?}"
            );
            let before = live_summaries(&workspace);
            let kernel = fixture.file("kernel/src/lib.rs");
            kernel.write(&to).unwrap();
            workspace = workspace.update(&BTreeSet::from([kernel]));
            let after = live_summaries(&workspace);
            let kernel_moved = before["kernel"].1 != after["kernel"].1;
            let top_derived = before["top"].0 != after["top"].0;
            if kernel_moved != moves || top_derived != moves {
                failures.push(format!(
                    "{column}: expected the output {} and top {}; kernel's output {}, top {}",
                    if moves { "to move" } else { "to stay" },
                    if moves { "derived again" } else { "reused" },
                    if kernel_moved { "moved" } else { "stayed" },
                    if top_derived {
                        "was derived again"
                    } else {
                        "was reused"
                    },
                ));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    #[hardwon(
        "#11173: removing a trait impl in a crate reached only through another crate dropped the dependent's trait endpoints incrementally"
    )]
    fn changing_the_declaring_unit_of_a_trait_impl_derives_the_dependent_summary_again() {
        // `top` implements its own trait for `mid::Item`, which `mid` re-exports by glob
        // from `kernel`, the declaring unit. `kernel` is not a direct dependency of `top`,
        // so only a recorded read keeps `top`'s endpoint honest when `kernel` changes.
        // After each edit, top's endpoints must be those of a store built from the edited
        // sources. The topology digest already hashes `mid`'s public surface, so a change of
        // `kernel` that `mid` shows re-derives `top` before its summary is read; this pins that the
        // endpoint, read by the declaring item's name, agrees with a fresh store either way.
        // The last two edits change a trait impl of `kernel` and leave `mid`'s source and
        // `kernel`'s exports alone; whether `top` is derived again is not asserted for them.
        // Removing the impl was red before the endpoint was read by name: `top` kept only its
        // trait endpoint, where a fresh store has the subject endpoints too. Likely cause (not
        // isolated): `kernel`'s file got a new blob, `top`'s topology kept the old `(blob, site)`
        // of `Item` because no public surface changed, and the content-address join found nothing.
        // (what the edit does, kernel's new source, whether top must be derived again)
        const KERNEL: &str = "pub struct Item;\npub struct Other;\n\
                              pub trait Marker { fn a(&self) {} }\nimpl Marker for Item {}\n";
        let edits = [
            (
                "renamed",
                "pub struct Renamed;\npub struct Other;\n\
                 pub trait Marker { fn a(&self) {} }\n",
                Some(true),
            ),
            (
                "removed",
                "pub struct Other;\npub trait Marker { fn a(&self) {} }\n",
                Some(true),
            ),
            (
                "made private",
                "struct Item;\npub struct Other;\n\
                 pub trait Marker { fn a(&self) {} }\nimpl Marker for Item {}\n",
                Some(true),
            ),
            (
                "moved to a submodule and re-exported",
                "mod inner { pub struct Item; }\npub use inner::Item;\npub struct Other;\n\
                 pub trait Marker { fn a(&self) {} }\nimpl Marker for Item {}\n",
                Some(true),
            ),
            (
                "a comment before it, which moves its file and site",
                "// moved\npub struct Item;\npub struct Other;\n\
                 pub trait Marker { fn a(&self) {} }\nimpl Marker for Item {}\n",
                Some(false),
            ),
            (
                "its impl removed",
                "pub struct Item;\npub struct Other;\npub trait Marker { fn a(&self) {} }\n",
                None,
            ),
            (
                "its trait's method set changed",
                "pub struct Item;\npub struct Other;\n\
                 pub trait Marker { fn a(&self) {} fn b(&self) {} }\nimpl Marker for Item {}\n",
                None,
            ),
        ];
        let top_source = "pub trait Local {}\nimpl Local for mid::Item {}\n\
                          impl mid::Marker for mid::Other {}\n";
        let endpoints = |workspace: &WorkspaceAnalyzer| -> Vec<(String, String, Option<String>)> {
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            conn.prepare(
                "SELECT endpoints.endpoint_role, endpoints.endpoint_state,
                        endpoints.target_module_path
                 FROM rust_resolution_unit_summary_trait_endpoints AS endpoints
                 JOIN resolution_unit_summary_versions AS versions
                   ON versions.summary_id = endpoints.summary_id
                  AND versions.valid_until IS NULL
                 JOIN rust_crate_versions AS crate_versions
                   ON crate_versions.crate_key = versions.unit_key
                  AND crate_versions.valid_until IS NULL
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 WHERE topology.crate_name = 'top' AND topology.target_kind = 'lib'
                 ORDER BY 1, 2, 3",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
        };
        let mut failures = Vec::new();
        for (what, edited, moves) in edits {
            let fixture = walk_fixture("pub use kernel::*;\n", top_source, KERNEL);
            let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            let before = live_summaries(&workspace);
            let before_endpoints = endpoints(&workspace);
            assert!(
                before_endpoints
                    .iter()
                    .any(|row| row.0 == "subject" && row.1 == "resolved"),
                "{what}: top's subject endpoint is resolved: {before_endpoints:?}"
            );
            let kernel = fixture.file("kernel/src/lib.rs");
            kernel.write(edited).unwrap();
            workspace = workspace.update(&BTreeSet::from([kernel]));
            let after = live_summaries(&workspace);
            let fresh = walk_fixture("pub use kernel::*;\n", top_source, edited)
                .workspace_analyzer(AnalyzerConfig::default());
            if endpoints(&workspace) != endpoints(&fresh) {
                failures.push(format!(
                    "{what}: top's endpoints {:?} differ from a fresh store's {:?}",
                    endpoints(&workspace),
                    endpoints(&fresh)
                ));
            }
            let derived_again = before["top"].0 != after["top"].0;
            if moves == Some(true) && !derived_again {
                failures.push(format!("{what}: top's summary was reused"));
            }
            if moves == Some(false) && derived_again {
                failures.push(format!("{what}: top's summary was derived again"));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    #[hardwon(
        "#11173: a transitive change that left the direct dependency's output equal left the consumer's summary reused"
    )]
    fn a_moved_transitive_output_derives_the_consumer_again_and_cuts_off_on_equal_output() {
        let fixture = vector_reexport_fixture();
        let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let before = live_summaries(&workspace);
        let core = fixture.file("lib/vector-core/src/lib.rs");
        core.write("pub mod event;\npub fn unrelated() {}\n")
            .unwrap();
        workspace = workspace.update(&BTreeSet::from([core]));
        let after = live_summaries(&workspace);
        assert_ne!(before["vector_core"].1, after["vector_core"].1);
        assert_eq!(
            before["vector_lib"].1, after["vector_lib"].1,
            "the direct dependency's output did not move"
        );
        assert_ne!(
            before["vector"].0, after["vector"].0,
            "vector recorded vector_core, whose output moved"
        );
        assert_eq!(
            before["vector"].1, after["vector"].1,
            "equal output cuts off"
        );
        let recorded: Vec<u8> = workspace
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT consumed_output_digest FROM resolution_unit_summary_consumed_units
                 WHERE summary_id = ?1",
                [after["vector"].0],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(recorded, after["vector_core"].1);
    }

    #[test]
    #[hardwon("#11904: rejected duplicate placements are not proven external endpoints")]
    fn a_half_without_a_single_declaration_is_written_as_an_unresolved_endpoint() {
        // Three impls whose halves cannot name one declaration, in three shapes: `Twin` is
        // declared by two byte-identical files that both mount as module `x` (an invalid
        // duplicate module, analyzed all the same); `mid::Item` and `mid::Marker` are
        // declared by one file that `left` and `right` both mount and `mid` globs both of.
        // The binder already rejects each as `unbound`, so the chase never reaches two
        // placements from source; the chase's own two-placement filter binds nothing for
        // the same effect and is defensive. Either way no `rust_crate_trait_impls` row
        // exists (it names two declarations), and each half must still be present in the
        // summary as an endpoint written unresolved, never absent.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"top\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [workspace]\nmembers = [\"mid\", \"left\", \"right\"]\nresolver = \"2\"\n\
                 [dependencies]\nmid = { path = \"mid\" }\n",
            )
            .file(
                "src/lib.rs",
                "#[path = \"x1.rs\"]\npub mod x;\n#[path = \"x2.rs\"]\npub mod x;\n\
                 pub struct Own;\npub trait Local {}\n\
                 impl Local for x::Twin {}\n\
                 impl Local for mid::Item {}\nimpl mid::Marker for Own {}\n",
            )
            .file("src/x1.rs", "pub struct Twin;\n")
            .file("src/x2.rs", "pub struct Twin;\n")
            .file(
                "mid/Cargo.toml",
                "[package]\nname = \"mid\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\nleft = { path = \"../left\" }\nright = { path = \"../right\" }\n",
            )
            .file(
                "mid/src/lib.rs",
                "pub use left::types::*;\npub use right::types::*;\n",
            )
            .file(
                "left/Cargo.toml",
                "[package]\nname = \"left\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "left/src/lib.rs",
                "#[path = \"../../shared/types.rs\"]\npub mod types;\n",
            )
            .file(
                "right/Cargo.toml",
                "[package]\nname = \"right\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "right/src/lib.rs",
                "#[path = \"../../shared/types.rs\"]\npub mod types;\n",
            )
            .file("shared/types.rs", "pub struct Item;\npub trait Marker {}\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().unwrap();
        store.assert_rust_summary_differential_for_test();
        let conn = store.read_conn().unwrap();
        let endpoints: BTreeSet<(String, String, String)> = conn
            .prepare(
                "SELECT endpoints.endpoint_role, endpoints.endpoint_state,
                        COALESCE(endpoints.unresolved_spelling, '') || ':'
                            || COALESCE(endpoints.unresolved_reason, '')
                 FROM rust_resolution_unit_summary_trait_endpoints AS endpoints
                 JOIN resolution_unit_summary_versions AS versions
                   ON versions.summary_id = endpoints.summary_id
                  AND versions.valid_until IS NULL
                 JOIN rust_crate_versions AS crate_versions
                   ON crate_versions.crate_key = versions.unit_key
                  AND crate_versions.valid_until IS NULL
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 WHERE topology.crate_name = 'top' AND topology.target_kind = 'lib'",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for (role, spelling) in [
            // Rejected module placements do not certify a complete duplicate-only route.
            ("subject", "Twin:unbound_incomplete"),
            // Item has competing declarations in the left and right crates.
            ("subject", "Item:ambiguous"),
            // Marker has competing trait declarations in the left and right crates.
            ("trait", "Marker:ambiguous"),
        ] {
            assert!(
                endpoints.contains(&(
                    role.to_owned(),
                    "unresolved".to_owned(),
                    spelling.to_owned()
                )),
                "the {role} half spelled {spelling} is an unresolved endpoint: {endpoints:?}"
            );
        }
    }

    #[test]
    #[hardwon(
        "#11904: impl children were reported complete beside an unresolved impl half behind an open route"
    )]
    fn impl_children_unresolved_subjects_follow_dependency_reach() {
        use crate::analyzer::{RustAnalyzer, resolve_analyzer};

        let hidden = "mod other { pub use unknown::*; } mod inner { pub use crate::other::Thing as Hidden; } use inner::*; impl Clone for Hidden { fn clone(&self) -> Self { todo!() } }";
        for (case, source, in_top, reaches, expected_complete) in [
            ("same crate hidden rename", hidden, true, false, false),
            ("unrelated crate hidden rename", hidden, false, false, true),
            (
                "closed absent subject",
                "mod closed {} impl Clone for closed::Missing {}",
                true,
                false,
                true,
            ),
            (
                "dependent ambiguous subject",
                "mod left { pub struct Item; } mod right { pub struct Item; } use left::*; use right::*; impl Clone for Item {}",
                false,
                true,
                false,
            ),
        ] {
            let dependency = if reaches {
                "top = { path = \"..\" }\n"
            } else {
                ""
            };
            let fixture = InlineTestProject::new()
                .file("Cargo.toml", "[package]\nname = \"top\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\nmembers = [\"other\"]\n[dependencies]\nunknown = { path = \"absent\" }\n")
                .file("src/lib.rs", format!("pub struct Target;\n{}", if in_top { source } else { "" }))
                .file("other/Cargo.toml", format!("[package]\nname = \"other\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nunknown = {{ path = \"../absent\" }}\n{dependency}"))
                .file("other/src/lib.rs", if in_top { "" } else { source })
                .build();
            let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            let analyzer = resolve_analyzer::<RustAnalyzer>(workspace.analyzer()).unwrap();
            let target = workspace
                .analyzer()
                .get_all_declarations()
                .into_iter()
                .find(|unit| unit.identifier() == "Target")
                .expect("fixture declares Target");
            let children = analyzer.inner.direct_children_limited(&target, 32);
            assert_eq!(children.complete, expected_complete, "{case}");
        }
    }

    #[test]
    #[hardwon(
        "#11904: an unresolved inherent impl subject left a type's children reported complete"
    )]
    fn impl_children_unresolved_inherent_subjects_are_same_crate_only() {
        use crate::analyzer::{RustAnalyzer, resolve_analyzer};

        let hidden = "mod other { pub use unknown::*; } mod inner { pub use crate::other::Thing as Hidden; } use inner::*; impl Hidden { pub fn m(&self) {} }";
        for in_top in [true, false] {
            let fixture = InlineTestProject::new()
                .file("Cargo.toml", "[package]\nname = \"top\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\nmembers = [\"other\"]\n[dependencies]\nunknown = { path = \"absent\" }\n")
                .file("src/lib.rs", format!("pub struct Target;\n{}", if in_top { hidden } else { "" }))
                .file("other/Cargo.toml", "[package]\nname = \"other\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ntop = { path = \"..\" }\nunknown = { path = \"../absent\" }\n")
                .file("other/src/lib.rs", if in_top { "" } else { hidden })
                .build();
            let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            let analyzer = resolve_analyzer::<RustAnalyzer>(workspace.analyzer()).unwrap();
            let target = workspace
                .analyzer()
                .get_all_declarations()
                .into_iter()
                .find(|unit| unit.identifier() == "Target")
                .expect("fixture declares Target");
            let children = analyzer.inner.direct_children_limited(&target, 32);
            assert_eq!(
                children.complete, !in_top,
                "inherent impl in asked crate: {in_top}"
            );
        }
    }

    #[test]
    #[hardwon("#11904: an impl half behind an open route was certified unbound_external")]
    fn unresolved_impl_halves_require_a_closed_or_sysroot_route() {
        let cases = [
            (
                "std",
                "impl std::fmt::Display for Local {}",
                "unbound_external",
            ),
            (
                "absolute std",
                "impl ::std::fmt::Display for Local {}",
                "unbound_external",
            ),
            (
                "closed shadowed std",
                "mod std { pub use missing::*; } impl std::Marker for Local {}",
                "unbound_external",
            ),
            (
                "open shadowed std",
                "mod std { pub use unknown::*; } impl std::Marker for Local {}",
                "unbound_incomplete",
            ),
            (
                "closed absence",
                "mod closed {} impl closed::Missing for Local {}",
                "unbound_external",
            ),
            (
                "dependency glob",
                "use dep::*; impl Missing for Local {}",
                "unbound_incomplete",
            ),
            (
                "hidden rename",
                "mod other { pub use unknown::*; } mod inner { pub use crate::other::Thing as Hidden; } use inner::*; impl Hidden for Local {}",
                "unbound_incomplete",
            ),
        ];
        for (case, source, expected) in cases {
            // `unknown` is declared but has no source or topology in the fixture.
            // `missing` is undeclared: the closed shadowed std is certified by
            // complete zero-candidate lookup, not by the sysroot exception.
            // The open shadowed std must retain its non-sysroot boundary.
            let fixture = InlineTestProject::new()
                .file("Cargo.toml", "[package]\nname = \"top\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\nmembers = [\"dep\"]\n[dependencies]\ndep = { path = \"dep\" }\nunknown = { path = \"absent\" }\n")
                .file("src/lib.rs", format!("pub struct Local;\n{source}\n"))
                .file("dep/Cargo.toml", "[package]\nname = \"dep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nunknown = { path = \"../absent\" }\n")
                .file("dep/src/lib.rs", "pub use unknown::*;\n")
                .build();
            let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            let endpoints: Vec<(String, String, String)> = conn
                .prepare(
                    "SELECT endpoints.endpoint_state,
                            COALESCE(endpoints.unresolved_spelling, ''),
                            COALESCE(endpoints.unresolved_reason, '')
                     FROM rust_resolution_unit_summary_trait_endpoints AS endpoints
                     JOIN resolution_unit_summary_versions AS versions
                       ON versions.summary_id = endpoints.summary_id
                      AND versions.valid_until IS NULL
                     JOIN rust_crate_versions AS crate_versions
                       ON crate_versions.crate_key = versions.unit_key
                      AND crate_versions.valid_until IS NULL
                     JOIN rust_crate_topologies AS topology USING(topology_id)
                     WHERE topology.crate_name = 'top' AND topology.target_kind = 'lib'
                       AND endpoints.endpoint_role = 'trait'",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(endpoints.len(), 1, "{case}: {endpoints:?}");
            assert_eq!(endpoints[0].0, "unresolved", "{case}: {endpoints:?}");
            assert_eq!(endpoints[0].2, expected, "{case}: {endpoints:?}");
        }
    }

    /// The recorded consumed set and the first-hop ordinals of a consumer that
    /// reaches one declaration through two direct dependencies, rendered.
    fn two_route_consumed_set() -> String {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"top\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [workspace]\nmembers = [\"mid-a\", \"mid-b\", \"mid-c\", \"core\"]\nresolver = \"2\"\n\
                 [dependencies]\nmid-a = { path = \"mid-a\" }\nmid-b = { path = \"mid-b\" }\nmid-c = { path = \"mid-c\" }\n",
            )
            .file(
                "src/lib.rs",
                "pub use mid_a::event::Event;\npub use mid_b::event::Event as EventB;\npub use mid_c::event::Event as EventC;\n",
            )
            .file("core/Cargo.toml", "[package]\nname = \"core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("core/src/lib.rs", "pub mod event;\n")
            .file("core/src/event.rs", "pub enum Event { Log }\n")
            .file("mid-a/Cargo.toml", "[package]\nname = \"mid-a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ncore = { path = \"../core\" }\n")
            .file("mid-a/src/lib.rs", "pub use core::event;\n")
            .file("mid-b/Cargo.toml", "[package]\nname = \"mid-b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ncore = { path = \"../core\" }\n")
            .file("mid-b/src/lib.rs", "pub use core::event;\n")
            .file("mid-c/Cargo.toml", "[package]\nname = \"mid-c\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\ncore = { path = \"../core\" }\n")
            .file("mid-c/src/lib.rs", "pub use core::event;\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let sets = consumed_sets(&workspace);
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let hops: Vec<(String, String, Option<i64>)> = conn
            .prepare(
                "SELECT topology.crate_name, exports.name, exports.alias_dependency_ordinal
                 FROM rust_crate_versions AS crate_versions
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN resolution_unit_summary_versions AS versions
                   ON versions.unit_key = crate_versions.crate_key AND versions.valid_until IS NULL
                 JOIN rust_resolution_unit_summary_exports AS exports
                   ON exports.summary_id = versions.summary_id
                 WHERE crate_versions.valid_until IS NULL AND topology.target_kind = 'lib'
                   AND exports.origin <> 'declaration'
                 ORDER BY topology.crate_name, exports.name",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        format!("{sets:?}\n{hops:?}")
    }

    #[test]
    #[hardwon(
        "#11173: canonical_export_target probed direct dependencies in hash-map order, so the probes made varied between runs"
    )]
    fn the_recorded_consumed_set_is_identical_in_two_fresh_processes() {
        const DUMP: &str = "BIFROST_11173_DUMP_CONSUMED_SET";
        if std::env::var_os(DUMP).is_some() {
            eprintln!("CONSUMED_SET_CHILD_RAN");
            println!("<<{}>>", two_route_consumed_set());
            return;
        }
        let run = || {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "engine_tests::rust_unit_summaries::tests::the_recorded_consumed_set_is_identical_in_two_fresh_processes",
                    "--nocapture",
                ])
                .env(DUMP, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                stderr.contains("CONSUMED_SET_CHILD_RAN"),
                "child test body did not run: {stderr}"
            );
            let start = stdout.find("<<").expect("dump start") + 2;
            let end = stdout.find(">>").expect("dump end");
            stdout[start..end].to_owned()
        };
        let first = run();
        assert!(
            first.contains("core"),
            "the consumed set names core: {first}"
        );
        assert!(
            first.contains("EventB"),
            "the re-exports published: {first}"
        );
        assert_eq!(first, run());
        assert_eq!(first, two_route_consumed_set(), "and in this process");
    }

    #[test]
    #[hardwon("#5133: local imports polluted module aliases and suppressed module glob exports")]
    fn module_native_reexport_selector_5133_keeps_local_bindings_and_restricted_exports() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"module_scope\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                r#"pub mod chosen {
    pub enum Item { First }
    pub enum ModuleHidden { First }
}
pub mod other {
    pub enum Item { Second }
    pub enum ModuleHidden { Second }
    pub enum LocalOnly { Second }
}
pub use crate::chosen as Alias;
pub use crate::chosen::*;
use crate::other::ModuleHidden;
pub(crate) use crate::chosen::Item as RestrictedNamed;
pub mod restricted {
    pub(crate) use crate::chosen::*;
}
pub fn public_local() {
    pub use crate::other as Alias;
    pub use crate::other::Item;
    pub use crate::other::*;
    pub(crate) use crate::other::LocalOnly as LocalRestricted;
}
pub fn private_local() {
    use crate::other as Alias;
    use crate::other::Item;
}
pub fn enclosing() {
    pub mod nested {
        pub use crate::chosen::Item as NestedItem;
    }
}
"#,
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(summaries.len(), 1, "complete module summary: {summaries:?}");
        let conn = workspace.store().unwrap().read_conn().unwrap();
        let summary_id = summaries["module_scope"].0;
        let rows = conn
            .prepare(
                "SELECT module_path, name, visibility, target_module_path, target_name
                 FROM rust_resolution_unit_summary_exports
                 WHERE summary_id = ?1 AND namespace = 'type'
                   AND origin IN ('reexport', 'glob_reexport')
                 ORDER BY module_path, name",
            )
            .unwrap()
            .query_map([summary_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let expected = [
            ("crate", "Alias", "public", "crate", "chosen"),
            ("crate", "Item", "public", "crate::chosen", "Item"),
            ("crate", "RestrictedNamed", "crate", "crate::chosen", "Item"),
            (
                "crate::nested",
                "NestedItem",
                "public",
                "crate::chosen",
                "Item",
            ),
            (
                "crate::restricted",
                "Item",
                "crate",
                "crate::chosen",
                "Item",
            ),
            (
                "crate::restricted",
                "ModuleHidden",
                "crate",
                "crate::chosen",
                "ModuleHidden",
            ),
        ]
        .map(|(module, name, visibility, target_module, target)| {
            (
                module.to_owned(),
                name.to_owned(),
                visibility.to_owned(),
                target_module.to_owned(),
                target.to_owned(),
            )
        });
        assert_eq!(rows, expected, "only module-native imports produce exports");
        let retained: (i64, i64) = conn
            .query_row(
                "SELECT count(*), count(DISTINCT imports.binder_scope)
                 FROM rust_resolution_unit_summary_import_routes AS imports
                 WHERE imports.summary_id = ?1 AND imports.module_path = 'crate'
                   AND imports.bound_name = 'Alias' AND imports.namespace = 'type'",
                [summary_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            retained,
            (3, 3),
            "module, public local, and private local aliases remain usable"
        );
        let gaps: Vec<(String, String)> = conn
            .prepare(
                "SELECT gap_kind, subject FROM resolution_unit_summary_gaps
                 WHERE summary_id = ?1 ORDER BY gap_kind, subject",
            )
            .unwrap()
            .query_map([summary_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            gaps.is_empty(),
            "valid local public imports are not reexport gaps: {gaps:?}"
        );
    }

    // Keep cross-store comparisons independent of database-local ids. The
    // declaration path and source site identify the same source in either store.
    fn vector_surface(workspace: &WorkspaceAnalyzer) -> Vec<(String, String, String, i64)> {
        let summary_id = live_summaries(workspace)["vector"].0;
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        select_export_endpoints(&conn);
        conn.prepare(
            "SELECT identities.spelling, exports.namespace, members.rel_path, exports.endpoint_site
             FROM test_export_endpoints AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             JOIN resolution_unit_summary_members AS members
               ON members.blob_id = exports.endpoint_blob
             WHERE exports.summary_id = ?1
             GROUP BY identities.spelling, exports.namespace, members.rel_path, exports.endpoint_site
             ORDER BY identities.spelling, exports.namespace, members.rel_path, exports.endpoint_site",
        )
        .unwrap()
        .query_map([summary_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    fn vector_topologies(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, i64> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT topology.crate_name, versions.topology_id
             FROM rust_crate_versions AS versions
             JOIN rust_crate_topologies AS topology USING(topology_id)
             WHERE versions.lang = 'rust' AND versions.valid_until IS NULL
               AND topology.target_kind = 'lib'
             ORDER BY topology.crate_name",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(|row| row.unwrap())
        .collect()
    }

    fn vector_lib_surface_digest(workspace: &WorkspaceAnalyzer) -> Vec<u8> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.query_row(
            "SELECT topologies.export_surface_digest
             FROM rust_crate_versions AS versions
             JOIN rust_crate_topologies AS topologies USING(topology_id)
             WHERE versions.lang = 'rust' AND versions.valid_until IS NULL
               AND topologies.crate_name = 'vector_lib' AND topologies.target_kind = 'lib'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn assert_vector_event_export(
        workspace: &WorkspaceAnalyzer,
        unit: &str,
        expected_path: &str,
        expected_first_hop: &str,
    ) {
        let summary_id = live_summaries(workspace)[unit].0;
        let conn = workspace.store().unwrap().read_conn().unwrap();
        select_export_endpoints(&conn);
        let rows = conn
            .prepare(
                "SELECT DISTINCT identities.spelling, exports.namespace, exports.origin,
                        exports.visibility, members.rel_path,
                        exports.alias_dependency_ordinal, names.extern_name,
                        summaries.complete, summaries.publication_state
                 FROM test_export_endpoints AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 JOIN resolution_unit_summaries AS summaries USING(summary_id)
                 JOIN resolution_unit_summary_members AS members
                   ON members.blob_id = exports.endpoint_blob
                 LEFT JOIN rust_unit_summary_dependency_names AS names
                   ON names.summary_id = exports.summary_id
                  AND names.dependency_ordinal = exports.alias_dependency_ordinal
                 WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                 ORDER BY exports.namespace",
            )
            .unwrap()
            .query_map([summary_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, bool>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rows,
            vec![(
                "Event".to_owned(),
                "type".to_owned(),
                "reexport".to_owned(),
                "exported".to_owned(),
                expected_path.to_owned(),
                Some(0),
                Some(expected_first_hop.to_owned()),
                true,
                "complete".to_owned(),
            )],
            "{unit} retains its actual Event export with a complete header"
        );
        let gaps: Vec<(String, String)> = conn
            .prepare(
                "SELECT gap_kind, subject FROM resolution_unit_summary_gaps
                 WHERE summary_id = ?1 ORDER BY gap_kind, subject",
            )
            .unwrap()
            .query_map([summary_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        assert!(
            gaps.iter().all(|(kind, _)| kind != "unresolved_reexport"),
            "{unit} has no unresolved reexport gap: {gaps:?}"
        );
    }

    fn vector_terminal_alias_fixture() -> crate::inline_project::BuiltInlineTestProject {
        InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"vector\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [workspace]\nmembers = [\"lib/vector-lib\", \"lib/vector-core\"]\nresolver = \"2\"\n\
                 [dependencies]\nvector-lib = { path = \"lib/vector-lib\" }\n",
            )
            .file("src/lib.rs", "pub use vector_lib::Event;\n")
            .file(
                "lib/vector-lib/Cargo.toml",
                "[package]\nname = \"vector-lib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\nvector-core = { path = \"../vector-core\" }\n",
            )
            .file("lib/vector-lib/src/lib.rs", "pub use vector_core::Event;\n")
            .file(
                "lib/vector-core/Cargo.toml",
                "[package]\nname = \"vector-core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "lib/vector-core/src/lib.rs",
                "pub enum Event { Log, Metric }\nfn private_body() -> u8 { 1 }\n",
            )
            .build()
    }

    fn assert_vector_body_then_manifest_churn(
        fixture: &crate::inline_project::BuiltInlineTestProject,
        declaration_path: &str,
        body_changed_source: &str,
        manifest_path: &str,
        facade_event_path: &str,
    ) {
        let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = live_summaries(&workspace);
        let initial_topologies = vector_topologies(&workspace);
        assert_eq!(initial.len(), 3, "initial vector summaries: {initial:?}");
        assert_eq!(initial_topologies.len(), 3, "initial vector topologies");
        assert_vector_event_export(&workspace, "vector", facade_event_path, "vector_lib");
        assert_vector_matches_fresh_store(fixture, &workspace);

        let initial_blob: i64 = workspace
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT members.blob_id FROM resolution_unit_summary_exports AS exports JOIN resolution_unit_summary_members AS members ON members.summary_id=exports.summary_id AND members.member_ordinal=exports.declaration_member_ordinal
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                   AND exports.origin = 'declaration'",
                [initial["vector_core"].0],
                |row| row.get(0),
            )
            .unwrap();

        let declaration = fixture.file(declaration_path);
        declaration.write(body_changed_source).unwrap();
        workspace = workspace.update(&BTreeSet::from([declaration]));
        let after_body = live_summaries(&workspace);
        assert_eq!(
            changed_summaries(&initial, &after_body),
            BTreeSet::from(["vector_core".to_owned()]),
            "changing only the private body rederives the declaring crate"
        );
        let after_body_topologies = vector_topologies(&workspace);
        assert_eq!(
            initial_topologies["vector_lib"], after_body_topologies["vector_lib"],
            "equal published output retains the dependent facade topology"
        );
        assert_eq!(
            initial_topologies["vector"], after_body_topologies["vector"],
            "equal published output retains the consumer topology"
        );
        assert_ne!(
            initial["vector_core"].0, after_body["vector_core"].0,
            "core summary is rederived for the new declaration blob"
        );
        let after_body_blob: i64 = workspace
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT members.blob_id FROM resolution_unit_summary_exports AS exports JOIN resolution_unit_summary_members AS members ON members.summary_id=exports.summary_id AND members.member_ordinal=exports.declaration_member_ordinal
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                   AND exports.origin = 'declaration'",
                [after_body["vector_core"].0],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(
            initial_blob, after_body_blob,
            "core Event declaration blob changes"
        );
        assert_eq!(
            initial["vector_core"].1, after_body["vector_core"].1,
            "private body does not change core's published output"
        );
        assert_eq!(
            initial["vector_lib"], after_body["vector_lib"],
            "facade summary is retained across equal core output"
        );
        assert_eq!(
            initial["vector"], after_body["vector"],
            "consumer summary is retained across equal facade output"
        );
        assert_vector_event_export(&workspace, "vector", facade_event_path, "vector_lib");
        assert_vector_matches_fresh_store(fixture, &workspace);

        let manifest = fixture.file(manifest_path);
        let manifest_path = fixture.root().join(manifest_path);
        let manifest_text = std::fs::read_to_string(&manifest_path).unwrap();
        std::fs::write(&manifest_path, format!("{manifest_text}# refresh\n")).unwrap();
        workspace = workspace.update(&BTreeSet::from([manifest]));
        let after_manifest = live_summaries(&workspace);
        assert_ne!(
            after_body["vector"].0, after_manifest["vector"].0,
            "manifest raw-read refresh rederives the consumer summary"
        );
        assert_eq!(
            after_body_topologies["vector"],
            vector_topologies(&workspace)["vector"],
            "manifest refresh retains the consumer topology frame"
        );
        assert_eq!(
            after_body_blob,
            workspace
                .store()
                .unwrap()
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT members.blob_id FROM resolution_unit_summary_exports AS exports JOIN resolution_unit_summary_members AS members ON members.summary_id=exports.summary_id AND members.member_ordinal=exports.declaration_member_ordinal
                     JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                     WHERE exports.summary_id = ?1 AND identities.spelling = 'Event'
                       AND exports.origin = 'declaration'",
                    [after_manifest["vector_core"].0],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            "manifest refresh leaves the current core declaration blob intact"
        );
        assert_vector_event_export(&workspace, "vector", facade_event_path, "vector_lib");
        assert_vector_matches_fresh_store(fixture, &workspace);
    }

    #[test]
    #[hardwon("#5133: retained module exports hid declaration blob churn on manifest refresh")]
    fn vector_module_reexport_body_churn_then_manifest_refresh_matches_fresh_store() {
        let fixture = vector_reexport_fixture();
        fixture
            .file("lib/vector-core/src/event.rs")
            .write("pub enum Event { Log, Metric }\nfn private_body() -> u8 { 1 }\n")
            .unwrap();
        assert_vector_body_then_manifest_churn(
            &fixture,
            "lib/vector-core/src/event.rs",
            "pub enum Event { Log, Metric }\nfn private_body() -> u8 { 2 }\n",
            "Cargo.toml",
            "lib/vector-core/src/event.rs",
        );
    }

    #[test]
    #[hardwon("#5133: retained terminal aliases hid declaration blob churn on manifest refresh")]
    fn vector_terminal_alias_body_churn_then_manifest_refresh_matches_fresh_store() {
        let fixture = vector_terminal_alias_fixture();
        assert_vector_body_then_manifest_churn(
            &fixture,
            "lib/vector-core/src/lib.rs",
            "pub enum Event { Log, Metric }\nfn private_body() -> u8 { 2 }\n",
            "Cargo.toml",
            "lib/vector-core/src/lib.rs",
        );
    }

    fn assert_vector_consumed_live_facade(workspace: &WorkspaceAnalyzer) {
        let summaries = live_summaries(workspace);
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let consumed: Vec<u8> = conn
            .query_row(
                "SELECT dependencies.consumed_output_digest
             FROM resolution_unit_summary_dependencies AS dependencies
             JOIN resolution_unit_summaries AS facade
               ON facade.unit_key = dependencies.dependency_unit_key AND facade.summary_id = ?2
             WHERE dependencies.summary_id = ?1",
                rusqlite::params![summaries["vector"].0, summaries["vector_lib"].0],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            consumed, summaries["vector_lib"].1,
            "consumer recorded the live facade output"
        );
    }

    fn assert_vector_matches_fresh_store(
        fixture: &crate::inline_project::BuiltInlineTestProject,
        workspace: &WorkspaceAnalyzer,
    ) {
        // This constructor opens a new ephemeral store. Reconciliation against
        // the incremental store would reuse the very summary keys under test.
        let fresh = fixture.workspace_analyzer(AnalyzerConfig::default());
        assert!(!std::ptr::eq(
            workspace.store().unwrap().as_ref(),
            fresh.store().unwrap().as_ref(),
        ));
        let digests = |analyzer: &WorkspaceAnalyzer| {
            live_summaries(analyzer)
                .into_iter()
                .map(|(name, (_, digest))| (name, digest))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(
            digests(workspace),
            digests(&fresh),
            "fresh-store published outputs"
        );
        assert_eq!(
            vector_surface(workspace),
            vector_surface(&fresh),
            "fresh-store consumer exports"
        );
    }

    #[test]
    #[hardwon("#5133: withdrawing a forwarded module must republish its named downstream alias")]
    fn vector_transitive_reexport_edits_match_fresh_store_and_cut_off_equal_output() {
        let fixture = vector_reexport_fixture();
        let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let mut previous = live_summaries(&workspace);
        assert_eq!(vector_surface(&workspace).len(), 1, "initial Event export");
        assert_vector_consumed_live_facade(&workspace);
        for (path, source, expected_changed) in [
            (
                "lib/vector-core/src/lib.rs",
                "pub mod event;\nfn private_body() -> u8 { 2 }\n",
                // Adding a private declaration changes the complete own-binding
                // inventory. Refresh its direct consumer; equal facade output
                // still cuts off propagation to vector below. vector recorded
                // vector_core as read through the facade, so it derives again
                // (#11173 walk slice 2a) and republishes an equal output.
                BTreeSet::from([
                    "vector".to_owned(),
                    "vector_core".to_owned(),
                    "vector_lib".to_owned(),
                ]),
            ),
            // An unrelated child export is outside the module the facade forwards.
            (
                "lib/vector-core/src/lib.rs",
                "pub mod event;\npub fn unrelated() {}\n",
                BTreeSet::from([
                    "vector".to_owned(),
                    "vector_core".to_owned(),
                    "vector_lib".to_owned(),
                ]),
            ),
        ] {
            let file = fixture.file(path);
            file.write(source).unwrap();
            workspace = workspace.update(&BTreeSet::from([file]));
            let incremental = live_summaries(&workspace);
            assert_eq!(
                changed_summaries(&previous, &incremental),
                expected_changed,
                "{path}"
            );
            assert_eq!(
                previous["vector_lib"].1, incremental["vector_lib"].1,
                "equal facade output: {path}"
            );
            assert_eq!(
                previous["vector"].1, incremental["vector"].1,
                "equal consumer output: {path}"
            );
            assert_vector_consumed_live_facade(&workspace);
            assert_vector_matches_fresh_store(&fixture, &workspace);
            previous = incremental;
        }

        // Withdraw the module that actually supplies vector::Event, rather than
        // adding an unrelated facade name that leaves that route intact.
        let facade = fixture.file("lib/vector-lib/src/lib.rs");
        facade.write("// event is no longer forwarded\n").unwrap();
        workspace = workspace.update(&BTreeSet::from([facade.clone()]));
        let withdrawn = live_summaries(&workspace);
        assert_eq!(
            changed_summaries(&previous, &withdrawn),
            BTreeSet::from(["vector_lib".to_owned(), "vector".to_owned(),])
        );
        assert_ne!(previous["vector_lib"].1, withdrawn["vector_lib"].1);
        assert_ne!(previous["vector"].1, withdrawn["vector"].1);
        assert!(
            vector_surface(&workspace).is_empty(),
            "withdrawn Event must not survive in shared rows"
        );
        let header: (bool, String) = workspace.store().unwrap().read_conn().unwrap().query_row(
            "SELECT complete, publication_state FROM resolution_unit_summaries WHERE summary_id = ?1",
            [withdrawn["vector"].0], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(
            header,
            (false, "complete".to_owned()),
            "unresolved reexport seals an incomplete header"
        );
        assert_vector_consumed_live_facade(&workspace);
        assert_vector_matches_fresh_store(&fixture, &workspace);

        facade.write("pub use vector_core::event;\n").unwrap();
        workspace = workspace.update(&BTreeSet::from([facade]));
        let restored = live_summaries(&workspace);
        assert_eq!(
            changed_summaries(&withdrawn, &restored),
            BTreeSet::from(["vector_lib".to_owned(), "vector".to_owned(),])
        );
        assert_eq!(previous["vector_lib"].1, restored["vector_lib"].1);
        assert_eq!(previous["vector"].1, restored["vector"].1);
        assert_eq!(vector_surface(&workspace).len(), 1, "restored Event export");
        assert_vector_consumed_live_facade(&workspace);
        assert_vector_matches_fresh_store(&fixture, &workspace);
    }

    #[test]
    #[hardwon(
        "#5133: a removed descendant of a forwarded module must not leave a stale consumer export"
    )]
    fn vector_transitive_reexport_descendant_removal_withdraws_consumer() {
        let fixture = vector_reexport_fixture();
        let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let before = live_summaries(&workspace);
        let original_facade_surface_digest = vector_lib_surface_digest(&workspace);
        assert_eq!(vector_surface(&workspace).len(), 1);
        let leaf = fixture.file("lib/vector-core/src/event.rs");
        leaf.write("// Event was removed; the forwarded event module still exists\n")
            .unwrap();
        workspace = workspace.update(&BTreeSet::from([leaf]));
        let after = live_summaries(&workspace);
        // Print before assertions so a contract gap identifies the precise
        // cutoff and digests even when the stale consumer fails the test.
        eprintln!(
            "descendant removal before={before:?}, after={after:?}, consumer={:?}",
            vector_surface(&workspace)
        );
        assert_ne!(before["vector_core"].1, after["vector_core"].1);
        assert_ne!(
            before["vector_lib"].1, after["vector_lib"].1,
            "the facade publishes the forwarded module's descendant surface"
        );
        assert_ne!(
            original_facade_surface_digest,
            vector_lib_surface_digest(&workspace),
            "the facade topology digest includes the forwarded descendant surface"
        );
        assert_ne!(
            before["vector"].0, after["vector"].0,
            "consumer must republish"
        );
        assert!(
            vector_surface(&workspace).is_empty(),
            "removed Event must not survive in shared rows"
        );
        assert_vector_consumed_live_facade(&workspace);
        assert_vector_matches_fresh_store(&fixture, &workspace);

        let leaf = fixture.file("lib/vector-core/src/event.rs");
        leaf.write("pub enum Event { Log, Metric }\n").unwrap();
        workspace = workspace.update(&BTreeSet::from([leaf]));
        let restored = live_summaries(&workspace);
        assert_eq!(
            changed_summaries(&after, &restored),
            BTreeSet::from([
                "vector_core".to_owned(),
                "vector_lib".to_owned(),
                "vector".to_owned()
            ])
        );
        assert_eq!(
            original_facade_surface_digest,
            vector_lib_surface_digest(&workspace),
            "restoring the original descendant restores the facade surface digest"
        );
        assert_eq!(vector_surface(&workspace).len(), 1, "restored Event export");
        assert_vector_consumed_live_facade(&workspace);
        assert_vector_matches_fresh_store(&fixture, &workspace);
    }

    #[test]
    #[hardwon(
        "#5133: restricted tuple constructors escaped through enclosing and cross-crate reexports"
    )]
    fn restricted_tuple_constructor_is_not_exported_but_public_constructor_is() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"core\", \"facade\", \"consumer\"]\nresolver = \"2\"\n")
            .file("core/Cargo.toml", "[package]\nname = \"constructor_core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("core/src/lib.rs", "pub mod transform;\n")
            .file("core/src/transform/mod.rs", "mod outputs;\npub use outputs::{OutputBuffer, Mixed, Public, Unit, Empty, NonExhaustive};\n")
            .file("core/src/transform/outputs.rs", "pub struct OutputBuffer(pub(super) Vec<u8>);\n\
                pub struct Mixed(pub u8, pub(crate) u8, u8);\n\
                pub struct Public(pub u8);\n\
                pub struct Unit;\n\
                pub struct Empty();\n\
                #[non_exhaustive]\npub struct NonExhaustive(pub u8);\n")
            .file("facade/Cargo.toml", "[package]\nname = \"constructor_facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nconstructor_core = { path = \"../core\" }\n")
            .file("facade/src/lib.rs", "pub use constructor_core::transform;\n")
            .file("consumer/Cargo.toml", "[package]\nname = \"constructor_consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nconstructor_facade = { path = \"../facade\" }\n")
            .file("consumer/src/lib.rs", "pub use constructor_facade::transform::{OutputBuffer, Mixed, Public, Unit, Empty, NonExhaustive};\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(summaries.len(), 3, "constructor summaries: {summaries:?}");
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let expected = vec![
            ("Empty".to_owned(), "type".to_owned()),
            ("Empty".to_owned(), "value".to_owned()),
            ("Mixed".to_owned(), "type".to_owned()),
            ("NonExhaustive".to_owned(), "type".to_owned()),
            ("OutputBuffer".to_owned(), "type".to_owned()),
            ("Public".to_owned(), "type".to_owned()),
            ("Public".to_owned(), "value".to_owned()),
            ("Unit".to_owned(), "type".to_owned()),
            ("Unit".to_owned(), "value".to_owned()),
        ];
        for (name, module) in [
            ("constructor_core", "crate::transform::outputs"),
            ("constructor_core", "crate::transform"),
            ("constructor_consumer", "crate"),
        ] {
            let summary_id = summaries[name].0;
            // The topology is the differential oracle: assert the corrected
            // visibility there independently instead of accepting oracle agreement.
            for sql in [
                "SELECT name, namespace FROM rust_crate_exports AS exports
                 JOIN rust_crate_versions AS versions USING(topology_id)
                 JOIN resolution_unit_summary_versions AS summaries
                   ON summaries.workspace_id = versions.workspace_id
                  AND summaries.lang = versions.lang AND summaries.generation = versions.generation
                  AND summaries.unit_key = versions.crate_key AND summaries.valid_until IS NULL
                 WHERE summaries.summary_id = ?1 AND versions.valid_until IS NULL
                   AND exports.module_path = ?2 AND exports.visibility = 'public'
                 ORDER BY name, namespace",
                "SELECT name, namespace FROM rust_resolution_unit_summary_exports
                 WHERE summary_id = ?1 AND module_path = ?2 AND visibility = 'public'
                 ORDER BY name, namespace",
            ] {
                let rows = conn
                    .prepare(sql)
                    .unwrap()
                    .query_map(rusqlite::params![summary_id, module], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    rows, expected,
                    "{name} {module}: type survives; only legal constructors are public; query={sql}"
                );
            }
        }
        // A module facade has no copied descendant export rows. Its published
        // module must keep the core target, not flatten OutputBuffer into a value.
        let facade_route: (bool, String, String) = conn.query_row(
            "SELECT exports.target_unit_key = core.unit_key, exports.target_module_path, exports.target_name
             FROM rust_resolution_unit_summary_exports AS exports
             JOIN resolution_unit_summaries AS core ON core.summary_id = ?2
             WHERE exports.summary_id = ?1 AND exports.module_path = 'crate'
               AND exports.name = 'transform' AND exports.namespace = 'type'",
            rusqlite::params![summaries["constructor_facade"].0, summaries["constructor_core"].0],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(
            facade_route,
            (true, "crate".to_owned(), "transform".to_owned())
        );
        for name in [
            "constructor_core",
            "constructor_facade",
            "constructor_consumer",
        ] {
            let rows = conn
                .prepare(
                    "SELECT identities.spelling, exports.namespace
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 WHERE exports.summary_id = ?1 AND identities.spelling IN
                   ('OutputBuffer', 'Mixed', 'Public', 'Unit', 'Empty', 'NonExhaustive')
                 ORDER BY identities.spelling, exports.namespace",
                )
                .unwrap()
                .query_map([summaries[name].0], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let expected_rows = if name == "constructor_facade" {
                Vec::new()
            } else {
                expected.clone()
            };
            assert_eq!(
                rows, expected_rows,
                "{name}: shared public constructor projection"
            );
        }
    }

    #[test]
    #[hardwon("#5133: a tuple field attribute before pub hid a legal public constructor")]
    fn attributed_public_tuple_fields_keep_the_constructor_public() {
        let fixture = InlineTestProject::with_language(brokk_bifrost_core::analyzer::model::Language::Rust)
            .file(
                "Cargo.toml",
                "[package]\nname = \"attributed_constructor\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .file(
                "src/lib.rs",
                "#![allow(dead_code)]\n\
                 pub struct Attributed(#[allow(dead_code)] pub u8, #[allow(dead_code)] pub String);\n\
                 pub struct Mixed(#[allow(dead_code)] pub u8, #[allow(dead_code)] u8);\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(summaries.len(), 1, "fixture summaries: {summaries:?}");

        // Rust permits construction of Attributed because every tuple field is
        // public, even though each field has an attribute before its modifier.
        // Mixed remains non-constructible outside the crate because one field
        // is private.
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        select_export_endpoints(&conn);
        for sql in [
            "SELECT name, namespace FROM rust_crate_exports
             JOIN rust_crate_versions USING(topology_id)
             JOIN resolution_unit_summary_versions
               ON resolution_unit_summary_versions.workspace_id = rust_crate_versions.workspace_id
              AND resolution_unit_summary_versions.lang = rust_crate_versions.lang
              AND resolution_unit_summary_versions.generation = rust_crate_versions.generation
              AND resolution_unit_summary_versions.unit_key = rust_crate_versions.crate_key
              AND resolution_unit_summary_versions.valid_until IS NULL
             WHERE resolution_unit_summary_versions.summary_id = ?1
               AND rust_crate_versions.valid_until IS NULL
               AND rust_crate_exports.module_path = 'crate'
               AND rust_crate_exports.visibility = 'public'
               AND rust_crate_exports.name IN ('Attributed', 'Mixed')
             ORDER BY name, namespace",
            "SELECT identities.spelling, exports.namespace
             FROM rust_resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             WHERE exports.summary_id = ?1 AND exports.module_path = 'crate'
               AND exports.visibility = 'public'
               AND identities.spelling IN ('Attributed', 'Mixed')
             ORDER BY identities.spelling, exports.namespace",
            "SELECT identities.spelling, exports.namespace
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             WHERE exports.summary_id = ?1 AND exports.visibility = 'exported'
               AND identities.spelling IN ('Attributed', 'Mixed')
             ORDER BY identities.spelling, exports.namespace",
        ] {
            let rows = conn
                .prepare(sql)
                .unwrap()
                .query_map([summaries["attributed_constructor"].0], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                rows,
                vec![
                    ("Attributed".to_owned(), "type".to_owned()),
                    ("Attributed".to_owned(), "value".to_owned()),
                    ("Mixed".to_owned(), "type".to_owned()),
                ],
                "public Rust tuple constructor rows from analyzer store; query={sql}"
            );
        }
        let complete: bool = conn
            .query_row(
                "SELECT complete = 1 FROM resolution_unit_summaries WHERE summary_id = ?1",
                [summaries["attributed_constructor"].0],
                |row| row.get(0),
            )
            .unwrap();
        assert!(complete, "shared summary header must be complete");
    }

    #[test]
    #[hardwon("#5133: an earlier narrow glob route hid the same declaration's later public route")]
    fn restricted_tuple_constructor_wider_glob_route_reaches_named_downstream_alias() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers = [\"core\", \"facade\", \"consumer\"]\nresolver = \"2\"\n")
            .file("core/Cargo.toml", "[package]\nname = \"glob_core\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
            .file("core/src/lib.rs", "pub enum Item { First, Second }\n")
            .file("facade/Cargo.toml", "[package]\nname = \"glob_facade\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nglob_core = { path = \"../core\" }\n")
            .file("facade/src/lib.rs", "mod narrow { pub(crate) use glob_core::*; }\n\
                mod wide { pub use glob_core::*; }\n\
                pub mod api {\n\
                    pub(crate) use crate::narrow::*;\n\
                    pub use crate::wide::*;\n\
                }\n\
                pub use api::Item as Exported;\n")
            .file("consumer/Cargo.toml", "[package]\nname = \"glob_consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nglob_facade = { path = \"../facade\" }\n")
            .file("consumer/src/lib.rs", "pub use glob_facade::Exported as Visible;\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        select_export_endpoints(&conn);
        let rows = conn.prepare(
            "SELECT contexts.crate_name, exports.module_path, exports.name, exports.visibility
             FROM rust_resolution_unit_summary_exports AS exports
             JOIN rust_resolution_unit_summary_contexts AS contexts USING(summary_id)
             JOIN resolution_unit_summary_versions AS versions
               ON versions.summary_id = exports.summary_id AND versions.valid_until IS NULL
             WHERE (contexts.crate_name = 'glob_facade' AND
                      ((exports.module_path = 'crate::api' AND exports.name = 'Item') OR
                       (exports.module_path = 'crate' AND exports.name = 'Exported')))
                OR (contexts.crate_name = 'glob_consumer' AND exports.module_path = 'crate' AND exports.name = 'Visible')
             ORDER BY contexts.crate_name, exports.module_path, exports.name",
        ).unwrap().query_map([], |row| Ok((
            row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            rows,
            vec![
                (
                    "glob_consumer".to_owned(),
                    "crate".to_owned(),
                    "Visible".to_owned(),
                    "public".to_owned(),
                ),
                (
                    "glob_facade".to_owned(),
                    "crate".to_owned(),
                    "Exported".to_owned(),
                    "public".to_owned(),
                ),
                (
                    "glob_facade".to_owned(),
                    "crate::api".to_owned(),
                    "Item".to_owned(),
                    "public".to_owned(),
                ),
            ],
            "the later wider route must widen and reschedule the same declaration"
        );
        let shared: Vec<(String, String)> = conn.prepare(
            "SELECT contexts.crate_name, identities.spelling
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             JOIN rust_resolution_unit_summary_contexts AS contexts USING(summary_id)
             JOIN resolution_unit_summary_versions AS versions
               ON versions.summary_id = exports.summary_id AND versions.valid_until IS NULL
             WHERE identities.spelling IN ('Exported', 'Visible') ORDER BY contexts.crate_name, identities.spelling",
        ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            shared,
            vec![
                ("glob_consumer".to_owned(), "Visible".to_owned()),
                ("glob_facade".to_owned(), "Exported".to_owned())
            ]
        );
        let core_sources: Vec<String> = conn
            .prepare(
                "SELECT DISTINCT members.rel_path
             FROM test_export_endpoints AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id = ?2
              AND members.blob_id = exports.endpoint_blob
             WHERE exports.summary_id = ?1 AND identities.spelling = 'Visible'
             ORDER BY members.rel_path",
            )
            .unwrap()
            .query_map(
                rusqlite::params![summaries["glob_consumer"].0, summaries["glob_core"].0],
                |row| row.get(0),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<String>>>()
            .unwrap();
        assert_eq!(core_sources, vec!["core/src/lib.rs"]);
    }

    #[test]
    #[hardwon("#5133: a private glob candidate caused a false ambiguity with a public item")]
    fn rust_glob_export_ignores_inaccessible_private_candidate() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"glob_visibility\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "mod a { pub fn item() {} }\nmod b { fn item() {} }\npub use a::*;\npub use b::*;\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        let summary_id = summaries["glob_visibility"].0;
        let conn = workspace.store().unwrap().read_conn().unwrap();

        let shared: Vec<(String, String)> = conn
            .prepare(
                "SELECT identities.spelling, exports.namespace
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 WHERE exports.summary_id = ?1
                   AND identities.spelling = 'item' AND exports.visibility = 'exported'
                 ORDER BY identities.spelling, exports.namespace",
            )
            .unwrap()
            .query_map([summary_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(shared, vec![("item".to_owned(), "value".to_owned())]);

        let rust_root: Vec<(String, String, String)> = conn
            .prepare(
                "SELECT name, namespace, visibility
                 FROM rust_resolution_unit_summary_exports
                 WHERE summary_id = ?1 AND module_path = 'crate' AND name = 'item'
                 ORDER BY name, namespace",
            )
            .unwrap()
            .query_map([summary_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            rust_root,
            vec![("item".to_owned(), "value".to_owned(), "public".to_owned())]
        );
    }

    /// Live summary ids of every Rust target, keyed by crate name and target kind.
    fn live_target_summaries(workspace: &WorkspaceAnalyzer) -> BTreeMap<String, i64> {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let mut statement = conn
            .prepare(
                "SELECT topology.crate_name || ' [' || topology.target_kind || ']',
                        summary_versions.summary_id
                 FROM rust_crate_versions AS topology_versions
                 JOIN rust_crate_topologies AS topology USING(topology_id)
                 JOIN resolution_unit_summary_versions AS summary_versions
                   ON summary_versions.workspace_id = topology_versions.workspace_id
                  AND summary_versions.lang = topology_versions.lang
                  AND summary_versions.generation = topology_versions.generation
                  AND summary_versions.unit_key = topology_versions.crate_key
                  AND summary_versions.valid_until IS NULL
                 WHERE topology_versions.lang = 'rust'
                   AND topology_versions.valid_until IS NULL",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    #[hardwon(
        "#11822: editing one binary's main.rs re-derived every Rust unit through a content-keyed configuration read"
    )]
    fn a_target_root_body_edit_and_presence_leave_unrelated_units_unchanged() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"app\", \"other\"]\nresolver = \"2\"\n",
            )
            .file(
                "app/Cargo.toml",
                "[package]\nname = \"app_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("app/src/lib.rs", "pub fn app() -> u32 { 1 }\n")
            .file("app/src/bin/tool/main.rs", "fn main() { let _ = 1; }\n")
            .file(
                "other/Cargo.toml",
                "[package]\nname = \"other_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("other/src/lib.rs", "pub fn other() -> u32 { 1 }\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = live_target_summaries(&workspace);
        assert!(
            initial.keys().any(|name| name.starts_with("tool ")),
            "the directory-style target root is its own unit: {initial:?}"
        );

        // Target discovery retains the root as configuration; its bytes belong
        // to its own unit and its presence no longer invalidates unrelated units.
        let configuration_rows: i64 = workspace
            .store()
            .unwrap()
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM workspace_file_versions
                 WHERE input_kind = 'configuration' AND valid_until IS NULL
                   AND rel_path = 'app/src/bin/tool/main.rs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            configuration_rows, 1,
            "the target root is a configuration input"
        );

        // A full refresh recaptures configuration; `update` keeps an existing
        // target root's captured bytes, so it could not exercise the read.
        std::fs::write(
            fixture.root().join("app/src/bin/tool/main.rs"),
            "fn main() { let _ = 2; }\n",
        )
        .unwrap();
        let edited = workspace.update_all();
        let after_edit = live_target_summaries(&edited);
        let moved: BTreeSet<_> = initial
            .iter()
            .filter(|(name, id)| after_edit.get(*name) != Some(*id))
            .map(|(name, _)| name.clone())
            .collect();
        assert!(
            moved.iter().all(|name| name.starts_with("tool ")),
            "a target root's body belongs to its own unit only; moved {moved:?} of {initial:?}"
        );
        assert!(
            !moved.is_empty(),
            "the edited root's own unit derives again: {initial:?} -> {after_edit:?}"
        );

        std::fs::create_dir_all(fixture.root().join("app/src/bin/second")).unwrap();
        std::fs::write(
            fixture.root().join("app/src/bin/second/main.rs"),
            "fn main() {}\n",
        )
        .unwrap();
        let added = edited.update_all();
        let after_add = live_target_summaries(&added);
        assert_eq!(
            after_edit["other_unit [lib]"], after_add["other_unit [lib]"],
            "a new target belongs to its own inventory; unrelated inputs stay equal: {after_edit:?} -> {after_add:?}"
        );

        std::fs::remove_file(fixture.root().join("app/src/bin/second/main.rs")).unwrap();
        let removed = added.update_all();
        let after_remove = live_target_summaries(&removed);
        assert_eq!(
            after_add["other_unit [lib]"], after_remove["other_unit [lib]"],
            "removing a target leaves unrelated inputs equal: {after_add:?} -> {after_remove:?}"
        );
    }

    #[test]
    fn body_edit_stops_at_rust_output_digest_and_public_item_reaches_direct_dependents() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"base\", \"alpha\", \"beta\", \"leaf\"]\nresolver = \"2\"\n",
            )
            .file(
                "base/Cargo.toml",
                "[package]\nname = \"base_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("base/src/lib.rs", "pub fn first() -> u32 { 1 }\n")
            .file(
                "alpha/Cargo.toml",
                "[package]\nname = \"alpha_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file(
                "alpha/src/lib.rs",
                "pub use base_unit::first; pub fn alpha() -> u32 { crate::first() }\n",
            )
            .file(
                "beta/Cargo.toml",
                "[package]\nname = \"beta_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file(
                "beta/src/lib.rs",
                "pub use base_unit::first; pub fn beta() -> u32 { crate::first() }\n",
            )
            .file(
                "leaf/Cargo.toml",
                "[package]\nname = \"leaf_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nalpha_unit = { path = \"../alpha\" }\n",
            )
            .file(
                "leaf/src/lib.rs",
                "pub fn leaf() -> u32 { alpha_unit::alpha() }\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = live_summaries(&workspace);
        assert_eq!(initial.len(), 4, "live Rust summaries: {initial:?}");
        let initial_alpha_routes = summary_root_routes(&workspace, initial["alpha_unit"].0);
        let initial_beta_routes = summary_root_routes(&workspace, initial["beta_unit"].0);
        assert!(
            !initial_alpha_routes.is_empty(),
            "alpha root routes: {initial_alpha_routes:?}"
        );
        assert!(
            !initial_beta_routes.is_empty(),
            "beta root routes: {initial_beta_routes:?}"
        );

        let base_path = fixture.root().join("base/src/lib.rs");
        let body_edit = "pub fn first() -> u32 { 2 }\n";
        std::fs::write(&base_path, body_edit).unwrap();
        let body_update = workspace.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_body = live_summaries(&body_update);
        assert_eq!(
            changed_summaries(&initial, &after_body),
            BTreeSet::from(["base_unit".to_owned()]),
            "body-only edit should derive just its Rust crate"
        );
        assert_eq!(
            initial["base_unit"].1, after_body["base_unit"].1,
            "body-only edit must preserve the crate output digest"
        );
        assert_eq!(
            summary_root_routes(&body_update, after_body["alpha_unit"].0),
            initial_alpha_routes,
            "body-only target edits leave alpha's live root-route rows untouched"
        );
        assert_eq!(
            summary_root_routes(&body_update, after_body["beta_unit"].0),
            initial_beta_routes,
            "body-only target edits leave beta's live root-route rows untouched"
        );

        let public_item_edit = format!("{body_edit}pub fn second() -> u32 {{ 2 }}\n");
        std::fs::write(&base_path, public_item_edit).unwrap();
        let public_update = body_update.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_public_item = live_summaries(&public_update);
        assert_eq!(
            changed_summaries(&after_body, &after_public_item),
            BTreeSet::from([
                "alpha_unit".to_owned(),
                "base_unit".to_owned(),
                "beta_unit".to_owned(),
            ]),
            "an exported item should derive its crate and direct dependents only"
        );
        assert_eq!(
            summary_root_routes(&public_update, after_public_item["alpha_unit"].0),
            initial_alpha_routes,
            "an exported target change republishes alpha's root routes with its new summary"
        );
        assert_eq!(
            summary_root_routes(&public_update, after_public_item["beta_unit"].0),
            initial_beta_routes,
            "an exported target change republishes beta's root routes with its new summary"
        );
        assert_eq!(
            after_body["alpha_unit"].1, after_public_item["alpha_unit"].1,
            "an importing crate keeps its output digest"
        );
        assert_eq!(
            after_body["beta_unit"].1, after_public_item["beta_unit"].1,
            "an importing crate keeps its output digest"
        );
    }

    #[test]
    #[ignore = "finds real bug: the legacy topology reconcile keeps a glob-chain export after its target unit drops the name; the test-only differential reports it"]
    fn a_name_reached_through_a_glob_chain_follows_its_target_on_edit() {
        // leaf names `first` through its own glob re-export of alpha, and alpha
        // glob-re-exports base_unit. leaf's stored route is a pointer to its own
        // crate root, so the answer depends on alpha's live glob rows and on
        // base_unit's live exports. Removing `first` from base_unit must make the
        // answer unresolved, whichever summary rows are stale.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"base\", \"alpha\", \"leaf\"]\nresolver = \"2\"\n",
            )
            .file(
                "base/Cargo.toml",
                "[package]\nname = \"base_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("base/src/lib.rs", "pub fn first() -> u32 { 1 }\n")
            .file(
                "alpha/Cargo.toml",
                "[package]\nname = \"alpha_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file("alpha/src/lib.rs", "pub use base_unit::*;\n")
            .file(
                "leaf/Cargo.toml",
                "[package]\nname = \"leaf_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nalpha_unit = { path = \"../alpha\" }\n",
            )
            .file(
                "leaf/src/lib.rs",
                "pub use alpha_unit::*;\npub fn leaf() -> u32 { crate::first() }\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let status_of = |analyzer: &WorkspaceAnalyzer| {
            let result = crate::searchtools::get_definitions_by_location_with_cancellation(
                analyzer.analyzer(),
                crate::searchtools::GetDefinitionParams {
                    references: vec![crate::searchtools::DefinitionReferenceQuery {
                        path: "leaf/src/lib.rs".to_owned(),
                        line: Some(2),
                        column: Some(31),
                    }],
                },
                None,
            );
            result.results[0].status.clone()
        };
        assert_eq!(
            status_of(&workspace),
            "resolved",
            "crate::first resolves before the edit"
        );

        std::fs::write(
            fixture.root().join("base/src/lib.rs"),
            "pub fn second() -> u32 { 2 }\n",
        )
        .unwrap();
        let update = workspace.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        assert_ne!(
            status_of(&update),
            "resolved",
            "crate::first must not resolve once base_unit no longer exports first"
        );
    }

    type BindingProjection = Vec<(String, String, String, Vec<u8>, String)>;
    type ProvenanceProjection = Vec<(i64, i64, String, Vec<u8>, String)>;

    fn summary_binding_projection(
        workspace: &WorkspaceAnalyzer,
        summary_id: i64,
    ) -> BindingProjection {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT module_path, name, namespace, target_unit_key, target_name
             FROM rust_resolution_unit_summary_effective_bindings
             WHERE summary_id = ?1
             ORDER BY module_path, name, namespace, target_unit_key",
        )
        .unwrap()
        .query_map([summary_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    fn summary_provenance_projection(
        workspace: &WorkspaceAnalyzer,
        summary_id: i64,
    ) -> ProvenanceProjection {
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        conn.prepare(
            "SELECT import_ordinal, hop_ordinal, target_binding_name, target_unit_key, namespace
             FROM rust_resolution_unit_summary_import_route_provenance
             WHERE summary_id = ?1
             ORDER BY import_ordinal, hop_ordinal, target_unit_key",
        )
        .unwrap()
        .query_map([summary_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    #[test]
    #[hardwon(
        "#5780: canonical endpoints discarded distinct facade dependencies and their output digest"
    )]
    fn canonical_binding_provenance_retains_facades_and_invalidates_consumers() {
        let fixture = InlineTestProject::new()
            .file("Cargo.toml", "[workspace]\nmembers=['api','facade','consumer']\nresolver='2'\n")
            .file("api/Cargo.toml", "[package]\nname='api_unit'\nversion='0.1.0'\nedition='2024'\n")
            .file("api/src/lib.rs", "pub struct Item;\n")
            .file("facade/Cargo.toml", "[package]\nname='facade_unit'\nversion='0.1.0'\nedition='2024'\n[dependencies]\napi_unit={path='../api'}\n")
            .file("facade/src/lib.rs", "pub mod one { pub use api_unit::Item as Alias; } pub mod two { pub use api_unit::Item as Alias; }\n")
            .file("consumer/Cargo.toml", "[package]\nname='consumer_unit'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nfacade_unit={path='../facade'}\n")
            .file("consumer/src/lib.rs", "pub use facade_unit::one::Alias as First; pub use facade_unit::two::Alias as Second;\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let before = live_summaries(&workspace);
        {
            let conn = workspace.store().unwrap().read_conn().unwrap();
            let providers: Vec<(String, String, String)> = conn
                .prepare(
                    "SELECT DISTINCT p.bound_name,p.provider_module_path,p.target_name
                 FROM rust_crate_binding_provenance p
                 JOIN rust_crate_topologies t USING(topology_id)
                 JOIN rust_crate_versions v USING(topology_id)
                 WHERE t.crate_name='consumer_unit' AND v.valid_until IS NULL
                 ORDER BY 1,2,3",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(
                providers,
                vec![
                    ("First".into(), "crate::one".into(), "Item".into()),
                    ("Second".into(), "crate::two".into(), "Item".into())
                ]
            );
        }
        // Same canonical exports, different admitted first-hop dependencies.
        // A dependent reads that provenance, so the output digest must move.
        std::fs::write(fixture.root().join("facade/src/lib.rs"),
            "pub mod one { pub use crate::two::Alias; } pub mod two { pub use api_unit::Item as Alias; }\n").unwrap();
        let changed = workspace.update(&BTreeSet::from([fixture.file("facade/src/lib.rs")]));
        let after = live_summaries(&changed);
        assert_ne!(
            before["facade_unit"].1, after["facade_unit"].1,
            "dependency-visible provenance belongs in the output digest"
        );
        assert_ne!(
            before["consumer_unit"].0, after["consumer_unit"].0,
            "consumer must record the changed facade output"
        );
        std::fs::write(
            fixture.root().join("facade/src/lib.rs"),
            "pub mod one {} pub mod two { pub use api_unit::Item as Alias; }\n",
        )
        .unwrap();
        let removed = changed.update(&BTreeSet::from([fixture.file("facade/src/lib.rs")]));
        let conn = removed.store().unwrap().read_conn().unwrap();
        let first: i64 = conn
            .query_row(
                "SELECT count(*) FROM rust_crate_binding_provenance p
             JOIN rust_crate_topologies t USING(topology_id)
             JOIN rust_crate_versions v USING(topology_id)
             WHERE t.crate_name='consumer_unit' AND v.valid_until IS NULL AND p.bound_name='First'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            first, 0,
            "removing one facade cannot reuse its former canonical endpoint"
        );
    }

    #[test]
    fn target_export_republishes_importer_binding_rows_and_body_edit_does_not() {
        // `alpha` re-exports `base_unit::first`, so its effective bindings and
        // import-route provenance depend on base's binding closure. A body-only
        // edit in base leaves that closure unchanged; a new public item changes
        // base's summary, so alpha must republish under its new summary id with
        // the same binding rows.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"base\", \"alpha\"]\nresolver = \"2\"\n",
            )
            .file(
                "base/Cargo.toml",
                "[package]\nname = \"base_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file("base/src/lib.rs", "pub fn first() -> u32 { 1 }\n")
            .file(
                "alpha/Cargo.toml",
                "[package]\nname = \"alpha_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nbase_unit = { path = \"../base\" }\n",
            )
            .file(
                "alpha/src/lib.rs",
                "pub use base_unit::first; pub fn alpha() -> u32 { crate::first() }\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = live_summaries(&workspace);
        let alpha_id = initial["alpha_unit"].0;
        let initial_bindings = summary_binding_projection(&workspace, alpha_id);
        let initial_provenance = summary_provenance_projection(&workspace, alpha_id);
        assert!(
            initial_bindings.iter().any(|row| row.1 == "first"),
            "alpha effective bindings must carry the re-exported target: {initial_bindings:?}"
        );
        assert!(
            !initial_provenance.is_empty(),
            "alpha import-route provenance must cite the re-exported import"
        );

        let base_path = fixture.root().join("base/src/lib.rs");
        std::fs::write(&base_path, "pub fn first() -> u32 { 2 }\n").unwrap();
        let body_update = workspace.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_body = live_summaries(&body_update);
        assert_eq!(
            after_body["alpha_unit"].0, alpha_id,
            "a body-only target edit must not republish alpha"
        );
        assert_eq!(
            summary_binding_projection(&body_update, alpha_id),
            initial_bindings,
            "a body-only target edit must leave alpha's effective bindings unchanged"
        );
        assert_eq!(
            summary_provenance_projection(&body_update, alpha_id),
            initial_provenance,
            "a body-only target edit must leave alpha's import-route provenance unchanged"
        );

        std::fs::write(
            &base_path,
            "pub fn first() -> u32 { 2 }\npub fn second() -> u32 { 2 }\n",
        )
        .unwrap();
        let export_update = body_update.update(&BTreeSet::from([fixture.file("base/src/lib.rs")]));
        let after_export = live_summaries(&export_update);
        let republished_id = after_export["alpha_unit"].0;
        assert_ne!(
            republished_id, alpha_id,
            "an exported target change must republish alpha under a new summary"
        );
        assert_eq!(
            summary_binding_projection(&export_update, republished_id),
            initial_bindings,
            "an exported target change must republish alpha's effective bindings with the same rows"
        );
        assert_eq!(
            summary_provenance_projection(&export_update, republished_id),
            initial_provenance,
            "an exported target change must republish alpha's import-route provenance with the same rows"
        );
    }

    #[test]
    #[hardwon(
        "73413900c759: a private import of a name its target binds twice failed the provenance insert and aborted the crate's summary pass"
    )]
    fn private_import_of_a_twice_bound_name_deduplicates_the_endpoint() {
        // `mod agent` reaches `select` through an explicit public re-export
        // and through a crate-visible glob that the explicit one shadows.
        // #5780 admits the named binding before flattening the glob, so one
        // canonical endpoint reaches each source import without duplicate proof
        // rows. The original summary-insert crash must remain impossible.
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"shadow\"]\nresolver = \"2\"\n",
            )
            .file(
                "shadow/Cargo.toml",
                "[package]\nname = \"shadow_unit\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "shadow/src/lib.rs",
                "mod inner { pub fn select() -> u32 { 1 } }\n\
                 mod agent {\n\
                     pub(crate) use crate::inner::*;\n\
                     pub use crate::inner::select;\n\
                 }\n\
                 mod user {\n\
                     use crate::agent::select;\n\
                     pub fn run() -> u32 { select() }\n\
                 }\n",
            )
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        let summary_id = summaries
            .get("shadow_unit")
            .expect("a double-bound private import must not abort the crate's summary pass")
            .0;
        let provenance = summary_provenance_projection(&workspace, summary_id);
        let mut rows_per_import = std::collections::BTreeMap::<i64, usize>::new();
        for row in &provenance {
            *rows_per_import.entry(row.0).or_default() += 1;
        }
        assert!(
            !rows_per_import.is_empty() && rows_per_import.values().all(|count| *count == 1),
            "each import keeps one row for the canonical endpoint: {provenance:?}"
        );
    }

    #[test]
    #[hardwon(
        "d04c9b381fde: a dev-dependency cycle ordered a consumer before its provider and left its trait endpoint unnamed"
    )]
    fn dev_dependency_cycle_does_not_leave_a_consumers_trait_endpoint_open() {
        // `cycle_a` depends on `cycle_b` and `cycle_b` dev-depends on `cycle_a`,
        // as Vector's vector-config and vector-config-macros do. Every chain
        // crate depends on the next one and the last on `cycle_a`, so the chain
        // consumes the cycle. A dev-dependency is an input of the test targets,
        // not of the library, so it must not order the library units; otherwise
        // the whole chain lands in the unordered remainder, and a crate can be
        // derived before the crate whose trait it implements.
        const CHAIN: usize = 8;
        let mut members = vec!["\"cycle_a\"".to_owned(), "\"cycle_b\"".to_owned()];
        members.extend((0..CHAIN).map(|index| format!("\"chain_{index}\"")));
        let mut fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                format!(
                    "[workspace]\nmembers = [{}]\nresolver = \"2\"\n",
                    members.join(", ")
                ),
            )
            .file(
                "cycle_a/Cargo.toml",
                "[package]\nname = \"cycle_a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\ncycle_b = { path = \"../cycle_b\" }\n",
            )
            .file("cycle_a/src/lib.rs", "pub fn a() {}\n")
            .file(
                "cycle_b/Cargo.toml",
                "[package]\nname = \"cycle_b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dev-dependencies]\ncycle_a = { path = \"../cycle_a\" }\n",
            )
            .file("cycle_b/src/lib.rs", "pub fn b() {}\n");
        for index in 0..CHAIN {
            let next = if index + 1 < CHAIN {
                format!("chain_{}", index + 1)
            } else {
                "cycle_a".to_owned()
            };
            let source = if index + 1 < CHAIN {
                format!(
                    "pub trait Tr{index} {{}}\npub struct S{index};\nimpl {next}::Tr{next_index} for S{index} {{}}\n",
                    next_index = index + 1
                )
            } else {
                format!("pub trait Tr{index} {{}}\n")
            };
            fixture = fixture
                .file(
                    format!("chain_{index}/Cargo.toml"),
                    format!(
                        "[package]\nname = \"chain_{index}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                         [dependencies]\n{next} = {{ path = \"../{next}\" }}\n"
                    ),
                )
                .file(format!("chain_{index}/src/lib.rs"), source);
        }
        let fixture = fixture.build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let summaries = live_summaries(&workspace);
        assert_eq!(
            summaries.len(),
            CHAIN + 2,
            "every unit publishes a summary: {:?}",
            summaries.keys().collect::<Vec<_>>()
        );
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let live_endpoints = |state: &str| -> Vec<(String, String)> {
            conn.prepare(
                "SELECT summaries.summary_id, endpoints.endpoint_role
                 FROM rust_resolution_unit_summary_trait_endpoints AS endpoints
                 JOIN resolution_unit_summary_versions AS versions
                   ON versions.summary_id = endpoints.summary_id AND versions.valid_until IS NULL
                 JOIN resolution_unit_summaries AS summaries
                   ON summaries.summary_id = versions.summary_id
                 WHERE endpoints.endpoint_state = ?1
                 ORDER BY summaries.summary_id, endpoints.endpoint_role",
            )
            .unwrap()
            .query_map([state], |row| {
                Ok((row.get::<_, i64>(0)?.to_string(), row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        };
        let resolved = live_endpoints("resolved");
        let unresolved = live_endpoints("unresolved");
        assert_eq!(
            resolved.len(),
            2 * (CHAIN - 1),
            "every chain impl names its subject and its trait: {resolved:?}"
        );
        assert!(
            unresolved.is_empty(),
            "no consumer was derived before its provider: {unresolved:?}"
        );
        let unavailable: Vec<(String, String)> = conn
            .prepare(
                "SELECT gaps.gap_kind, gaps.subject
                 FROM resolution_unit_summary_gaps AS gaps
                 JOIN resolution_unit_summary_versions AS versions
                   ON versions.summary_id = gaps.summary_id AND versions.valid_until IS NULL
                 WHERE gaps.gap_kind = 'unit_summary_unavailable'",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            unavailable.is_empty(),
            "a dev-dependency derived later is consumed once it exists: {unavailable:?}"
        );
    }

    /// The integration test target `t` of `cycle_b` re-exports from `cycle_a`, which `cycle_b`
    /// dev-depends on and which depends on `cycle_b`. Its closure-binding read of
    /// `cycle_a` crosses a dev-dependency edge, which does not order the units, so
    /// the read can find `cycle_a` unsettled and is retried once it settles
    /// (#11173 D6c). The closure read skips the dependency-witness check, so that
    /// retry keeps the summary correct: after `cycle_a`'s output moves, the
    /// incremental store holds what a fresh store derives.
    #[test]
    fn a_closure_binding_read_across_a_dev_dependency_converges_to_the_fresh_store() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers = [\"cycle_a\", \"cycle_b\"]\nresolver = \"2\"\n",
            )
            .file(
                "cycle_a/Cargo.toml",
                "[package]\nname = \"cycle_a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dependencies]\ncycle_b = { path = \"../cycle_b\" }\n",
            )
            .file("cycle_a/src/lib.rs", "pub fn a() {}\n")
            .file(
                "cycle_b/Cargo.toml",
                "[package]\nname = \"cycle_b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                 [dev-dependencies]\ncycle_a = { path = \"../cycle_a\" }\n",
            )
            .file("cycle_b/src/lib.rs", "pub fn b() {}\n")
            .file("cycle_b/tests/t.rs", "pub use cycle_a::a;\n")
            .build();
        // Every live summary, by crate and target kind: (output digest, the
        // dependency outputs it recorded, its effective bindings).
        type Published = BTreeMap<(String, String), (Vec<u8>, Vec<Vec<u8>>, BindingProjection)>;
        let state = |workspace: &WorkspaceAnalyzer| -> Published {
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            let rows: Vec<(String, String, i64, Vec<u8>)> = conn
                .prepare(
                    "SELECT topology.crate_name, topology.target_kind, summaries.summary_id,
                            summaries.output_digest
                     FROM rust_crate_versions AS crate_versions
                     JOIN rust_crate_topologies AS topology USING(topology_id)
                     JOIN resolution_unit_summary_versions AS versions
                       ON versions.unit_key = crate_versions.crate_key AND versions.valid_until IS NULL
                     JOIN resolution_unit_summaries AS summaries
                       ON summaries.summary_id = versions.summary_id
                     WHERE crate_versions.valid_until IS NULL
                       AND summaries.publication_state = 'complete'",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            rows.into_iter()
                .map(|(name, kind, summary_id, output)| {
                    let mut recorded: Vec<Vec<u8>> = conn
                        .prepare(
                            "SELECT consumed_output_digest
                             FROM resolution_unit_summary_dependencies WHERE summary_id = ?1",
                        )
                        .unwrap()
                        .query_map([summary_id], |row| row.get(0))
                        .unwrap()
                        .collect::<rusqlite::Result<_>>()
                        .unwrap();
                    recorded.sort();
                    let bindings = summary_binding_projection(workspace, summary_id);
                    ((name, kind), (output, recorded, bindings))
                })
                .collect()
        };
        let mut workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let initial = state(&workspace);
        let test_target = ("t".to_owned(), "test".to_owned());
        let lib = ("cycle_a".to_owned(), "lib".to_owned());
        assert!(initial.contains_key(&test_target), "{:?}", initial.keys());
        assert!(
            initial[&test_target]
                .2
                .iter()
                .any(|binding| binding.1 == "a"),
            "the test target binds the re-exported name: {:?}",
            initial[&test_target].2
        );

        let file = fixture.file("cycle_a/src/lib.rs");
        file.write("pub fn a() {}\npub fn extra() {}\n").unwrap();
        workspace = workspace.update(&BTreeSet::from([file]));
        let incremental = state(&workspace);
        assert_ne!(initial[&lib].0, incremental[&lib].0, "cycle_a output moved");
        assert!(
            incremental[&test_target].1.contains(&incremental[&lib].0),
            "the test target recorded cycle_a's final output: {:?}",
            incremental[&test_target].1
        );
        let fresh = state(&fixture.workspace_analyzer(AnalyzerConfig::default()));
        assert_eq!(incremental, fresh, "incremental equals a fresh store");
    }

    #[test]
    fn impl_children_of_one_same_named_type_among_many_units_are_its_own() {
        // Twelve crates each declare `Widget`, with an inherent and a trait impl in another file. The
        // children of one crate's `Widget` are that crate's impl members only: the
        // reader finds impls by the declaration they name, not by the type's spelling.
        use brokk_bifrost_core::analyzer::model::CodeUnitType;

        const CRATES: usize = 12;
        let members = (0..CRATES)
            .map(|index| format!("\"unit_{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut fixture = InlineTestProject::new().file(
            "Cargo.toml",
            format!("[workspace]\nmembers = [{members}]\nresolver = \"2\"\n"),
        );
        for index in 0..CRATES {
            fixture = fixture
                .file(
                    format!("unit_{index}/Cargo.toml"),
                    format!(
                        "[package]\nname = \"unit_{index}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    ),
                )
                .file(
                    format!("unit_{index}/src/lib.rs"),
                    "pub struct Widget;\npub trait Tr { fn t(&self); }\nmod impls;\n",
                )
                // The impls are in a second file, so their members are cross-file children.
                .file(
                    format!("unit_{index}/src/impls.rs"),
                    format!(
                        "use crate::{{Tr, Widget}};\n\
                         impl Widget {{ pub fn inherent_{index}() {{}} }}\n\
                         impl Tr for Widget {{ fn t(&self) {{}} fn trait_{index}(&self) {{}} }}\n"
                    ),
                );
        }
        let fixture = fixture.build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        let analyzer = workspace.analyzer();
        let widgets = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class && unit.identifier() == "Widget")
            .collect::<Vec<_>>();
        assert_eq!(widgets.len(), CRATES, "{widgets:?}");
        for widget in widgets {
            let path = brokk_bifrost_core::path_utils::workspace_relative_slash_path(
                widget.source().rel_path(),
            );
            let index: usize = path
                .strip_prefix("unit_")
                .and_then(|rest| rest.split('/').next())
                .and_then(|number| number.parse().ok())
                .expect("fixture crate path");
            let mut names = analyzer
                .direct_children(&widget)
                .into_iter()
                .filter(|child| child.is_function())
                .map(|child| child.identifier().to_owned())
                .collect::<Vec<_>>();
            names.sort();
            let mut expected = vec![
                format!("inherent_{index}"),
                format!("trait_{index}"),
                "t".to_owned(),
            ];
            expected.sort();
            assert_eq!(names, expected, "{path}");
        }
    }

    /// The children `Widget` gets from its impls, and whether they are complete.
    fn widget_children(workspace: &WorkspaceAnalyzer) -> (bool, Vec<String>) {
        use crate::analyzer::{RustAnalyzer, resolve_analyzer};
        use brokk_bifrost_core::analyzer::model::CodeUnitType;

        let analyzer = resolve_analyzer::<RustAnalyzer>(workspace.analyzer()).unwrap();
        let widget = workspace
            .analyzer()
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.kind() == CodeUnitType::Class && unit.identifier() == "Widget")
            .expect("fixture declares Widget");
        let children = analyzer.inner.direct_children_limited(&widget, 32);
        let mut names = children
            .rows
            .iter()
            .filter(|unit| unit.is_function())
            .map(|unit| unit.identifier().to_owned())
            .collect::<Vec<_>>();
        names.sort();
        (children.complete, names)
    }

    /// A one-crate project whose `Widget` is declared in `lib.rs` and impl'd in `impls.rs`.
    fn widget_workspace(
        impls: &str,
    ) -> (
        brokk_bifrost_analysis::inline_project::BuiltInlineTestProject,
        WorkspaceAnalyzer,
    ) {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            )
            .file(
                "src/lib.rs",
                "pub struct Widget;\npub trait Tr {}\nmod impls;\n",
            )
            .file("src/impls.rs", impls)
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        (project, workspace)
    }

    #[test]
    #[hardwon(
        "#11904: members of a trait impl whose trait is unresolved were missing from the subject's children"
    )]
    fn impl_children_unresolved_traits_keep_subject_members() {
        use crate::analyzer::{RustAnalyzer, resolve_analyzer};

        for (source, member) in [
            (
                "impl std::fmt::Display for D { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { todo!() } }",
                "fmt",
            ),
            ("use unknown::*; impl Missing for D { fn m(&self) {} }", "m"),
        ] {
            let project = InlineTestProject::new()
                .file("Cargo.toml", "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nunknown = { path = \"absent\" }\n")
                .file("src/lib.rs", "pub struct D; mod impls;")
                .file("src/impls.rs", format!("use crate::D; {source}"))
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let analyzer = resolve_analyzer::<RustAnalyzer>(workspace.analyzer()).unwrap();
            let owner = workspace
                .analyzer()
                .get_all_declarations()
                .into_iter()
                .find(|unit| unit.identifier() == "D")
                .unwrap();
            let children = analyzer.inner.direct_children_limited(&owner, 32);
            let names = children
                .rows
                .iter()
                .filter(|unit| unit.is_function())
                .map(|unit| unit.identifier().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(names, vec![member.to_owned()], "{source}");
            assert!(children.complete, "{source}");
        }
    }

    fn rewrite_summary_rows(workspace: &WorkspaceAnalyzer, sql: &'static str) {
        workspace
            .store()
            .unwrap()
            .conn
            .execute(move |conn| {
                let _fixture =
                    brokk_bifrost_analysis::analyzer::store::sealed_families::Fixture::new(conn);
                conn.execute_batch(sql)?;
                Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
            .expect("rewrite published summary rows");
    }

    #[test]
    #[hardwon(
        "#11173: an impl the summary cannot attribute to its owner left an empty Complete child list"
    )]
    fn impl_children_are_incomplete_when_an_impl_cannot_be_attributed_to_the_owner() {
        // The impls are in a second file: members in the owner's own file are file-state
        // children and never reach the summaries.
        let resolved = "use crate::{Tr, Widget};\nimpl Tr for Widget { fn known() {} }\n";
        // Control: every impl resolves, so the children are complete.
        let (_project, workspace) = widget_workspace(resolved);
        assert_eq!(
            widget_children(&workspace),
            (true, vec!["known".to_owned()])
        );

        // A trait no route binds (std or another external trait) is not a gap: no
        // workspace declaration exists for it. Its members belong to the resolved subject.
        let (_project, workspace) = widget_workspace(&format!(
            "{resolved}impl Clone for Widget {{ fn clone(&self) -> Self {{ Widget }} }}\n"
        ));
        assert_eq!(
            widget_children(&workspace),
            (true, vec!["clone".to_owned(), "known".to_owned()])
        );

        // A trait a route bound but the summary could not name: its impl's members
        // are still listed through the resolved subject.
        let (_project, workspace) = widget_workspace(resolved);
        rewrite_summary_rows(
            &workspace,
            "UPDATE rust_resolution_unit_summary_trait_endpoints
             SET endpoint_state='unresolved', target_unit_key=NULL, target_identity_id=NULL,
                 local_target_member_ordinal=NULL, dependency_ordinal=NULL,
                 unresolved_spelling='Tr', unresolved_reason='bound_without_declaration'
             WHERE endpoint_role='trait'",
        );
        let (complete, names) = widget_children(&workspace);
        assert!(
            complete,
            "an unnamed trait endpoint does not hide children: {names:?}"
        );
        assert_eq!(names, vec!["known".to_owned()]);

        // The subject endpoint the summary could not name, as a unit derived on a
        // dependency cycle leaves it: unresolved, with only its spelling.
        let (_project, workspace) = widget_workspace(resolved);
        rewrite_summary_rows(
            &workspace,
            "UPDATE rust_resolution_unit_summary_trait_endpoints
             SET endpoint_state='unresolved', target_unit_key=NULL, target_identity_id=NULL,
                 local_target_member_ordinal=NULL, dependency_ordinal=NULL,
                 unresolved_spelling='Widget', unresolved_reason='bound_without_declaration'
             WHERE endpoint_role='subject'",
        );
        let (complete, names) = widget_children(&workspace);
        assert!(
            !complete,
            "an unnamed subject endpoint hides children: {names:?}"
        );
        assert!(names.is_empty(), "{names:?}");
    }

    #[test]
    #[hardwon("#11173: an aliased bound subject silently lost impl children on a dependency cycle")]
    fn impl_children_alias_bound_without_declaration_is_incomplete() {
        let (_project, workspace) = widget_workspace(
            "use crate::{Tr, Widget as Alias};\nimpl Tr for Alias { fn made() {} }\n",
        );
        assert_eq!(widget_children(&workspace), (true, vec!["made".to_owned()]));
        // Reuse D2's dependency-cycle mirror shape: the provider had no live
        // summary when the consumer was derived. The seek name is the target,
        // while the source relation still spells Alias.
        rewrite_summary_rows(
            &workspace,
            "UPDATE rust_resolution_unit_summary_trait_endpoints
             SET endpoint_state='unresolved', target_unit_key=NULL, target_identity_id=NULL,
                 local_target_member_ordinal=NULL, dependency_ordinal=NULL,
                 unresolved_spelling='Widget', unresolved_reason='bound_without_declaration'
             WHERE endpoint_role='subject'",
        );
        let (complete, names) = widget_children(&workspace);
        assert!(!complete, "{names:?}");
        assert!(names.is_empty(), "{names:?}");
    }

    #[test]
    #[hardwon("#11173: cfg alternative subjects each received the same trait impl as Complete")]
    fn impl_children_of_an_ambiguous_trait_subject_are_incomplete() {
        let (_project, workspace) =
            widget_workspace("use crate::{Tr, Widget};\nimpl Tr for Widget { fn made() {} }\n");
        assert_eq!(widget_children(&workspace), (true, vec!["made".to_owned()]));
        // Two declaration exports carry the subject's name (cfg alternatives
        // in one module): its identity is per spelling, so the trait impl
        // cannot be attributed to either declaration.
        rewrite_summary_rows(
            &workspace,
            "INSERT INTO rust_resolution_unit_summary_exports
             SELECT summary_id, module_path, namespace, name, identity_id, visibility,
                    restricted_module_path, origin, declaration_member_ordinal,
                    declaration_site + 1000, alias_dependency_ordinal, target_unit_key,
                    alias_identity_id, target_module_path, target_name
             FROM rust_resolution_unit_summary_exports
             WHERE name='Widget' AND origin='declaration';",
        );
        let (complete, names) = widget_children(&workspace);
        assert!(
            !complete,
            "an ambiguous trait subject must be incomplete: {names:?}"
        );
        assert!(names.is_empty(), "{names:?}");
    }

    #[test]
    fn a_foreign_inherent_subject_resolves_only_through_exactly_one_export() {
        let (_project, workspace) =
            widget_workspace("use crate::Widget;\nimpl Widget { fn made() {} }\n");
        assert_eq!(widget_children(&workspace), (true, vec!["made".to_owned()]));

        // One export carries the name form: the impl is attributed to it.
        rewrite_summary_rows(
            &workspace,
            "UPDATE rust_resolution_unit_summary_inherent_impls
             SET subject_form='foreign', subject_member_ordinal=NULL, subject_site=NULL,
                 subject_unit_key=(SELECT unit_key FROM resolution_unit_summaries
                                   WHERE summary_id=rust_resolution_unit_summary_inherent_impls.summary_id),
                 subject_module_path='crate', subject_kind='declaration', subject_namespace='type',
                 subject_name='Widget', subject_origin='declaration';",
        );
        assert_eq!(widget_children(&workspace), (true, vec!["made".to_owned()]));

        // Two exports carry it (cfg alternatives): neither can claim the impl.
        rewrite_summary_rows(
            &workspace,
            "INSERT INTO rust_resolution_unit_summary_exports
             SELECT summary_id, module_path, namespace, name, identity_id, visibility,
                    restricted_module_path, origin, declaration_member_ordinal,
                    declaration_site + 1000, alias_dependency_ordinal, target_unit_key,
                    alias_identity_id, target_module_path, target_name
             FROM rust_resolution_unit_summary_exports
             WHERE name='Widget' AND origin='declaration';",
        );
        let (complete, names) = widget_children(&workspace);
        assert!(
            !complete,
            "an ambiguous name form must be incomplete: {names:?}"
        );
        assert!(names.is_empty(), "{names:?}");
    }

    #[test]
    #[ignore = "operator measurement: needs BIFROST_RUST_UNIT_SUMMARY_CORPUS, a writable Rust repository copy"]
    fn measure_rust_unit_summary_reconcile_on_a_corpus() {
        use std::sync::Arc;
        use std::time::Instant;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_core::analyzer::project::TestProject;

        let root = std::path::PathBuf::from(
            std::env::var("BIFROST_RUST_UNIT_SUMMARY_CORPUS")
                .expect("BIFROST_RUST_UNIT_SUMMARY_CORPUS names a writable Rust repository copy"),
        )
        .canonicalize()
        .unwrap();
        let project: Arc<dyn brokk_bifrost_core::analyzer::project::Project> =
            Arc::new(TestProject::new(root.clone(), Language::Rust));
        let started = Instant::now();
        let workspace =
            WorkspaceAnalyzer::build_ephemeral_footgun(project, AnalyzerConfig::default())
                .expect("build the real Rust workspace");
        eprintln!("MEASURE Rust fresh build {:?}", started.elapsed());

        let report_rows = |label: &str, workspace: &WorkspaceAnalyzer| {
            let store = workspace.store().unwrap();
            let conn = store.read_conn().unwrap();
            let mut statement = conn
                .prepare(
                    "SELECT topology.crate_name, summaries.summary_id,
                       2
                       + (SELECT count(*) FROM resolution_unit_summary_members AS members
                          WHERE members.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_dependencies AS dependencies
                          WHERE dependencies.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_reads AS reads
                          WHERE reads.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_exports AS exports
                          WHERE exports.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_imports AS imports
                          WHERE imports.summary_id = summaries.summary_id)
                       + (SELECT count(*) FROM resolution_unit_summary_gaps AS gaps
                          WHERE gaps.summary_id = summaries.summary_id)
                     FROM rust_crate_versions AS topology_versions
                     JOIN rust_crate_topologies AS topology USING(topology_id)
                     JOIN resolution_unit_summary_versions AS summary_versions
                       ON summary_versions.workspace_id = topology_versions.workspace_id
                      AND summary_versions.lang = topology_versions.lang
                      AND summary_versions.generation = topology_versions.generation
                      AND summary_versions.unit_key = topology_versions.crate_key
                      AND summary_versions.valid_until IS NULL
                     JOIN resolution_unit_summaries AS summaries
                       ON summaries.summary_id = summary_versions.summary_id
                     WHERE topology_versions.lang = 'rust'
                       AND topology_versions.valid_until IS NULL
                       AND topology.publication_state = 'complete'
                     ORDER BY topology.crate_name, topology.target_kind",
                )
                .unwrap();
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            eprintln!("MEASURE {label} summary rows per crate: {rows:?}");
            rows
        };

        let fresh = report_rows("fresh", &workspace);
        assert!(
            !fresh.is_empty(),
            "the Rust workspace published no summaries"
        );
        let store = workspace.store().unwrap();
        let member = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT rel_path FROM resolution_unit_summary_members
                 ORDER BY rel_path LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let path = root.join(&member);
        let mut source = std::fs::read_to_string(&path).unwrap();
        source.push_str("\n// Rust unit summary measurement edit\n");
        std::fs::write(&path, source).unwrap();
        let started = Instant::now();
        let updated = workspace.update(&BTreeSet::from([ProjectFile::new(
            root.clone(),
            std::path::PathBuf::from(&member),
        )]));
        eprintln!(
            "MEASURE Rust one-file edit/update {:?} ({member})",
            started.elapsed()
        );
        let after = report_rows("one-file-edit", &updated);
        let fresh_summary_ids = fresh
            .iter()
            .map(|(_, summary_id, _)| *summary_id)
            .collect::<BTreeSet<_>>();
        let derived = after
            .iter()
            .filter(|(_, summary_id, _)| !fresh_summary_ids.contains(summary_id))
            .map(|(crate_name, summary_id, rows)| (crate_name.clone(), *summary_id, *rows))
            .collect::<Vec<_>>();
        eprintln!("MEASURE Rust one-file edit derived crate summaries: {derived:?}");
        assert_eq!(
            derived.len(),
            1,
            "a body-only edit should derive its crate summary and no dependents"
        );
    }

    #[test]
    #[hardwon("#5898: scoped ambiguity must not hide a mixed unresolved-glob inventory")]
    fn mixed_ambiguity_and_glob_gap_declines_incremental_import_batch() {
        use crate::analyzer::{RustAnalyzer, resolve_analyzer};
        use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;

        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='mixed_inventory'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "src/lib.rs",
                "mod one; mod two; use one::*; use two::*; pub fn run() { shadowed(); }\n",
            )
            .file("src/one.rs", "pub fn shadowed() {}\n")
            .file("src/two.rs", "pub fn other() {}\n")
            .build();
        let workspace = fixture.workspace_analyzer(AnalyzerConfig::default());
        // Simulate two independent producers sharing a rendered gap subject.
        // The additional evidence represents an unresolved glob boundary; an
        // existential check for ambiguity would wrongly discharge that boundary.
        workspace.store().unwrap().conn.execute(|conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER mixed_inventory AFTER INSERT ON rust_resolution_unit_summary_gaps
                 WHEN NEW.subject = 'crate::shadowed' AND NEW.gap_kind = 'open_export_inventory'
                 BEGIN
                   UPDATE rust_resolution_unit_summary_gaps
                   SET detail = jsonb_insert(detail, '$.evidence[#]', json_object(
                     'reason', 'OpenBoundary', 'namespace', 'value', 'member_blob', 0,
                     'binder_scope', 0, 'boundary', 'external_declared_unindexed',
                     'import_paths', json_array(json_array('unindexed'))))
                   WHERE summary_id = NEW.summary_id AND gap_kind = NEW.gap_kind
                     AND subject = NEW.subject;
                 END;",
            )?;
            Ok::<_, rusqlite::Error>(())
        }).unwrap();
        fixture
            .file("src/two.rs")
            .write("pub fn other() {} pub fn shadowed() {}\n")
            .unwrap();
        let changed = workspace.update(&BTreeSet::from([fixture.file("src/two.rs")]));
        {
            let conn = changed.store().unwrap().read_conn().unwrap();
            let rows: Vec<(bool, String, String, i64)> = conn.prepare(
                "SELECT completeness.complete, completeness.gap_kind, completeness.gap_subject,
                        json_array_length(gaps.detail, '$.evidence')
                 FROM resolution_unit_summary_versions AS version
                 JOIN rust_resolution_unit_summary_binding_completeness AS completeness USING(summary_id)
                 JOIN rust_resolution_unit_summary_gaps AS gaps USING(summary_id)
                 WHERE version.valid_until IS NULL AND gaps.gap_kind = 'open_export_inventory'
                   AND gaps.subject = 'crate::shadowed'",
            ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .unwrap().collect::<rusqlite::Result<_>>().unwrap();
            assert_eq!(rows, vec![(true, "complete".into(), "".into(), 2); 3]);
        }
        let analyzer = resolve_analyzer::<RustAnalyzer>(changed.analyzer()).unwrap();
        let completeness = changed
            .store()
            .unwrap()
            .rust_summary_binding_completeness_rows(
                &analyzer.inner.selected_workspace_snapshots(),
                &[
                    "src/lib.rs".into(),
                    "src/one.rs".into(),
                    "src/two.rs".into(),
                ],
            )
            .unwrap();
        assert_eq!(
            completeness
                .iter()
                .map(|row| (row.rel_path.as_str(), row.complete))
                .collect::<Vec<_>>(),
            vec![
                ("src/lib.rs", false),
                ("src/one.rs", false),
                ("src/two.rs", false)
            ],
        );
        let client = fixture.file("src/lib.rs");
        let selected = crate::hash::HashMap::from_iter([(client.clone(), vec![1])]);
        let mut visited = Vec::new();
        assert!(
            analyzer
                .for_each_import_edge_facts_from_infos(
                    &[fixture.file("src/two.rs"), client],
                    None,
                    &selected,
                    None,
                    &mut |file, _| {
                        visited.push(file.clone());
                        true
                    },
                )
                .is_none()
        );
        assert!(
            visited.is_empty(),
            "an incomplete batch publishes no edges: {visited:?}"
        );
    }
}

#[cfg(test)]
mod included_impl_subject_placement {
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "#7226: rust_crate_unresolved_trait_impls keyed no placing module, so two module placements of one included impl kept one row"
    )]
    fn included_impl_subjects_preserve_module_placement() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='placed_impl'\nversion='0.1.0'\nedition='2021'\n")
            .file("src/lib.rs", "pub mod one { pub struct W; include!(\"shared.rs\"); }\npub mod two { pub struct W; include!(\"shared.rs\"); }\n")
            .file("src/shared.rs", "impl std::ops::Deref for W { type Target = u8; fn deref(&self) -> &u8 { &0 } }\n")
            .build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let store = workspace.store().unwrap();
        let conn = store.read_conn().unwrap();
        let subjects = conn
            .prepare(
                "SELECT endpoint.owner_module_path, target.module_path, target.name
             FROM rust_resolution_unit_summary_trait_endpoints AS endpoint
             JOIN resolution_unit_summary_versions AS versions USING(summary_id)
             JOIN rust_resolution_unit_summary_exports AS target
               ON target.summary_id=endpoint.summary_id
              AND target.identity_id=endpoint.target_identity_id
              AND target.module_path=endpoint.target_module_path
              AND target.namespace='type' AND target.origin='declaration'
             WHERE versions.valid_until IS NULL AND endpoint.endpoint_role='subject'
               AND endpoint.endpoint_state='resolved'
             ORDER BY endpoint.owner_module_path, target.module_path",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            subjects,
            vec![
                (
                    "crate::one".to_owned(),
                    "crate::one".to_owned(),
                    "W".to_owned()
                ),
                (
                    "crate::two".to_owned(),
                    "crate::two".to_owned(),
                    "W".to_owned()
                ),
            ]
        );
    }
}
