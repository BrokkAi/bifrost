#[cfg(test)]
mod tests {

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::CLOSURE_SCOPE_MOUNTS_HEAD;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::CLOSURE_SCOPE_MOUNTS_TAIL;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::DETACHED_SCOPE_CRATES;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECT_IMPORTED_MACRO_DEFINITION;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned_queries;

    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RUST_UNIT_SUMMARY_DERIVATION_VERSION;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::types::Value;

    #[test]
    #[hardwon(
        "#5658: P3's published readers dropped #[macro_use] extern crate macros; the 41-state differential had no macro_use extern crate"
    )]
    fn published_macro_use_prelude_preserves_provider_completion_and_cfg_exclusion() {
        use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::{
            PUBLISHED_EXPORT, PUBLISHED_MACRO_PRELUDE, PUBLISHED_OPEN_INVENTORY,
        };
        // The same workspace as the private rust-route-precedence/macro-use-prelude
        // golden, inline so that the projected public tree can run this test.
        let builder = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nresolver=\"2\"\nmembers=[\"codegen\",\"disabled_codegen\",\"facade\",\"open_facade\",\"consumer\",\"open_consumer\"]\n",
            )
            .file(
                "codegen/Cargo.toml",
                "[package]\nname=\"codegen\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[lib]\nproc-macro=true\n",
            )
            .file(
                "codegen/src/lib.rs",
                "extern crate proc_macro;\n#[proc_macro]\npub fn routes(input: proc_macro::TokenStream) -> proc_macro::TokenStream { input }\n",
            )
            .file(
                "disabled_codegen/Cargo.toml",
                "[package]\nname=\"disabled_codegen\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[lib]\nproc-macro=true\n",
            )
            .file(
                "disabled_codegen/src/lib.rs",
                "extern crate proc_macro;\n#[proc_macro]\npub fn disabled_only(input: proc_macro::TokenStream) -> proc_macro::TokenStream { input }\n",
            )
            .file(
                "facade/Cargo.toml",
                "[package]\nname=\"facade\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[dependencies]\ncodegen={path=\"../codegen\"}\n",
            )
            .file("facade/src/lib.rs", "pub use codegen::*;\n")
            .file(
                "open_facade/Cargo.toml",
                "[package]\nname=\"open_facade\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[dependencies]\ndisabled_codegen={path=\"../disabled_codegen\"}\n",
            )
            .file("open_facade/src/lib.rs", "pub use disabled_codegen::*;\nunknown_provider_items!();\n")
            .file(
                "consumer/Cargo.toml",
                "[package]\nname=\"consumer\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[dependencies]\nfacade={path=\"../facade\"}\nopen_facade={path=\"../open_facade\"}\n",
            )
            .file(
                "consumer/src/lib.rs",
                "#[macro_use]\nextern crate facade;\n#[cfg(any())]\n#[macro_use]\nextern crate open_facade;\npub mod nested;\n",
            )
            .file(
                "consumer/src/nested.rs",
                "pub fn run() {\n    routes!();\n    disabled_only!();\n    missing_macro!();\n}\n",
            )
            .file(
                "open_consumer/Cargo.toml",
                "[package]\nname=\"open_consumer\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[dependencies]\nopen_facade={path=\"../open_facade\"}\n",
            )
            .file(
                "open_consumer/src/lib.rs",
                "#[macro_use]\nextern crate open_facade;\n#[macro_export]\nmacro_rules! owned_macro { () => {} }\n",
            );
        let project = builder.build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        brokk_bifrost_analysis::analyzer::store::rust_crates::register_point_export_functions(
            &conn,
        )
        .unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'",[]).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path) SELECT row_number() OVER(),blob_id,'rust','rust',rel_path FROM (SELECT DISTINCT blob_id,rel_path FROM selected_rust_crate_containers)",[]).unwrap();
        conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL)
            .unwrap();
        let topology = |name: &str| {
            conn.query_row(
                "SELECT topology_id FROM rust_crate_topologies WHERE crate_name=?1",
                [name],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        };
        let consumer = topology("consumer");
        let open_consumer = topology("open_consumer");
        let provider = topology("open_facade");
        let parameters = |owner: i64, module: &str, namespace: &str, name: &str, requester: i64| {
            vec![
                Value::Integer(owner),
                Value::Text(module.into()),
                Value::Text(namespace.into()),
                Value::Text(name.into()),
                Value::Integer(requester),
                Value::Text(module.into()),
            ]
        };
        let details = |owner, module, name, requester| {
            conn.prepare_cached(PUBLISHED_OPEN_INVENTORY)
                .unwrap()
                .query_map(
                    rusqlite::params_from_iter(parameters(owner, module, "macro", name, requester)),
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let export_count = |owner, module, name, requester| {
            conn.prepare_cached(PUBLISHED_EXPORT)
                .unwrap()
                .query_map(
                    rusqlite::params_from_iter(parameters(owner, module, "macro", name, requester)),
                    |_| Ok(()),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
                .len()
        };
        let own_certificates:i64=conn.query_row("SELECT count(*) FROM rust_crate_binding_owners owner JOIN rust_crate_binding_names name USING(owner_id) WHERE owner.topology_id=?1 AND name.namespace='macro' AND name.name='missing_macro'",[open_consumer],|row|row.get(0)).unwrap();
        assert_eq!(
            own_certificates, 0,
            "provider completion fallback must be tested without an own certificate"
        );
        let provider_blockers:i64=conn.query_row("SELECT count(*) FROM rust_crate_binding_owners owner JOIN rust_crate_binding_blockers blocker USING(owner_id) WHERE owner.topology_id=?1 AND owner.module_path='crate' AND blocker.namespace='macro' AND blocker.name=''",[provider],|row|row.get(0)).unwrap();
        assert!(
            provider_blockers > 0,
            "fixture provider must publish owner-wide macro blockers"
        );
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let provider_details = details(provider, "crate", "missing_macro", open_consumer);
            assert!(
                !provider_details.is_empty(),
                "open provider must have durable reason details"
            );
            assert_eq!(
                details(open_consumer, "crate", "missing_macro", open_consumer),
                provider_details,
                "requester must inherit the provider's exact durable reasons"
            );
            assert!(
                details(open_consumer, "crate", "owned_macro", open_consumer).is_empty(),
                "a complete own certificate shadows provider incompleteness"
            );
            assert_eq!(
                export_count(consumer, "crate::nested", "routes", consumer),
                1
            );
            assert_eq!(
                export_count(consumer, "crate::nested", "disabled_only", consumer),
                0,
                "disabled provider must supply no endpoint"
            );
            assert!(
                details(consumer, "crate::nested", "disabled_only", consumer).is_empty(),
                "disabled open provider must supply no open reason"
            );
            assert!(
                details(consumer, "crate::nested", "missing_macro", consumer).is_empty(),
                "unlisted name in the remaining closed provider is absent"
            );
            for namespace in ["type", "value"] {
                assert!(
                    !conn
                        .prepare_cached(PUBLISHED_MACRO_PRELUDE)
                        .unwrap()
                        .exists(rusqlite::params_from_iter(parameters(
                            consumer, "crate", namespace, "routes", consumer
                        )))
                        .unwrap()
                );
            }
            assert!(
                !conn
                    .prepare_cached(PUBLISHED_MACRO_PRELUDE)
                    .unwrap()
                    .exists(rusqlite::params_from_iter(parameters(
                        consumer, "crate", "macro", "routes", provider
                    )))
                    .unwrap(),
                "foreign topology cannot inherit the requester's prelude"
            );
            for (name, sql) in [
                ("macro_prelude", PUBLISHED_MACRO_PRELUDE),
                ("macro_export", PUBLISHED_EXPORT),
                ("macro_completion", PUBLISHED_OPEN_INVENTORY),
            ] {
                let pin = brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::PinnedQuery {
                    name: name.into(),
                    sql: sql.into(),
                    params: parameters(
                        open_consumer,
                        "crate",
                        "macro",
                        "missing_macro",
                        open_consumer,
                    ),
                };
                let plan = explain_pin(&conn, &pin);
                eprintln!("{state:?} {name}: {plan:?}");
                assert!(
                    plan.iter().all(|step| !step.contains("AUTOMATIC")),
                    "{state:?} {name}: {plan:?}"
                );
            }
        }
    }

    /// External globs can bind any namespace, while a root macro-use import
    /// contributes to every macro lookup from its crate. Keep these checks in
    /// helper proof and keep ordinary point lookup inventory closed.
    #[test]
    #[hardwon("#4458: unindexed external imports left derive-helper proof falsely closed")]
    fn unindexed_helper_scope_does_not_open_point_inventory() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nunindexed='1'\n",
            )
            .file(
                "src/lib.rs",
                "#[macro_use] extern crate unindexed; pub mod inner { use unindexed::prelude::*; }",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().expect("the fixture builds a store");
        let conn = store.conn.lock().expect("the fixture store lock");
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        brokk_bifrost_analysis::analyzer::store::rust_crates::register_point_export_functions(
            &conn,
        )
        .unwrap();
        conn.execute(
            "INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'",
            [],
        )
        .unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let (topology, blob): (i64, i64) = conn
            .query_row(
                "SELECT topology_id,blob_id FROM selected_rust_crate_containers WHERE container_path='crate' AND rel_path='src/lib.rs'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        conn.execute(
            "INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path) VALUES(0,?1,'rust','rust','src/lib.rs')",
            [blob],
        )
        .unwrap();
        conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();

        for (module, namespace, name, expected) in [
            (
                "crate::inner",
                "macro",
                "missing_macro",
                "UnindexedExternalGlobImport",
            ),
            (
                "crate",
                "macro",
                "missing_macro",
                "UnindexedExternalMacroUseImport",
            ),
        ] {
            let helper_scope_open = conn
                .prepare(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::UNINDEXED_SCOPE)
                .unwrap()
                .exists(rusqlite::params![
                    topology, module, namespace, name, topology, module
                ])
                .unwrap();
            assert!(helper_scope_open, "{module} {namespace} {name}: {expected}");
            if expected == "UnindexedExternalGlobImport" {
                let point_inventory = conn
                    .prepare(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::PUBLISHED_OPEN_INVENTORY)
                    .unwrap()
                    .query_map(
                        rusqlite::params![topology, module, namespace, name, topology, module],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(
                    point_inventory.is_empty(),
                    "an external glob stays an external boundary for ordinary name lookups: {point_inventory:?}"
                );
            }
        }
    }

    fn assert_rust_workspace_graph_builds(project: &BuiltInlineTestProject, failure: &str) {
        use brokk_bifrost_rust_analysis::analyzer::rust::native_graph::build_rust_native_workspace_graph_for_files;

        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        let analyzer = RustAnalyzer::from_project(project.project().clone());
        let files = analyzer
            .source_file_inventory()
            .rows
            .into_iter()
            .filter(|file| {
                brokk_bifrost_core::analyzer::common::language_for_file(file) == Language::Rust
            })
            .collect::<Vec<_>>();
        if let Err(error) = build_rust_native_workspace_graph_for_files(
            &analyzer,
            &files,
            8,
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        ) {
            panic!("{failure}: {error}");
        }
    }

    #[test]
    fn imported_macro_definition_matches_the_topology_reader() {
        let source = "use provider::chosen as renamed;\nuse provider::*;\nfn named() { renamed!(); }\nfn glob() { chosen!(); }\n";
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nprovider={path='provider'}\n",
            )
            .file("src/lib.rs", source)
            .file(
                "provider/Cargo.toml",
                "[package]\nname='provider'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "provider/src/lib.rs",
                "#[macro_export]\nmacro_rules! chosen { () => {} }\n",
            )
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        conn.execute(
            "INSERT INTO selected_workspace_revisions
             SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'",
            [],
        )
        .unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();

        const LEGACY: &str = r#"WITH candidates(rel_path, declaration_id, local_extent, is_glob) AS (
            SELECT DISTINCT target_source.rel_path, bridge.declaration_id,
                   COALESCE(source.local_end-source.local_start, 9223372036854775807), 0
            FROM rust_crate_container_sources AS owner
            CROSS JOIN selected_rust_crates AS selected
              ON selected.topology_id=owner.topology_id
            CROSS JOIN rust_crate_imports AS import
              ON import.topology_id=owner.topology_id
             AND import.module_path=owner.container_path
             AND import.blob_id=owner.blob_id
            CROSS JOIN source_rust_import_targets AS source
              ON source.blob_id=import.blob_id
             AND source.ordinal=import.import_ordinal
             AND source.native_scope=import.binder_scope
            CROSS JOIN selected_rust_crates AS target
              ON target.crate_key=import.target_crate_key
            CROSS JOIN rust_crate_exports AS export
              ON export.topology_id=target.topology_id
             AND export.module_path=import.target_module_path
             AND export.namespace='macro'
             AND export.name=import.target_name
            CROSS JOIN source_native_declaration_bridges AS bridge
              ON bridge.blob_id=export.declaration_blob_id
             AND bridge.source_site=export.declaration_site
            CROSS JOIN rust_crate_container_sources AS target_source
              ON target_source.topology_id=export.topology_id
             AND target_source.blob_id=export.declaration_blob_id
            WHERE owner.rel_path=?1 AND import.namespace='macro'
              AND import.bound_name=?3
              AND source.owner_start<=?2 AND ?2<source.owner_end
              AND (source.local_start IS NULL
                   OR (source.local_start<=?2 AND ?2<source.local_end))
            UNION ALL
            SELECT DISTINCT target_source.rel_path, bridge.declaration_id,
                   COALESCE(source.local_end-source.local_start, 9223372036854775807), 1
            FROM rust_crate_container_sources AS owner
            CROSS JOIN selected_rust_crates AS selected
              ON selected.topology_id=owner.topology_id
            CROSS JOIN rust_crate_glob_imports AS import
              ON import.topology_id=owner.topology_id
             AND import.module_path=owner.container_path
             AND import.blob_id=owner.blob_id
            CROSS JOIN source_rust_import_targets AS source
              ON source.blob_id=import.blob_id
             AND source.ordinal=import.import_ordinal
             AND source.native_scope=import.binder_scope
            CROSS JOIN selected_rust_crates AS target
              ON target.crate_key=import.target_crate_key
            CROSS JOIN rust_crate_exports AS export
              ON export.topology_id=target.topology_id
             AND export.module_path=import.target_module_path
             AND export.namespace='macro' AND export.name=?3
            CROSS JOIN source_native_declaration_bridges AS bridge
              ON bridge.blob_id=export.declaration_blob_id
             AND bridge.source_site=export.declaration_site
            CROSS JOIN rust_crate_container_sources AS target_source
              ON target_source.topology_id=export.topology_id
             AND target_source.blob_id=export.declaration_blob_id
            WHERE owner.rel_path=?1
              AND source.owner_start<=?2 AND ?2<source.owner_end
              AND (source.local_start IS NULL
                   OR (source.local_start<=?2 AND ?2<source.local_end))
        )
        SELECT rel_path, declaration_id, local_extent, is_glob
        FROM candidates ORDER BY local_extent, is_glob, rel_path, declaration_id"#;

        for (name, is_glob) in [("renamed", false), ("chosen", true)] {
            let position = source.find(&format!("{name}!")).expect("macro invocation") as i64;
            let params = rusqlite::params!["src/lib.rs", position, name];
            let legacy = conn
                .prepare(LEGACY)
                .unwrap()
                .query_map(params, |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let summary = conn
                .prepare(SELECT_IMPORTED_MACRO_DEFINITION)
                .unwrap()
                .query_map(params, |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(summary, legacy, "macro={name:?}");
            assert!(
                summary.iter().any(|row| row.3 == is_glob),
                "macro={name:?} expected glob={is_glob}; rows={summary:?}"
            );
        }
    }

    /// The three answers a file no Cargo target mounts must give, and the one
    /// workspace shape that is not that case.
    ///
    /// `extra/orphan.rs` is in the workspace and in no Cargo target of it, so
    /// the derivation gives it its own `detached` topology whose `crate` root
    /// holds only that file. `crate::helpers::helper()` out of it used to walk
    /// that synthetic root, find nothing, and answer a decided negative, while
    /// the whole-workspace projection called itself complete and the dead-code
    /// report published "dead, 0 usages" for every declaration in the file.
    #[test]
    #[hardwon("fef6e65216dc: a detached file under no Cargo target is incomplete, not absent")]
    fn a_file_under_no_cargo_target_answers_incomplete_and_stops_the_projection() {
        use brokk_bifrost_rust_analysis::analyzer::rust::native_graph::RustNativeWorkspaceGraphOutcome;

        use brokk_bifrost_rust_analysis::analyzer::rust::native_graph::build_rust_native_workspace_graph_for_files;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::resolve_definition_batch_with_trace;

        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        const ORPHAN: &str = "fn caller_one() { crate::helpers::helper(); }";
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub mod helpers;")
            .file("src/helpers.rs", "pub fn helper() {}")
            .file("extra/orphan.rs", ORPHAN)
            .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());

        let file = project.file("extra/orphan.rs");
        let start = ORPHAN.find("helper()").expect("call site");
        let outcome = resolve_definition_batch_with_trace(
            &analyzer,
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(start),
                end_byte: Some(start + "helper".len()),
            }],
            file,
            std::sync::Arc::<str>::from(ORPHAN),
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        );
        let answer = &outcome[0].0;
        assert_eq!(
            answer.status,
            DefinitionLookupStatus::Incomplete,
            "a crate-rooted route out of an unmounted file is not a proved absence: {answer:?}"
        );
        assert!(
            answer
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("unmounted_file(")),
            "the incompleteness must name the file it is about: {answer:?}"
        );

        let files = analyzer
            .source_file_inventory()
            .rows
            .into_iter()
            .filter(|file| {
                brokk_bifrost_core::analyzer::common::language_for_file(file) == Language::Rust
            })
            .collect::<Vec<_>>();
        let projection = build_rust_native_workspace_graph_for_files(
            &analyzer,
            &files,
            8,
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        )
        .expect("projection");
        assert!(
            matches!(projection, RustNativeWorkspaceGraphOutcome::Incomplete(_)),
            "a whole-workspace projection that admits an unmounted file cannot be complete"
        );

        // The same workspace with the file taken out: the incompleteness above
        // is the orphan's and not this fixture's.
        let mounted = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub mod helpers;")
            .file("src/helpers.rs", "pub fn helper() {}")
            .build();
        let mounted_analyzer = RustAnalyzer::from_project(mounted.project().clone());
        let mounted_files = mounted_analyzer
            .source_file_inventory()
            .rows
            .into_iter()
            .filter(|file| {
                brokk_bifrost_core::analyzer::common::language_for_file(file) == Language::Rust
            })
            .collect::<Vec<_>>();
        assert!(
            matches!(
                build_rust_native_workspace_graph_for_files(
                    &mounted_analyzer,
                    &mounted_files,
                    8,
                    &brokk_bifrost_core::cancellation::CancellationToken::new(),
                )
                .expect("projection"),
                RustNativeWorkspaceGraphOutcome::Complete(_)
            ),
            "the crate this workspace does declare still projects completely"
        );
    }

    /// The dead-code half of the case above. The projection is incomplete
    /// with `UnmountedFile`, but the bucket abstains per candidate spelled by
    /// an unresolved reference (lane UP, 2026-09-17), and the unresolved
    /// reference here is `helper`, not `caller_one`, so the orphan's own
    /// declaration is still reported dead. What closes it is the file itself
    /// on the projection's input-failure channel from a crate-rows read
    /// (plan open item: the declaration-only half of DC-A).
    #[test]
    #[ignore = "finds real bug: an unmounted file's own declarations are reported dead; the bucket abstains per unresolved name, not per unmounted file"]
    fn an_unmounted_files_own_declarations_are_not_reported_dead() {
        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        const ORPHAN: &str = "fn caller_one() { crate::helpers::helper(); }";
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub mod helpers;")
            .file("src/helpers.rs", "pub fn helper() {}")
            .file("extra/orphan.rs", ORPHAN)
            .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        let report = crate::code_quality::report_dead_code_and_unused_abstraction_smells(
            &analyzer,
            crate::code_quality::ReportDeadCodeAndUnusedAbstractionSmellsParams {
                file_paths: vec!["extra/orphan.rs".to_owned()],
                ..Default::default()
            },
        )
        .report;
        assert!(
            report.contains("Skipped symbols"),
            "the dead-code bucket must abstain on an unmounted file's candidates: {report}"
        );
    }

    /// One import site answers once, however many times the crate being
    /// walked compiles the file it is written in.
    ///
    /// `src/shared.rs` is a module of `app/lib` and of `app/bin`, and a bin
    /// target depends on its own package's lib, so the bin crate's context
    /// reads two module rows for that one file. The two answer
    /// `use app::Thing;` differently by construction: from the bin's topology
    /// `app` names the lib, whose export inventory the unexpanded
    /// `generate!()` leaves open, and from the lib's own topology `app` names
    /// nothing at all, because a crate is not its own dependency. Each row
    /// used to push its own dead-end descriptor for the one candidate path
    /// that import site spells, so the selected context received two
    /// derivations of one path whose completions disagreed and rejected the
    /// publication. That is the store error Bifrost's own whole-workspace
    /// `usage_graph` raised.
    #[test]
    #[hardwon("77aab427cd16: one source import must not derive a duplicate dead end")]
    fn one_import_site_derives_one_dead_end_when_its_file_is_compiled_twice() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "generate!();\npub mod shared;\n")
            .file(
                "src/main.rs",
                "mod shared;\nfn main() { shared::use_it(); }\n",
            )
            .file(
                "src/shared.rs",
                "use app::Thing;\npub fn use_it() { let _ = Thing; }\n",
            )
            .build();
        assert_rust_workspace_graph_builds(&project, "one import site must derive one dead end");
    }

    /// The same answer when the two placements are in one crate.
    ///
    /// Owner decision of 2026-09-22 keyed `duplicate_placement` on the module
    /// path, so a file reached from two `mod` declarations is now two modules
    /// of one topology instead of a gap, which is the shape Bifrost's own
    /// `test-support/inline_project.rs` has in several libraries. `MODULES` is
    /// keyed on the blob and the file, not on the topology, so those two
    /// placements arrive at the crate context exactly as two topologies do;
    /// this pins that they combine into one dead end rather than two. The bin
    /// target makes the completions disagree, which is what turns a duplicate
    /// publication into the store error: from the bin `app` names the lib with
    /// an open inventory, and from the lib `app` names nothing.
    #[test]
    #[hardwon("80645bcc16c2: module placement identity must not duplicate a file import")]
    fn two_placements_of_one_file_in_one_crate_derive_one_dead_end() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='app'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "generate!();\npub mod alpha;\npub mod beta;\n")
            .file(
                "src/main.rs",
                "mod alpha;\nmod beta;\nfn main() { alpha::shared::use_it(); beta::shared::use_it(); }\n",
            )
            .file(
                "src/alpha.rs",
                "#[path = \"../test-support/shared.rs\"]\npub mod shared;\n",
            )
            .file(
                "src/beta.rs",
                "#[path = \"../test-support/shared.rs\"]\npub mod shared;\n",
            )
            .file(
                "test-support/shared.rs",
                "use app::Thing;\npub fn use_it() { let _ = Thing; }\n",
            )
            .build();
        assert_rust_workspace_graph_builds(
            &project,
            "two placements in one crate must derive one dead end",
        );
    }

    /// The scope of the reason above, which a reader must not widen by
    /// accident. A workspace that declares no Cargo target at all publishes one
    /// `detached` topology per Rust file by design; that is the model, not a
    /// gap, and the lexical route is what carries such a workspace. Making
    /// every file in it "unmounted" would turn the whole non-Cargo Rust surface
    /// into an abstention.
    #[test]
    #[hardwon("fef6e65216dc: Cargo-free workspaces remain answerable")]
    fn a_workspace_with_no_cargo_target_at_all_is_not_an_unmounted_file() {
        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::resolve_definition_batch_with_trace;

        const CALLER: &str = "fn caller_one() { crate::helpers::helper(); }";
        let project = InlineTestProject::new()
            .file("helpers.rs", "pub fn helper() {}")
            .file("callers.rs", CALLER)
            .build();
        let analyzer = RustAnalyzer::from_project(project.project().clone());
        let file = project.file("callers.rs");
        let start = CALLER.find("helper()").expect("call site");
        let outcome = resolve_definition_batch_with_trace(
            &analyzer,
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(start),
                end_byte: Some(start + "helper".len()),
            }],
            file,
            std::sync::Arc::<str>::from(CALLER),
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        );
        let answer = &outcome[0].0;
        assert!(
            !answer
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("unmounted_file(")),
            "no Cargo target exists to leave this file out of: {answer:?}"
        );
        assert_ne!(
            answer.status,
            DefinitionLookupStatus::Incomplete,
            "{answer:?}"
        );
    }

    /// Resolve the member of a Rust type-qualified path or of a method call on
    /// a receiver, at the analyzer boundary, and say which definitions it
    /// named. The member is the path's last segment after `::` or `.`.
    #[cfg(test)]
    fn qualified_member_definitions(
        files: &[(&str, &str)],
        caret_file: &str,
        path: &str,
    ) -> (
        brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus,
        Vec<String>,
    ) {
        let outcome = qualified_member_outcome(files, caret_file, path);
        let names = outcome
            .definitions
            .iter()
            .map(|unit| unit.short_name().to_owned())
            .collect();
        (outcome.status, names)
    }

    /// The whole definition outcome [`qualified_member_definitions`] reads.
    #[cfg(test)]
    fn qualified_member_outcome(
        files: &[(&str, &str)],
        caret_file: &str,
        path: &str,
    ) -> brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_definition_batch_with_source;
        let mut project = InlineTestProject::new();
        for (name, contents) in files {
            project = project.file(*name, *contents);
        }
        let project = project.build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let source = files
            .iter()
            .find(|(name, _)| *name == caret_file)
            .map(|(_, contents)| *contents)
            .expect("caret file");
        let member = path
            .rsplit(['.', ':'])
            .next()
            .expect("a qualified path has a member");
        let at = source.find(path).expect("the fixture spells the path")
            + path.rfind(member).expect("member position");
        let file = project.file(caret_file);
        resolve_definition_batch_with_source(
            workspace.analyzer(),
            vec![DefinitionLookupRequest {
                file: file.clone(),
                line: None,
                column: None,
                start_byte: Some(at),
                end_byte: Some(at + member.len()),
            }],
            file,
            std::sync::Arc::<str>::from(source),
        )
        .into_iter()
        .next()
        .expect("one request has one outcome")
    }

    /// The join's read is bounded by the subject, not by the crate's impls.
    ///
    /// The plan pin above proves the statement seeks
    /// `rust_crate_trait_impls_subject` on both subject columns. This proves
    /// what that buys: growing the crate from two trait implementations to
    /// forty-one leaves the request reading the same one row, and leaves the
    /// answer unchanged. One statement per qualifier value, and its rows are
    /// the subject's traits.
    #[test]
    fn the_trait_impl_join_reads_one_subject_however_many_impls_the_crate_holds() {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        let mut rows = Vec::new();
        for unrelated in [1usize, 40] {
            let mut source = String::from(
                "struct Foo;\ntrait Trait {\n    fn frobnicate();\n}\nimpl Trait for Foo {}\n",
            );
            for ordinal in 0..unrelated {
                source.push_str(&format!(
                    "struct Other{ordinal};\nimpl Trait for Other{ordinal} {{}}\n"
                ));
            }
            source.push_str("\nfn bar() {\n    Foo::frobnicate();\n}\n");
            let project = InlineTestProject::new().file("t.rs", &source).build();
            let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().expect("the fixture builds a store");
            let conn = store.conn.lock().expect("the fixture store lock");
            brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn)
                .unwrap();
            brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
            let (blob, site): (i64, i64) = conn
                .query_row(
                    "SELECT declaration_blob_id,declaration_site FROM rust_crate_exports WHERE namespace='type' AND name='Foo' AND origin='declaration'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("the subject has an export row");
            let topology: i64 = conn
                .query_row("SELECT topology_id FROM selected_rust_crates", [], |row| {
                    row.get(0)
                })
                .expect("one crate");
            let impls: i64 = conn
                .query_row("SELECT count(*) FROM rust_crate_trait_impls", [], |row| {
                    row.get(0)
                })
                .unwrap();
            conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path) SELECT 0,?1,'rust','rust','t.rs'", [blob]).unwrap();
            conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
            let read: i64 = conn
                .query_row(
                    &format!(
                        "SELECT count(*) FROM ({})",
                        brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_rows::TRAIT_IMPLS_VISIBLE_AT
                    ),
                    rusqlite::params![
                        blob,
                        site,
                        topology,
                        "crate",
                        "t.rs",
                        0,
                        0,
                        RUST_UNIT_SUMMARY_DERIVATION_VERSION
                    ],
                    |row| row.get(0),
                )
                .expect("the join reads its subject");
            drop(conn);
            let answer = self::qualified_member_definitions(
                &[("t.rs", source.as_str())],
                "t.rs",
                "Foo::frobnicate",
            );
            rows.push((unrelated, impls, read, answer));
        }
        eprintln!("trait-impl join reads (unrelated impls, table rows, rows read): {rows:?}");
        assert_eq!(
            (rows[0].1, rows[1].1),
            (2, 41),
            "the fixture must really grow the crate's impls: {rows:?}"
        );
        assert_eq!(
            rows[0].2, rows[1].2,
            "the join must read one subject's traits whatever else the crate implements: {rows:?}"
        );
        assert_eq!(rows[0].2, 1, "the subject implements one trait: {rows:?}");
        for (unrelated, _, _, answer) in &rows {
            assert_eq!(
                answer,
                &(
                    DefinitionLookupStatus::Resolved,
                    vec!["Trait.frobnicate".to_owned()]
                ),
                "the answer must not move with {unrelated} unrelated impls"
            );
        }
    }

    /// A method nothing indexed supplies is an open boundary, never a proved
    /// absence, in both call forms.
    ///
    /// A blanket `impl<T: Bound> Runner for T {}` leaves no crate row at all:
    /// `spelled_impl_header_path` has no nominal path for a type-parameter
    /// subject, so the lowering writes no `resolution_trait_implementations`
    /// row, and derivation writes neither a `rust_crate_trait_impls` row nor a
    /// `rust_crate_unresolved_trait_impls` row for it. A derive, a `Deref`
    /// target and a default method of a trait from an unindexed crate are the
    /// same shape. The producer declares the member surface open for every
    /// qualified reference, and the answer is the boundary that declaration
    /// permits, as for `Host::ITEM`.
    #[test]
    fn a_method_the_indexed_rows_cannot_supply_is_an_open_boundary() {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        let fixtures = [
            (
                "blanket receiver",
                "trait Bound {}\ntrait Runner {\n    fn run(&self) {}\n}\nimpl<T: Bound> Runner for T {}\nstruct Service;\nimpl Bound for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n",
                "service.run",
            ),
            (
                "blanket where-clause",
                "trait Bound {}\ntrait Runner {\n    fn run(&self) {}\n}\nimpl<T> Runner for T where T: Bound {}\nstruct Service;\nimpl Bound for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n",
                "service.run",
            ),
            (
                "blanket type-qualified",
                "trait Bound {}\ntrait Runner {\n    fn run(&self) {}\n}\nimpl<T: Bound> Runner for T {}\nstruct Service;\nimpl Bound for Service {}\n\nfn caller(service: Service) {\n    Service::run(&service);\n}\n",
                "Service::run",
            ),
            (
                "derive",
                "#[derive(Clone)]\nstruct Service;\n\nfn caller(service: Service) {\n    service.clone();\n}\n",
                "service.clone",
            ),
            (
                "deref target",
                "struct Inner;\nimpl Inner {\n    fn run(&self) {}\n}\nstruct Service {\n    inner: Inner,\n}\nimpl std::ops::Deref for Service {\n    type Target = Inner;\n    fn deref(&self) -> &Inner {\n        &self.inner\n    }\n}\n\nfn caller(service: Service) {\n    service.run();\n}\n",
                "service.run",
            ),
            (
                "unindexed trait default",
                "use std::fmt::Write;\nstruct Service;\nimpl Write for Service {\n    fn write_str(&mut self, _: &str) -> std::fmt::Result {\n        Ok(())\n    }\n}\n\nfn caller(mut service: Service) {\n    service.write_char('a');\n}\n",
                "service.write_char",
            ),
        ];
        for (label, source, path) in fixtures {
            let outcome = qualified_member_outcome(&[("t.rs", source)], "t.rs", path);
            assert_eq!(
                (outcome.status, outcome.definitions.len()),
                (
                    if label == "derive" {
                        DefinitionLookupStatus::Incomplete
                    } else {
                        DefinitionLookupStatus::UnresolvableImportBoundary
                    },
                    0,
                ),
                "{label}: {outcome:?}"
            );
        }
    }

    /// The reverse half: the impl item and the other trait's default each see
    /// the tied call as a usage they cannot prove.
    #[test]
    fn an_impl_item_tie_is_an_unproven_usage_of_each_candidate() {
        const TIED: &str = "struct Service;\ntrait One {\n    fn run(&self);\n}\ntrait Two {\n    fn run(&self) {}\n}\nimpl One for Service {\n    fn run(&self) {}\n}\nimpl Two for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n";
        for (line, symbol) in [(9, "Service.run"), (6, "Two.run")] {
            assert_one_unproven_usage(&scan_usages_at(TIED, line), symbol, 14);
        }
    }

    /// Scan the usages of the declaration at one line of a one-file fixture.
    #[cfg(test)]
    fn scan_usages_at(source: &str, line: usize) -> crate::searchtools::ScanUsagesResult {
        use crate::searchtools::{
            ScanUsagesByLocationParams, ScanUsagesTarget, scan_usages_by_location,
        };
        let project = InlineTestProject::new().file("t.rs", source).build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        scan_usages_by_location(
            workspace.analyzer(),
            ScanUsagesByLocationParams {
                targets: vec![ScanUsagesTarget {
                    path: "t.rs".to_owned(),
                    line,
                    column: None,
                    symbol: None,
                }],
                include_tests: true,
                paths: None,
                include_same_owner: true,
            },
        )
    }

    /// The call as an unproven usage of `symbol`: not a proven usage, and not
    /// a verified absence.
    #[cfg(test)]
    fn assert_one_unproven_usage(
        result: &crate::searchtools::ScanUsagesResult,
        symbol: &str,
        call_line: usize,
    ) {
        assert_eq!(result.results.len(), 1, "{symbol}: {result:#?}");
        let entry = &result.results[0];
        assert_eq!(entry.symbol.as_deref(), Some(symbol), "{result:#?}");
        assert_eq!(
            (
                entry.status,
                entry.total_hits,
                entry.unproven_hits,
                entry
                    .unproven_files
                    .iter()
                    .flat_map(|file| file.hits.iter().map(|hit| hit.line))
                    .collect::<Vec<_>>(),
            ),
            (
                crate::searchtools::ScanUsagesStatus::UnverifiedAbsent,
                Some(0),
                Some(1),
                vec![call_line],
            ),
            "{symbol}: the call is an unproven usage: {entry:#?}"
        );
    }

    /// The reverse half of the E0034 test above: each of the two tied trait
    /// methods sees the call as a usage it cannot prove, never as a proven
    /// one, because the call binds neither.
    #[test]
    fn a_tied_method_call_is_an_unproven_usage_of_each_trait_method() {
        const TIED: &str = "struct Service;\ntrait One {\n    fn run(&self) {}\n}\ntrait Two {\n    fn run(&self) {}\n}\nimpl One for Service {}\nimpl Two for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n";
        for (line, symbol) in [(3, "One.run"), (6, "Two.run")] {
            assert_one_unproven_usage(&scan_usages_at(TIED, line), symbol, 12);
        }
    }

    /// The reverse half of the open-boundary test: a trait default's usages are
    /// not a verified absence while a blanket impl may lend the default to the
    /// receiver of a call that names it.
    #[test]
    fn a_blanket_impl_call_is_an_unproven_usage_of_the_trait_default() {
        const BLANKET: &str = "trait Bound {}\ntrait Runner {\n    fn run(&self) {}\n}\nimpl<T: Bound> Runner for T {}\nstruct Service;\nimpl Bound for Service {}\n\nfn caller(service: Service) {\n    service.run();\n}\n";
        assert_one_unproven_usage(&scan_usages_at(BLANKET, 3), "Runner.run", 10);
    }

    /// The receiver form of the test above: a trait default method's usages
    /// reach a method call on a value whose type implements the trait with an
    /// empty impl body. The forward answer is the typed member route's, and a
    /// reverse scan confirms each candidate with that same forward answer.
    #[test]
    fn a_trait_default_methods_usages_reach_the_receiver_call_site() {
        use crate::searchtools::{
            ScanUsagesByLocationParams, ScanUsagesTarget, scan_usages_by_location,
        };
        const ONE: &str = "struct Foo;\ntrait Trait {\n    fn frobnicate(&self) {}\n}\nimpl Trait for Foo {}\n\nfn bar(foo: Foo) {\n    foo.frobnicate();\n}\n";
        let project = InlineTestProject::new().file("t.rs", ONE).build();
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let result = scan_usages_by_location(
            workspace.analyzer(),
            ScanUsagesByLocationParams {
                targets: vec![ScanUsagesTarget {
                    path: "t.rs".to_owned(),
                    line: 3,
                    column: None,
                    symbol: None,
                }],
                include_tests: true,
                paths: None,
                include_same_owner: true,
            },
        );
        assert_eq!(result.summary.found, 1, "{result:#?}");
        let entry = &result.results[0];
        assert_eq!(entry.symbol.as_deref(), Some("Trait.frobnicate"));
        assert!(entry.complete, "{entry:#?}");
        assert_eq!(entry.total_hits, Some(1), "{entry:#?}");
        let hits = &entry.files[0].hits;
        assert_eq!(
            (entry.files[0].path.as_str(), hits[0].line),
            ("t.rs", 8),
            "the trait default's one usage is the receiver call: {entry:#?}"
        );
    }

    #[test]
    fn rust_supertrait_callable_reverse_reaches_trait_body_self() {
        let source = "trait Base {\n    fn base();\n}\ntrait Mid: Base {}\ntrait Sub: Mid {\n    fn caller() { Self::base(); }\n}\n";
        let result = scan_usages_at(source, 2);
        assert_eq!(result.summary.found, 1, "{result:#?}");
        let entry = &result.results[0];
        assert_eq!(entry.symbol.as_deref(), Some("Base.base"));
        assert_eq!(entry.total_hits, Some(1), "{entry:#?}");
        let lines = entry
            .files
            .iter()
            .flat_map(|file| file.hits.iter().map(|hit| hit.line))
            .collect::<Vec<_>>();
        assert_eq!(lines, [6], "{entry:#?}");
    }

    #[test]
    fn rust_supertrait_callable_reverse_reaches_generic_receiver() {
        let source = "trait Base {\n    fn base(&self);\n}\ntrait Mid: Base {}\ntrait Sub: Mid {}\nfn caller<T: Sub>(value: T) {\n    value.base();\n}\n";
        let result = scan_usages_at(source, 2);
        assert_eq!(result.summary.found, 1, "{result:#?}");
        let entry = &result.results[0];
        assert_eq!(entry.symbol.as_deref(), Some("Base.base"));
        assert_eq!(entry.total_hits, Some(1), "{entry:#?}");
        let lines = entry
            .files
            .iter()
            .flat_map(|file| file.hits.iter().map(|hit| hit.line))
            .collect::<Vec<_>>();
        assert_eq!(lines, [7], "{entry:#?}");
    }

    #[test]
    #[hardwon("#2767: an extern alias in an included member keeps its crate-root route")]
    fn crate_point_root_extern_alias_is_visible_in_include_member() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='demo'\nversion='0.1.0'\nedition='2024'\n[dependencies]\ndep={path='dep'}\n")
            .file("src/lib.rs", "extern crate dep as tk; mod host { include!(\"generated.rs\"); }")
            .file("src/generated.rs", "fn generated() { tk::target(); }")
            .file("dep/Cargo.toml", "[package]\nname='dep'\nversion='0.1.0'\nedition='2024'\n")
            .file("dep/src/lib.rs", "pub fn target() {}")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn_for_workspace(&Default::default()).unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let topology: i64 = conn
            .query_row(
                "SELECT topology_id FROM selected_rust_crates WHERE crate_name='demo'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let aliases = conn.prepare("SELECT imported_name,bound_name,native_scope,is_extern_crate FROM source_rust_import_targets").unwrap().query_map([], |row| Ok((row.get::<_,Option<String>>(0)?,row.get::<_,Option<String>>(1)?,row.get::<_,Option<i64>>(2)?,row.get::<_,bool>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let targets = conn
            .prepare(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::DEPENDENCY.as_str())
            .unwrap()
            .query_map(
                rusqlite::params![topology, "tk", RUST_UNIT_SUMMARY_DERIVATION_VERSION],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            targets.len(),
            1,
            "root extern alias must reach its dependency: {aliases:?}"
        );
        drop(conn);

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::trace::resolve_definition_batch_with_trace;
        let file = project.file("src/generated.rs");
        let source = "fn generated() { tk::target(); }";
        let start = source.find("target").unwrap();
        let request = DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(start),
            end_byte: Some(start + "target".len()),
        };
        let result = resolve_definition_batch_with_trace(
            analyzer.analyzer(),
            vec![request],
            file,
            std::sync::Arc::<str>::from(source),
            &brokk_bifrost_core::cancellation::CancellationToken::new(),
        );
        assert_eq!(
            result[0].0.status,
            DefinitionLookupStatus::Resolved,
            "{:?}",
            result[0].0
        );
    }

    /// The textual-macro climb reads a file's whole ancestry in one
    /// statement: the file that declares each module on the way to the crate
    /// root, with the byte of its `mod` item, and the host of an included
    /// file, with the byte of its `include!`. It used to ask one file at a
    /// time, twice (declarers and include hosts), and found each declaring
    /// container by scanning every container of the crate for the one whose
    /// path spelled the child's with one more segment; the recursion now seeks
    /// the declaring container's source rows on the child's recorded parent.
    /// Pinned on a populated store under both statistics states, with the
    /// answer each file gives.
    #[test]
    #[hardwon("53b66d27a224: macro ancestry reads were repeated for each reference")]
    fn macro_walk_ancestry_reads_every_parent_in_one_statement() {
        let lib = "macro_rules! shout { () => {} }\npub mod inner;\n";
        let inner = "pub mod deep;\npub mod host { include!(\"table.rs\"); }\n";
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='climb'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", lib)
            .file("src/inner.rs", inner)
            .file("src/inner/deep.rs", "pub fn g() {}\n")
            .file("src/table.rs", "pub fn t() {}\n")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        // The walk reads the selected mounts; stage each summary member's file as
        // one mount, the way a selected operation does.
        conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) SELECT row_number() OVER(),blob_id,'rust',rel_path FROM (SELECT DISTINCT member.blob_id,member.rel_path FROM selected_rust_unit_summaries AS units CROSS JOIN main.resolution_unit_summary_members AS member ON member.summary_id=units.summary_id)", []).unwrap();
        conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
        let parents: Vec<(String, String, Option<String>)> = conn
            .prepare("SELECT placement.module_path, member.rel_path, placement.parent_module_path
             FROM selected_rust_unit_summaries AS units
             CROSS JOIN main.rust_unit_summary_placements AS placement
              ON placement.summary_id=units.summary_id
             CROSS JOIN main.resolution_unit_summary_members AS member
              ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal
             ORDER BY placement.module_path, member.rel_path")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let row = |container: &str, file: &str, parent: Option<&str>| {
            (
                container.to_owned(),
                file.to_owned(),
                parent.map(str::to_owned),
            )
        };
        assert_eq!(
            parents,
            [
                row("crate", "src/lib.rs", None),
                row("crate::inner", "src/inner.rs", Some("crate")),
                row(
                    "crate::inner::deep",
                    "src/inner/deep.rs",
                    Some("crate::inner")
                ),
                row("crate::inner::host", "src/inner.rs", Some("crate::inner")),
                row("crate::inner::host", "src/table.rs", Some("crate::inner")),
            ]
        );
        let declared = |source: &str, item: &str| source.find(item).unwrap() as i64;
        let edge = |child: &str, parent: &str, position: i64| {
            (child.to_owned(), parent.to_owned(), position)
        };
        let lib_inner = edge("src/inner.rs", "src/lib.rs", declared(lib, "pub mod inner"));
        let text = |value: &str| Value::Text(value.to_owned());
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for (file, expected) in [
                ("src/lib.rs", vec![]),
                ("src/inner.rs", vec![lib_inner.clone()]),
                (
                    "src/inner/deep.rs",
                    vec![
                        lib_inner.clone(),
                        edge("src/inner/deep.rs", "src/inner.rs", 0),
                    ],
                ),
                (
                    "src/table.rs",
                    vec![
                        lib_inner.clone(),
                        edge("src/table.rs", "src/inner.rs", declared(inner, "include!")),
                    ],
                ),
            ] {
                let requested = serde_json::json!([file]).to_string();
                let mut answer = conn
                    .prepare_cached(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::MACRO_WALK_ANCESTRY)
                    .unwrap()
                    .query_map([&requested], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                answer.sort();
                assert_eq!(answer, expected, "{state:?} {file}");
                // Two files at once answer the union of their ancestries.
                let pair = serde_json::json!([file, "src/table.rs"]).to_string();
                let both = conn
                    .prepare_cached(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::MACRO_WALK_ANCESTRY)
                    .unwrap()
                    .query_map([&pair], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()
                    .unwrap();
                let union = expected
                    .iter()
                    .cloned()
                    .chain([
                        lib_inner.clone(),
                        edge("src/table.rs", "src/inner.rs", declared(inner, "include!")),
                    ])
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(both, union, "{state:?} {file} with src/table.rs");
                let mut pin = pinned_queries()
                    .into_iter()
                    .find(|pin| pin.name == "rust_macro_walk_ancestry")
                    .expect("the climb is a registered pin");
                pin.params = vec![text(&requested)];
                let plan = explain_pin(&conn, &pin);
                assert!(
                    // The shared walk seeks container rows by summary and canonical path.
                    plan.iter().any(|step| step.contains(
                        "SEARCH parent USING PRIMARY KEY (summary_id=? AND container_path=?)"
                    )),
                    "{state:?} {file}: the declaring container is not sought: {plan:?}"
                );
                // The recursion scans only its requested files and its own
                // queue.
                assert!(
                    !plan.iter().any(|step| (step.contains("SCAN")
                        && !step.starts_with("SCAN requested")
                        && step != "SCAN climb")
                        || step.contains("AUTOMATIC")),
                    "{state:?} {file}: {plan:?}"
                );
            }
        }
    }

    #[test]
    fn point_target_walk_closes_long_cycles_without_revisiting_each_depth() {
        // Each module re-exports the next. All 70 are reachable, including
        // those beyond the former depth cap; the last closes the cycle.
        let source = (0..70)
            .map(|index| {
                format!(
                    "pub mod m{index} {{ pub use crate::m{}::*; }}\n",
                    (index + 1) % 70
                )
            })
            .collect::<String>();
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='cycle'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", &source)
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let topology: i64 = conn
            .query_row(
                "SELECT topology_id FROM selected_rust_crates WHERE crate_name='cycle'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let sql = format!(
            "{} SELECT module_path FROM targets",
            brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::POINT_TARGETS_SQL_FOR_TEST
        );
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let modules = conn
                .prepare(&sql)
                .unwrap()
                .query_map(
                    rusqlite::params![
                        topology,
                        "crate::m0",
                        "type",
                        "Absent",
                        topology,
                        "crate::m0"
                    ],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let distinct = modules
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            let expected = (0..70)
                .map(|index| format!("crate::m{index}"))
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                distinct, expected,
                "{state:?}: every reachable module contributes inventory"
            );
            assert!(
                modules.len() <= 71,
                "{state:?}: cycle repeats targets: {modules:?}"
            );
        }
    }

    #[test]
    fn rust_crate_point_queries_have_populated_plan_pins() {
        let project = InlineTestProject::new()
            .file("Cargo.toml", "[package]\nname='point'\nversion='0.1.0'\nedition='2021'\n")
            .file("src/lib.rs", "mod inner; use inner::Thing as Alias; use inner::*; pub fn make() -> Alias { Alias }")
            .file("src/inner.rs", "pub struct Thing; pub struct Other;")
            .file("src/edited.rs", "mod inner; use inner::Other as Renamed; use inner::*; pub fn make() -> Renamed { Renamed }")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        brokk_bifrost_analysis::analyzer::store::rust_crates::register_point_export_functions(
            &conn,
        )
        .unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let (topology, key, blob): (i64, Vec<u8>, i64) = conn.query_row("SELECT topology_id,crate_key,blob_id FROM selected_rust_crate_containers WHERE container_path='crate' AND rel_path='src/lib.rs'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
        let summary_id: i64 = conn
            .query_row(
                "SELECT summary_id FROM selected_rust_unit_summaries WHERE unit_key=?1",
                [&key],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path) VALUES(0,?1,'rust','rust','src/lib.rs')", [blob]).unwrap();
        conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
        let (target_blob, target_site): (i64, i64) = conn.query_row(
            "SELECT declaration_blob_id,declaration_site FROM rust_crate_exports WHERE topology_id=?1 AND module_path='crate::inner' AND namespace='type' AND name='Thing' AND origin='declaration'",
            [topology], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        let target_blob_oid: String = conn
            .query_row(
                "SELECT blob_oid FROM blobs WHERE id=?1",
                [target_blob],
                |row| row.get(0),
            )
            .unwrap();
        let edited_blob: i64 = conn
            .query_row(
                "SELECT blobs.id FROM selected_workspace_file_versions AS files
             JOIN blobs ON blobs.lang=files.lang AND blobs.blob_oid=files.blob_oid
             WHERE files.lang='rust' AND files.rel_path='src/edited.rs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let blob_oid: String = conn
            .query_row("SELECT blob_oid FROM blobs WHERE id=?1", [blob], |row| {
                row.get(0)
            })
            .unwrap();
        let int = Value::Integer;
        let text = |value: &str| Value::Text(value.to_owned());
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            let scope_pins = [
                brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::PinnedQuery {
                    name: "rust_scope_detached_summary".to_owned(),
                    sql: format!("{DETACHED_SCOPE_CRATES}(?1)"),
                    params: vec![Value::Blob(key.clone())],
                },
                brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::PinnedQuery {
                    name: "rust_scope_dependency_closure".to_owned(),
                    sql: format!("{CLOSURE_SCOPE_MOUNTS_HEAD}(?1){CLOSURE_SCOPE_MOUNTS_TAIL}"),
                    params: vec![Value::Blob(key.clone())],
                },
            ];
            for pin in &scope_pins {
                let plan = explain_pin(&conn, pin);
                eprintln!("{state:?} {}: {plan:?}", pin.name);
                assert!(
                    plan.iter().all(|step| !step.contains("AUTOMATIC")),
                    "{state:?} {} uses an automatic index: {plan:?}",
                    pin.name
                );
                assert!(
                    plan.iter().any(|step| {
                        step.contains("SEARCH")
                            && step.contains(if pin.name == "rust_scope_dependency_closure" {
                                "selected_rust_unit_closure_summary"
                            } else {
                                "selected_rust_unit_summaries_key"
                            })
                    }),
                    "{state:?} {} must use selected shared unit versions: {plan:?}",
                    pin.name
                );
                assert!(
                    plan.iter().all(|step| {
                        !step.contains("rust_crate_dependencies")
                            && !step.contains("rust_crate_container_sources")
                    }),
                    "{state:?} {} must read summary dependencies and members: {plan:?}",
                    pin.name
                );
                if pin.name == "rust_scope_dependency_closure" {
                    assert!(
                        plan.iter().any(|step| {
                            step.contains("SEARCH closure USING")
                                && step.contains("selected_rust_unit_closure_summary")
                                && step.contains("root_unit_key=?")
                        }),
                        "{state:?} closure mounts must seek the materialized root rows: {plan:?}"
                    );
                    assert!(
                        plan.iter().any(|step| {
                            step.contains("SEARCH members USING PRIMARY KEY (summary_id=?)")
                        }),
                        "{state:?} closure mounts must seek selected summary members: {plan:?}"
                    );
                }
            }
            for mut pin in pinned_queries().into_iter().filter(|pin| {
                pin.name.starts_with("rust_point_") || pin.name.starts_with("rust_published_")
            }) {
                pin.params = match pin.name.as_str() {
                    "rust_point_macro_import_target_range" => vec![int(blob), int(0)],
                    "rust_point_boundary_import_names" => vec![int(0), int(0)],
                    "rust_point_imported_macro_definition" => {
                        vec![text("src/lib.rs"), int(0), text("Macro")]
                    }
                    "rust_point_demand_modules" => {
                        vec![int(blob), text("src/lib.rs"), text(&format!("[{topology}]"))]
                    }
                    "rust_point_demand_export_node" => vec![int(blob), int(0)],
                    "rust_point_demand_reverse_export_names" => {
                        vec![int(target_blob), int(target_site), text("type"), int(0)]
                    }
                    "rust_point_demand_overlay_exports" => {
                        vec![int(topology), text("crate"), text("type")]
                    }
                    "rust_point_demand_prefix_modules" => vec![int(0), int(0), int(topology)],
                    "rust_point_unresolved_trait_impl_files" => vec![
                        text("Unbound"),
                        int(RUST_UNIT_SUMMARY_DERIVATION_VERSION),
                    ],
                    "rust_point_item_macro_decisions" => {
                        vec![text(&blob_oid), text("src/lib.rs")]
                    }
                    "rust_point_summary_importing_files" => {
                        vec![text(&target_blob_oid), text("src/inner.rs")]
                    }
                    "rust_point_selected_macro_item_unit" => vec![
                        int(0),
                        Value::Null,
                        Value::Null,
                        int(brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::semantic_role_code(
                            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweredSemanticRole::Definition,
                        )),
                    ],
                    "rust_point_prefix_spellings" => vec![text("[[0,0]]")],
                    "rust_point_naming" => vec![text("src/lib.rs")],
                    "rust_point_workspace_access_roots" => vec![int(blob)],
                    "rust_point_overlay_import_targets" => vec![int(blob), int(0)],
                    "rust_point_file_blob"
                    | "rust_point_gap_details"
                    | "rust_point_macro_hosts"
                    | "rust_point_macro_gated_unmounted_file" => {
                        vec![text("src/lib.rs")]
                    }
                    "rust_point_access_placements"
                    | "rust_point_access_reference_placements" => {
                        vec![Value::Blob(key.clone()), int(blob), Value::Null]
                    }
                    "rust_point_access_memberships" => {
                        vec![Value::Blob(key.clone()), int(blob)]
                    }
                    "rust_point_access_visibility" => vec![
                        int(topology),
                        text("crate"),
                        int(topology),
                        text("crate"),
                        text("private"),
                        Value::Null,
                    ],
                    "rust_point_crate" | "rust_point_cfg" => vec![Value::Blob(key.clone())],
                    "rust_point_module_placements" => vec![int(blob), text("crate")],
                    "rust_point_file_crates" => vec![int(blob), text("src/lib.rs")],
                    "rust_point_scopes" => vec![int(blob), int(0)],
                    "rust_point_import_inventory" => vec![int(blob)],
                    "rust_point_modules" => vec![int(summary_id)],
                    "rust_point_gaps" => vec![int(topology)],
                    "rust_point_named" => vec![
                        int(topology),
                        text("crate"),
                        int(blob),
                        int(0),
                        text("Alias"),
                        text("type"),
                        int(blob),
                    ],
                    "rust_point_globs" => vec![int(topology), text("crate"), int(blob), int(0)],
                    "rust_point_topology_prelude" => vec![int(topology)],
                    "rust_point_dependency" => vec![
                        int(topology),
                        text("point"),
                        int(RUST_UNIT_SUMMARY_DERIVATION_VERSION),
                    ],
                    "rust_point_dependency_boundary" => vec![text("point")],
                    "rust_point_import_root_name" => vec![int(blob), int(0), text("Thing")],
                    "rust_published_macro_prelude" => vec![int(topology),text("crate"),text("macro"),text("helper"),int(topology),text("crate")],
                    "rust_published_open_inventory" => {
                        vec![int(topology), text("crate"), text("type"), text("Thing"), int(topology), text("crate")]
                    }
                    "rust_point_unindexed_scope" => {
                        vec![int(topology), text("crate::inner"), text("macro"), text("helper"), int(topology), text("crate")]
                    }
                    "rust_point_open_route" => {
                        vec![int(topology), text("crate"), text("inner")]
                    }
                    "rust_point_binding_target_topology" => vec![text(&crate::analyzer::canonical_hash::lower_hex_string(key.as_slice().try_into().unwrap()))],
                    "rust_point_binding_inventory" => vec![
                        int(topology), text("crate"), text("type"), text("Renamed"), int(0), int(0),
                    ],
                    "rust_point_unknown_import_inventory" => vec![
                        int(topology), text("crate"), text("Renamed"), text("type"), int(0), int(0),
                    ],
                    "rust_published_module_prefix" | "rust_published_binding_exact" => vec![
                        int(topology),
                        text("crate"),
                        text("type"),
                        text("Thing"),
                        int(topology),
                        text("crate"),
                    ],
                    "rust_point_parent" => vec![int(topology), text("crate::inner")],
                    "rust_point_container_declaration" => {
                        vec![int(topology), text("crate::inner")]
                    }
                    "rust_point_anchored_import_binds" => vec![int(0), text("Alias")],
                    "rust_published_root_reexport" => vec![int(topology), text("crate"), text("type"), text("Alias"), int(topology), text("crate")],
                    "rust_point_module_import_prefix_starts" => vec![int(topology), text("crate"), int(blob), int(0), text("alias"), text("type"), int(blob)],
                    "rust_point_macro_gated_import_route" => vec![
                        int(topology),
                        text("crate"),
                        int(blob),
                        int(0),
                        text("Alias"),
                        int(blob),
                    ],
                    "rust_point_generated_surface_prefix"
                    | "rust_point_generated_surface_module_prefix"
                    | "rust_point_generated_surface_module_declaration_prefix" => {
                        vec![int(0), text("Thing")]
                    }
                    "rust_point_generated_surface_source_module_prefix" => {
                        vec![int(blob), text("Thing"), text("src/lib.rs")]
                    }
                    "rust_point_derive_helper_conditions" => vec![int(3), text("[[0,null]]")],
                    "rust_point_external_binding" => vec![
                        int(topology), text("crate::inner"), text("type"), text("Thing"), int(topology), text("crate"),
                        int(brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::namespace_code(brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type)),
                    ],
                    "rust_published_export" => vec![
                        int(topology),
                        text("crate::inner"),
                        text("type"),
                        text("Thing"),
                        int(topology),
                        text("crate"),
                    ],
                    "rust_point_definition_module" => {
                        vec![int(blob), int(0), int(topology), text("crate")]
                    }
                    "rust_point_macro_item_module" => {
                        vec![
                            int(blob),
                            int(0),
                            int(topology),
                            text("crate"),
                            text("inner"),
                        ]
                    }
                    "rust_point_macro_item_hosts" => vec![text("src/lib.rs")],
                    "rust_point_named_macro_module" => {
                        vec![int(topology), text("crate"), text("inner")]
                    }
                    "rust_point_macro_item_name" => vec![int(blob), int(0)],
                    "rust_point_macro_items_present" => Vec::new(),
                    "rust_point_nominal_type_target" | "rust_point_block_local_type_target" => {
                        vec![int(0), int(0)]
                    }
                    "rust_point_block_local_type_gap_for_target" => vec![
                        int(0),
                        int(0),
                        int(0),
                        int(brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(
                            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin::Extracted(
                                brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedScopeOrBinder,
                            ),
                        )),
                    ],
                    "rust_point_trait_visible_at" | "rust_point_trait_impls_visible_at" => vec![
                        int(target_blob),
                        int(target_site),
                        int(topology),
                        text("crate"),
                        text("src/inner.rs"),
                        int(0),
                        int(0),
                        int(RUST_UNIT_SUMMARY_DERIVATION_VERSION),
                    ],
                    "rust_point_trait_impl_member_at" => vec![
                        int(0),
                        int(0),
                        int(target_blob),
                        int(target_site),
                        text("src/inner.rs"),
                        int(target_blob),
                        int(target_site),
                        text("src/inner.rs"),
                        int(RUST_UNIT_SUMMARY_DERIVATION_VERSION),
                    ],
                    "rust_point_store_trait_impl_rows"
                    | "rust_point_store_trait_impl_spellings"
                    | "rust_point_store_traits_implemented_by"
                    | "rust_point_store_types_implementing"
                    | "rust_point_store_traits_of_impl" => {
                        vec![
                            text(&blob_oid),
                            int(0),
                            text("src/lib.rs"),
                            int(RUST_UNIT_SUMMARY_DERIVATION_VERSION),
                        ]
                    }
                    "rust_point_reference_module_placements"
                    | "rust_point_owner_declaration" => vec![int(0), int(0)],
                    "rust_point_impl_item_traits" => vec![
                        int(0),
                        int(0),
                        int(RUST_UNIT_SUMMARY_DERIVATION_VERSION),
                    ],
                    "rust_point_external_type_identity" => {
                        let namespace = brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::namespace_code(brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type);
                        let token: i64 = conn.query_row(
                            "SELECT json_extract(binding.end_fixed_key,'$[#-2][0]') FROM resolution_paths binding JOIN resolution_identities identity ON identity.id=binding.root_terminal WHERE binding.blob_id=?1 AND binding.start_node<>-1 AND binding.end_node=-1 AND binding.end_open_tail=1 AND identity.namespace=?2 LIMIT 1",
                            rusqlite::params![blob, namespace], |row| row.get(0)).unwrap();
                        vec![int(0), int(token), int(namespace)]
                    }
                    "rust_point_reference_names_macro_module" => vec![int(0), int(0), text("inner")],
                    "rust_point_reference_names_workspace_crate" => {
                        vec![
                            int(0),
                            int(0),
                            text("inner"),
                            int(RUST_UNIT_SUMMARY_DERIVATION_VERSION),
                        ]
                    }
                    name if name.starts_with("rust_point_targets_") => {
                        let mut params = pin.params.clone();
                        params[0] = int(topology);
                        params[4] = int(topology);
                        params
                    }
                    name => panic!("populate the new point query's parameters: {name}"),
                };
                let mut parameter_sets = vec![pin.params.clone()];
                if pin.name == "rust_point_named" {
                    let mut selected = pin.params.clone();
                    selected[4] = text("Renamed");
                    selected[6] = int(edited_blob);
                    parameter_sets.push(selected);
                }
                for parameters in parameter_sets {
                    pin.params = parameters;
                    if pin.name == "rust_point_named" {
                        let names = conn
                            .prepare_cached(&pin.sql)
                            .unwrap()
                            .query_map(rusqlite::params_from_iter(pin.params.iter()), |row| {
                                row.get::<_, String>(2)
                            })
                            .unwrap()
                            .collect::<rusqlite::Result<Vec<_>>>()
                            .unwrap();
                        let expected = if pin.params[6] == int(blob) {
                            "Thing"
                        } else {
                            "Other"
                        };
                        assert_eq!(names, [expected], "{state:?} {:?}", pin.params);
                    }
                    let plan = explain_pin(&conn, &pin);
                    if pin.name.starts_with("rust_published_") {
                        assert!(
                            plan.iter().all(|step| !step.contains("AUTOMATIC")),
                            "{state:?}: {} must use declared indexes: {plan:?}",
                            pin.name
                        );
                    }
                    eprintln!("{state:?} {}: {plan:?}", pin.name);
                    if pin.name == "rust_point_external_binding" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH route USING PRIMARY KEY (summary_id=? AND module_path=? AND bound_name=?)")
                            }),
                            "{state:?}: {} must seek named Rust re-export routes: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_import_routes_binder")
                            }),
                            "{state:?}: {} must seek Rust import binders by member/scope/name: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().all(|step| !step.contains("AUTOMATIC")),
                            "{state:?}: {} must not build automatic route indexes: {plan:?}",
                            pin.name
                        );
                    }
                    if pin.name == "rust_point_summary_importing_files" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "rust_resolution_unit_summary_import_routes_target_identity",
                                )
                            }),
                            "{state:?} reverse named imports must use the target identity index: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| !step.contains("AUTOMATIC")),
                            "{state:?} reverse importer lookup must not build automatic indexes: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| !step.contains("SCAN versions")),
                            "{state:?} reverse importer lookup must seek the live target summary instead of scanning versions: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_imported_macro_definition" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob (blob_id=?)")
                            }),
                            "{state:?} imported macro lookup must seek selected members from the path-selected blob: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_import_routes_site")
                            }),
                            "{state:?} imported macro lookup must seek named route sites: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH export USING COVERING INDEX rust_summary_decl_export_endpoint (summary_id=? AND module_path=? AND namespace=? AND name=?)")
                            }),
                            "{state:?} imported macro lookup must seek target exports by unit/module/name: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH route USING PRIMARY KEY (summary_id=? AND member_ordinal=? AND source_import_id=? AND route_ordinal=?)")
                            }),
                            "{state:?} imported macro glob lookup must seek its Rust summary route: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_imports")
                                    && !step.contains("rust_crate_glob_imports")
                                    && !step.contains("rust_crate_exports")
                                    && !step.contains("rust_crate_container_sources")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?} imported macro lookup must use only live summary rows: {plan:?}"
                        );
                    }
                    if matches!(
                        pin.name.as_str(),
                        "rust_point_access_placements"
                            | "rust_point_access_reference_placements"
                            | "rust_point_module_placements"
                    ) {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob (blob_id=?")
                            }),
                            "{state:?} placement lookup must seek the materialized blob index: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_boundary_import_names" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_placements_member")
                            }),
                            "{state:?} boundary import names must seek member placements: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH gap USING PRIMARY KEY (summary_id=? AND gap_kind=? AND subject=?)")
                            }),
                            "{state:?} boundary import names must seek a summary gap by exact subject: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_gaps")
                                    && !step.contains("rust_crate_container_sources")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?} boundary import names must use selected summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_demand_reverse_export_names" {
                        for index in [
                            "rust_resolution_unit_summary_reexport_routes_target_identity",
                            "rust_resolution_unit_summary_glob_reexport_routes_target_identity",
                            "rust_resolution_unit_summary_import_routes_target_identity",
                        ] {
                            assert!(
                                plan.iter().any(|step| step.contains(index)),
                                "{state:?}: reverse demand closure must seek {index}: {plan:?}"
                            );
                        }
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_reexport_routes")
                                    && !step.contains("rust_crate_glob_reexport_routes")
                                    && !step.contains("rust_crate_imports")
                            }),
                            "{state:?}: reverse demand closure must use summary route rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_demand_prefix_modules" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_dependencies")
                            }),
                            "{state:?}: prefix reachability must traverse shared summary dependencies: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "SEARCH modules USING PRIMARY KEY (summary_id=? AND container_path=?) LEFT-JOIN",
                                )
                            }),
                            "{state:?}: prefix module lookup must seek Rust summary containers: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_dependencies")
                                    && !step.contains("rust_crate_containers")
                            }),
                            "{state:?}: prefix module lookup must use live summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_item_macro_decisions" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob")
                            }),
                            "{state:?}: item macro placements must seek members by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH decided USING PRIMARY KEY (summary_id=? AND member_ordinal=? AND invocation_occurrence_id=?)")
                            }),
                            "{state:?}: macro decisions must seek the selected member invocation: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_decided_item_macros")
                                    && !step.contains("rust_crate_topologies")
                            }),
                            "{state:?}: item macro decisions must use live summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_unresolved_trait_impl_files" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "rust_resolution_unit_summary_trait_endpoints_unresolved",
                                )
                            }),
                            "{state:?}: unresolved trait candidates must seek by role and spelling: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_versions_summary")
                            }),
                            "{state:?}: unresolved trait candidates must validate the shared live version: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_unresolved_trait_impls")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: unresolved trait candidates use published summary rows without automatic indexes: {plan:?}"
                        );
                    }
                    if matches!(
                        pin.name.as_str(),
                        "rust_point_trait_visible_at" | "rust_point_trait_impls_visible_at"
                    ) {
                        for index in [
                            "rust_resolution_unit_summary_exports_declaration",
                            "rust_resolution_unit_summary_exports_alias_target",
                            "rust_resolution_unit_summary_import_routes_target_identity",
                            "rust_resolution_unit_summary_glob_imports_target_identity",
                        ] {
                            assert!(
                                plan.iter().any(|step| step.contains(index)),
                                "{state:?}: {} must seek {index}: {plan:?}",
                                pin.name
                            );
                        }
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_trait_impls")
                                    && !step.contains("rust_crate_exports")
                                    && !step.contains("rust_crate_imports")
                                    && !step.contains("rust_crate_glob_imports")
                                    && !step.contains("rust_crate_versions")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: {} must use only live summary rows: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH rust_versions USING PRIMARY KEY")
                            }),
                            "{state:?}: {} must seek topology ids from the Rust summary crosswalk: {plan:?}",
                            pin.name
                        );
                    }
                    if matches!(
                        pin.name.as_str(),
                        "rust_point_trait_impl_member_at" | "rust_point_impl_item_traits"
                    ) {
                        let endpoint_index = if pin.name == "rust_point_trait_impl_member_at" {
                            "rust_resolution_unit_summary_trait_endpoints_target"
                        } else {
                            "rust_resolution_unit_summary_trait_endpoints_impl"
                        };
                        assert!(
                            plan.iter().any(|step| step.contains(endpoint_index)),
                            "{state:?}: {} must seek endpoints through {endpoint_index}: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_trait_impls")
                                    && !step.contains("rust_crate_versions")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: {} must use live summary endpoints: {plan:?}",
                            pin.name
                        );
                    }
                    if pin.name.starts_with("rust_point_store_trait_")
                        || pin.name.starts_with("rust_point_store_types_implementing")
                    {
                        let endpoint_index = if pin.name == "rust_point_store_traits_of_impl" {
                            "rust_resolution_unit_summary_trait_endpoints_impl"
                        } else {
                            "rust_resolution_unit_summary_trait_endpoints_target"
                        };
                        assert!(
                            plan.iter().any(|step| step.contains(endpoint_index)),
                            "{state:?}: {} must seek through {endpoint_index}: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_trait_impls")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: {} must use live Rust summary endpoints without automatic indexes: {plan:?}",
                            pin.name
                        );
                    }
                    if pin.name == "rust_point_selected_macro_item_unit" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "rust_resolution_unit_summary_generated_names_declaration",
                                )
                            }),
                            "{state:?}: selected macro items must seek by declaration: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob")
                            }),
                            "{state:?}: selected macro items must seek their live member by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter()
                                .all(|step| !step.contains("rust_crate_macro_items")),
                            "{state:?}: selected macro items must use Rust summary names: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_demand_modules" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob")
                            }),
                            "{state:?}: module enumeration must seek selected summary members by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_placements_member")
                            }),
                            "{state:?}: module enumeration must seek placements by member: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_container_sources")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: module enumeration must use live summary placements: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_owner_declaration" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("resolution_unit_summary_members_blob")
                            }),
                            "{state:?}: declaration membership must seek selected summary members by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter()
                                .all(|step| !step.contains("rust_crate_container_sources")),
                            "{state:?}: declaration membership must use live summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_dependency_boundary"
                        || pin.name == "rust_point_dependency"
                    {
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_dependencies")
                                    && !step.contains("rust_crate_topologies")
                            }),
                            "{state:?}: dependency names and boundaries must use live summary rows: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains(
                                    "SEARCH resolution_unit_summary_dependency_names USING",
                                ) && (step.contains(
                                    "resolution_unit_summary_dependency_names_owner_name",
                                ) || step
                                    .contains("resolution_unit_summary_dependency_names_name"))
                                    && step.contains("summary_id=?")
                                    && step.contains("name=?")
                            }),
                            "{state:?}: dependency lookup must seek the Rust extern-name crosswalk: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_topology_prelude" {
                        assert!(
                            plan.iter()
                                .all(|step| !step.contains("rust_crate_topologies")),
                            "{state:?}: edition and prelude must come from selected Rust summary contexts: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_reference_names_workspace_crate" {
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_dependencies")
                                    && !step.contains("rust_crate_imports")
                                    && !step.contains("rust_crate_container_sources")
                                    && !step.contains("rust_crate_topologies")
                                    && !step.contains("rust_crate_versions")
                                    && !step.contains("SCAN versions")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: workspace crate names must use live summary dependencies and routes: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_versions_topology")
                            }),
                            "{state:?}: requester crate selection must seek the live summary topology crosswalk: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_import_routes_binder")
                            }),
                            "{state:?}: workspace crate aliases must seek summary import routes: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_reference_names_macro_module" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_generated_names_module")
                            }),
                            "{state:?}: macro module names must seek the selected summary's generated-name rows: {plan:?}"
                        );
                        assert!(
                            plan.iter()
                                .all(|step| !step.contains("rust_crate_macro_items")),
                            "{state:?}: macro module names must use live Rust summary rows: {plan:?}"
                        );
                    }
                    if pin.name == "rust_published_export" {
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("SEARCH exports USING PRIMARY KEY (summary_id=? AND module_path=? AND namespace=? AND name=?)")
                                    || step.contains("SEARCH exports USING INDEX rust_summary_decl_export_endpoint (summary_id=? AND module_path=? AND namespace=? AND name=?)")
                            }),
                            "{state:?}: exports must seek a selected unit/module/name: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| {
                                step.contains("rust_resolution_unit_summary_generated_names_name")
                            }),
                            "{state:?}: generated names must use their name index: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_overlay_import_targets" {
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("resolution_unit_summary_members_blob")),
                            "{state:?}: overlay import source must seek shared membership by blob: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| { step.contains(
                                "SEARCH route USING COVERING INDEX rust_resolution_unit_summary_import_routes_site (summary_id=? AND member_ordinal=? AND import_id=? AND route_ordinal=?)"
                            ) || step.contains("SEARCH route USING PRIMARY KEY (summary_id=? AND member_ordinal=? AND import_id=? AND route_ordinal=?)") }),
                            "{state:?}: overlay import routes must seek by summary/member/import/route: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| !step.contains("AUTOMATIC")),
                            "{state:?}: overlay import route lookup must not build an automatic index: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_parent" {
                        assert!(
                            plan.iter().any(|step| step.contains(
                                "SEARCH placement USING PRIMARY KEY (summary_id=? AND container_path=?)"
                            )),
                            "{state:?}: parent module placement must use its summary/path key: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_container_declaration" {
                        assert!(
                            plan.iter().any(|step| step.contains(
                                "SEARCH child USING PRIMARY KEY (summary_id=? AND container_path=?)"
                            )) && plan.iter().any(|step| step.contains(
                                "SEARCH parent USING PRIMARY KEY (summary_id=? AND container_path=?)"
                            )),
                            "{state:?}: module declaration placements must use their summary/path keys: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_dependency" {
                        assert!(
                            plan.iter().any(|step| step
                                .contains("rust_resolution_unit_summary_versions_topology")),
                            "{state:?}: owner must use the live summary topology crosswalk index: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| step
                                .contains("resolution_unit_summary_dependency_names_owner_name")
                                || step.contains("resolution_unit_summary_dependency_names_name")),
                            "{state:?}: dependency extern names must use their summary index: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| {
                                !step.contains("rust_crate_versions")
                                    && !step.contains("SCAN versions")
                                    && !step.contains("SCAN shared_version")
                                    && !step.contains("AUTOMATIC")
                            }),
                            "{state:?}: dependency targets must come from selected live summaries without scans or automatic indexes: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_macro_import_target_range" {
                        assert!(
                            plan.iter().any(|step| step.contains(
                                "SEARCH source_occurrence_arenas USING PRIMARY KEY (blob_id=?)"
                            )),
                            "{state:?}: {plan:?}"
                        );
                        assert!(
                            !plan
                                .iter()
                                .any(|step| step.contains("SCAN") || step.contains("json_each")),
                            "{state:?}: {plan:?}"
                        );
                    }
                    assert!(
                        !plan.iter().any(|step| step.contains("SCAN exports")),
                        "{state:?} {} scans exports: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan.iter().any(|step| step.contains("AUTOMATIC")),
                        "{state:?} {} uses an automatic index: {plan:?}",
                        pin.name
                    );
                    assert!(
                        plan.iter().any(|step| step.contains("SEARCH")),
                        "{state:?} {} has no indexed lookup: {plan:?}",
                        pin.name
                    );
                    if pin.name == "rust_graph_crate_member_files" {
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("selected_rust_unit_summaries_key")),
                            "{state:?} {} must seek the active unit version: {plan:?}",
                            pin.name
                        );
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("resolution_unit_summary_members")),
                            "{state:?} {} must seek shared summary members: {plan:?}",
                            pin.name
                        );
                    }
                    if pin.name == "rust_point_file_crates" {
                        assert!(
                            plan.iter()
                                .any(|step| step.contains("resolution_unit_summary_members_blob")),
                            "{state:?} {} must seek members by blob: {plan:?}",
                            pin.name
                        );
                    }
                    // The derive-helper read is driven by the mounts a lookup
                    // reached: the mount is sought by ordinal and the
                    // candidate declarations come from the partial index, so
                    // the only scans are the two `json_each` tables and the
                    // placement view's own scope-alignment recursion.
                    if pin.name == "rust_point_derive_helper_conditions" {
                        assert!(
                            plan.iter().any(|step| step
                                .contains("source_rust_macro_inputs_conditional_frontier")),
                            "{state:?} conditional frontiers must use their partial index: {plan:?}"
                        );
                        assert!(
                            plan.iter().any(|step| step
                                .contains("source_rust_declaration_properties_derive_helpers")),
                            "{state:?} derive-helper read skips its partial index: {plan:?}"
                        );
                        assert!(
                            plan.iter().all(|step| !step.starts_with("SCAN ")
                                || step.contains("reached")
                                || step.contains("helper")
                                || step == "SCAN CONSTANT ROW"
                                || step == "SCAN aligned"),
                            "{state:?} derive-helper read scans a table: {plan:?}"
                        );
                    }
                    if pin.name == "rust_point_named" {
                        assert!(
                            !plan.iter().any(|step| step.contains("SCAN imports")),
                            "{state:?} {:?} scans import inventory: {plan:?}",
                            pin.params
                        );
                    }
                    // The implemented-trait read keys every table by the one
                    // mount and semantic it asks about. The only scans allowed
                    // are the placement view's own scope-alignment recursion.
                    if matches!(
                        pin.name.as_str(),
                        "rust_point_reference_module_placements"
                            | "rust_point_owner_declaration"
                            | "rust_point_impl_item_traits"
                            | "rust_point_trait_impl_member_at"
                            | "rust_point_external_type_identity"
                    ) {
                        assert!(
                            !plan.iter().any(|step| step.starts_with("SCAN ")
                                && step != "SCAN CONSTANT ROW"
                                && step != "SCAN aligned"),
                            "{state:?} {} scans a table: {plan:?}",
                            pin.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn rust_unit_membership_and_graph_queries_have_indexed_plans() {
        let project = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='pin'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub fn item() {}\n")
            .build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context(&conn);
        brokk_bifrost_analysis::analyzer::store::rust_crates::register_point_export_functions(
            &conn,
        )
        .unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        let (key, blob): (Vec<u8>, i64) = conn.query_row(
            "SELECT crate_key,blob_id FROM selected_rust_crate_containers WHERE rel_path='src/lib.rs' LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        let summary_id: i64 = conn
            .query_row(
                "SELECT summary_id FROM selected_rust_unit_summaries WHERE unit_key=?1",
                [&key],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,persisted_relative_path) VALUES(0,?1,'rust','rust','src/lib.rs')", [blob]).unwrap();
        conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
        let member_files = pinned("rust_graph_crate_member_files");
        let graph_keys = pinned("rust_graph_crate_keys");
        let file_crates = pinned("rust_point_file_crates");
        let mut cfg = pinned("rust_point_cfg");
        let mut modules = pinned("rust_point_modules");
        let mut module_placements = pinned("rust_point_module_placements");
        let graph_definitions = pinned("rust_graph_definitions");
        let mut member_files = member_files;
        member_files.params = vec![rusqlite::types::Value::Blob(key.clone())];
        let mut file_crates = file_crates;
        file_crates.params = vec![
            rusqlite::types::Value::Integer(blob),
            rusqlite::types::Value::Text("src/lib.rs".to_owned()),
        ];
        cfg.params = vec![rusqlite::types::Value::Blob(key.clone())];
        modules.params = vec![rusqlite::types::Value::Integer(summary_id)];
        module_placements.params = vec![
            rusqlite::types::Value::Integer(blob),
            rusqlite::types::Value::Text("crate".to_owned()),
        ];
        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for pin in [
                &graph_keys,
                &member_files,
                &file_crates,
                &cfg,
                &modules,
                &module_placements,
                &graph_definitions,
            ] {
                let plan = explain_pin(&conn, pin);
                eprintln!("{state:?} {}: {plan:?}", pin.name);
                assert!(
                    !plan.iter().any(|step| step.contains("AUTOMATIC")),
                    "{state:?} {} uses an automatic index: {plan:?}",
                    pin.name
                );
                assert!(
                    pin.name == "rust_graph_crate_keys"
                        || plan.iter().any(|step| step.contains("SEARCH")),
                    "{state:?} {} has no indexed seek: {plan:?}",
                    pin.name
                );
            }
            let member_plan = explain_pin(&conn, &member_files);
            let keys_plan = explain_pin(&conn, &graph_keys);
            assert!(
                keys_plan
                    .iter()
                    .any(|step| step.contains("SCAN selected_rust_unit_summaries USING COVERING INDEX selected_rust_unit_summaries_key")),
                "{state:?} crate key enumeration must walk the selected unit key index: {keys_plan:?}"
            );
            assert!(
                member_plan.iter().any(|step| {
                    step.contains("SEARCH units USING INDEX selected_rust_unit_summaries_key")
                        && step.contains("unit_key=?")
                }),
                "{state:?} member enumeration must seek the active unit version: {member_plan:?}"
            );
            assert!(
                member_plan.iter().any(|step| {
                    step.contains("SEARCH members USING PRIMARY KEY (summary_id=?)")
                }),
                "{state:?} member enumeration must seek shared members: {member_plan:?}"
            );
            let file_plan = explain_pin(&conn, &file_crates);
            assert!(
                file_plan
                    .iter()
                    .any(|step| step.contains("resolution_unit_summary_members_blob")),
                "{state:?} file-to-crate lookup must seek members by blob: {file_plan:?}"
            );
            let cfg_plan = explain_pin(&conn, &cfg);
            assert!(
                cfg_plan.iter().any(|step| {
                    step.contains("SEARCH units USING INDEX selected_rust_unit_summaries_key")
                        && step.contains("unit_key=?")
                }),
                "{state:?} Rust cfg lookup must seek the selected unit version: {cfg_plan:?}"
            );
            assert!(
                cfg_plan
                    .iter()
                    .any(|step| { step.contains("SEARCH contexts USING INTEGER PRIMARY KEY") }),
                "{state:?} Rust cfg lookup must seek the summary context: {cfg_plan:?}"
            );
            let graph_plan = explain_pin(&conn, &graph_definitions);
            assert!(
                graph_plan.iter().any(|step| step == "SCAN units"),
                "{state:?} graph definition enumeration must enumerate only materialized selected units: {graph_plan:?}"
            );
            assert!(
                graph_plan.iter().any(|step| {
                    step.contains("SEARCH members USING PRIMARY KEY (summary_id=?)")
                }),
                "{state:?} graph definition enumeration must seek summary members: {graph_plan:?}"
            );
            let modules_plan = explain_pin(&conn, &modules);
            assert!(
                modules_plan.iter().any(|step| {
                    step.contains("SEARCH root USING INDEX selected_rust_unit_summaries_summary")
                        && step.contains("summary_id=?")
                }),
                "{state:?} module enumeration must seek its live summary: {modules_plan:?}"
            );
            assert!(
                modules_plan.iter().any(|step| {
                    step.contains("SEARCH graph USING INDEX selected_rust_unit_closure_summary")
                }),
                "{state:?} module dependency closure must seek materialized root rows: {modules_plan:?}"
            );
            assert!(
                modules_plan
                    .iter()
                    .any(|step| step.contains("SEARCH p USING PRIMARY KEY (summary_id=?)")),
                "{state:?} module enumeration must seek Rust placements by the selected closure summary: {modules_plan:?}"
            );
            let module_placements_plan = explain_pin(&conn, &module_placements);
            assert!(
                module_placements_plan
                    .iter()
                    .any(|step| step.contains("resolution_unit_summary_members_blob (blob_id=?)")),
                "{state:?} module placement lookup must seek the materialized blob index: {module_placements_plan:?}"
            );
        }
    }

    /// An override never ties with the method it overrides. Here the trait's
    /// own module holds an item macro the producer cannot expand, so the
    /// impl's trait path names `Op` through a lookup that is not proven
    /// exhaustive and the impl's trait frontier is incomplete. The frontier
    /// still names `Op`, so the trait-item replay skips `Op` and answers the
    /// override alone. Found by the point-answer census (2026-09-24): counting
    /// such an item as one of an unnameable trait made the replay find `Op`
    /// again and report a false E0034 tie. rustc calls the override.
    #[test]
    #[hardwon("2150d85feb2f: an impl override was counted twice as an E0034 tie")]
    fn an_override_does_not_tie_with_the_method_it_overrides() {
        let source = "unexpanded_item_macro!();\ntrait Op {\n    fn name(&self) -> u8 {\n        0\n    }\n}\nstruct Service;\nimpl Op for Service {\n    fn name(&self) -> u8 {\n        1\n    }\n}\n\nfn caller(service: Service) {\n    service.name();\n}\n";
        let outcome = qualified_member_outcome(&[("t.rs", source)], "t.rs", "service.name");
        let names = outcome
            .definitions
            .iter()
            .map(|unit| unit.short_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["Service.name".to_owned()], "{outcome:?}");
        assert!(
            outcome
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.kind != "unordered_candidates"),
            "{outcome:?}"
        );
    }

    /// A two-crate workspace in the shape the point-answer census found the
    /// cross-crate tie on: `core-crate` declares `CodeUnitIndex`, `analysis`
    /// implements it for `JavaAnalyzer` in `analyzer/java/mod.rs` and names it
    /// through `analyzer_mod`'s re-export, and `java_prelude` precedes the
    /// impl. `analysis` calls the method from the impl's file, from another
    /// file of its library, and from an integration test.
    fn cross_crate_override_files(analysis_mod: &str, java_prelude: &str) -> Vec<(String, String)> {
        [
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"core\", \"analysis\"]\nresolver = \"2\"\n".to_owned(),
            ),
            (
                "core/Cargo.toml",
                "[package]\nname = \"core-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
                    .to_owned(),
            ),
            ("core/src/lib.rs", "pub mod analyzer;\n".to_owned()),
            ("core/src/analyzer/mod.rs", "pub mod code_unit_index;\n".to_owned()),
            (
                "core/src/analyzer/code_unit_index.rs",
                "pub trait CodeUnitIndex {\n    fn get_definitions(&self) -> u8 {\n        0\n    }\n}\n"
                    .to_owned(),
            ),
            (
                "analysis/Cargo.toml",
                "[package]\nname = \"analysis\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncore-crate = { path = \"../core\" }\n"
                    .to_owned(),
            ),
            ("analysis/src/lib.rs", "pub mod analyzer;\nmod caller;\n".to_owned()),
            (
                "analysis/src/caller.rs",
                "use crate::analyzer::java::JavaAnalyzer;\nuse crate::analyzer::CodeUnitIndex;\n\nfn same_crate(same: JavaAnalyzer) {\n    same.get_definitions();\n}\n"
                    .to_owned(),
            ),
            ("analysis/src/analyzer/mod.rs", analysis_mod.to_owned()),
            ("analysis/src/analyzer/java/tests.rs", "fn t() {}\n".to_owned()),
            (
                "analysis/src/analyzer/java/mod.rs",
                format!(
                    "pub struct JavaAnalyzer;\n{java_prelude}\nimpl CodeUnitIndex for JavaAnalyzer {{\n    fn get_definitions(&self) -> u8 {{\n        1\n    }}\n}}\n\nfn same_file(analyzer: JavaAnalyzer) {{\n    analyzer.get_definitions();\n}}\n"
                ),
            ),
            (
                "analysis/tests/t.rs",
                "use analysis::analyzer::java::JavaAnalyzer;\nuse analysis::analyzer::CodeUnitIndex;\n\nfn integration(ext: JavaAnalyzer) {\n    ext.get_definitions();\n}\n"
                    .to_owned(),
            ),
        ]
        .into_iter()
        .map(|(name, contents)| (name.to_owned(), contents))
        .collect()
    }

    const MODULE_IMPORT_REEXPORT: &str = "pub mod java;\nuse core_crate::analyzer::{code_unit_index};\npub use code_unit_index::CodeUnitIndex;\n";

    /// The override answers alone, with no tie reason, from every caller.
    fn assert_override_alone(analysis_mod: &str, java_prelude: &str, callers: &[(&str, &str)]) {
        let files = cross_crate_override_files(analysis_mod, java_prelude);
        let files = files
            .iter()
            .map(|(name, contents)| (name.as_str(), contents.as_str()))
            .collect::<Vec<_>>();
        for (caller, path) in callers {
            let outcome = qualified_member_outcome(&files, caller, path);
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                names,
                vec!["JavaAnalyzer.get_definitions".to_owned()],
                "{caller}: {outcome:?}"
            );
            assert!(
                outcome.diagnostics.iter().all(|diagnostic| {
                    diagnostic.kind != "unordered_candidates"
                        && !diagnostic.message.contains("inconsistent_precedence")
                }),
                "{caller}: {outcome:?}"
            );
        }
    }

    const ALL_CALLERS: [(&str, &str); 3] = [
        (
            "analysis/src/analyzer/java/mod.rs",
            "analyzer.get_definitions",
        ),
        ("analysis/src/caller.rs", "same.get_definitions"),
        ("analysis/tests/t.rs", "ext.get_definitions"),
    ];

    /// An impl item's trait is the one crate derivation bound in the impl's
    /// own crate. Asked from an integration test, the impl header's lexical
    /// lookup runs in the test's crate, whose request compiles no route for
    /// the library's `crate::`; the crate rows still name `CodeUnitIndex`, so
    /// the override answers alone from the impl's file, from its crate, and
    /// from the test. Found by the point-answer census (2026-09-24): 1,522
    /// Bifrost sites, all calls from another crate, tied the override with
    /// the declaration it overrides.
    #[test]
    #[hardwon("2cb71a73a409: a module re-export must not create a false override tie")]
    fn a_cross_crate_override_does_not_tie_through_a_module_import_reexport() {
        assert_override_alone(
            MODULE_IMPORT_REEXPORT,
            "use crate::analyzer::CodeUnitIndex;",
            &ALL_CALLERS,
        );
    }

    #[test]
    #[hardwon("2cb71a73a409: a direct re-export must preserve the impl trait owner")]
    fn a_cross_crate_override_does_not_tie_through_a_direct_reexport() {
        assert_override_alone(
            "pub mod java;\npub use core_crate::analyzer::code_unit_index::CodeUnitIndex;\n",
            "use crate::analyzer::CodeUnitIndex;",
            &ALL_CALLERS,
        );
    }

    /// A `#[cfg(test)] mod` beside the impl leaves a placement gap in the
    /// file; it does not make the override tie.
    #[test]
    #[hardwon("2cb71a73a409: cfg test modules must not change cross-crate override identity")]
    fn a_cross_crate_override_does_not_tie_beside_a_cfg_test_module() {
        assert_override_alone(
            MODULE_IMPORT_REEXPORT,
            "#[cfg(test)]\nmod tests;\nuse crate::analyzer::CodeUnitIndex;",
            &ALL_CALLERS,
        );
    }

    /// A qualified item macro beside the impl could add an inherent
    /// `get_definitions`, so the answer is not proven, but the override still
    /// does not tie with the declaration it overrides.
    #[test]
    #[hardwon("2cb71a73a409: a qualified item macro must not create a false trait candidate")]
    fn a_cross_crate_override_does_not_tie_beside_a_qualified_item_macro() {
        assert_override_alone(
            "pub mod java;\nmacro_rules! fwd { ($t:ty) => { impl $t { pub fn extra(&self) {} } }; }\npub(crate) use fwd;\nuse core_crate::analyzer::{code_unit_index};\npub use code_unit_index::CodeUnitIndex;\n",
            "crate::analyzer::fwd!(JavaAnalyzer);\nuse crate::analyzer::CodeUnitIndex;",
            &ALL_CALLERS,
        );
    }

    /// A lookup a request demands in a file of a crate it is not made on
    /// behalf of, through that file's own `crate::` route, answers incomplete.
    /// Here an integration test calls `make().spin()`, and `make`'s return
    /// type is spelled `crate::widget::Widget` in the library; the test's
    /// request compiles no route for the library's `crate::`. The lookup used
    /// to claim a complete absence, so the call answered `NoDefinition`.
    #[test]
    #[hardwon("2cb71a73a409: an unbridged dependency root cannot prove absence")]
    fn a_lookup_through_another_crates_root_is_incomplete_not_absent() {
        let files: Vec<(&str, &str)> = vec![
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"analysis\"]\nresolver = \"2\"\n",
            ),
            (
                "analysis/Cargo.toml",
                "[package]\nname = \"analysis\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            (
                "analysis/src/lib.rs",
                "pub mod widget;\npub fn make() -> crate::widget::Widget {\n    crate::widget::Widget\n}\n",
            ),
            (
                "analysis/src/widget.rs",
                "pub struct Widget;\nimpl Widget {\n    pub fn spin(&self) {}\n}\n",
            ),
            (
                "analysis/tests/t.rs",
                "fn caller() {\n    analysis::make().spin();\n}\n",
            ),
        ];
        let outcome = qualified_member_outcome(&files, "analysis/tests/t.rs", "make().spin");
        assert_eq!(
            outcome.status,
            brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Incomplete,
            "{outcome:?}"
        );
    }

    const TDIM_FROM_IMPLS: &str = "pub struct Symbol;\npub struct TDim;\nimpl From<Symbol> for TDim {\n    fn from(s: Symbol) -> TDim {\n        TDim\n    }\n}\nimpl<'a> From<&'a Symbol> for TDim {\n    fn from(s: &'a Symbol) -> TDim {\n        TDim\n    }\n}\nmacro_rules! from_i {\n    ($i: ty) => {\n        impl From<$i> for TDim {\n            fn from(v: $i) -> TDim {\n                TDim\n            }\n        }\n    };\n}\nfrom_i!(i32);\nfrom_i!(i64);\n";

    /// Several impls of one trait the rows cannot name (`From`, from std) for
    /// one self type are not an E0034 tie: they may be impls of one generic
    /// trait, and rustc picks between them by the argument's type. When the
    /// arguments cannot decide it, the answer keeps the candidates and says
    /// it is not decided. Found by the point-answer census (2026-09-24): 81
    /// tract `TDim::from` sites answered a tie between `impl From<Symbol> for
    /// TDim` and `impl From<&Symbol> for TDim`, beside `from_i!`'s impls.
    #[test]
    #[hardwon("140ac61e6887: impls of one unnameable trait were reported as an E0034 tie")]
    fn impls_of_one_unnameable_trait_are_undecided_not_a_tie() {
        for call in [
            "fn caller() {\n    let d = TDim::from(12);\n}\n",
            "fn caller(s: Symbol) {\n    let d = TDim::from(s);\n}\n",
        ] {
            let source = format!("{TDIM_FROM_IMPLS}{call}");
            let outcome = qualified_member_outcome(&[("t.rs", &source)], "t.rs", "TDim::from");
            let mut signatures = outcome
                .definitions
                .iter()
                .map(|unit| unit.signature().unwrap_or_default().to_owned())
                .collect::<Vec<_>>();
            signatures.sort();
            assert_eq!(
                signatures,
                vec![
                    "impl From<&'a Symbol> for TDim::fn from(s: &'a Symbol) -> TDim { ... }"
                        .to_owned(),
                    "impl From<Symbol> for TDim::fn from(s: Symbol) -> TDim { ... }".to_owned(),
                ],
                "{call}: {outcome:?}"
            );
            assert_eq!(
                outcome.status,
                brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Incomplete,
                "{call}: {outcome:?}"
            );
            assert!(
                outcome.diagnostics.iter().all(|diagnostic| {
                    diagnostic.kind != "unordered_candidates"
                        && !diagnostic.message.contains("inconsistent_precedence")
                }),
                "{call}: {outcome:?}"
            );
        }
    }

    /// The argument decides among impls of one unnameable trait when the
    /// coercion filter proves every other impl's parameter cannot take it:
    /// a `u8` value binds no `&str` parameter.
    #[test]
    #[hardwon("140ac61e6887: argument evidence must narrow impls of one unnameable trait")]
    fn the_argument_decides_among_impls_of_one_unnameable_trait() {
        let source = "pub struct W;\nimpl From<u8> for W {\n    fn from(v: u8) -> W {\n        W\n    }\n}\nimpl<'a> From<&'a str> for W {\n    fn from(v: &'a str) -> W {\n        W\n    }\n}\n\nfn caller(x: u8) {\n    let w = W::from(x);\n}\n";
        let outcome = qualified_member_outcome(&[("t.rs", source)], "t.rs", "W::from");
        let signatures = outcome
            .definitions
            .iter()
            .map(|unit| unit.signature().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            signatures,
            vec!["impl From<u8> for W::fn from(v: u8) -> W { ... }".to_owned()],
            "{outcome:?}"
        );
        assert_eq!(
            outcome.status,
            brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
            "{outcome:?}"
        );
    }

    /// Two traits that both declare `import_statements`, each implemented for
    /// `JavascriptAnalyzer` in another crate, and an integration test that
    /// calls the method with `imports` in scope. `core-crate` declares
    /// `IAnalyzer` in `iface` and `JsTsSource` in `source`.
    fn trait_scope_outcome(imports: &str) -> Vec<String> {
        let test = format!(
            "{imports}\nuse analysis::JavascriptAnalyzer;\n\nfn caller(analyzer: JavascriptAnalyzer) {{\n    analyzer.import_statements();\n}}\n"
        );
        let files = [
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\"core\", \"analysis\"]\nresolver = \"2\"\n",
            ),
            (
                "core/Cargo.toml",
                "[package]\nname = \"core-crate\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
            ),
            ("core/src/lib.rs", "pub mod iface;\npub mod source;\n"),
            (
                "core/src/iface.rs",
                "pub trait IAnalyzer {\n    fn import_statements(&self) -> u8;\n}\n",
            ),
            (
                "core/src/source.rs",
                "pub trait JsTsSource {\n    fn import_statements(&self) -> u8;\n}\n",
            ),
            (
                "analysis/Cargo.toml",
                "[package]\nname = \"analysis\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncore-crate = { path = \"../core\" }\n",
            ),
            (
                "analysis/src/lib.rs",
                "use core_crate::iface::IAnalyzer;\nuse core_crate::source::JsTsSource;\n\npub struct JavascriptAnalyzer;\n\nimpl JsTsSource for JavascriptAnalyzer {\n    fn import_statements(&self) -> u8 {\n        1\n    }\n}\n\nimpl IAnalyzer for JavascriptAnalyzer {\n    fn import_statements(&self) -> u8 {\n        2\n    }\n}\n",
            ),
            ("analysis/tests/t.rs", test.as_str()),
        ];
        let outcome =
            qualified_member_outcome(&files, "analysis/tests/t.rs", "analyzer.import_statements");
        let mut signatures = outcome
            .definitions
            .iter()
            .map(|unit| unit.signature().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        signatures.sort();
        let tie = outcome.diagnostics.iter().any(|diagnostic| {
            diagnostic.kind == "unordered_candidates"
                || diagnostic.message.contains("inconsistent_precedence")
        });
        signatures.push(format!("tie={tie}"));
        signatures
    }

    const IANALYZER_ITEM: &str =
        "impl IAnalyzer for JavascriptAnalyzer::fn import_statements(&self) -> u8 { ... }";
    const JSTS_ITEM: &str =
        "impl JsTsSource for JavascriptAnalyzer::fn import_statements(&self) -> u8 { ... }";

    /// rustc considers a trait's method for a method call only when the trait
    /// is in scope where the call is written. With `IAnalyzer` imported and
    /// `JsTsSource` not, the call is `IAnalyzer`'s. Found by the point-answer
    /// census (2026-09-24): Bifrost's JavaScript and TypeScript import tests
    /// answered a tie between the two.
    #[test]
    #[hardwon("6b483a993525: an out of scope trait method was admitted as a candidate")]
    fn a_trait_method_out_of_scope_at_the_call_is_not_a_candidate() {
        assert_eq!(
            trait_scope_outcome("use core_crate::iface::IAnalyzer;"),
            vec![IANALYZER_ITEM.to_owned(), "tie=false".to_owned()]
        );
    }

    /// With both traits in scope the call is rustc's E0034, and stays a tie.
    #[test]
    #[hardwon("6b483a993525: scope filtering must preserve the real E0034 tie")]
    fn two_trait_methods_in_scope_at_the_call_stay_a_tie() {
        assert_eq!(
            trait_scope_outcome(
                "use core_crate::iface::IAnalyzer;\nuse core_crate::source::JsTsSource;"
            ),
            vec![
                IANALYZER_ITEM.to_owned(),
                JSTS_ITEM.to_owned(),
                "tie=true".to_owned()
            ]
        );
    }

    /// A glob import brings a trait into scope as a named import does.
    #[test]
    #[hardwon("6b483a993525: a trait introduced by a glob import was omitted")]
    fn a_trait_in_scope_through_a_glob_import_is_a_candidate() {
        assert_eq!(
            trait_scope_outcome("use core_crate::iface::*;"),
            vec![IANALYZER_ITEM.to_owned(), "tie=false".to_owned()]
        );
    }

    /// A test module two packages' integration tests splice in with
    /// `include!`, each host naming the dependency's items through a glob
    /// import (tract's `api/tests/mobilenet/mod.rs`). The spliced file's
    /// lookups are lowered in the host's stage, so the context anchors they
    /// select decode to that staged catalog. The anchor check accepted only
    /// a persisted catalog and failed every point request in the file with a
    /// store error (678 tract sites in the point-answer census, 2026-09-24).
    #[test]
    #[hardwon("b29b68d51e93: included source used the wrong staged catalog at its host")]
    fn an_include_spliced_module_resolves_through_its_hosts_glob_imports() {
        for both_hosts in [false, true] {
            let mut files = vec![
                (
                    "Cargo.toml",
                    "[workspace]\nmembers = [\"api/rs\", \"api/proxy\"]\nresolver = \"2\"\n",
                ),
                (
                    "api/rs/Cargo.toml",
                    "[package]\nname = \"tract\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                ),
                (
                    "api/rs/src/lib.rs",
                    "pub struct Thing;\nimpl Thing {\n    pub fn make() -> Thing {\n        Thing\n    }\n}\n",
                ),
                (
                    "api/proxy/Cargo.toml",
                    "[package]\nname = \"tract-proxy\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntract = { path = \"../rs\" }\n",
                ),
                ("api/proxy/src/lib.rs", "pub use tract::Thing;\n"),
                (
                    "api/tests/mobilenet/mod.rs",
                    "fn build() -> Thing {\n    Thing::make()\n}\n",
                ),
                (
                    "api/rs/tests/mobilenet.rs",
                    "use tract::*;\n\ninclude!(\"../../tests/mobilenet/mod.rs\");\n",
                ),
            ];
            if both_hosts {
                files.push((
                    "api/proxy/tests/mobilenet.rs",
                    "use tract_proxy::*;\n\ninclude!(\"../../tests/mobilenet/mod.rs\");\n",
                ));
            }
            let outcome =
                qualified_member_outcome(&files, "api/tests/mobilenet/mod.rs", "Thing::make");
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["Thing.make".to_owned()], "{outcome:?}");
            assert_eq!(
                outcome.status,
                brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
                "{outcome:?}"
            );
        }
    }

    /// A trait whose body writes `Self::` gets a `Self` lower bound through a
    /// reference the producer writes to the trait's own name. That reference
    /// is the producer's device, not something a user wrote, so it publishes
    /// no range: no reference row spans the trait (the point-answer census
    /// found 31 such rows answering `invalid_location`), and the `Self::`
    /// path still resolves through the bound.
    #[test]
    #[hardwon("f2faba63346c: a synthetic Self lower bound published a fake source span")]
    fn a_traits_self_lower_bound_publishes_no_reference_row() {
        let source = "pub trait Model {\n    type Fact;\n    fn fact(&self) -> Self::Fact;\n}\n";
        let outcome = qualified_member_outcome(&[("t.rs", source)], "t.rs", "Self::Fact");
        let names = outcome
            .definitions
            .iter()
            .map(|unit| unit.short_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["Model.Fact".to_owned()], "{outcome:?}");

        let project = InlineTestProject::new().file("t.rs", source).build();
        let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.read_conn().unwrap();
        let spans = conn
            .prepare(
                "SELECT count(*) FROM resolution_sites WHERE role=0 AND start_byte=0 AND end_byte=?1",
            )
            .unwrap()
            .query_row([source.trim_end().len()], |row| row.get::<_, i64>(0))
            .unwrap();
        assert_eq!(spans, 0, "a reference row spans the trait declaration");
    }

    const RECEIVER_SHAPES: &str = "pub struct T;\nimpl T {\n    pub fn b(&self) -> u8 {\n        1\n    }\n}\npub struct S {\n    pub ts: Vec<T>,\n}\nimpl S {\n    pub fn maybe(&self) -> Result<T, ()> {\n        Ok(T)\n    }\n    pub fn opt(&self) -> Option<T> {\n        None\n    }\n}\n";

    /// `value?.member()` takes the member on the operand's value with one
    /// `Result` or `Option` layer removed, as a `?` let initializer does. The
    /// receiver slot had no producer, and the answer was incomplete with
    /// `missing-slot-producer` (the point-answer census, 2026-09-24).
    #[test]
    #[hardwon("365b87dd9c25: try receiver slots lost their operand producer")]
    fn a_try_receiver_reaches_the_unwrapped_values_member() {
        for body in [
            "fn f(s: S) -> Result<(), ()> { s.maybe()?.b(); Ok(()) }",
            "fn f(s: S) -> Option<()> { s.opt()?.b(); None }",
        ] {
            let source = format!("{RECEIVER_SHAPES}{body}\n");
            let outcome = qualified_member_outcome(&[("t.rs", &source)], "t.rs", "?.b");
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["T.b".to_owned()], "{body}: {outcome:?}");
            assert_eq!(
                outcome.status,
                brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
                "{body}: {outcome:?}"
            );
        }
    }

    /// An index receiver has no value type the producer models, so the
    /// member answers incomplete, and the reason is the receiver slot's own
    /// unsupported-expression gap, a fragment-local reason, not the
    /// operation's `missing-slot-producer` service reason.
    #[test]
    #[hardwon("365b87dd9c25: an index receiver reported the wrong incomplete reason")]
    fn an_index_receivers_member_names_its_unsupported_receiver() {
        let source = format!("{RECEIVER_SHAPES}fn f(s: S) {{ s.ts[0].b(); }}\n");
        let outcome = qualified_member_outcome(&[("t.rs", &source)], "t.rs", "].b");
        assert!(outcome.definitions.is_empty(), "{outcome:?}");
        assert_eq!(
            outcome.status,
            brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Incomplete,
            "{outcome:?}"
        );
        assert!(
            outcome
                .diagnostics
                .iter()
                .all(|diagnostic| !diagnostic.message.contains("SemanticId#op:")),
            "the reason is the slot's own gap: {outcome:?}"
        );
    }

    /// A method on the result of `into()` over an `impl Into<PathBuf>` value
    /// is not a decided absence: `NormalizePath::normalize` is implemented
    /// for `PathBuf` and rustc calls it. `Into` is a prelude name, so the
    /// bound, the value's type and the conversion's result are open, not
    /// empty. Found by the missing-slot-producer re-sweep (2026-09-25): 46
    /// sites such as Bifrost's `root.into().canonicalize()?.normalize()`
    /// answered `NoDefinition`.
    #[test]
    fn a_member_on_an_into_conversion_is_not_a_decided_absence() {
        let lib = "use std::path::PathBuf;\npub trait NormalizePath {\n    fn normalize(self) -> PathBuf;\n}\nimpl NormalizePath for PathBuf {\n    fn normalize(self) -> PathBuf {\n        self\n    }\n}\npub fn f(p: impl Into<PathBuf>) {\n    let c = p.into();\n    c.normalize();\n}\n";
        let outcome = prelude_outcome("2021", lib, "c.normalize");
        assert_ne!(
            outcome.status,
            brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::NoDefinition,
            "{outcome:?}"
        );
    }

    /// Opaque external type identities travel through normal type transfers.
    /// They can name a candidate but never prove external member completeness.
    #[test]
    #[hardwon("0f37730c3963: external import identity was lost through receiver type flow")]
    fn a_workspace_impl_for_an_external_type_supplies_the_receivers_member() {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
        let head = "use std::path::PathBuf;\npub trait NormalizePath {\n    fn normalize(&self) -> u8;\n}\nimpl NormalizePath for PathBuf {\n    fn normalize(&self) -> u8 { 7 }\n}\n";
        for (body, expected) in [
            ("pub fn f(c: PathBuf) { c.normalize(); }", 1),
            (
                "pub fn f(p: impl Into<PathBuf>) { let c: PathBuf = p.into(); c.normalize(); }",
                1,
            ),
            ("pub fn f(c: &PathBuf) { c.normalize(); }", 1),
            ("pub fn f(c: Box<PathBuf>) { c.normalize(); }", 1),
            ("pub fn f(c: Option<PathBuf>) { c.normalize(); }", 0),
            ("pub fn f(c: *const PathBuf) { c.normalize(); }", 0),
            (
                "pub fn f(value: Option<PathBuf>) { let c = value.unwrap(); c.normalize(); }",
                1,
            ),
        ] {
            let outcome = prelude_outcome("2021", &format!("{head}{body}\n"), "c.normalize");
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>();
            assert_ne!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{body}: {outcome:?}"
            );
            assert_eq!(names.len(), expected, "{body}: {outcome:?}");
            if expected != 0 {
                assert_eq!(
                    outcome.status,
                    DefinitionLookupStatus::Incomplete,
                    "{outcome:?}"
                );
                assert!(names[0].ends_with("PathBuf.normalize"), "{body}: {names:?}");
            }
        }
    }

    #[test]
    #[hardwon("0f37730c3963: external aliases and same-spelled local types shared an identity")]
    fn external_subject_identity_keeps_aliases_and_unrelated_bindings_distinct() {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;
        for (source, expected) in [
            (
                "use std::path::PathBuf as Buffer; trait N { fn normalize(&self); } impl N for Buffer { fn normalize(&self) {} } fn f(c: Buffer) { c.normalize(); }",
                1,
            ),
            (
                "mod left { use std::path::PathBuf; pub trait N { fn normalize(&self); } impl N for PathBuf { fn normalize(&self) {} } } mod right { use std::ffi::PathBuf; use crate::left::N; fn f(c: PathBuf) { c.normalize(); } }",
                0,
            ),
            (
                "use std::path::PathBuf; mod hidden { use super::PathBuf; pub trait N { fn normalize(&self); } impl N for PathBuf { fn normalize(&self) {} } } fn f(c: PathBuf) { c.normalize(); }",
                0,
            ),
            (
                "use std::path::PathBuf; mod visible { use super::PathBuf; pub trait N { fn normalize(&self); } impl N for PathBuf { fn normalize(&self) {} } } use visible::N; fn f(c: PathBuf) { c.normalize(); }",
                1,
            ),
        ] {
            let outcome = prelude_outcome("2021", source, "c.normalize");
            assert_ne!(
                outcome.status,
                DefinitionLookupStatus::Resolved,
                "{source}: {outcome:?}"
            );
            assert_eq!(outcome.definitions.len(), expected, "{source}: {outcome:?}");
        }
    }

    /// The status and boundary names a point answer gives `path` in a crate
    /// of `edition` whose root file is `lib`.
    fn prelude_outcome(
        edition: &str,
        lib: &str,
        path: &str,
    ) -> brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupOutcome {
        let manifest =
            format!("[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"{edition}\"\n");
        qualified_member_outcome(
            &[("Cargo.toml", manifest.as_str()), ("src/lib.rs", lib)],
            "src/lib.rs",
            path,
        )
    }

    /// An unqualified type or value name that no scope binds falls through to
    /// the crate's implicit std prelude, which Bifrost does not index: an open
    /// boundary, never a proved absence, in type, bound and value positions
    /// alike, and members of a value typed through it are not decided absent.
    #[test]
    #[hardwon("f5fb9c487416: prelude names were incorrectly treated as proved absences")]
    fn a_prelude_name_is_an_unindexed_import_boundary() {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::UnresolvableImportBoundary;
        for (lib, path) in [
            ("pub fn f(v: Vec<u8>) {}\n", "Vec"),
            ("pub fn f(p: impl Clone) {}\n", "Clone"),
            ("pub fn f() { let x = Some(1); }\n", "Some"),
            ("pub fn f() { let v = Vec::<u8>::new(); }\n", "Vec"),
            ("pub fn f(p: impl Clone) { p.clone(); }\n", "p.clone"),
            ("pub fn f<P: Clone>(p: P) { p.clone(); }\n", "p.clone"),
            (
                "pub fn f<P>(p: P) where P: Clone { p.clone(); }\n",
                "p.clone",
            ),
        ] {
            let outcome = prelude_outcome("2021", lib, path);
            assert_eq!(
                outcome.status, UnresolvableImportBoundary,
                "{lib}: {outcome:?}"
            );
        }
    }

    /// A lexical binding of a prelude name wins over the prelude, as in rustc.
    /// A struct's private constructor is such a binding in its own module.
    #[test]
    #[hardwon("f5fb9c487416: a local item must shadow its implicit prelude spelling")]
    fn a_local_item_shadows_the_prelude() {
        for (lib, name) in [
            ("pub type A = Vec;\npub struct Vec;\n", "Vec"),
            (
                "pub fn f() { let _ = Some(1); }\nstruct Some(u8);\n",
                "Some",
            ),
            ("pub fn f() { let _ = None; }\nstruct None;\n", "None"),
        ] {
            let outcome = prelude_outcome("2021", lib, name);
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.short_name().to_owned())
                .collect::<Vec<_>>();
            assert_eq!(names, vec![name.to_owned()], "{lib}: {outcome:?}");
            assert_eq!(
                outcome.status,
                brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
                "{lib}: {outcome:?}"
            );
        }
    }

    /// A struct pattern reads the fields its path names: for `E::V { .. }`
    /// that is the variant's own member scope, not the enum's, exactly as a
    /// struct literal writes them. Explicit and shorthand fields alike.
    #[test]
    #[hardwon("#3746: a variant pattern field resolved against the enum scope")]
    fn a_variant_struct_pattern_field_resolves_on_the_variant() {
        for body in [
            "pub fn f(e: E) { let E::V { ty: x } = e; let _ = x; }\n",
            "pub fn f(e: E) { match e { E::V { ty } => { let _ = ty; } } }\n",
        ] {
            let lib = format!("{body}pub enum E {{ V {{ ty: u8 }} }}\n");
            let outcome = prelude_outcome("2021", &lib, "ty");
            let names = outcome
                .definitions
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["demo.E.V.ty".to_owned()], "{body}: {outcome:?}");
            assert_eq!(
                outcome.status,
                brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::Resolved,
                "{body}: {outcome:?}"
            );
        }
    }

    /// The crate's edition and prelude kind decide the name set: `TryFrom`
    /// joined the prelude in 2021, `#![no_std]` selects core's prelude, which
    /// has `Option` but not `String`, and `#![no_core]` has no prelude.
    #[test]
    #[hardwon("f5fb9c487416: edition and no_std prelude names were classified incorrectly")]
    fn the_crates_edition_and_prelude_kind_select_the_prelude_names() {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::NoDefinition;

        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus::UnresolvableImportBoundary;
        for (edition, lib, path, expected) in [
            (
                "2018",
                "pub fn f(v: impl TryFrom<u8>) {}\n",
                "TryFrom",
                NoDefinition,
            ),
            (
                "2021",
                "pub fn f(v: impl TryFrom<u8>) {}\n",
                "TryFrom",
                UnresolvableImportBoundary,
            ),
            (
                "2021",
                "#![no_std]\npub fn f(v: Option<u8>) {}\n",
                "Option",
                UnresolvableImportBoundary,
            ),
            (
                "2021",
                "#![no_std]\npub fn f(v: String) {}\n",
                "String",
                NoDefinition,
            ),
            (
                "2021",
                "#![no_core]\npub fn f(v: Option<u8>) {}\n",
                "Option",
                NoDefinition,
            ),
        ] {
            let outcome = prelude_outcome(edition, lib, path);
            assert_eq!(outcome.status, expected, "{edition} {lib}: {outcome:?}");
        }
    }

    const UNNAMEABLE_TRAIT_TIE: &str = "use std::fmt::Display;\nstruct Service;\ntrait Two {\n    fn fmt(&self) {}\n}\nimpl Display for Service {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        Ok(())\n    }\n}\nimpl Two for Service {}\n\nfn caller(service: Service, f: &mut std::fmt::Formatter<'_>) {\n    service.fmt(f);\n}\n";

    /// An impl item of a trait the rows cannot name (here `std::fmt::Display`)
    /// is one trait candidate among the receiver's others. An in-scope trait
    /// whose default supplies the same method makes the call E0034, and the
    /// answer keeps both candidates with the cause named. With no such trait,
    /// the item answers alone and complete: the rows enumerated every trait the
    /// call site can name, and none supplies the method.
    #[test]
    #[hardwon("21a0f8b34f4a: an unnameable trait item was lost from a real candidate tie")]
    fn an_impl_item_of_an_unnameable_trait_meets_the_nameable_traits() {
        use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

        let alone = "use std::fmt::Display;\nstruct Service;\nimpl Display for Service {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        Ok(())\n    }\n}\n\nfn caller(service: Service, f: &mut std::fmt::Formatter<'_>) {\n    service.fmt(f);\n}\n";
        let unrelated = "use std::fmt::Display;\nstruct Service;\ntrait Two {\n    fn other(&self) {}\n}\nimpl Display for Service {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        Ok(())\n    }\n}\nimpl Two for Service {}\n\nfn caller(service: Service, f: &mut std::fmt::Formatter<'_>) {\n    service.fmt(f);\n}\n";
        for (label, source) in [("alone", alone), ("unrelated trait", unrelated)] {
            assert_eq!(
                qualified_member_definitions(&[("t.rs", source)], "t.rs", "service.fmt"),
                (
                    DefinitionLookupStatus::Resolved,
                    vec!["Service.fmt".to_owned()]
                ),
                "{label}"
            );
        }

        let outcome =
            qualified_member_outcome(&[("t.rs", UNNAMEABLE_TRAIT_TIE)], "t.rs", "service.fmt");
        let names = outcome
            .definitions
            .iter()
            .map(|unit| unit.short_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            (outcome.status, names),
            (
                DefinitionLookupStatus::Ambiguous,
                vec!["Service.fmt".to_owned(), "Two.fmt".to_owned()]
            ),
            "{outcome:?}"
        );
        assert!(
            outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == "unordered_candidates"),
            "the ambiguity names its cause: {outcome:?}"
        );
    }

    /// The reverse half: the unnameable trait's impl item and the nameable
    /// trait's default each see the tied call as a usage they cannot prove.
    #[test]
    #[hardwon(
        "21a0f8b34f4a: both candidates in an unnameable-trait tie need unproven reverse edges"
    )]
    fn an_unnameable_trait_items_tie_is_an_unproven_usage_of_each_candidate() {
        for (line, symbol) in [(7, "Service.fmt"), (4, "Two.fmt")] {
            assert_one_unproven_usage(&scan_usages_at(UNNAMEABLE_TRAIT_TIE, line), symbol, 14);
        }
    }
}
