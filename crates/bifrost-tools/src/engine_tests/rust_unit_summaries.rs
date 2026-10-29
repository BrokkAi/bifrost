#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer;

    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    include!("rust_forwarded_surface_tests.rs");

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
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
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
            let (count, ordinal, minimum): (i64, i64, i64) = conn
                .query_row(
                    "SELECT count(*), MIN(exports.alias_dependency_ordinal),
                       (SELECT MIN(dependency_ordinal)
                        FROM resolution_unit_summary_dependencies WHERE summary_id = ?1)
                     FROM resolution_unit_summary_exports AS exports
                     JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                     JOIN resolution_unit_summary_exports AS declaration
                       ON declaration.summary_id = ?2
                      AND declaration.identity_id = exports.identity_id
                      AND declaration.namespace = exports.namespace
                      AND declaration.declaration_blob_id = exports.declaration_blob_id
                      AND declaration.declaration_site = exports.declaration_site
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
        let rows = conn
            .prepare(
                "SELECT identities.spelling, exports.namespace, exports.origin,
                        dependency_names.extern_name, declaration_members.rel_path,
                        summaries.complete, summaries.publication_state,
                        rust_exports.target_unit_key = leaf.unit_key,
                        rust_exports.target_module_path, rust_exports.target_name,
                        rust_exports.alias_identity_id = declaration.identity_id
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 JOIN resolution_unit_summaries AS summaries USING(summary_id)
                 JOIN rust_unit_summary_dependency_names AS dependency_names
                   ON dependency_names.summary_id = exports.summary_id
                  AND dependency_names.dependency_ordinal = exports.alias_dependency_ordinal
                 JOIN resolution_unit_summary_exports AS declaration
                   ON declaration.summary_id = ?2
                  AND declaration.declaration_blob_id = exports.declaration_blob_id
                  AND declaration.declaration_site = exports.declaration_site
                  AND declaration.namespace = exports.namespace
                 JOIN resolution_unit_summary_members AS declaration_members
                   ON declaration_members.summary_id = declaration.summary_id
                  AND declaration_members.blob_id = declaration.declaration_blob_id
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
        conn.prepare(
            "SELECT identities.spelling, exports.namespace, members.rel_path, exports.declaration_site
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             JOIN resolution_unit_summary_members AS members
               ON members.blob_id = exports.declaration_blob_id
             WHERE exports.summary_id = ?1
             GROUP BY identities.spelling, exports.namespace, members.rel_path, exports.declaration_site
             ORDER BY identities.spelling, exports.namespace, members.rel_path, exports.declaration_site",
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
        let rows = conn
            .prepare(
                "SELECT DISTINCT identities.spelling, exports.namespace, exports.origin,
                        exports.visibility, members.rel_path,
                        exports.alias_dependency_ordinal, names.extern_name,
                        summaries.complete, summaries.publication_state
                 FROM resolution_unit_summary_exports AS exports
                 JOIN resolution_identities AS identities ON identities.id = exports.identity_id
                 JOIN resolution_unit_summaries AS summaries USING(summary_id)
                 JOIN resolution_unit_summary_members AS members
                   ON members.blob_id = exports.declaration_blob_id
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
                "SELECT declaration_blob_id FROM resolution_unit_summary_exports AS exports
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
                "SELECT declaration_blob_id FROM resolution_unit_summary_exports AS exports
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
                    "SELECT declaration_blob_id FROM resolution_unit_summary_exports AS exports
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
                // still cuts off propagation to vector below.
                BTreeSet::from(["vector_core".to_owned(), "vector_lib".to_owned()]),
            ),
            // An unrelated child export is outside the module the facade forwards.
            (
                "lib/vector-core/src/lib.rs",
                "pub mod event;\npub fn unrelated() {}\n",
                BTreeSet::from(["vector_core".to_owned(), "vector_lib".to_owned()]),
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
                previous["vector"], incremental["vector"],
                "consumer is reused: {path}"
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
             FROM resolution_unit_summary_exports AS exports
             JOIN resolution_identities AS identities ON identities.id = exports.identity_id
             JOIN resolution_unit_summary_members AS members
               ON members.summary_id = ?2
              AND members.blob_id = exports.declaration_blob_id
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
