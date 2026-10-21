#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::BASE_TARGET_ACTIVATION_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::CALLER_ROOTS_SQL;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::GLOBS_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::IMPORTS_SQL;

    use brokk_bifrost_core::analyzer::Language;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::MODULE_SOURCES_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::ROOT_REFERENCES_SQL;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::SAME_BLOB_TYPE_EXPORTS_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::SAME_BLOB_TYPE_EXPORT_KEYS_SQL;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reverse_rows::TEXTUAL_MACRO_SOURCES_SQL;

    use rusqlite::params;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::explain_pin;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::pinned;

    use brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::prepare_pin_context;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

    use crate::inline_project::BuiltInlineTestProject;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeDerivationResult;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    use brokk_bifrost_test_macros::hardwon;
    use rusqlite::types::Value;
    fn inverse_result_for(
        fixture: &BuiltInlineTestProject,
        source_path: &str,
        target_name: &str,
    ) -> EdgeDerivationResult {
        use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        use brokk_bifrost_rust_analysis::analyzer::rust::selected_reverse::RustSelectedReverseOutcome;

        use brokk_bifrost_rust_analysis::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries;

        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let rust =
            brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(
                analyzer.analyzer(),
            )
            .unwrap();
        let target = rust
            .declarations(&fixture.file(source_path))
            .into_iter()
            .find(|unit| unit.identifier() == target_name)
            .unwrap_or_else(|| panic!("missing target {target_name:?} in {source_path}"));
        let result =
            with_rust_selected_reverse_queries(rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(&[target])
            });
        match result {
            RustSelectedReverseOutcome::Ready(Some(mut rows)) => {
                assert_eq!(rows.len(), 1, "one requested target: {rows:?}");
                rows.remove(0)
            }
            other => panic!("reverse query did not return one target row: {other:?}"),
        }
    }

    fn workspace_api_client(api_source: &str, client_source: &str) -> BuiltInlineTestProject {
        InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[workspace]\nmembers=['api','client']\nresolver='2'\n",
            )
            .file(
                "api/Cargo.toml",
                "[package]\nname='api'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "client/Cargo.toml",
                "[package]\nname='client'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nrenamed={package='api',path='../api'}\n",
            )
            .file("api/src/lib.rs", api_source)
            .file("client/src/lib.rs", client_source)
            .build()
    }

    #[test]
    fn reverse_inventory_gap_candidate_names_are_target_scoped() {
        let different = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub fn target() {} pub fn caller() { missing::different(); }",
            )
            .build();
        let result = inverse_result_for(&different, "src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "a different terminal name cannot name target: {result:?}"
        );

        let different_method = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub fn target() {} pub fn caller() { callbacks[0]().inspect(); }",
            )
            .build();
        let result = inverse_result_for(&different_method, "src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "a named method under a nameless call wrapper cannot name target: {result:?}"
        );

        let same = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub fn target() {} pub fn caller() { missing::target(); }",
            )
            .build();
        let result = inverse_result_for(&same, "src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "the same terminal name keeps target's reverse inventory open: {result:?}"
        );
    }

    #[test]
    #[hardwon(
        "#5437: an unrelated impl's Self route kept every class target's reverse inventory open"
    )]
    fn reverse_inventory_scopes_self_candidates_to_the_target_impls() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='self_scope'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "pub mod target;\npub mod unrelated;\n")
            .file(
                "src/target.rs",
                "pub struct Target;\nimpl Target { pub fn make() -> Self { Self } }\n",
            )
            .file(
                "src/unrelated.rs",
                "pub struct Other;\nimpl Other { pub fn make() { Self::missing(); } }\n",
            )
            .build();
        let result = inverse_result_for(&fixture, "src/target.rs", "Target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "an unrelated impl's Self route must not open Target's inventory: {result:?}"
        );
        let self_hits = result
            .edges
            .iter()
            .filter(|edge| edge.site.file.rel_path() == std::path::Path::new("src/target.rs"))
            .count();
        assert!(
            self_hits >= 2,
            "the target's own Self references remain exact candidates: {result:?}"
        );
    }

    #[test]
    #[hardwon("#5437: a built-in macro frontier opened every reverse inventory in its crate")]
    fn reverse_inventory_bounds_builtin_macro_frontiers_by_name() {
        let fixture = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub struct Target;\npub fn check(value: Option<u8>) { let _ = matches!(value, Some(1)); }\n",
            )
            .build();
        let result = inverse_result_for(&fixture, "src/lib.rs", "Target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "matches! cannot synthesize Target: {result:?}"
        );
    }

    #[test]
    #[hardwon(
        "#5437: an imported macro's unexpanded frontier opened every reverse inventory in its crate"
    )]
    fn reverse_inventory_bounds_imported_macro_frontiers_by_definition() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='macro_frontier'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file(
                "src/lib.rs",
                "mod consumer;\nmod macros;\npub mod target;\n",
            )
            .file(
                "src/macros.rs",
                "macro_rules! define_thing {\n    ($name:ident) => {\n        #[derive(Debug)]\n        pub struct $name;\n        impl $name { pub fn new() -> Self { Self } }\n    };\n}\npub(crate) use define_thing;\n",
            )
            .file(
                "src/consumer.rs",
                "use crate::macros::define_thing;\ndefine_thing!(Unrelated);\n",
            )
            .file("src/target.rs", "pub struct Target;\n")
            .build();
        let result = inverse_result_for(&fixture, "src/target.rs", "Target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "an imported macro that cannot name Target must not open its inventory: {result:?}"
        );
    }

    #[test]
    fn unresolved_glob_imports_are_scoped_by_call_name() {
        let different = workspace_api_client(
            "pub fn target() {}",
            "use target::missing::*; pub fn caller() { different(); }",
        );
        let result = inverse_result_for(&different, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "an unresolved glob cannot rename a differently named call: {result:?}"
        );

        let same = workspace_api_client(
            "pub fn target() {}",
            "use renamed::missing::*; pub fn caller() { target(); }",
        );
        let result = inverse_result_for(&same, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "a call spelled target may resolve through the unresolved glob: {result:?}"
        );
    }

    #[test]
    fn reverse_inventory_follows_transitive_and_unresolved_import_aliases() {
        let chain = workspace_api_client(
            "pub fn target() {}",
            "use renamed::target as first; use crate::first as second; use crate::second as third; pub fn caller() { missing::third(); }",
        );
        let result = inverse_result_for(&chain, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "a gap spelled through a transitive use alias can name target: {result:?}"
        );

        let unresolved = workspace_api_client(
            "pub fn target() {}",
            "use missing::target as maybe_target; pub fn caller() { missing_again::maybe_target(); }",
        );
        let result = inverse_result_for(&unresolved, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "an unresolved renamed import whose source names target stays conservative: {result:?}"
        );
    }

    #[test]
    fn reverse_inventory_follows_type_aliases_and_contextual_self() {
        let alias = workspace_api_client(
            "pub struct Target;",
            "type Alias = renamed::Target; pub fn caller() { missing::Alias::new(); }",
        );
        let result = inverse_result_for(&alias, "api/src/lib.rs", "Target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "a type alias path can name the target type: {result:?}"
        );

        let self_path = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub struct Target; impl Target { pub fn caller() { Self::missing(); } }",
            )
            .build();
        let result = inverse_result_for(&self_path, "src/lib.rs", "Target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "an unindexed member does not hide the exact authored Self type use: {result:?}"
        );
        assert!(
            result.edges.iter().any(|edge| {
                edge.reference_kind
                    == Some(
                        brokk_bifrost_core::analyzer::usages::model::ReferenceKind::SelfTypeAlias,
                    )
                    && edge.proof == brokk_bifrost_core::analyzer::usages::model::UsageProof::Proven
                    && edge
                        .site
                        .enclosing
                        .as_ref()
                        .is_some_and(|owner| owner.identifier() == "caller")
            }),
            "the structured Self alias remains an exact type use: {result:?}"
        );
    }

    #[test]
    fn reverse_inventory_keeps_workspace_member_and_renamed_crate_roots() {
        let workspace_root = workspace_api_client(
            "pub fn target() {}",
            "pub fn caller() { renamed::missing::target(); }",
        );
        let result = inverse_result_for(&workspace_root, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "a path rooted at another workspace member can name target: {result:?}"
        );

        let extern_rename = workspace_api_client(
            "pub fn target() {}",
            "extern crate renamed as external_name; pub fn caller() { external_name::missing::target(); }",
        );
        let result = inverse_result_for(&extern_rename, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "an extern-crate rename to a workspace member is not an external root: {result:?}"
        );
    }

    #[test]
    fn reverse_inventory_keys_ufcs_and_method_calls_by_method_name() {
        let fixture = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub struct Target; impl Target { pub fn run(&self) {} } pub fn ufcs() { <Target as MissingTrait>::run(&Target); } pub fn method(value: MissingType) { value.run(); }",
            )
            .build();
        let result = inverse_result_for(&fixture, "src/lib.rs", "run");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "unresolved UFCS and receiver paths retain the run method candidate: {result:?}"
        );

        let different_methods = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub struct Target; impl Target { pub fn run(&self) {} } pub fn ufcs() { <Target as MissingTrait>::stop(&Target); } pub fn associated() { Target::stop(); }",
            )
            .build();
        let result = inverse_result_for(&different_methods, "src/lib.rs", "run");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "an owner type or UFCS path does not make a different method name a run candidate: {result:?}"
        );
    }

    #[test]
    fn reverse_inventory_distinguishes_free_and_member_call_shapes() {
        let free_function = workspace_api_client(
            "pub fn target() {}",
            "pub struct Receiver; impl Receiver { pub fn target(&self) {} } pub fn caller(value: MissingType) { value.target(); }",
        );
        let result = inverse_result_for(&free_function, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "a member-call gap cannot name a free function with the same spelling: {result:?}"
        );

        let method = workspace_api_client(
            "pub struct Owner; impl Owner { pub fn target(&self) {} }",
            "pub fn target<T>(value: T) -> T { value } pub fn caller() { target(#[cfg(any())] 1); }",
        );
        let result = inverse_result_for(&method, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "an unqualified free-function call gap cannot name a same-named associated method: {result:?}"
        );
    }

    #[test]
    #[hardwon("#3828: an identifier-synthesizing proc macro hid an unindexed reverse reference")]
    fn reverse_inventory_treats_unexpanded_proc_macros_conservatively() {
        let fixture = workspace_api_client(
            "pub fn target() {}",
            "pub fn caller() { paste! { [<tar get>]() } }",
        );
        let result = inverse_result_for(&fixture, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "an unavailable identifier-synthesizing macro cannot prove target absent: {result:?}"
        );
    }

    #[test]
    #[hardwon(
        "#5437: qualified expression macros stayed open even when their input could not name the target"
    )]
    fn reverse_inventory_bounds_expression_macros_by_their_input() {
        let qualified_expression = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub fn target() {} pub fn caller() { serde_json::json!({\"key\": 1}); }",
            )
            .build();
        let result = inverse_result_for(&qualified_expression, "src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "a qualified expression macro with no target in its input cannot name target: {result:?}"
        );

        let unqualified_expression = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub fn target() {} pub fn caller() { json!({\"key\": 1}); }",
            )
            .build();
        let result = inverse_result_for(&unqualified_expression, "src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "an unknown expression macro is bounded by its input: {result:?}"
        );

        let literal_names_target = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub fn target() {} pub fn caller() { serde_json::json!({\"target is missing\": missing_value}); }",
            )
            .build();
        let result = inverse_result_for(&literal_names_target, "src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "a string literal that spells target keeps the macro frontier open: {result:?}"
        );

        let control_escape = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub fn target() {} pub fn caller() { serde_json::json!({\"filename\": \"report\\x00\\x0d.pdf\"}); }",
            )
            .build();
        let result = inverse_result_for(&control_escape, "src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "a control escape cannot spell target: {result:?}"
        );

        let escape_spells_target = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub fn target() {} pub fn caller() { serde_json::json!({\"name\": \"\\x74arget\"}); }",
            )
            .build();
        let result = inverse_result_for(&escape_spells_target, "src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "an escape that spells target keeps the macro frontier open: {result:?}"
        );

        let qualified_synthesizer = InlineTestProject::new()
            .file(
                "src/lib.rs",
                "pub fn target() {} pub fn caller() { paste::paste! { [<tar get>]() } }",
            )
            .build();
        let result = inverse_result_for(&qualified_synthesizer, "src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "a qualified identifier-synthesizing macro cannot prove target absent: {result:?}"
        );
    }

    #[test]
    fn reverse_inventory_uses_macro_rules_input_and_transcriber_names() {
        let with_target = workspace_api_client(
            "pub fn target() {}",
            "macro_rules! relay { ($($tokens:item)*) => { $($tokens)* pub fn generated() {} }; } relay!(pub fn caller() { missing::target(); });",
        );
        let result = inverse_result_for(&with_target, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "macro_rules invocation tokens include target: {result:?}"
        );

        let transcriber_target = workspace_api_client(
            "pub fn target() {}",
            "macro_rules! relay { ($($tokens:item)*) => { $($tokens)* pub fn generated() { target(); } }; } relay!(pub fn caller() { missing::different(); });",
        );
        let result = inverse_result_for(&transcriber_target, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Incomplete { .. }),
            "macro_rules transcriber identifiers include target: {result:?}"
        );

        let without_target = workspace_api_client(
            "pub fn target() {}",
            "macro_rules! relay { ($($tokens:item)*) => { $($tokens)* pub fn generated() {} }; } relay!(pub fn caller() { missing::different(); });",
        );
        let result = inverse_result_for(&without_target, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "visible macro_rules with no target candidate does not open target inventory: {result:?}"
        );
    }

    #[test]
    fn reverse_inventory_resolves_exported_macro_crate_root_to_definition_crate() {
        let fixture = workspace_api_client(
            "pub fn target() {} #[macro_export] macro_rules! call_target { () => { $crate::target() }; }",
            "pub fn caller() { renamed::call_target!(); }",
        );
        let result = inverse_result_for(&fixture, "api/src/lib.rs", "target");
        assert!(
            matches!(result.completeness, EdgeCompleteness::Complete),
            "the exported macro's $crate target resolves to its definition crate: {result:?}"
        );
        assert!(
            result.edges.iter().all(|edge| edge
                .site
                .file
                .rel_path()
                .to_string_lossy()
                .contains("api")),
            "the $crate expansion is attributed to its macro definition crate: {result:?}"
        );
    }

    #[test]
    #[hardwon("a21c12124e36: relative import roots lost binder scope in reverse reads")]
    fn reverse_import_binder_scope_reaches_plain_value_reads() {
        use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

        use brokk_bifrost_rust_analysis::analyzer::rust::RustAnalyzer;

        use brokk_bifrost_rust_analysis::analyzer::rust::selected_reverse::RustSelectedReverseOutcome;

        use brokk_bifrost_rust_analysis::analyzer::rust::selected_reverse::with_rust_selected_reverse_queries;
        let fixture = InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", "[package]\nname='demo'\nversion='0.1.0'\n")
            .file(
                "src/lib.rs",
                "pub mod outer { #[path=\"mapped.rs\"] pub mod mapped; pub mod consumer; }",
            )
            .file("src/outer/mapped.rs", "pub const VALUE: usize = 1;")
            .file(
                "src/outer/consumer.rs",
                "use super::mapped::VALUE; fn valid() { let _ = VALUE; }",
            )
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let rust =
            brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<RustAnalyzer>(
                analyzer.analyzer(),
            )
            .unwrap();
        let target = rust
            .declarations(&fixture.file("src/outer/mapped.rs"))
            .into_iter()
            .find(|unit| unit.identifier() == "VALUE")
            .unwrap();
        let result =
            with_rust_selected_reverse_queries(rust, &CancellationToken::new(), |queries| {
                queries.inverse_for(&[target])
            });
        assert!(
            matches!(result,RustSelectedReverseOutcome::Ready(Some(ref rows)) if rows[0].edges.len()==2),
            "{result:?}"
        );
    }

    #[test]
    #[hardwon("62fb17236b23: reverse candidate discovery scanned unrelated same-name routes")]
    fn reverse_root_candidates_ignore_unrelated_same_named_references() {
        let mut measurements = Vec::new();
        for unrelated in [0, 32] {
            let mut builder = InlineTestProject::new().file(
                "Cargo.toml",
                "[package]\nname='root_reference_pin'\nversion='0.1.0'\nedition='2021'\n",
            );
            // Keep a fixed later key in the same root/name index range so both
            // fixtures execute a range boundary check rather than one ending
            // at B-tree EOF (which omits two VM instructions).
            let mut source = "pub fn target() {} pub fn z_after() {} pub fn caller() { crate::target(); crate::z_after(); }\n".to_owned();
            for index in 0..unrelated {
                source.push_str(&format!("pub mod decoy{index};\n"));
                builder = builder.file(
                    format!("src/decoy{index}.rs"),
                    format!(
                        "pub fn target() {{}} pub fn caller() {{ crate::decoy{index}::target(); }}"
                    ),
                ).file(format!("isolated/decoy{index}.rs"), "pub fn target() {} pub fn caller() { crate::target(); }");
            }
            let fixture = builder.file("src/lib.rs", source).build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.conn.lock().unwrap();
            brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn)
                .unwrap();
            conn.execute("DELETE FROM selected_workspace_revisions", [])
                .unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
            prepare_pin_context(&conn);
            conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) SELECT row_number() OVER(),blob_id,'rust',rel_path FROM (SELECT DISTINCT blob_id,rel_path FROM rust_crate_container_sources)", []).unwrap();
            conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
            for state in PlannerStatisticsState::BOTH {
                state.install(&conn);
                let key: Vec<u8> = conn
                    .query_row(
                        "SELECT crate_key FROM selected_rust_crates WHERE target_kind='lib'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let mut root_pin = pinned("rust_reverse_root_references");
                root_pin.params = vec![
                    Value::Blob(key.clone()),
                    Value::Text("crate".into()),
                    Value::Text("target".into()),
                ];
                eprintln!(
                    "root candidate plan unrelated={unrelated} {state}: {:?}",
                    explain_pin(&conn, &root_pin)
                );
                let mut statement = conn.prepare(ROOT_REFERENCES_SQL).unwrap();
                let rows = statement
                    .query_map(params![key, "crate", "target"], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    rows.len(),
                    1,
                    "only the selected crate route can name this definition: {rows:?}"
                );
                measurements.push((
                    unrelated,
                    state,
                    rows.len(),
                    statement.get_status(rusqlite::StatementStatus::VmStep),
                ));
            }
        }
        eprintln!("same-name different-route candidate reads: {measurements:?}");
        for index in 0..2 {
            assert_eq!(
                measurements[index].2,
                measurements[index + 2].2,
                "different module routes cannot grow this definition's candidates: {measurements:?}"
            );
            assert_eq!(
                measurements[index].3,
                measurements[index + 2].3,
                "different module routes cannot grow this definition's query work: {measurements:?}"
            );
        }
    }

    #[test]
    #[hardwon("62fb17236b23: reverse root-name discovery fanned out over unrelated definitions")]
    fn reverse_root_name_work_ignores_unrelated_same_named_definitions() {
        let mut measurements = Vec::new();
        for unrelated in [0, 32] {
            let mut builder = InlineTestProject::new().file(
                "Cargo.toml",
                "[package]\nname='root_pin'\nversion='0.1.0'\nedition='2021'\n",
            );
            let mut source = "pub fn target() {} pub fn caller() { crate::target(); }\n".to_owned();
            for index in 0..unrelated {
                source.push_str(&format!("pub mod decoy{index};\n"));
                builder = builder.file(
                    format!("src/decoy{index}.rs"),
                    format!("pub fn target() {{}} // {index}"),
                );
            }
            let fixture = builder.file("src/lib.rs", source).build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.conn.lock().unwrap();
            brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn)
                .unwrap();
            conn.execute("DELETE FROM selected_workspace_revisions", [])
                .unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
            prepare_pin_context(&conn);
            conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,persisted_relative_path) SELECT row_number() OVER(),blob_id,'rust',rel_path FROM (SELECT DISTINCT blob_id,rel_path FROM rust_crate_container_sources)", []).unwrap();
            conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();
            for state in PlannerStatisticsState::BOTH {
                state.install(&conn);
                let key: Vec<u8> = conn
                    .query_row(
                        "SELECT crate_key FROM selected_rust_crates WHERE target_kind='lib'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let mut statement = conn.prepare(ROOT_REFERENCES_SQL).unwrap();
                let rows = statement
                    .query_map(params![key, "crate", "target"], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(
                    rows.len(),
                    1,
                    "one rooted call, no decoy references: {rows:?}"
                );
                measurements.push((
                    unrelated,
                    state,
                    statement.get_status(rusqlite::StatementStatus::VmStep),
                ));
            }
        }
        eprintln!("root candidate name VM steps: {measurements:?}");
        for index in 0..2 {
            assert_eq!(
                measurements[index].2,
                measurements[index + 2].2,
                "unrelated declarations are not candidate reads: {measurements:?}"
            );
        }
    }

    /// The tier-1 root-route family is what build-time crate derivation reads
    /// instead of joining path bodies, reference sites and recipes across the
    /// member blobs of a crate. What it must hold is that each route is one
    /// contiguous run of segment rows closed by exactly one terminal row, that
    /// the terminal row names a reference site of the same blob, and that the
    /// whole family follows the fragment out of the store.
    #[test]
    fn root_route_rows_describe_their_routes_and_follow_fragment_deletion() {
        let source = "pub mod api { pub fn target() {} } pub fn caller() { crate::api::target(); } fn typed(_: external::Shared) {}";
        let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        let root_start = source.find("external::Shared").unwrap() + "external::".len();
        let root_end = root_start + "Shared".len();
        let published_reference_identity: bool = conn
            .query_row(
                "SELECT EXISTS(
                   SELECT 1
                   FROM rust_crate_container_sources AS source
                   JOIN resolution_sites AS site ON site.blob_id=source.blob_id
                   JOIN resolution_semantic_sites AS site_semantic
                     ON site_semantic.blob_id=site.blob_id AND site_semantic.source_site=site.site
                    AND site_semantic.semantic_role='reference'
                   JOIN resolution_reference_lookup_identities AS reference
                     ON reference.blob_id=site_semantic.blob_id
                    AND reference.semantic_key=site_semantic.semantic_key
                   JOIN resolution_identities AS identity ON identity.id=reference.identity_id
                   WHERE source.rel_path='src/lib.rs' AND site.role=0
                     AND site.start_byte=?1 AND site.end_byte=?2
                     AND identity.spelling='external'
                 )",
                params![
                    i64::try_from(root_start).unwrap(),
                    i64::try_from(root_end).unwrap()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            published_reference_identity,
            "a qualified terminal reference has its first route segment's lookup identity"
        );
        let blob: i64 = conn
            .query_row(
                "SELECT blob_id FROM resolution_root_route_segments LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let malformed: Vec<(i64, i64, i64, i64, i64)> = conn
            .prepare(
                "SELECT blob_id, path_key, COUNT(*),
                        SUM(terminal_spelling IS NOT NULL), MAX(position)
                 FROM resolution_root_route_segments
                 GROUP BY blob_id, path_key
                 HAVING SUM(terminal_spelling IS NOT NULL) <> 1
                     OR MAX(position) <> COUNT(*) - 1
                     OR SUM(CASE WHEN terminal_spelling IS NOT NULL THEN position END)
                        <> COUNT(*) - 1",
            )
            .unwrap()
            .query_map([], |row| {
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
            .unwrap();
        assert!(
            malformed.is_empty(),
            "each root route is a contiguous run closed by one terminal row: {malformed:?}"
        );
        let unsited: Vec<(i64, i64)> = conn
            .prepare(
                "SELECT route.blob_id, route.path_key
                 FROM resolution_root_route_segments AS route
                 WHERE route.terminal_spelling IS NOT NULL
                   AND NOT EXISTS(
                       SELECT 1 FROM resolution_semantic_sites AS site
                       WHERE site.blob_id = route.blob_id
                         AND site.source_site = route.reference_source_site
                         AND site.semantic_role = 'reference')",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            unsited.is_empty(),
            "every root route names a reference site of its own blob: {unsited:?}"
        );
        conn.execute_batch("SAVEPOINT root_routes").unwrap();
        conn.execute(
            "DELETE FROM resolution_fragment_interiors WHERE blob_id=?1",
            [blob],
        )
        .unwrap();
        for table in [
            "resolution_root_route_segments",
            "resolution_reference_lookup_identities",
        ] {
            assert_eq!(
                conn.query_row(
                    &format!("SELECT count(*) FROM {table} WHERE blob_id=?1"),
                    [blob],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
                0,
                "{table} must follow its fragment out of the store"
            );
        }
        conn.execute_batch("ROLLBACK TO root_routes; RELEASE root_routes")
            .unwrap();
    }

    #[test]
    fn same_blob_type_export_readers_use_live_summary_rows() {
        let fixture = InlineTestProject::new()
            .file(
                "Cargo.toml",
                "[package]\nname='same_blob_exports'\nversion='0.1.0'\nedition='2021'\n",
            )
            .file("src/lib.rs", "#[path=\"shared.rs\"] mod shared;\n")
            .file(
                "tests/summary.rs",
                "#[path=\"../src/shared.rs\"] mod shared;\n",
            )
            .file(
                "src/shared.rs",
                "#[cfg(test)] pub struct Target;\n#[cfg(not(test))] pub struct Target;\n",
            )
            .build();
        let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
        let store = analyzer.store().unwrap();
        let conn = store.conn.lock().unwrap();
        brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn).unwrap();
        conn.execute("DELETE FROM selected_workspace_revisions", [])
            .unwrap();
        conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
        brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
        prepare_pin_context(&conn);

        let declarations: Vec<(i64, i64)> = conn
            .prepare(
                "SELECT declaration_blob_id,declaration_site FROM rust_crate_exports
                 WHERE namespace='type' AND name='Target' AND origin='declaration'
                 ORDER BY declaration_site",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            declarations.len(),
            2,
            "target cfg alternatives: {declarations:?}"
        );
        let (blob, target_site) = declarations[0];

        let legacy_keys_sql = "SELECT DISTINCT sites.semantic_key
            FROM rust_crate_exports AS exports INDEXED BY rust_crate_exports_declaration
            CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=exports.topology_id
            CROSS JOIN source_native_declaration_bridges AS export_bridge
              ON export_bridge.blob_id=exports.declaration_blob_id
             AND export_bridge.source_site=exports.declaration_site
            CROSS JOIN source_declaration_units AS export_unit
              ON export_unit.blob_id=export_bridge.blob_id
             AND export_unit.declaration_id=export_bridge.declaration_id
            CROSS JOIN source_native_declaration_bridges AS target_bridge
              ON target_bridge.blob_id=exports.declaration_blob_id AND target_bridge.source_site=?3
            CROSS JOIN source_declaration_units AS target_unit
              ON target_unit.blob_id=target_bridge.blob_id
             AND target_unit.declaration_id=target_bridge.declaration_id
             AND target_unit.unit_key=export_unit.unit_key
            CROSS JOIN resolution_semantic_sites AS sites
              ON sites.blob_id=exports.declaration_blob_id
             AND sites.source_site=exports.declaration_site
             AND sites.semantic_role='definition'
            WHERE exports.declaration_blob_id=?1 AND exports.namespace='type'
              AND exports.name=?2 AND exports.declaration_site<>?3";
        let legacy_keys: Vec<i64> = conn
            .prepare(legacy_keys_sql)
            .unwrap()
            .query_map(params![blob, "Target", target_site], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let summary_keys: Vec<i64> = conn
            .prepare(SAME_BLOB_TYPE_EXPORT_KEYS_SQL)
            .unwrap()
            .query_map(params![blob, "Target", target_site], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(summary_keys, legacy_keys, "same-blob semantic keys");

        let legacy_exports_sql = "SELECT exports.topology_id, owner.crate_key,
                exports.module_path, 'type', exports.name, exports.visibility, 0
            FROM rust_crate_exports AS exports INDEXED BY rust_crate_exports_declaration
            CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=exports.topology_id
            CROSS JOIN source_native_declaration_bridges AS export_bridge
              ON export_bridge.blob_id=exports.declaration_blob_id
             AND export_bridge.source_site=exports.declaration_site
            CROSS JOIN source_declaration_units AS export_unit
              ON export_unit.blob_id=export_bridge.blob_id
             AND export_unit.declaration_id=export_bridge.declaration_id
            CROSS JOIN source_native_declaration_bridges AS target_bridge
              ON target_bridge.blob_id=exports.declaration_blob_id AND target_bridge.source_site=?3
            CROSS JOIN source_declaration_units AS target_unit
              ON target_unit.blob_id=target_bridge.blob_id
             AND target_unit.declaration_id=target_bridge.declaration_id
             AND target_unit.unit_key=export_unit.unit_key
            WHERE exports.declaration_blob_id=?1 AND exports.namespace='type'
              AND exports.name=?2 AND exports.declaration_site<>?3
              AND EXISTS(SELECT 1 FROM rust_crate_container_sources AS source
                         INDEXED BY rust_crate_containers_path
                         WHERE source.topology_id=exports.topology_id
                           AND source.container_path=exports.module_path
                           AND source.blob_id=exports.declaration_blob_id
                           AND source.rel_path=?4)";
        let legacy_exports = conn
            .prepare(legacy_exports_sql)
            .unwrap()
            .query_map(params![blob, "Target", target_site, "src/lib.rs"], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let summary_exports = conn
            .prepare(SAME_BLOB_TYPE_EXPORTS_SQL)
            .unwrap()
            .query_map(params![blob, "Target", target_site, "src/lib.rs"], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(summary_exports, legacy_exports, "same-blob exports");

        for state in PlannerStatisticsState::BOTH {
            state.install(&conn);
            for (name, sql, params, indexes) in [
                (
                    "same_blob_type_export_keys",
                    SAME_BLOB_TYPE_EXPORT_KEYS_SQL,
                    vec![
                        Value::Integer(blob),
                        Value::Text("Target".into()),
                        Value::Integer(target_site),
                    ],
                    &[
                        "resolution_unit_summary_members_blob",
                        "rust_resolution_unit_summary_exports_declaration",
                    ][..],
                ),
                (
                    "same_blob_type_exports",
                    SAME_BLOB_TYPE_EXPORTS_SQL,
                    vec![
                        Value::Integer(blob),
                        Value::Text("Target".into()),
                        Value::Integer(target_site),
                        Value::Text("src/lib.rs".into()),
                    ],
                    &[
                        "resolution_unit_summary_members_blob",
                        "resolution_unit_summary_placements_member",
                        "rust_resolution_unit_summary_exports_declaration",
                    ][..],
                ),
            ] {
                let pin = brokk_bifrost_analysis::analyzer::store::planner_statistics::pinned_plans::PinnedQuery {
                    name: name.to_owned(),
                    sql: sql.to_owned(),
                    params,
                };
                let plan = explain_pin(&conn, &pin);
                for index in indexes {
                    assert!(
                        plan.iter().any(|row| row.contains(index)),
                        "{state:?} {name} requires {index}: {plan:?}"
                    );
                }
                assert!(
                    !plan.iter().any(|row| row.contains("AUTOMATIC")),
                    "{state:?} {name}: {plan:?}"
                );
            }
        }
    }

    #[test]
    fn reverse_rows_export_and_import_work_is_independent_of_unrelated_inventory() {
        let mut measurements = Vec::new();
        for unrelated in [0, 32] {
            let mut builder = InlineTestProject::new()
                .file("Cargo.toml", "[workspace]\nmembers=['api','barrel','client']\nresolver='2'\n")
                .file("api/Cargo.toml", "[package]\nname='api'\nversion='0.1.0'\nedition='2021'\n")
                .file("barrel/Cargo.toml", "[package]\nname='barrel'\nversion='0.1.0'\nedition='2021'\n[dependencies]\napi={path='../api'}\n")
                .file("client/Cargo.toml", "[package]\nname='client'\nversion='0.1.0'\nedition='2021'\n[dependencies]\nbarrel={path='../barrel'}\n")
                .file("barrel/src/lib.rs", "pub use api::target as renamed; pub use api::*;\n")
                .file("client/src/lib.rs", "use barrel::renamed as local; use barrel::*; pub fn caller() { local(); }\n");
            let mut api =
                "pub fn target() {}\n#[macro_export]\nmacro_rules! sample { () => {}; }\n"
                    .to_owned();
            for index in 0..unrelated {
                api.push_str(&format!("pub mod decoy{index};\n"));
                builder = builder.file(
                    format!("api/src/decoy{index}.rs"),
                    format!("pub fn other{index}() {{}}\n"),
                );
            }
            let fixture = builder.file("api/src/lib.rs", api).build();
            let analyzer = fixture.workspace_analyzer(AnalyzerConfig::default());
            let store = analyzer.store().unwrap();
            let conn = store.conn.lock().unwrap();
            brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views(&conn)
                .unwrap();
            conn.execute("DELETE FROM selected_workspace_revisions", [])
                .unwrap();
            conn.execute("INSERT INTO selected_workspace_revisions SELECT workspace_id,lang,generation,revision FROM workspace_heads WHERE lang='rust'", []).unwrap();
            brokk_bifrost_analysis::analyzer::store::fill_selected_rust_units(&conn).unwrap();
            prepare_pin_context(&conn);
            conn.execute("INSERT INTO selected_resolution_mounts(mount_ordinal,blob_id,storage_language,semantic_language,producer_epoch,interior_digest,persisted_relative_path) SELECT row_number() OVER(), member.blob_id, 'rust', interior.semantic_language, interior.producer_epoch, interior.interior_digest, member.rel_path FROM (SELECT DISTINCT blob_id,rel_path FROM selected_rust_crate_containers) AS member JOIN resolution_fragment_interiors AS interior USING(blob_id)", []).unwrap();
            conn.execute_batch(brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_crate_context::SELECTED_MODULE_PLACEMENTS_FILL_SQL).unwrap();

            let (blob, site): (i64, i64) = conn.query_row("SELECT declaration_blob_id,declaration_site FROM rust_crate_exports e JOIN rust_crate_topologies t USING(topology_id) WHERE t.crate_name='api' AND e.name='target'", [], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
            let key: Vec<u8> = conn
                .query_row(
                    "SELECT crate_key FROM selected_rust_crates WHERE crate_name='barrel'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let legacy_activation_sql = r#"
SELECT properties.cfg_condition, json(owner.cfg_atoms), owner.target_kind
FROM source_declaration_units AS units
CROSS JOIN source_native_declaration_bridges AS bridge
  ON bridge.blob_id=units.blob_id AND bridge.declaration_id=units.declaration_id
CROSS JOIN resolution_semantic_sites AS site
  ON site.blob_id=bridge.blob_id AND site.source_site=bridge.source_site
 AND site.semantic_role='definition'
CROSS JOIN source_rust_declaration_properties AS properties
  ON properties.blob_id=bridge.blob_id AND properties.declaration_id=bridge.declaration_id
CROSS JOIN rust_crate_container_sources AS sources INDEXED BY rust_crate_containers_blob
  ON sources.blob_id=site.blob_id
CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=sources.topology_id
WHERE units.blob_id=?1 AND units.unit_key=(
  SELECT target_units.unit_key
  FROM source_native_declaration_bridges AS target_bridge
  CROSS JOIN source_declaration_units AS target_units
    ON target_units.blob_id=target_bridge.blob_id
   AND target_units.declaration_id=target_bridge.declaration_id
  WHERE target_bridge.blob_id=?1 AND target_bridge.source_site=?2
)
"#;
            let legacy_activation = conn
                .prepare(legacy_activation_sql)
                .unwrap()
                .query_map(params![blob, site], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            let summary_activation = conn
                .prepare(BASE_TARGET_ACTIVATION_SQL)
                .unwrap()
                .query_map(params![blob, site], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(summary_activation, legacy_activation, "target activation");
            let client_blob: i64 = conn.query_row("SELECT blob_id FROM selected_rust_crate_containers WHERE rel_path='client/src/lib.rs'", [], |row| row.get(0)).unwrap();
            let legacy_caller_roots_sql = r#"
WITH source(blob_id,persisted_relative_path) AS (
 SELECT blob_id,persisted_relative_path FROM temp.selected_resolution_mounts
 WHERE storage_language='rust' AND persisted_relative_path=?1
 UNION ALL
 SELECT blob.id,mask.persisted_relative_path
 FROM temp.selected_resolution_overlay_masks AS mask
 CROSS JOIN workspace_file_versions AS version
   ON version.file_version_id=mask.masked_file_version_id
 CROSS JOIN blobs AS blob
   ON blob.blob_oid=version.blob_oid AND blob.lang=version.lang
  AND blob.generation=version.generation
 WHERE mask.storage_language='rust' AND mask.persisted_relative_path=?1
)
SELECT DISTINCT roots.rel_path
FROM source
CROSS JOIN rust_crate_container_sources AS placement INDEXED BY rust_crate_containers_blob
  ON placement.blob_id=source.blob_id AND placement.rel_path=source.persisted_relative_path
CROSS JOIN selected_rust_crates AS owner ON owner.topology_id=placement.topology_id
CROSS JOIN rust_crate_container_sources AS roots
  ON roots.topology_id=owner.topology_id AND roots.container_path='crate'
WHERE roots.source_kind='declared'
  AND (owner.target_kind<>'detached' OR NOT EXISTS(
    SELECT 1
    FROM rust_crate_container_sources AS parent INDEXED BY rust_crate_containers_blob
    CROSS JOIN selected_rust_crates AS container ON container.topology_id=parent.topology_id
    WHERE parent.blob_id=roots.blob_id AND parent.rel_path=roots.rel_path
      AND parent.topology_id<>owner.topology_id AND parent.container_path<>'crate'
      AND container.target_kind='detached'
  ))
"#;
            let caller_paths = if unrelated > 0 {
                vec!["client/src/lib.rs", "api/src/decoy0.rs"]
            } else {
                vec!["client/src/lib.rs"]
            };
            for candidate_path in caller_paths {
                let mut legacy_roots = conn
                    .prepare(legacy_caller_roots_sql)
                    .unwrap()
                    .query_map([candidate_path], |row| row.get::<_, String>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let mut summary_roots = conn
                    .prepare(CALLER_ROOTS_SQL)
                    .unwrap()
                    .query_map([candidate_path], |row| row.get::<_, String>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                legacy_roots.sort();
                summary_roots.sort();
                assert_eq!(
                    summary_roots, legacy_roots,
                    "caller roots for {candidate_path}"
                );
            }
            let oracle = conn.prepare("SELECT topology_id,module_path,namespace,name FROM rust_crate_exports_reachable WHERE declaration_blob_id=?1 AND declaration_site=?2 ORDER BY 1,2,3,4").unwrap().query_map(params![blob, site], |row| Ok((row.get::<_, i64>(0)?,row.get::<_, String>(1)?,row.get::<_, String>(2)?,row.get::<_, String>(3)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert_eq!(oracle.len(), 3, "{oracle:?}");
            for state in PlannerStatisticsState::BOTH {
                state.install(&conn);
                let mut export_pin = pinned("rust_reverse_exports");
                export_pin.params = vec![
                    Value::Integer(blob),
                    Value::Integer(site),
                    Value::Text("api/src/lib.rs".into()),
                ];
                let mut statement = conn.prepare(&export_pin.sql).unwrap();
                let mut rows = statement
                    .query_map(params![blob, site, "api/src/lib.rs"], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                rows.sort();
                rows.dedup();
                assert_eq!(rows, oracle, "{state:?}");
                let export_work = statement.get_status(rusqlite::StatementStatus::VmStep);
                let mut legacy_module_statement = conn
                    .prepare(
                        "SELECT candidate.blob_id
                         FROM rust_crate_container_sources AS candidate
                         CROSS JOIN selected_rust_crate_containers AS selected
                           ON selected.topology_id=candidate.topology_id
                          AND selected.container_path=candidate.container_path
                          AND selected.rel_path=candidate.rel_path
                          AND selected.blob_id=candidate.blob_id
                         WHERE candidate.topology_id=(
                           SELECT topology_id FROM selected_rust_crates WHERE crate_key=?1)
                           AND candidate.container_path=?2",
                    )
                    .unwrap();
                let mut legacy_module_sources = legacy_module_statement
                    .query_map(params![key, "crate"], |row| row.get::<_, i64>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let mut summary_module_statement = conn.prepare(MODULE_SOURCES_SQL).unwrap();
                let mut summary_module_sources = summary_module_statement
                    .query_map(params![key, "crate"], |row| row.get::<_, i64>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                legacy_module_sources.sort_unstable();
                legacy_module_sources.dedup();
                summary_module_sources.sort_unstable();
                summary_module_sources.dedup();
                assert_eq!(
                    summary_module_sources, legacy_module_sources,
                    "{state:?} module sources"
                );
                assert_eq!(summary_module_sources.len(), 1, "{state:?} module source");
                let mut legacy_macro_statement = conn
                    .prepare(
                        "SELECT member.blob_id
                         FROM rust_crate_container_sources AS placement
                           INDEXED BY rust_crate_containers_blob
                         CROSS JOIN selected_rust_crates AS owner
                           ON owner.topology_id=placement.topology_id
                         CROSS JOIN rust_crate_container_sources AS member
                           INDEXED BY rust_crate_containers_path
                           ON member.topology_id=placement.topology_id
                         WHERE placement.blob_id=?1 AND EXISTS(
                           SELECT 1 FROM temp.selected_resolution_mounts AS selected
                             INDEXED BY selected_resolution_mounts_blob_ordinal
                           WHERE selected.blob_id=member.blob_id
                             AND selected.storage_language='rust'
                             AND selected.persisted_relative_path=member.rel_path)",
                    )
                    .unwrap();
                let mut legacy_macro_sources = legacy_macro_statement
                    .query_map([blob], |row| row.get::<_, i64>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let mut summary_macro_statement = conn.prepare(TEXTUAL_MACRO_SOURCES_SQL).unwrap();
                let mut summary_macro_sources = summary_macro_statement
                    .query_map([blob], |row| row.get::<_, i64>(0))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                legacy_macro_sources.sort_unstable();
                legacy_macro_sources.dedup();
                summary_macro_sources.sort_unstable();
                summary_macro_sources.dedup();
                assert_eq!(
                    summary_macro_sources, legacy_macro_sources,
                    "{state:?} macro sources"
                );
                assert_eq!(
                    summary_macro_sources.len(),
                    unrelated as usize + 1,
                    "{state:?} textual macro scope"
                );
                // Named routes now identify the canonical declaration, so both
                // barrel::renamed and client::local invert api::target directly.
                let import_key: Vec<u8> = conn
                    .query_row(
                        "SELECT crate_key FROM selected_rust_crates WHERE crate_name='api'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let mut legacy_import_statement = conn
                    .prepare(
                        "SELECT sources.blob_id, imports.bound_name,
                                CASE WHEN sources.blob_id=imports.blob_id
                                     THEN imports.binder_scope END,
                                imports.topology_id, owner.crate_key, imports.module_path
                         FROM rust_crate_imports AS imports
                         CROSS JOIN selected_rust_crates AS owner
                           ON owner.topology_id=imports.topology_id
                         CROSS JOIN rust_crate_container_sources AS sources
                           ON sources.topology_id=imports.topology_id
                          AND sources.container_path=imports.module_path
                         WHERE imports.target_crate_key=?1
                           AND imports.target_module_path=?2 AND imports.target_name=?3",
                    )
                    .unwrap();
                let mut legacy_imports = legacy_import_statement
                    .query_map(params![import_key, "crate", "target"], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<u32>>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, String>(5)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let mut summary_import_statement = conn.prepare(IMPORTS_SQL).unwrap();
                let mut summary_imports = summary_import_statement
                    .query_map(params![import_key, "crate", "target"], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<u32>>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, String>(5)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                legacy_imports.sort();
                summary_imports.sort();
                assert_eq!(summary_imports, legacy_imports, "{state:?} imports");
                let mut import_pin = pinned("rust_reverse_imports");
                import_pin.params = vec![
                    Value::Blob(import_key.clone()),
                    Value::Text("crate".into()),
                    Value::Text("target".into()),
                ];
                let mut imports = conn.prepare(&import_pin.sql).unwrap();
                let mut bindings = imports
                    .query_map(params![import_key, "crate", "target"], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                bindings.sort();
                let barrel_blob: i64 = conn.query_row(
                    "SELECT blob_id FROM selected_rust_crate_containers WHERE rel_path='barrel/src/lib.rs'",
                    [], |row| row.get(0)).unwrap();
                let mut expected = vec![
                    (barrel_blob, "renamed".into()),
                    (client_blob, "local".into()),
                ];
                expected.sort();
                assert_eq!(bindings, expected);
                let import_work = imports.get_status(rusqlite::StatementStatus::VmStep);
                let mut legacy_glob_statement = conn
                    .prepare(
                        "SELECT sources.blob_id,
                                CASE WHEN sources.blob_id=imports.blob_id
                                     THEN imports.binder_scope END,
                                imports.topology_id, owner.crate_key, imports.module_path
                         FROM rust_crate_glob_imports AS imports
                         CROSS JOIN selected_rust_crates AS owner
                           ON owner.topology_id=imports.topology_id
                         CROSS JOIN rust_crate_container_sources AS sources
                           ON sources.topology_id=imports.topology_id
                          AND sources.container_path=imports.module_path
                         WHERE imports.target_crate_key=?1 AND imports.target_module_path=?2",
                    )
                    .unwrap();
                let mut legacy_globs = legacy_glob_statement
                    .query_map(params![key, "crate"], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<u32>>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                let mut summary_glob_statement = conn.prepare(GLOBS_SQL).unwrap();
                let mut summary_globs = summary_glob_statement
                    .query_map(params![key, "crate"], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<u32>>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, String>(4)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                legacy_globs.sort();
                summary_globs.sort();
                assert_eq!(summary_globs, legacy_globs, "{state:?} globs");
                assert_eq!(summary_globs.len(), 1, "{state:?} glob route");
                measurements.push((unrelated, state, export_work, import_work));
                let cases = [
                    (
                        {
                            let mut p = pinned("rust_reverse_definition_blob");
                            p.params = vec![Value::Integer(0)];
                            p
                        },
                        "SEARCH mount USING PRIMARY KEY",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_definition_semantics");
                            p.params = vec![Value::Integer(blob)];
                            p
                        },
                        "SEARCH crosswalk USING",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_masked_blob");
                            p.params = vec![Value::Text("client/src/lib.rs".into())];
                            p
                        },
                        "SEARCH mask USING PRIMARY KEY",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_blob_definition_site");
                            p.params = vec![Value::Integer(blob), Value::Integer(0)];
                            p
                        },
                        "SEARCH resolution_semantic_sites USING",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_base_target_activation");
                            p.params = vec![Value::Integer(blob), Value::Integer(site)];
                            p
                        },
                        "resolution_unit_summary_members_blob",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_definition_site");
                            p.params = vec![Value::Integer(0), Value::Integer(0)];
                            p
                        },
                        "SEARCH mounts USING PRIMARY KEY",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_root_references");
                            p.params = vec![
                                Value::Blob(key.clone()),
                                Value::Text("crate".into()),
                                Value::Text("renamed".into()),
                            ];
                            p
                        },
                        "rust_resolution_unit_summary_root_routes_target",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_target_activation");
                            p.params = vec![Value::Integer(0), Value::Integer(0)];
                            p
                        },
                        "resolution_unit_summary_members_blob",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_contract_owner");
                            p.params = vec![Value::Integer(0), Value::Integer(0)];
                            p
                        },
                        "SEARCH owner USING",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_reference_lookup_blobs");
                            p.params = vec![Value::Blob(
                                ResolutionLookupSemanticRecipe::new(
                                    Language::Rust,
                                    ResolutionNamespace::Callable,
                                    "target",
                                )
                                .name_digest()
                                .to_vec(),
                            )];
                            p
                        },
                        "resolution_reference_lookup_identities_identity",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_caller_roots");
                            p.params = vec![Value::Text("client/src/lib.rs".into())];
                            p
                        },
                        "resolution_unit_summary_members_blob",
                    ),
                    (pinned("rust_graph_definitions"), "SEARCH site USING"),
                    (
                        export_pin,
                        "rust_resolution_unit_summary_exports_declaration",
                    ),
                    (
                        import_pin,
                        "rust_resolution_unit_summary_import_routes_target_identity",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_globs");
                            p.params = vec![Value::Blob(key.clone()), Value::Text("crate".into())];
                            p
                        },
                        "rust_resolution_unit_summary_glob_imports_target_identity",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_module_sources");
                            p.params = vec![Value::Blob(key.clone()), Value::Text("crate".into())];
                            p
                        },
                        "SEARCH placement USING PRIMARY KEY (summary_id=? AND container_path=?)",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_textual_macro_sources");
                            p.params = vec![Value::Integer(blob)];
                            p
                        },
                        "resolution_unit_summary_members_blob",
                    ),
                    (
                        {
                            let mut p = pinned("rust_reverse_locators");
                            p.params = vec![Value::Integer(client_blob)];
                            p
                        },
                        "selected_resolution_mounts_blob_ordinal",
                    ),
                ];
                for (pin, index) in cases {
                    let plan = explain_pin(&conn, &pin);
                    assert!(
                        plan.iter().any(|row| row.contains(index)),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                    assert!(
                        !plan.iter().any(|row| row.contains("AUTOMATIC")),
                        "{state:?} {}: {plan:?}",
                        pin.name
                    );
                    if pin.name == "rust_reverse_root_references" {
                        assert!(
                            plan.iter().any(|row| {
                                row.contains("rust_resolution_unit_summary_root_routes_target")
                            }),
                            "{state:?} {} must seek live root routes by target identity: {plan:?}",
                            pin.name
                        );
                    }
                    if pin.name == "rust_reverse_exports" {
                        for index in [
                            "rust_resolution_unit_summary_reexport_routes_target_identity",
                            "rust_resolution_unit_summary_glob_reexport_routes_target_identity",
                        ] {
                            assert!(
                                plan.iter().any(|row| row.contains(index)),
                                "{state:?} {} must seek route targets with {index}: {plan:?}",
                                pin.name
                            );
                        }
                    }
                    for table in [
                        "exports", "routes", "imports", "paths", "sites", "names", "sources",
                    ] {
                        assert!(
                            !plan
                                .iter()
                                .any(|row| row.starts_with(&format!("SCAN {table}"))),
                            "{state:?} {}: {plan:?}",
                            pin.name
                        );
                    }
                }
            }
        }
        eprintln!("reverse rows VM steps: {measurements:?}");
        for index in 0..2 {
            assert_eq!(
                (measurements[index].2, measurements[index].3),
                (measurements[index + 2].2, measurements[index + 2].3),
                "unrelated export inventory must not add candidate reads: {measurements:?}"
            );
        }
    }
}
