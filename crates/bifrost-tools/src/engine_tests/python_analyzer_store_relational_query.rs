#[cfg(test)]
mod python_extraction_tests {
    use brokk_bifrost_test_macros::hardwon;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::relational_query::EXACT_PATH_REQUEST;

    use brokk_bifrost_analysis::analyzer::store::relational_query::NORMALIZED_PATH_REQUEST;

    use brokk_bifrost_analysis::analyzer::store::relational_query::STRUCTURAL_MEMBER_PATH_REQUEST;

    use brokk_bifrost_analysis::analyzer::store::relational_query::batched_path_sql;

    use brokk_bifrost_analysis::analyzer::store::relational_query::path_view_predicate;

    use brokk_bifrost_analysis::analyzer::store::relational_query::path_view_sql;

    use brokk_bifrost_analysis::analyzer::store::relational_query::render_name;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::fq_name::segment_interner;

    use brokk_bifrost_core::analyzer::{
        DefinitionLanguageScope, RelationalDefinitionQuery, RelationalDefinitionRequest,
        RelationalName, symbol_path::parse_symbol_path_fq,
    };
    use brokk_bifrost_python_analysis::analyzer::python::PythonAdapter;
    /// Query-plan pin for the path-derived arm (Part 2 of the issue #2588
    /// plan). A path-derived module unit is a declaration the analyzer invents
    /// for a file whose module name comes from its path: `pkg/service.py` is
    /// the module `pkg.service` although no line in it says so. Python,
    /// JavaScript, and TypeScript have them.
    ///
    /// Before Part 2, both the point query and (by exclusion) the batched
    /// query read the wide three-arm views with `source_kind = 'path'`. SQLite
    /// materialized the whole compound as a co-routine, ran the two content
    /// arms whose rows it then discarded, and had no index for the columns the
    /// path predicate names, so it drove the arm from
    /// `idx_workspace_file_versions_snapshot_blob` on (workspace, lang,
    /// generation) -- every live file of the language -- once per request.
    ///
    /// This test calls the real `path_view_predicate` and the real SQL
    /// builders, so it fails if production stops routing a shape through the
    /// lean view or changes a predicate to one that cannot seek. Removing the
    /// `short_name` term from the identifier shape, for example, leaves the
    /// query with nothing but `lang`, and the index assertion fails.
    #[test]
    #[hardwon("3932076e7002: path-derived policy queries scanned every live file per request")]
    fn path_unit_queries_seek_path_symbol_indexes() {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let connection = store.conn.lock().expect("store mutex");
        let explain = |sql: String, bindings: &[&str]| {
            let mut statement = connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .expect("prepare path query plan");
            statement
                .query_map(rusqlite::params_from_iter(bindings), |row| {
                    row.get::<_, String>(3)
                })
                .expect("read path query plan")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("collect path query plan")
        };
        let assert_seeks_path_index = |case_name: &str, index: &str, plan: &[String]| {
            assert!(
                plan.iter().any(|detail| detail.contains(index)),
                "{case_name} must seek {index}: {plan:#?}"
            );
            assert!(
                plan.iter().all(|detail| !detail.contains("SCAN rows")),
                "{case_name} must not scan workspace_file_path_symbol_rows: {plan:#?}"
            );
            assert!(
                plan.iter().all(|detail| !detail.contains("CO-ROUTINE")),
                "{case_name} must not materialize a compound view: {plan:#?}"
            );
            assert!(
                plan.iter().all(|detail| !detail.contains("TEMP B-TREE")),
                "{case_name} must not sort in SQL: {plan:#?}"
            );
        };

        let module_name = RelationalName::stable(parse_symbol_path_fq(
            Language::Python,
            "pkg.service",
            segment_interner(),
        ));
        let decorated_name = RelationalName::stable(parse_symbol_path_fq(
            Language::Python,
            "pkg.service`",
            segment_interner(),
        ));
        let file = ProjectFile::new(
            std::env::current_dir().expect("test working directory must be available"),
            "pkg/service.py".to_string(),
        );
        let adapter = PythonAdapter::for_test_file(&file);
        let short = "idx_workspace_file_path_symbol_rows_short";
        let package = "idx_workspace_file_path_symbol_rows_package";
        let normalized = "idx_workspace_file_path_symbol_rows_normalized";

        let point_cases: [(&str, &RelationalName, RelationalDefinitionQuery, &str); 10] = [
            (
                "exact name",
                &module_name,
                RelationalDefinitionQuery::ExactName,
                package,
            ),
            (
                "normalized name",
                &module_name,
                RelationalDefinitionQuery::NormalizedName,
                normalized,
            ),
            (
                "structural children",
                &module_name,
                RelationalDefinitionQuery::StructuralChildren,
                package,
            ),
            (
                "structural members",
                &module_name,
                RelationalDefinitionQuery::StructuralMembers {
                    identifier: "service".to_string(),
                },
                package,
            ),
            (
                "visible members",
                &module_name,
                RelationalDefinitionQuery::VisibleMembers {
                    identifier: "service".to_string(),
                },
                package,
            ),
            (
                "identifier",
                &module_name,
                RelationalDefinitionQuery::Identifier { file: None },
                short,
            ),
            (
                "file identifier",
                &module_name,
                RelationalDefinitionQuery::Identifier {
                    file: Some(file.clone()),
                },
                short,
            ),
            (
                "identifier prefix",
                &decorated_name,
                RelationalDefinitionQuery::IdentifierPrefix { file: None },
                short,
            ),
            (
                "package types",
                &module_name,
                RelationalDefinitionQuery::PackageTypes {
                    simple_name: "service".to_string(),
                },
                package,
            ),
            (
                "package types in package",
                &module_name,
                RelationalDefinitionQuery::PackageTypesInPackage,
                package,
            ),
        ];

        for (case_name, name, query, index) in point_cases {
            let request = RelationalDefinitionRequest {
                ordinal: 0,
                language_scope: DefinitionLanguageScope::Language(Language::Python),
                name: name.clone(),
                query,
            };
            let (prefix, tail, _) = render_name(&adapter, &request.name);
            let (predicate, values) = path_view_predicate(&adapter, &request, &prefix, &tail)
                .unwrap_or_else(|| panic!("{case_name} must reach the path view"));
            let bindings: Vec<&str> = std::iter::once("python")
                .chain(values.iter().map(String::as_str))
                .collect();
            let plan = explain(path_view_sql(&predicate), &bindings);
            assert_seeks_path_index(case_name, index, &plan);
        }

        // The batched half. The request relation is bound as one JSON text
        // parameter; an empty array is enough for the planner, which never
        // reads the values.
        for (case_name, request, index) in [
            ("batched exact name", &EXACT_PATH_REQUEST, package),
            (
                "batched normalized name",
                &NORMALIZED_PATH_REQUEST,
                normalized,
            ),
            (
                "batched structural members",
                &STRUCTURAL_MEMBER_PATH_REQUEST,
                package,
            ),
        ] {
            let sql = batched_path_sql(request.columns, request.values, request.predicate);
            let plan = explain(sql, &["[]", "python"]);
            assert_seeks_path_index(case_name, index, &plan);
        }

        // A request with a non-empty prefix cannot match a path row, whose
        // prefix is always empty, so no query is issued at all.
        let anchored_name = RelationalName::new(
            parse_symbol_path_fq(Language::Python, "vendor", segment_interner()),
            parse_symbol_path_fq(Language::Python, "pkg.service", segment_interner()),
        );
        let anchored_request = RelationalDefinitionRequest {
            ordinal: 0,
            language_scope: DefinitionLanguageScope::Language(Language::Python),
            name: anchored_name,
            query: RelationalDefinitionQuery::ExactName,
        };
        let (prefix, tail, _) = render_name(&adapter, &anchored_request.name);
        assert!(
            path_view_predicate(&adapter, &anchored_request, &prefix, &tail).is_none(),
            "a prefixed request must not issue a path query"
        );
    }
}
