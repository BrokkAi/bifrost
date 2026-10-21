#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::AT_SITE;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::ENUMERATE;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::POINT;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::TOKEN_SITE;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::named_routes;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::route_at_site;

    use brokk_bifrost_analysis::analyzer::store::resolution_operation::imports::scope_routes;
    use brokk_bifrost_core::analyzer::Language;
    use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
    #[test]
    fn shared_import_rows_round_trip_and_seek_on_populated_store() {
        let fixture = brokk_bifrost_analysis::test_support::AnalyzerFixture::new_for_language(
            Language::Rust,
            &[(
                "lib.rs",
                "use external::source as renamed; use unused::*; use core::option::{self as options}; use core::marker::Copy::{self as C}; fn f(_: renamed) {}",
            )],
        );
        let connection = fixture.analyzer.store().unwrap().conn.lock().unwrap();
        let (blob, scope) = connection.query_row("SELECT blob_id, root_scope FROM resolution_root_imports WHERE bound_name='renamed'", [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?))).unwrap();
        let cancel = CancellationToken::default();
        let routes = named_routes(&connection, blob, scope, "renamed", &cancel)
            .unwrap()
            .unwrap();
        assert_eq!(routes.len(), 2, "named plus unused glob: {routes:?}");
        let named = routes.iter().find(|r| r.kind == "named").unwrap();
        assert_eq!(named.segments, ["external"]);
        assert!(
            named.demands.iter().all(|d| d.1 == "renamed"
                && d.2.as_deref() == Some("named_reference")
                && d.3.is_some()
                && d.4.as_deref() == Some("source")),
            "{named:?}"
        );
        let glob = routes.iter().find(|r| r.kind == "glob").unwrap();
        assert_eq!(glob.segments, ["unused"]);
        assert!(
            glob.demands.is_empty(),
            "unused routes survive without demands: {glob:?}"
        );
        let all_routes = scope_routes(&connection, blob, scope, &cancel)
            .unwrap()
            .unwrap();
        assert_eq!(all_routes.len(), 4);
        for (name, expected) in [
            ("options", vec!["core", "option"]),
            ("C", vec!["core", "marker", "Copy"]),
        ] {
            let routes = named_routes(&connection, blob, scope, name, &cancel)
                .unwrap()
                .unwrap();
            let route = routes.iter().find(|route| route.kind == "named").unwrap();
            assert_eq!(route.named_path(brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::namespace_code(brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace::Type)).unwrap(), expected);
        }
        assert_eq!(
            route_at_site(&connection, blob, named.site)
                .unwrap()
                .as_ref(),
            Some(named)
        );
        for state in PlannerStatisticsState::BOTH {
            state.install(&connection);
            for (name, sql, values) in [
                (
                    "point",
                    POINT,
                    vec![
                        blob.into(),
                        i64::from(scope).into(),
                        "renamed".to_owned().into(),
                    ],
                ),
                (
                    "enumerate",
                    ENUMERATE,
                    vec![blob.into(), i64::from(scope).into()],
                ),
                (
                    "site",
                    AT_SITE,
                    vec![blob.into(), i64::from(named.site).into()],
                ),
                ("token_site", TOKEN_SITE, vec![blob.into(), 0.into()]),
            ] {
                let values: Vec<rusqlite::types::Value> = values;
                let plan = connection
                    .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                    .unwrap()
                    .query_map(rusqlite::params_from_iter(&values), |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                eprintln!("IMPORT_PLAN {state:?} {name}: {plan:?}");
                assert!(
                    plan.iter()
                        .all(|line| !line.contains("MATERIALIZE") && !line.starts_with("SCAN ")),
                    "{state:?} {name}: {plan:?}"
                );
                assert!(
                    plan.iter().any(|line| line.starts_with("SEARCH ")),
                    "{state:?} {name}: {plan:?}"
                );
            }
        }
    }
}
