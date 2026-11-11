#[cfg(test)]
mod python_residency_tests {

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::RouteEndpoint;

    use brokk_bifrost_core::analyzer::structural::routes::RouteHopKind;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::test_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::test_support::rows_of_kind;
    /// The Python facade fixture of issue #1649: a package with an
    /// implementation module, and a `facade.py` whose body the test supplies.
    fn python_facade(facade: &str) -> Fixture {
        Fixture::new(
            Language::Python,
            &[
                ("pkg/__init__.py", ""),
                ("pkg/impl.py", "class Widget:\n    pass\n"),
                ("facade.py", facade),
            ],
        )
    }
    /// `from x import *` forwards the whole public surface of `x` as one star
    /// hop on the module reference. The expansion stays the import machinery's
    /// answer, so the producer records the hop and enumerates nothing.
    #[test]
    fn python_star_import_is_one_reexport_hop() {
        let fixture = Fixture::new(
            Language::Python,
            &[
                ("pkg/__init__.py", "from .impl import *\n"),
                ("pkg/impl.py", "class Widget:\n    pass\n"),
            ],
        );
        let rows = fixture.rows(0);
        let reexports = rows_of_kind(&rows, RouteHopKind::ReExport);
        assert_eq!(reexports.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Site { name, range, .. } = &reexports[0].from else {
            panic!("re-export site expected");
        };
        assert_eq!(name, "impl");
        assert_eq!(range.start_byte, fixture.at(0, "impl import"));
        let RouteEndpoint::Declaration(target) = &reexports[0].to else {
            panic!("re-export target must be a declaration");
        };
        assert_eq!(target.source(), &fixture.files[1]);
    }
    /// A computed `__all__` settles no name's membership, so the facade's
    /// site-anchored relations report incomplete instead of guessing. The
    /// nested-owner relations are untouched by that gap, and the site still
    /// carries the plain import its occurrence role already states.
    #[test]
    fn python_computed_all_leaves_site_relations_incomplete() {
        let rows = python_facade("__all__ = build_exports()\nimport pkg.impl as impl\n").rows(2);
        assert!(
            !rows.completeness.covers(RouteHopKind::ReExport),
            "an unreadable __all__ must not read as a complete re-export answer: {:?}",
            rows.completeness
        );
        assert!(
            !rows.completeness.covers(RouteHopKind::Import),
            "the same site is unclassified for the import relation: {:?}",
            rows.completeness
        );
        assert!(
            rows.completeness.covers(RouteHopKind::NestedOwner),
            "nested owners are declaration-anchored, so the gap does not reach them: {:?}",
            rows.completeness
        );
        assert!(
            rows_of_kind(&rows, RouteHopKind::ReExport).is_empty(),
            "nothing is guessed into a re-export row: {:?}",
            rows.rows
        );
        assert_eq!(
            rows_of_kind(&rows, RouteHopKind::Import).len(),
            1,
            "rows: {:?}",
            rows.rows
        );
    }
    #[test]
    fn python_partial_all_scopes_export_uncertainty_to_unproven_names() {
        use brokk_bifrost_analysis::analyzer::structural::identity_routes::identity_routes_from;
        use brokk_bifrost_analysis::cancellation::CancellationToken;
        use brokk_bifrost_core::analyzer::structural::routes::RouteTermination;

        let fixture = python_facade(concat!(
            "class Listed: pass\n",
            "class Hidden:\n    def nested(self): pass\n",
            "class Later: pass\n",
            "__all__ = ['Listed', 'impl']\n",
            "__all__ += computed()\n",
            "__all__ += [computed(), 'Later']\n",
            "import pkg.impl as impl\n",
            "from pkg.impl import Widget as Widget\n",
            "from pkg.impl import Widget as Unknown\n",
        ));
        let rows = fixture.rows(2);
        let exports = rows_of_kind(&rows, RouteHopKind::Export);
        assert_eq!(exports.len(), 2, "rows: {:?}", rows.rows);
        let routes = identity_routes_from(
            fixture.analyzer(),
            &exports[0].from,
            Some(&[RouteHopKind::Export]),
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(
            routes
                .iter()
                .any(|route| route.termination == RouteTermination::Terminal),
            "{routes:?}"
        );
        assert!(
            routes
                .iter()
                .all(|route| route.termination != RouteTermination::Incomplete),
            "{routes:?}"
        );
        for name in ["Listed", "Later", "Hidden", "nested"] {
            let routes = identity_routes_from(
                fixture.analyzer(),
                &RouteEndpoint::Declaration(fixture.declaration(name)),
                Some(&[RouteHopKind::Export]),
                &CancellationToken::new(),
            )
            .unwrap();
            assert_eq!(
                routes
                    .iter()
                    .any(|route| route.termination == RouteTermination::Incomplete),
                name == "Hidden",
                "{name}: {routes:?}"
            );
        }
        let reexports = rows_of_kind(&rows, RouteHopKind::ReExport);
        assert!(!reexports.is_empty(), "rows: {:?}", rows.rows);
        for row in reexports {
            let routes = identity_routes_from(
                fixture.analyzer(),
                &row.from,
                Some(&[
                    RouteHopKind::Import,
                    RouteHopKind::Export,
                    RouteHopKind::ReExport,
                    RouteHopKind::Alias,
                ]),
                &CancellationToken::new(),
            )
            .unwrap();
            assert!(
                routes
                    .iter()
                    .any(|route| route.termination == RouteTermination::Terminal),
                "{routes:?}"
            );
            assert!(
                routes
                    .iter()
                    .all(|route| route.termination != RouteTermination::Incomplete),
                "{routes:?}"
            );
        }
        let unknown = rows_of_kind(&rows, RouteHopKind::Import)
            .into_iter()
            .find(|row| matches!(&row.from, RouteEndpoint::Site { name, .. } if name == "Widget"))
            .expect("unclassified import still carries Import");
        let routes = identity_routes_from(
            fixture.analyzer(),
            &unknown.from,
            Some(&[RouteHopKind::ReExport]),
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(
            routes
                .iter()
                .any(|route| route.termination == RouteTermination::Incomplete),
            "{routes:?}"
        );
    }
}
