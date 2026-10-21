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
    /// declaration-anchored relations are untouched by that gap, and the site
    /// still carries the plain import its occurrence role already states.
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
}
