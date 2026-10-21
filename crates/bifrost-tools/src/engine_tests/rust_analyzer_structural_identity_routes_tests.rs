#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::structural::routes::CanonicalIdentity;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::test_support::Fixture;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::RoundTripOutcome;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::RouteEndpoint;

    use brokk_bifrost_core::analyzer::structural::routes::RouteHopKind;

    use brokk_bifrost_core::analyzer::structural::routes::RouteTermination;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::canonical_identity_of;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::identity_routes_from;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::round_trip_from_site;

    use brokk_bifrost_analysis::analyzer::structural::identity_routes::test_support::rows_of_kind;

    use brokk_bifrost_core::analyzer::model::Language;
    /// Arity alone separates two identities whose every other component
    /// coincides: same language, same namespace, same segment kinds and
    /// spellings. This is what `generic_arity` exists to do, and it cannot be
    /// shown by two differently named siblings.
    #[test]
    fn same_named_generic_and_nongeneric_types_differ_on_arity_alone() {
        let fixture = Fixture::new(
            Language::Rust,
            &[
                ("src/a.rs", "pub struct S;\n"),
                ("src/b.rs", "pub struct S<T> {\n    pub value: T,\n}\n"),
            ],
        );
        let plain = canonical_identity_of(fixture.analyzer(), &fixture.declaration("a.S"));
        let generic = canonical_identity_of(fixture.analyzer(), &fixture.declaration("b.S"));
        assert_eq!(plain.generic_arity, Some(0));
        assert_eq!(generic.generic_arity, Some(1));
        assert_ne!(plain, generic);

        // Strip the owning module segment and the two are the same identity
        // except for the arity, so arity is doing the separating on its own.
        let terminal = |identity: &CanonicalIdentity| CanonicalIdentity {
            segments: identity.segments[identity.segments.len() - 1..].to_vec(),
            ..identity.clone()
        };
        let plain_terminal = terminal(&plain);
        let generic_terminal = terminal(&generic);
        assert_eq!(plain_terminal.segments, generic_terminal.segments);
        assert_ne!(plain_terminal, generic_terminal);
        assert_eq!(
            CanonicalIdentity {
                generic_arity: generic_terminal.generic_arity,
                ..plain_terminal.clone()
            },
            generic_terminal
        );
    }

    /// A Rust type-alias chain traverses hop by hop to the origin struct, and
    /// a mutual alias cycle terminates as an explicit cycle, not an answer.
    #[test]
    fn rust_type_alias_chain_traverses_and_cycles_stay_explicit() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!(
                    "pub struct Widget;\n",
                    "pub type A = Widget;\n",
                    "pub type B = A;\n",
                ),
            )],
        );
        let b = fixture.declaration("B");
        let routes = identity_routes_from(
            fixture.analyzer(),
            &RouteEndpoint::Declaration(b),
            None,
            &CancellationToken::new(),
        )
        .expect("not cancelled");
        let terminal: Vec<_> = routes
            .iter()
            .filter(|route| route.termination == RouteTermination::Terminal)
            .collect();
        assert_eq!(terminal.len(), 1, "routes: {routes:?}");
        assert_eq!(terminal[0].hops.len(), 2, "routes: {routes:?}");
        assert!(
            terminal[0]
                .terminal_declaration()
                .expect("terminal declaration")
                .fq_name()
                .ends_with("Widget")
        );
        assert!(
            terminal[0]
                .hops
                .iter()
                .all(|hop| hop.kind == RouteHopKind::Alias)
        );

        let cyclic = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!("pub type A = B;\n", "pub type B = A;\n"),
            )],
        );
        let a = cyclic.declaration("A");
        let routes = identity_routes_from(
            cyclic.analyzer(),
            &RouteEndpoint::Declaration(a),
            None,
            &CancellationToken::new(),
        )
        .expect("not cancelled");
        assert!(
            routes
                .iter()
                .any(|route| route.termination == RouteTermination::Cycle),
            "routes: {routes:?}"
        );
        assert!(
            routes
                .iter()
                .all(|route| route.termination != RouteTermination::Terminal),
            "a cycle must not also read as a terminal answer: {routes:?}"
        );
    }

    #[test]
    fn rust_type_declarations_record_generic_arity() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                "pub struct Plain;\npub struct Generic<T> {\n    pub value: T,\n}\n\
                 pub struct Pair<K, V> {\n    pub key: K,\n    pub value: V,\n}\n\
                 pub enum Choice<T> {\n    Only(T),\n}\npub trait Marker {}\n\
                 pub type Alias<T> = Option<T>;\npub type Plainest = usize;\n",
            )],
        );
        let arity = |fq_suffix: &str| {
            canonical_identity_of(fixture.analyzer(), &fixture.declaration(fq_suffix)).generic_arity
        };
        assert_eq!(arity("Plain"), Some(0));
        assert_eq!(arity("Generic"), Some(1));
        assert_eq!(arity("Pair"), Some(2));
        assert_eq!(arity("Choice"), Some(1));
        assert_eq!(arity("Marker"), Some(0));
        assert_eq!(arity("Alias"), Some(1));
        assert_eq!(arity("Plainest"), Some(0));
    }

    #[test]
    fn rust_pub_use_yields_reexport_and_alias_rows() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!(
                    "pub mod util {\n",
                    "    pub struct Widget;\n",
                    "}\n",
                    "pub use crate::util::Widget as W;\n",
                    "use crate::util::Widget;\n",
                    "pub fn build() -> Widget {\n",
                    "    Widget\n",
                    "}\n",
                ),
            )],
        );
        let rows = fixture.rows(0);

        let reexports = rows_of_kind(&rows, RouteHopKind::ReExport);
        assert_eq!(reexports.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Declaration(target) = &reexports[0].to else {
            panic!("re-export target must be a declaration");
        };
        assert!(target.fq_name().ends_with("Widget"));

        let aliases = rows_of_kind(&rows, RouteHopKind::Alias);
        assert_eq!(aliases.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Site { name, range, .. } = &aliases[0].from else {
            panic!("an import alias is a site, not a declaration");
        };
        assert_eq!(name, "W");
        assert_eq!(range.start_byte, fixture.at(0, "W;"));

        let imports = rows_of_kind(&rows, RouteHopKind::Import);
        assert_eq!(imports.len(), 1, "rows: {:?}", rows.rows);
    }

    #[test]
    fn rust_trait_member_implementation_rows() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!(
                    "pub trait Runner {\n",
                    "    fn run(&self);\n",
                    "}\n",
                    "pub struct App;\n",
                    "impl Runner for App {\n",
                    "    fn run(&self) {}\n",
                    "}\n",
                ),
            )],
        );
        let rows = fixture.rows(0);
        let implementations = rows_of_kind(&rows, RouteHopKind::Implementation);
        assert!(
            !implementations.is_empty(),
            "expected implementation rows; rows: {:?}",
            rows.rows
        );
    }

    #[test]
    fn round_trip_holds_for_rust_reexport_site() {
        let fixture = Fixture::new(
            Language::Rust,
            &[(
                "src/lib.rs",
                concat!(
                    "pub mod util {\n",
                    "    pub struct Widget;\n",
                    "}\n",
                    "pub use crate::util::Widget;\n",
                ),
            )],
        );
        let rows = fixture.rows(0);
        let reexports = rows_of_kind(&rows, RouteHopKind::ReExport);
        assert_eq!(reexports.len(), 1, "rows: {:?}", rows.rows);
        let RouteEndpoint::Site { file, range, name } = &reexports[0].from else {
            panic!("re-export site expected");
        };
        let outcome = round_trip_from_site(
            fixture.analyzer(),
            file,
            *range,
            name,
            &fixture.files,
            &CancellationToken::new(),
        )
        .expect("not cancelled");
        let RoundTripOutcome::Holds { terminals } = outcome else {
            panic!("round trip must hold, got {outcome:?}");
        };
        assert!(terminals[0].fq_name().ends_with("Widget"));
    }
}
