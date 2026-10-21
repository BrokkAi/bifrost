#[cfg(test)]
mod rust_departing_root_tests {
    use crate::engine_tests::rust_selection_fixture::RustSelectionFixtureExt;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::model::SemanticId;

    use brokk_bifrost_analysis::analyzer::resolution::local_identity::SelectedResolutionMountOrdinal;

    use brokk_bifrost_analysis::analyzer::store::resolution_selection::selection_test_support::SelectionFixture;
    #[test]
    fn ordinary_lookup_families_preserve_missing_and_late_shared_aliases() {
        use brokk_bifrost_analysis::analyzer::resolution::model::SharedNameId;

        use brokk_bifrost_analysis::analyzer::resolution::local_identity::SharedNameInterner;

        use brokk_bifrost_analysis::analyzer::store::resolution::SharedNameCache;

        use brokk_bifrost_analysis::analyzer::store::resolution::SharedNameTable;

        use brokk_bifrost_analysis::analyzer::store::resolution_authority::SelectedResolutionAuthority;

        use brokk_bifrost_analysis::analyzer::store::resolution_prepare::authority_rows;
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;

        let fixture = SelectionFixture::custom_rust_source(
            1,
            concat!(
                "mod model { pub struct Item; pub fn make() -> Item { Item } } ",
                "use crate::model::Item; ",
                "fn run(_: crate::model::Item) { let _: Item; let _ = model::make(); }",
            ),
        );
        let selection = fixture.open_ready(&[]);
        let host = selection
            .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
            .unwrap()
            .unwrap();
        let identities = selection
            .connection()
            .prepare("SELECT id,identity_digest FROM resolution_identities ORDER BY id")
            .unwrap()
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, [u8; 32]>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        type Lookup = fn(
        &SelectedResolutionAuthority<'_>,
        &brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionMountRecord,
        SemanticId,
        &CancellationToken,
    ) -> brokk_bifrost_analysis::analyzer::store::Result<Option<Vec<ResolutionSiteId>>>;
        let families: [(&str, Lookup); 3] = [
            (
                authority_rows::LOOKUP_REFERENCE_SHARED_SQL,
                |reader, host, key, token| reader.lookup_reference_sites(host, key, None, token),
            ),
            (
                authority_rows::ROOT_DEMAND_SHARED_SQL,
                |reader, host, key, token| reader.root_demand_reference_sites(host, key, token),
            ),
            (
                authority_rows::QUALIFIED_ROUTE_REFERENCE_SITES_SQL,
                |reader, host, key, token| reader.qualified_route_reference_sites(host, key, token),
            ),
        ];
        let live = CancellationToken::new();
        for (sql, read) in families {
            let mut statement = selection.connection().prepare(sql).unwrap();
            let (stored, digest, expected) = identities
                .iter()
                .find_map(|&(stored, digest)| {
                    let mut bindings = vec![
                        rusqlite::types::Value::Integer(host.blob_id()),
                        rusqlite::types::Value::Integer(stored),
                    ];
                    bindings.resize(statement.parameter_count(), rusqlite::types::Value::Null);
                    let sites = statement
                        .query_map(rusqlite::params_from_iter(bindings), |row| {
                            row.get::<_, u32>(0)
                        })
                        .unwrap()
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .unwrap();
                    (!sites.is_empty()).then_some((
                        stored,
                        digest,
                        sites
                            .into_iter()
                            .map(ResolutionSiteId::new)
                            .collect::<Vec<_>>(),
                    ))
                })
                .unwrap_or_else(|| {
                    panic!("actual parsed fixture must exercise lookup family: {sql}")
                });
            let before_publication = rusqlite::Connection::open_in_memory().unwrap();
            before_publication.execute_batch("CREATE TABLE resolution_identities(id INTEGER PRIMARY KEY,identity_digest BLOB NOT NULL UNIQUE)").unwrap();
            let names = SharedNameTable::new(SharedNameCache::new());
            let request = names.interner(&before_publication).intern(digest);
            assert!(!request.is_interned());
            let reader = SelectedResolutionAuthority::new(
                selection.connection(),
                &names,
                selection.requested_mount_rows(),
                selection.persisted_mount_count(),
                selection.authority_validations(),
                selection.authority_request_memo(),
            );
            let semantic = SemanticId::shared_name(request);
            assert_eq!(
                read(&reader, &host, semantic, &live).unwrap(),
                Some(Vec::new())
            );
            assert!(
                names.admit_persisted_names(&[(digest, SharedNameId::interned(stored))], &live)
            );
            assert_eq!(
                read(&reader, &host, semantic, &live).unwrap(),
                Some(expected)
            );
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            assert_eq!(read(&reader, &host, semantic, &cancelled).unwrap(), None);
        }
    }
}
