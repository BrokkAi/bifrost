#[cfg(test)]
mod rust_departing_root_tests {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
    use brokk_bifrost_test_macros::hardwon;
    use git2::Oid;
    use rusqlite::params;
    use rusqlite::params_from_iter;
    use std::sync::Arc;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::resolution::fact_lowering::LoweringGapOrigin;

    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    use brokk_bifrost_analysis::analyzer::store::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS;

    use brokk_bifrost_analysis::analyzer::store::resolution::TypedFactRelation;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid;

    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::GenerationId;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

    use brokk_bifrost_analysis::analyzer::store::StructuralFactRowsRead;

    use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::parsed_fixture_state;

    use brokk_bifrost_analysis::analyzer::store::js_ts_resolution_producer_support::persist_alias_fixture;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::rust_root_test_support::MEMBER_ISOLATING_HOLDER as MEMBER_ISOLATING_HOLDER;

    use brokk_bifrost_analysis::analyzer::store::resolution_producer_tests::rust_root_test_support::ROUTE_ISOLATING_HOLDER as ROUTE_ISOLATING_HOLDER;

    #[test]
    fn rust_attribute_macro_argument_keeps_its_primary_source_provenance() {
        let source = r#"
mod setup {
    fn target() {}
}

struct SetupFn;
impl SetupFn {
    fn new(_: fn()) -> Self { Self }
}

macro_rules! setup_fn {
    ($func:path) => { SetupFn::new($func) };
}

#[divan::bench(args = [setup_fn!(setup::target)])]
fn bench() {}
"#;
        let state = parsed_fixture_state(&RustAdapter, "benches/throughput.rs", source);
        let facts = state.source_facts.as_ref().expect("Rust source facts");
        let occurrences = facts.occurrences.occurrences();
        let primary_ranges = occurrences
        .iter()
        .filter(|occurrence| {
            occurrence.provenance
                == brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::PrimaryNode
        })
        .map(|occurrence| (occurrence.range.start_byte, occurrence.range.end_byte))
        .collect::<std::collections::HashSet<_>>();
        let has_embedded_primary_alias = facts.native_site_occurrences.iter().any(|site| {
            let occurrence = facts.occurrences.occurrence(*site);
            occurrence.provenance
                == brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
                && primary_ranges
                    .contains(&(occurrence.range.start_byte, occurrence.range.end_byte))
        });
        assert!(
            has_embedded_primary_alias,
            "fixture must retain both source mappings"
        );

        brokk_bifrost_analysis::analyzer::store::resolution_operation::rust_reference_context_sources(
        facts,
        &CancellationToken::default(),
    )
    .expect("an embedded reference with an exact primary range has source authority");
    }

    #[test]
    fn canonical_source_publication_reopens_shared_native_and_structural_rows() {
        let temp = tempfile::tempdir().expect("persistent source-facts store");
        let db = temp.path().join("source-facts.db");
        let source = "pub fn target() {}\npub fn caller() { target(); }\n";
        let content_oid = oid(source.as_bytes());
        let state = parsed_fixture_state(&RustAdapter, "src/lib.rs", source);
        let canonical = state.source_facts.as_ref().expect("Rust canonical facts");
        let expected =
            brokk_bifrost_analysis::analyzer::structural::facts::FileFacts::from_source_and_rows(
                source.to_owned(),
                canonical.occurrences.clone(),
                canonical.structural.clone(),
            )
            .persisted_rows()
            .unwrap();
        let version = brokk_bifrost_analysis::analyzer::structural::facts::STRUCTURAL_FACTS_VERSION;
        let work_items = canonical.structural.work_item_count();
        let generation;
        {
            let store = AnalyzerStore::open_persistent(&db).unwrap();
            generation = store
                .ensure_language_epoch_value("rust", "canonical-source-test-v1")
                .unwrap();
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    content_oid,
                    "rust",
                    generation,
                    &RustAdapter,
                    &state,
                )
                .unwrap();
            assert_eq!(
                store
                    .load_structural_facts_rows(content_oid, "rust", generation, version)
                    .unwrap(),
                Some(expected.clone())
            );
            let shared = store.conn.execute(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*)
                 FROM blobs AS blob
                 JOIN source_native_declaration_bridges AS bridge ON bridge.blob_id = blob.id
                 JOIN resolution_semantic_sites AS site ON site.blob_id = bridge.blob_id
                   AND site.source_site = bridge.source_site
                 JOIN source_declarations AS declaration
                   ON declaration.blob_id = bridge.blob_id
                  AND declaration.declaration_id = bridge.declaration_id
                 WHERE blob.blob_oid = ?1 AND blob.lang = 'rust'
                   AND site.semantic_role = 'definition'",
                    [content_oid.to_string()],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap()
            });
            assert!(
                shared > 0,
                "native and structural readers must share actual source rows"
            );
            assert!(matches!(store.load_structural_facts_rows_limited(
            content_oid, "rust", generation, version, work_items - 1, None,
        ).unwrap(), StructuralFactRowsRead::Exceeded { minimum_work_items } if minimum_work_items == work_items));
            let cancellation = CancellationToken::default();
            cancellation.cancel();
            assert!(matches!(
                store
                    .load_structural_facts_rows_limited(
                        content_oid,
                        "rust",
                        generation,
                        version,
                        work_items,
                        Some(&cancellation),
                    )
                    .unwrap(),
                StructuralFactRowsRead::Cancelled
            ));

            let mut failed = AnalyzerStore::prepare_parsed_blob(
                content_oid,
                "rust",
                generation,
                &RustAdapter,
                Arc::clone(&state),
            )
            .unwrap();
            failed.inject_invalid_range_for_test();
            let (outcomes, _) =
                store.persist_prepared_blobs(vec![failed], PersistBatchTargets::PRODUCTION);
            assert!(outcomes[0].error.is_some());
            assert_eq!(
                store
                    .load_structural_facts_rows(content_oid, "rust", generation, version)
                    .unwrap(),
                Some(expected.clone())
            );
        }
        let reopened = AnalyzerStore::open_persistent(&db).unwrap();
        assert_eq!(
            reopened
                .load_structural_facts_rows(content_oid, "rust", generation, version)
                .unwrap(),
            Some(expected)
        );
        assert!(
            reopened.conn.execute(|conn| {
                conn.execute(
                    "UPDATE source_occurrence_arenas
                    SET spans = jsonb_set(spans, '$[0][0]',
                                          json_extract(spans, '$[0][0]') + 1)",
                    [],
                )
                .is_err()
            }),
            "sealed canonical source rows must be immutable"
        );
    }

    fn rust_fact_probe_plan(
        store: &AnalyzerStore,
        oids: &[Oid],
        generation: GenerationId,
    ) -> Vec<String> {
        let oid_strings = oids.iter().map(Oid::to_string).collect::<Vec<_>>();
        let (placeholders, parameters) =
            brokk_bifrost_analysis::analyzer::store::rust_fact_oid_query_parameters(
                "rust",
                generation,
                &oid_strings,
            );
        let sql = AnalyzerStore::blobs_with_rust_facts_sql(&placeholders);
        store.conn.execute(move |conn| {
            conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .expect("prepare Rust fact publication probe plan")
                .query_map(params_from_iter(parameters.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .expect("query Rust fact publication probe plan")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("read Rust fact publication probe plan")
        })
    }

    #[test]
    fn rust_fact_probe_requires_complete_production_publication_and_route_witnesses() {
        let store = AnalyzerStore::open_ephemeral().expect("Rust fact probe store");
        let generation = store
            .ensure_language_epoch_value("rust", "rust-fact-probe-test-v1")
            .expect("Rust fact probe generation");
        let state = parsed_fixture_state(
            &RustAdapter,
            "src/lib.rs",
            "pub fn target() {}\npub fn caller() { target(); }\n",
        );
        let complete_oid = oid(b"complete Rust fact probe");
        let incomplete_oid = oid(b"incomplete Rust fact probe");
        let content_oids: Vec<_> = [complete_oid, incomplete_oid]
            .into_iter()
            .chain((0..126).map(|index| oid(format!("Rust fact probe history {index}").as_bytes())))
            .collect();
        for content_oid in content_oids {
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    content_oid,
                    "rust",
                    generation,
                    &RustAdapter,
                    &state,
                )
                .expect("persist production Rust fact probe fixture");
        }

        let present = store
            .blobs_with_rust_facts("rust", generation, &[complete_oid, incomplete_oid])
            .expect("probe complete Rust publication");
        assert!(present.contains(&complete_oid));
        assert!(present.contains(&incomplete_oid));

        let requested = [complete_oid, incomplete_oid];
        let before_analyze = rust_fact_probe_plan(&store, &requested, generation);
        store
            .refresh_planner_statistics()
            .expect("refresh populated Rust fact probe statistics");
        let after_analyze = rust_fact_probe_plan(&store, &requested, generation);
        for plan in [before_analyze, after_analyze] {
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("SEARCH keys USING") && detail.contains("blob_oid=?")
                }),
                "Rust fact probe must seek populated blobs by language/generation/OID: {plan:?}"
            );
            // The module manifest carries its root span inline; no root occurrence join remains.
            for alias in ["meta", "source", "module", "scope", "inventory"] {
                assert!(
                plan.iter()
                    .any(|detail| detail.contains(&format!("SEARCH {alias} USING PRIMARY KEY"))),
                "Rust fact probe must seek {alias} by its publication key: {plan:?}"
            );
            }
            assert!(
                plan.iter().all(|detail| {
                    ["keys", "meta", "source", "module", "scope", "inventory"]
                        .iter()
                        .all(|alias| !detail.contains(&format!("SCAN {alias}")))
                }),
                "Rust publication checks must not scan their tables: {plan:?}"
            );
        }

        store.mark_parsed_blob_incomplete_for_test(incomplete_oid, "rust");
        let present = store
            .blobs_with_rust_facts("rust", generation, &[complete_oid, incomplete_oid])
            .expect("probe incomplete parsed publication");
        assert!(present.contains(&complete_oid));
        assert!(!present.contains(&incomplete_oid));

        // This removes the module witness while leaving the parsed/source rows.
        // A complete source manifest alone must not make the catch-up probe claim
        // that ordinal-zero route facts exist.
        store.delete_rust_facts_for_test("rust");
        let present = store
            .blobs_with_rust_facts("rust", generation, &[complete_oid, incomplete_oid])
            .expect("probe missing Rust route witnesses");
        assert!(present.is_empty());
    }

    #[test]
    #[hardwon("a31af62cdcef: block-local cfg routes panicked lowering as placement boundaries")]
    fn rust_block_scoped_cfg_import_persists_its_predicate_and_local_binder() {
        // `zellij-server/src/lib.rs` gates a `use` inside a block expression. The
        // producer used to call that a placement boundary, and
        // `fact_lowering::placement_scope` aborted preparation on the Block
        // attachment scope, so native indexing of the corpus died with exit 101.
        // A block-scoped import binds only inside its block. Retain its predicate
        // and native binder without manufacturing a file placement boundary.
        let source = "pub fn helper() -> u8 { 1 }\npub fn spawn() -> u8 {\n    let value = {\n        #[cfg(test)]\n        use crate::helper;\n        helper()\n    };\n    value\n}\n";
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let content = oid(source);
        let snapshot =
            persist_alias_fixture(&store, content, "rust", &RustAdapter, "src/lib.rs", source);
        assert_eq!(snapshot.publication_state, "complete");

        // The omitted-binder and placement-boundary evidence this pins is
        // interior detail now; what the store keeps is the import's predicate and
        // its native local binder, which is the fact the regression destroyed.
        let retained: Vec<(String, Option<i64>)> = store.conn.execute(move |conn| {
            let mut statement = conn
                .prepare(
                    "SELECT target.cfg_condition, target.native_scope
             FROM source_rust_import_targets AS target
             JOIN blobs AS blob ON blob.id = target.blob_id
             WHERE blob.blob_oid = ?1 AND blob.lang = 'rust'",
                )
                .unwrap();
            statement
                .query_map([content.to_string()], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        });
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].0, "atom test");
        assert!(
            retained[0].1.is_some(),
            "the retained import has a native local scope"
        );
    }

    #[test]
    fn rust_generic_formals_defaults_and_impl_arguments_round_trip_through_schema() {
        let source = "struct X;\nstruct Y;\nstruct Box<T> { value: T }\n\
                  struct S<A, B = X> { a: A, b: B }\n\
                  struct Mixed<'a, A, const N: usize, B = Box<X>> { a: &'a A, b: B }\n\
                  impl<A> S<A, X> { fn f(&self) {} }\n\
                  impl<A> S<A, Y> { fn f(&self) {} }\n\
                  impl S<&'static X, *const Y> { fn refs(&self) {} }\n\
                  impl<'a, A, const N: usize> Mixed<'a, A, /* const position */ N, Box<X>> { fn g(&self) {} }\n\
                  impl<'a, A> Mixed<'a, A, 1, Y> { fn h(&self) {} }\n\
                  impl S<_, Y> { fn inferred(&self) {} }\n";
        let state = parsed_fixture_state(&RustAdapter, "src/lib.rs", source);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let content = oid(source.as_bytes());
        let publication =
            persist_alias_fixture(&store, content, "rust", &RustAdapter, "src/lib.rs", source);
        assert_eq!(publication.publication_state, "complete");
        let facts = &state.resolution_facts;
        let spelling = |site: i64| {
            let site = &facts.sites[usize::try_from(site).unwrap()];
            source[site.start_byte..site.end_byte].to_owned()
        };
        let (formals, defaults, arguments, nested_defaults, unsupported) = store.conn.execute(move |conn| {
        let blob: i64 = conn.query_row(
            "SELECT id FROM blobs WHERE blob_oid=?1 AND lang='rust'",
            [content.to_string()], |row| row.get(0),
        ).unwrap();
        let mut statement = conn.prepare(
            "SELECT owner.source_site, fact.ordinal, parameter.source_site
             FROM resolution_generic_formals fact
             JOIN resolution_semantic_sites owner ON owner.blob_id=fact.blob_id
               AND owner.semantic_key=fact.owner_definition AND owner.semantic_role='definition'
             JOIN resolution_semantic_sites parameter ON parameter.blob_id=fact.blob_id
               AND parameter.semantic_key=fact.parameter_definition AND parameter.semantic_role='definition'
             WHERE fact.blob_id=?1",
        ).unwrap();
        let formals = statement.query_map([blob], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let mut statement = conn.prepare(
            "SELECT owner.source_site, fact.ordinal, reference.source_site
             FROM resolution_generic_formal_defaults fact
             JOIN resolution_semantic_sites owner ON owner.blob_id=fact.blob_id
               AND owner.semantic_key=fact.owner_definition AND owner.semantic_role='definition'
             JOIN resolution_binding_projections binding ON binding.blob_id=fact.blob_id AND binding.output_slot=fact.default_slot
             JOIN resolution_semantic_sites reference ON reference.blob_id=fact.blob_id
               AND reference.semantic_key=binding.reference AND reference.semantic_role='reference'
             WHERE fact.blob_id=?1",
        ).unwrap();
        let defaults = statement.query_map([blob], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let projection = brokk_bifrost_core::analyzer::resolution_facts::ALL_BINDING_PROJECTION_KINDS.iter()
            .position(|kind| *kind == brokk_bifrost_core::analyzer::resolution_facts::BindingProjectionKind::TargetNominalTypeIdentity).unwrap() as i64;
        let mut statement = conn.prepare(
            "SELECT fact.application_slot, fact.ordinal, reference.source_site,
                    fact.indirection_delta, fact.reference_indirection_delta
             FROM resolution_type_arguments fact
             JOIN resolution_binding_projections projection ON projection.blob_id=fact.blob_id
               AND projection.output_slot=fact.application_slot AND projection.kind=?2
             JOIN resolution_binding_projections binding ON binding.blob_id=fact.blob_id AND binding.output_slot=fact.argument_slot
             JOIN resolution_semantic_sites reference ON reference.blob_id=fact.blob_id
               AND reference.semantic_key=binding.reference AND reference.semantic_role='reference'
             WHERE fact.blob_id=?1 ORDER BY fact.application_slot, fact.ordinal",
        ).unwrap();
        let arguments = statement.query_map(params![blob, projection], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let mut statement = conn.prepare(
            "SELECT fact.ordinal, reference.source_site, fact.indirection_delta, fact.reference_indirection_delta
             FROM resolution_generic_formal_defaults default_fact
             JOIN resolution_type_arguments fact ON fact.blob_id=default_fact.blob_id AND fact.application_slot=default_fact.default_slot
             JOIN resolution_binding_projections binding ON binding.blob_id=fact.blob_id AND binding.output_slot=fact.argument_slot
             JOIN resolution_semantic_sites reference ON reference.blob_id=fact.blob_id
               AND reference.semantic_key=binding.reference AND reference.semantic_role='reference'
             WHERE fact.blob_id=?1 ORDER BY fact.ordinal",
        ).unwrap();
        let nested_defaults = statement.query_map([blob], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let unsupported: i64 = conn.query_row(
            "SELECT COUNT(*) FROM resolution_gaps gap
             JOIN resolution_gap_reasons reason ON reason.blob_id=gap.blob_id AND reason.reason=gap.reason
             JOIN resolution_binding_projections projection ON projection.blob_id=gap.blob_id
               AND projection.output_slot=gap.subject AND projection.kind=?3
             WHERE gap.blob_id=?1 AND reason.origin=?2 AND gap.covers=7",
            params![blob, brokk_bifrost_analysis::analyzer::store::resolution_prepare::resolution_rows::gap_origin_code(LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedTypeSyntax)), projection], |row| row.get(0),
        ).unwrap();
        (formals, defaults, arguments, nested_defaults, unsupported)
    });
        let mut formals = formals
            .into_iter()
            .map(|(owner, ordinal, parameter)| (spelling(owner), ordinal, spelling(parameter)))
            .collect::<Vec<_>>();
        formals.sort();
        assert_eq!(
            formals,
            vec![
                ("Box".to_owned(), 0, "T".to_owned()),
                ("Mixed".to_owned(), 0, "A".to_owned()),
                ("Mixed".to_owned(), 2, "B".to_owned()),
                ("S".to_owned(), 0, "A".to_owned()),
                ("S".to_owned(), 1, "B".to_owned())
            ]
        );
        let mut defaults = defaults
            .into_iter()
            .map(|(owner, ordinal, default)| (spelling(owner), ordinal, spelling(default)))
            .collect::<Vec<_>>();
        defaults.sort();
        assert_eq!(
            defaults,
            vec![
                ("Mixed".to_owned(), 2, "Box".to_owned()),
                ("S".to_owned(), 1, "X".to_owned())
            ]
        );
        assert_eq!(
            nested_defaults
                .into_iter()
                .map(|(ordinal, site, pointer, reference)| (
                    ordinal,
                    spelling(site),
                    pointer,
                    reference
                ))
                .collect::<Vec<_>>(),
            vec![(0, "X".to_owned(), 0, 0)]
        );
        let mut by_application = std::collections::BTreeMap::<_, Vec<_>>::new();
        for (application, ordinal, argument, pointer, reference) in arguments {
            by_application.entry(application).or_default().push((
                ordinal,
                spelling(argument),
                pointer,
                reference,
            ));
        }
        let mut arguments = by_application.into_values().collect::<Vec<_>>();
        arguments.sort();
        // Lifetimes do not count. Consts share written positions with types,
        // so neither a const parameter nor a const literal shifts the later B.
        assert_eq!(
            arguments,
            vec![
                vec![(0, "A".to_owned(), 0, 0), (1, "X".to_owned(), 0, 0)],
                vec![(0, "A".to_owned(), 0, 0), (1, "Y".to_owned(), 0, 0)],
                vec![(0, "A".to_owned(), 0, 0), (2, "Box".to_owned(), 0, 0)],
                vec![(0, "A".to_owned(), 0, 0), (2, "Y".to_owned(), 0, 0)],
                vec![(0, "X".to_owned(), 1, 1), (1, "Y".to_owned(), 1, 0)],
                vec![(1, "Y".to_owned(), 0, 0)],
            ]
        );
        assert_eq!(
            unsupported, 0,
            "unknown argument positions do not gap the nominal impl subject"
        );
    }

    /// The resolution families a blob may persist, and what one Rust file costs.
    ///
    /// Ordinary keyed readers persist local identity and Rust source authority.
    /// Account those named catalogs separately from the existing discovery rows,
    /// whose original row-cost envelope remains unchanged.
    #[test]
    fn a_persisted_blob_carries_only_tier_one_families_at_a_bounded_row_cost() {
        const SOURCE: &str = "pub mod inner {\n    pub struct Thing {\n        pub field: u32,\n    }\n    impl Thing {\n        pub fn make(value: u32) -> Self {\n            Self { field: value }\n        }\n        pub fn read(&self) -> u32 {\n            self.field\n        }\n    }\n    pub trait Read {\n        fn read(&self) -> u32;\n    }\n    impl Read for Thing {\n        fn read(&self) -> u32 {\n            self.field\n        }\n    }\n}\nuse inner::{Read, Thing};\npub fn use_it(thing: &Thing) -> u32 {\n    Read::read(thing) + Thing::make(1).read()\n}\n";
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let content = oid(SOURCE);
        let snapshot =
            persist_alias_fixture(&store, content, "rust", &RustAdapter, "src/lib.rs", SOURCE);
        assert_eq!(snapshot.publication_state, "complete");

        let persisted = store.conn.execute(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name LIKE 'resolution\\_%' ESCAPE '\\'
                 ORDER BY name",
                )
                .expect("prepare persisted resolution table inventory");

            statement
                .query_map([], |row| row.get::<_, String>(0))
                .expect("read persisted resolution table inventory")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("collect persisted resolution table inventory")
        });
        let expected =
            brokk_bifrost_analysis::analyzer::store::resolution::PERSISTED_RESOLUTION_TABLES
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
        assert_eq!(
            persisted, expected,
            "the persisted resolution tables match the declared row families"
        );

        let families = RESOLUTION_MANIFEST_COUNT_COLUMNS
            .iter()
            .copied()
            .zip(snapshot.family_counts)
            .collect::<Vec<_>>();
        let catalogs = [
            (
                "expected_rust_reference_context_count",
                "resolution_rust_reference_contexts",
            ),
            (
                "expected_rust_declaration_authority_count",
                "resolution_rust_declaration_authorities",
            ),
            (
                "expected_semantic_catalog_count",
                "resolution_semantic_catalog",
            ),
            ("expected_node_catalog_count", "resolution_node_catalog"),
            (
                "expected_contract_reference_count",
                "resolution_contract_references",
            ),
        ];
        const BODY_FAMILIES: &[(&str, &str)] = &[
            ("expected_path_body_count", "resolution_paths"),
            ("expected_site_body_count", "resolution_sites"),
            ("expected_gap_body_count", "resolution_gaps"),
            ("expected_gap_reason_count", "resolution_gap_reasons"),
            ("expected_type_frontier_count", "resolution_type_frontiers"),
            ("expected_type_transfer_count", "resolution_type_transfers"),
            (
                "expected_type_production_count",
                "resolution_type_productions",
            ),
            (
                "expected_type_component_count",
                "resolution_type_components",
            ),
            (
                "expected_declared_type_argument_count",
                "resolution_declared_type_arguments",
            ),
            (
                "expected_underlying_type_count",
                "resolution_underlying_types",
            ),
            ("expected_type_argument_count", "resolution_type_arguments"),
            (
                "expected_generic_type_alias_parameter_count",
                "resolution_generic_type_alias_parameters",
            ),
            (
                "expected_generic_formal_default_count",
                "resolution_generic_formal_defaults",
            ),
            (
                "expected_generic_formal_count",
                "resolution_generic_formals",
            ),
            (
                "expected_intrinsic_seed_count",
                "resolution_intrinsic_seeds",
            ),
            (
                "expected_intrinsic_seed_identity_count",
                "resolution_intrinsic_seed_identities",
            ),
            (
                "expected_binding_projection_count",
                "resolution_binding_projections",
            ),
            (
                "expected_qualified_route_count",
                "resolution_qualified_routes",
            ),
            (
                "expected_declaration_type_count",
                "resolution_declaration_types",
            ),
            (
                "expected_deferred_member_owner_count",
                "resolution_deferred_member_owners",
            ),
            (
                "expected_construction_requirement_count",
                "resolution_construction_requirements",
            ),
            ("expected_supertype_count", "resolution_supertypes"),
            (
                "expected_definition_property_gap_count",
                "resolution_definition_property_gaps",
            ),
            (
                "expected_call_obligation_count",
                "resolution_call_obligations",
            ),
            (
                "expected_callable_signature_count",
                "resolution_callable_signatures",
            ),
            (
                "expected_callable_parameter_owner_count",
                "resolution_callable_parameter_owners",
            ),
            ("expected_capsule_input_count", "resolution_capsule_inputs"),
            (
                "expected_capsule_declaration_count",
                "resolution_capsule_declarations",
            ),
            (
                "expected_capsule_reference_context_count",
                "resolution_capsule_reference_contexts",
            ),
        ];
        assert_eq!(
            BODY_FAMILIES.len(),
            brokk_bifrost_analysis::analyzer::store::resolution_manifest::BODY_MANIFEST_COLUMNS
                .len()
        );
        assert!(
            brokk_bifrost_analysis::analyzer::store::resolution_manifest::BODY_MANIFEST_COLUMNS
                .iter()
                .all(|column| BODY_FAMILIES.iter().any(|(name, _)| name == column))
        );
        let body_counts = store.conn.execute(|conn| {
            BODY_FAMILIES
                .iter()
                .map(|(family, table)| {
                    let count = conn
                        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                            row.get::<_, usize>(0)
                        })
                        .unwrap();
                    (*family, count)
                })
                .collect::<Vec<_>>()
        });
        for (family, count) in &body_counts {
            assert_eq!(
                families.iter().find(|(name, _)| name == family).unwrap().1,
                *count,
                "body manifest agrees with actual stored rows: {family}"
            );
            assert!(!catalogs.iter().any(|(catalog, _)| catalog == family));
        }
        let catalog_counts = store.conn.execute(move |conn| {
            catalogs.map(|(family, table)| {
                let count: usize = conn
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .expect("read actual authority catalog rows");
                (family, count)
            })
        });
        for (family, count) in catalog_counts {
            assert_eq!(
                families.iter().find(|(name, _)| *name == family).unwrap().1,
                count,
                "catalog manifest agrees with durable rows: {family}"
            );
        }
        let manifest_rows: usize = store.conn.execute(|conn| {
            conn.query_row(
                "SELECT count(*) FROM resolution_fragment_interiors",
                [],
                |row| row.get(0),
            )
            .expect("read actual manifest rows")
        });
        assert_eq!(manifest_rows, 1, "one blob owns one manifest header");
        // #3737: a gap is a dense per-blob ordinal, and neither a gap nor a gap
        // reason is a catalog identity. A reason keeps a runtime position after the
        // catalog's rows, so typed reads classify it by key range.
        let (gap_rows, non_dense, reasons_without_catalog) = store.conn.execute(|conn| {
        conn.query_row(
            "SELECT (SELECT count(*) FROM resolution_gaps),
                    (SELECT count(*) FROM resolution_gaps g
                      WHERE g.gap >= (SELECT count(*) FROM resolution_gaps x WHERE x.blob_id = g.blob_id)),
                    (SELECT count(*) FROM resolution_gap_reasons r
                      WHERE EXISTS (SELECT 1 FROM resolution_semantic_catalog c
                                    WHERE c.blob_id = r.blob_id AND c.local_key = r.reason)
                         OR r.reason < (SELECT count(*) FROM resolution_semantic_catalog c
                                        WHERE c.blob_id = r.blob_id))",
            [],
            |row| Ok((row.get::<_, usize>(0)?, row.get::<_, usize>(1)?, row.get::<_, usize>(2)?)),
        )
        .expect("read gap key and reason catalog invariants")
    });
        assert!(gap_rows > 0, "the fixture must retain coverage gaps");
        assert_eq!(non_dense, 0, "gap keys are dense ordinals from zero");
        assert_eq!(
            reasons_without_catalog, 0,
            "a gap reason holds a key after the catalog's dense rows and has no row"
        );
        let discovery_rows = manifest_rows
            + families
                .iter()
                .filter(|(family, _)| {
                    !catalogs.iter().any(|(catalog, _)| catalog == family)
                        && !BODY_FAMILIES.iter().any(|(body, _)| body == family)
                })
                .map(|(_, count)| count)
                .sum::<usize>();
        let catalog_rows = catalog_counts.iter().map(|(_, count)| count).sum::<usize>();
        let body_rows = body_counts.iter().map(|(_, count)| count).sum::<usize>();
        assert_eq!(
            snapshot.logical_rows,
            discovery_rows + catalog_rows + body_rows
        );
        eprintln!(
            "one file's persisted resolution rows: {}, discovery rows: {discovery_rows}, body rows: {body_rows}, actual body rows: {body_counts:?}, actual catalog rows: {catalog_counts:?}, all families: {families:?}",
            snapshot.logical_rows,
        );
        // B1 adds keyed identity and source authority, not more discovery rows.
        // Keep the original discovery envelope and account the catalog rows from
        // their actual tables instead of hiding their cost in a larger total cap.
        assert!(
            discovery_rows < 200,
            "discovery rows: {discovery_rows}, body rows: {body_rows}, actual body rows: {body_counts:?}, actual catalog rows: {catalog_counts:?}, all families: {families:?}"
        );
    }

    /// One relation's shape in one persisted workspace.
    struct TypedRelationProfile {
        rows: i64,
        identities: i64,
        /// The most blobs any one identity is held by under this relation. This is
        /// the mount set the read opens for its worst request.
        max_holding_blobs: i64,
    }

    /// Every relation's shape in one persisted workspace, indexed by relation code.
    fn typed_relation_profiles(
        store: &AnalyzerStore,
    ) -> Vec<(TypedFactRelation, TypedRelationProfile)> {
        let measured = store.conn.execute(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT holder.relation,
                        SUM(holder.blobs),
                        COUNT(*),
                        MAX(holder.blobs)
                 FROM (SELECT relation, identity_id, COUNT(*) AS blobs
                       FROM resolution_typed_fact_lookups
                       GROUP BY relation, identity_id) AS holder
                 GROUP BY holder.relation
                 ORDER BY holder.relation",
                )
                .expect("prepare the typed relation profile");
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        TypedRelationProfile {
                            rows: row.get(1)?,
                            identities: row.get(2)?,
                            max_holding_blobs: row.get(3)?,
                        },
                    ))
                })
                .expect("read the typed relation profile")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("collect the typed relation profile")
        });
        measured
            .into_iter()
            .map(|(code, profile)| {
                let relation = *TypedFactRelation::ALL
                    .iter()
                    .find(|relation| relation.code() == code)
                    .unwrap_or_else(|| panic!("persisted relation {code} names no known variant"));
                (relation, profile)
            })
            .collect()
    }

    /// Every typed relation opens the blobs that hold its fact, and never a blob
    /// that merely spells the name.
    ///
    /// Two fixtures, each isolating one relation and letting the other grow, which
    /// is the evidence that they are two questions and not one:
    ///
    /// - the route fixture calls `shared_route` through a receiver in the holder
    ///   and declares a member under the name in every scale blob, so exactly one
    ///   blob holds a route and every blob declares a deferred member owner;
    /// - the member fixture declares `shared_member` in the holder alone and calls
    ///   it on an unresolvable receiver in every scale blob, so exactly one blob
    ///   declares the member and every scale blob holds a route.
    ///
    /// In both, every file of the workspace spells the name, so the file count is
    /// the mount set every typed read took before it had a relation to key on.
    /// That column used to be measured from `resolution_blob_identities`; the
    /// relation is deleted, and the fixture's own sources are now the authority
    /// for it -- each scale file writes the name once, by construction.
    ///
    /// This is a relation pin, as lane G1's was: it measures the mount set the
    /// membership join resolves to, one join before the read opens anything. The
    /// pin beside it,
    /// `every_typed_relation_names_exactly_the_shared_identities_its_read_answers`,
    /// is what proves that set is the set of blobs whose interior can answer, and
    /// it is also what still holds the invariant this pin used to check against
    /// the mention column: a relation names a blob only for an identity in that
    /// blob's own catalog.
    #[test]
    #[hardwon(
        "dfb60686e6e4: name-mention mounts opened typed-fact blobs that held no requested fact"
    )]
    fn a_typed_relation_opens_the_blobs_that_hold_its_fact_not_those_that_spell_the_name() {
        let route_digest = shared_callable_identity("shared_route");
        let member_digest = shared_callable_identity("shared_member");
        let mut isolated = Vec::new();
        for (fixture, holder, scale, digest) in [
            (
                "route",
                ROUTE_ISOLATING_HOLDER,
                (|index: usize| {
                    format!(
                        "pub struct S{index:04};\nimpl S{index:04} {{ pub fn shared_route(&self) -> usize {{ {index} }} }}\n"
                    )
                }) as fn(usize) -> String,
                route_digest,
            ),
            (
                "member",
                MEMBER_ISOLATING_HOLDER,
                (|index: usize| {
                    format!(
                        "pub fn scale_{index:04}(value: Absent{index:04}) -> usize {{ value.shared_member() }}\n"
                    )
                }) as fn(usize) -> String,
                member_digest,
            ),
        ] {
            let measured = [8usize, 24].map(|files| {
                let store = persist_rust_scale_workspace(files, holder, scale);
                let profiles = typed_relation_profiles(&store);
                for (relation, profile) in &profiles {
                    eprintln!(
                        "{fixture} fixture, {files} files: {} rows={} identities={} \
                     holding<={} of {files} blobs",
                        relation.label(),
                        profile.rows,
                        profile.identities,
                        profile.max_holding_blobs
                    );
                    assert!(
                        profile.max_holding_blobs <= i64::try_from(files).expect("file count"),
                        "{} opens more blobs than the {fixture} fixture has at \
                     {files} files",
                        relation.label()
                    );
                }
                (
                    files,
                    blobs_holding_relation(&store, TypedFactRelation::QualifiedRouteLookup, digest),
                    blobs_holding_relation(
                        &store,
                        TypedFactRelation::DeferredMemberOwnerLookup,
                        digest,
                    ),
                    i64::try_from(files).expect("file count"),
                )
            });
            eprintln!(
                "{fixture} fixture (files, route holders, member holders, blobs spelling the name): \
             {measured:?}"
            );
            isolated.push((fixture, measured));
        }
        let [route, member] = <[_; 2]>::try_from(isolated).expect("two fixtures");
        assert_eq!(
            (route.1[0].1, route.1[1].1),
            (1, 1),
            "one blob holds a route under `shared_route` at both sizes: {:?}",
            route.1
        );
        assert!(
            route.1[1].2 > route.1[0].2,
            "every blob declaring the member must grow the deferred-member relation, \
         which is what makes it a different question: {:?}",
            route.1
        );
        assert_eq!(
            (member.1[0].2, member.1[1].2),
            (1, 1),
            "one blob declares a member under `shared_member` at both sizes: {:?}",
            member.1
        );
        assert!(
            member.1[1].1 > member.1[0].1,
            "every blob calling through an unresolvable receiver must grow the route \
         relation: {:?}",
            member.1
        );
    }

    /// The interned identity of one shared Callable name recipe.
    fn shared_callable_identity(spelling: &str) -> [u8; 32] {
        brokk_bifrost_analysis::analyzer::resolution::local_identity::ResolutionLookupSemanticRecipe::new(
        Language::Rust,
        ResolutionNamespace::Callable,
        spelling,
    )
    .name_digest()
    }

    /// The blobs that hold a fact of one relation under one interned identity.
    /// This is the mount set a typed read of that relation opens.
    fn blobs_holding_relation(
        store: &AnalyzerStore,
        relation: TypedFactRelation,
        digest: [u8; 32],
    ) -> i64 {
        let code = relation.code();
        store.conn.execute(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM resolution_typed_fact_lookups AS family
             JOIN resolution_identities AS identity ON identity.id = family.identity_id
             WHERE family.relation = ?1 AND identity.identity_digest = ?2",
                params![code, digest.as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .expect("count the blobs one relation holds an identity under")
        })
    }

    fn persist_rust_scale_workspace(
        files: usize,
        holder: &str,
        scale: fn(usize) -> String,
    ) -> AnalyzerStore {
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        let generation = store
            .ensure_language_epoch_value("rust", "resolution-header-family-pin-v1")
            .expect("scale workspace generation");
        for index in 0..files {
            let (path, source) = if index == 0 {
                ("src/holder.rs".to_owned(), holder.to_owned())
            } else {
                (format!("src/scale_{index:04}.rs"), scale(index))
            };
            let state = parsed_fixture_state(&RustAdapter, &path, &source);
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    oid(source.as_bytes()),
                    "rust",
                    generation,
                    &RustAdapter,
                    &state,
                )
                .expect("persist one scale workspace blob");
        }
        store
    }

    /// A qualified route lookup names the blobs that hold a route, not the blobs
    /// that mention the name.
    ///
    /// `visit_qualified_route_pages_for_lookups` and
    /// `visit_qualified_route_pages_for_slot_lookups` took their mounts from
    /// `resolution_blob_identities`, which listed every blob whose identity
    /// catalog holds the name. That set grows with the workspace; the blobs that
    /// hold a route under the name do not. Both reads now take the
    /// `QualifiedRouteLookup` rows of `resolution_typed_fact_lookups`, and the
    /// mount set each opens is the count this pins. Every file of the fixture
    /// spells the name, so the file count is the set the old relation gave; the
    /// relation itself is deleted, so the fixture's sources are the authority
    /// for that column.
    /// The route inventory opens the blobs that hold a route, not the selection.
    ///
    /// `visit_qualified_route_inventory_pages` has no lookup to key on: an
    /// endpoint with an open tail and no fixed first symbol has to look at every
    /// route there is. It took `self.selection.mounts()` verbatim and produced
    /// every interior in the workspace. It now reads the `QualifiedRouteLookup`
    /// rows of `resolution_typed_fact_lookups` with no identity predicate, which
    /// is the same relation its two keyed siblings use and exactly the question it
    /// asks. A route lookup is always a shared name recipe --
    /// `prepare_typed_fact_lookups` asserts it -- so a blob that holds a route
    /// always has a row and the read loses nothing.
    #[test]
    #[hardwon("0670f752620a: open-tail route inventory lowered every selected blob")]
    fn the_route_inventory_names_the_blobs_that_hold_a_route_not_the_selection() {
        let rows = [8usize, 24].map(|files| {
            let store = persist_rust_scale_workspace(files, ROUTE_ISOLATING_HOLDER, |index| {
                format!("pub fn scale_{index:04}() -> usize {{ {index} }}\n")
            });
            let route_relation = TypedFactRelation::QualifiedRouteLookup.code();
            let route_blobs = store.conn.execute(move |conn| {
                conn.query_row(
                    "SELECT COUNT(DISTINCT blob_id) FROM resolution_typed_fact_lookups
                 WHERE relation = ?1",
                    [route_relation],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count the blobs that hold a qualified route")
            });
            (files, route_blobs, i64::try_from(files).unwrap())
        });
        // Measured here: (8 files, 1 route blob, 8 selected blobs) and (24, 1, 24).
        // Only the holder writes a call through a receiver, which is what makes a
        // route; the scale files are free functions with no qualified reference.
        // The selection column is what this read opened before.
        eprintln!("route inventory blobs (files, route, selection): {rows:?}");
        assert_eq!(
            rows[0].1, rows[1].1,
            "the route inventory's mount set must not grow with the workspace: {rows:?}"
        );
        assert!(
            rows[1].2 > rows[0].2,
            "the selection this read walked must grow with it: {rows:?}"
        );
    }
}
