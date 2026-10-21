#[cfg(test)]
use self::rust_root_test_support::*;

#[cfg(test)]
use brokk_bifrost_test_macros::hardwon;

#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
use git2::Oid;

#[cfg(test)]
use rusqlite::params;

#[cfg(test)]
use tree_sitter::Parser;

#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind;

#[cfg(test)]
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionTypeSlotRole;

#[cfg(test)]
use crate::CancellationToken;

#[cfg(test)]
use crate::analyzer::java::JavaAdapter;

#[cfg(test)]
use crate::analyzer::resolution::BindingFragmentId;

#[cfg(test)]
use crate::analyzer::resolution::DeferredMemberOwnerLookupName;

#[cfg(test)]
use crate::analyzer::resolution::LoweredCandidateDirection;

#[cfg(test)]
use crate::analyzer::resolution::LoweringCoverageFrontier;

#[cfg(test)]
use crate::analyzer::resolution::LoweringGapOrigin;

#[cfg(test)]
use crate::analyzer::resolution::PreloadedFactResolutionService;

#[cfg(test)]
use crate::analyzer::resolution::SelectedTypedFactSource;

#[cfg(test)]
use crate::analyzer::resolution::SemanticId;

#[cfg(test)]
use crate::analyzer::resolution::TypedFactPageVisitor;

#[cfg(test)]
use crate::analyzer::resolution::TypedFactRequest;

#[cfg(test)]
use crate::analyzer::resolution::rich_java_resolution_facts_for_test;

#[cfg(test)]
use crate::analyzer::store::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS;

#[cfg(test)]
use crate::analyzer::store::resolution::TypedFactRelation;

#[cfg(test)]
use crate::analyzer::store::resolution_prepare::ResolutionInteriorPreparation;

#[cfg(test)]
use crate::analyzer::store::resolution_prepare::prepare_resolution_bundle_with_unit_keys;

#[cfg(test)]
use crate::analyzer::store::test_adapters::LegacyJavaFixtureAdapter;

#[cfg(test)]
use crate::analyzer::store::file_state::FileState;

#[cfg(test)]
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;

#[cfg(test)]
use crate::analyzer::tree_sitter_analyzer::ParsedFile;

#[cfg(test)]
use crate::analyzer::CodeUnit;

#[cfg(test)]
use crate::analyzer::Language;

#[cfg(test)]
use crate::analyzer::ProjectFile;

#[cfg(test)]
use crate::hash::HashMap;

#[cfg(test)]
use super::test_blob_oid as oid;

use super::*;

#[cfg(test)]
fn parsed_unit_keys(parsed: &ParsedFile) -> HashMap<CodeUnit, i64> {
    parsed
        .declarations()
        .iter()
        .enumerate()
        .map(|(index, unit)| {
            (
                unit.clone(),
                i64::try_from(index).expect("parsed fixture unit count fits i64"),
            )
        })
        .collect()
}

#[cfg(test)]
fn java_state(root: &std::path::Path, rich_resolution: bool) -> Arc<FileState> {
    let file = ProjectFile::new(root.to_path_buf(), "src/Model.java");
    file.write("package demo; class Model { int value; }\n")
        .expect("write Java source");
    let source = file.read_to_string().expect("read Java source");
    let adapter = JavaAdapter;
    let mut parser = Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .expect("set Java grammar");
    let tree = parser.parse(&source, None).expect("parse Java source");
    let mut parsed: ParsedFile = adapter.parse_file(&file, &source, &tree);
    parsed.add_file_scope(&file, &source);
    let contains_tests = adapter.contains_tests(&file, &source, &tree, &parsed);
    let declarations = parsed.declarations().clone();
    let mut state = FileState {
        source,
        package_name: parsed.package_name,
        content_qualifier: parsed.content_qualifier,
        top_level_declarations: parsed.top_level_declarations,
        declarations,
        definition_lookup_units: parsed.definition_lookup_units,
        imports: parsed.imports,
        scala_exports: parsed.scala_exports,
        rust_usage_facts: parsed.rust_usage_facts,
        source_facts: parsed.source_facts,
        source_declaration_units: parsed.source_declaration_units,
        source_declaration_metadata: parsed.source_declaration_metadata,
        resolution_facts: parsed.resolution_facts,
        raw_supertypes: parsed.raw_supertypes,
        supertype_lookup_paths: parsed.supertype_lookup_paths,
        type_identifiers: parsed.type_identifiers,
        signatures: parsed.signatures,
        signature_metadata: parsed.signature_metadata,
        signature_metadata_signature_ordinals: parsed.signature_metadata_signature_ordinals,
        cpp_template_metadata: parsed.cpp_template_metadata,
        ruby_method_dispatch_modes: parsed.ruby_method_dispatch_modes,
        ranges: parsed.ranges,
        children: parsed.children,
        scala_traits: parsed.scala_traits,
        type_aliases: parsed.type_aliases,
        contains_tests,
        test_region_units: parsed.test_region_units,
        materialization_records: parsed.materialization_records,
        parse_errors: Some(Vec::new()),
        completeness: parsed.completeness,
        parse_complete: true,
        additional_projections: Vec::new(),
    };
    if rich_resolution {
        state.resolution_facts = rich_java_resolution_facts_for_test();
        // This is a synthetic bundle-law fixture, not source extraction. Its
        // native site IDs cannot refer to the unrelated parsed Java arena.
        state.source_facts = None;
        state.source_declaration_units.clear();
    }
    Arc::new(state)
}

#[cfg(test)]
fn with_projection(state: &Arc<FileState>) -> Arc<FileState> {
    let mut projection = state.as_ref().clone();
    projection.source.clear();
    projection.additional_projections.clear();
    let mut primary = state.as_ref().clone();
    primary.additional_projections = vec![(PROJECTION, Arc::new(projection))];
    Arc::new(primary)
}

#[cfg(test)]
fn prepare_legacy_java(
    oid: Oid,
    state: Arc<FileState>,
    generations: &HashMap<String, GenerationId>,
    required_projections: &[String],
) -> PreparedParsedBlob {
    prepare_with_adapter(
        oid,
        state,
        generations,
        required_projections,
        &LegacyJavaFixtureAdapter,
    )
}

#[cfg(test)]
fn assert_plan_search(plan: &[String], alias: &str, index: &str) {
    assert!(
        plan.iter().any(|detail| {
            detail.contains(&format!("SEARCH {alias} ")) && detail.contains(index)
        }),
        "complete-analysis query must seek {alias} through {index}: {plan:#?}"
    );
}

#[cfg(test)]
fn assert_bounded_complete_analysis_plan(plan: &[String]) {
    assert!(
        plan.iter().all(|detail| !detail.contains("AUTOMATIC")),
        "complete-analysis queries must not depend on automatic indexes: {plan:#?}"
    );
    for detail in plan.iter().filter(|detail| detail.contains("SCAN ")) {
        let scanned_alias = detail
            .split_once("SCAN ")
            .and_then(|(_, tail)| tail.split_ascii_whitespace().next())
            .expect("SCAN plan detail names its table alias");
        assert!(
            matches!(scanned_alias, "requested" | "projection" | "owner"),
            "only bounded TEMP request carriers may be scanned: {plan:#?}"
        );
    }
    for detail in plan
        .iter()
        .filter(|detail| detail.contains("USE TEMP B-TREE"))
    {
        assert!(
            detail.contains("USE TEMP B-TREE FOR ORDER BY"),
            "TEMP storage is allowed only for request-order restoration: {plan:#?}"
        );
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn persist_one(store: &AnalyzerStore, prepared: PreparedParsedBlob) -> PersistBatchStats {
    let (outcomes, stats) =
        store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);
    stats
}

#[cfg(test)]
fn payload_cost(store: &AnalyzerStore, oid: Oid, lang: &str) -> usize {
    let oid = oid.to_string();
    let lang = lang.to_owned();
    store.conn.execute(move |conn| {
        conn.query_row(
            "SELECT costs.payload_bytes
             FROM blobs
             JOIN blob_payload_costs AS costs ON costs.blob_id = blobs.id
             WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2",
            params![oid, lang],
            |row| row.get::<_, usize>(0),
        )
        .expect("persisted blob payload cost")
    })
}

#[cfg(test)]
fn rewrite_payload_cost(store: &AnalyzerStore, oid: Oid, lang: &str, value: Option<usize>) {
    let oid = oid.to_string();
    let lang = lang.to_owned();
    store.conn.execute(move |conn| match value {
        Some(value) => conn
            .execute(
                "UPDATE blob_payload_costs
                 SET payload_bytes = ?3
                 WHERE blob_id = (
                   SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2
                 )",
                params![oid, lang, value],
            )
            .expect("corrupt persisted payload cost"),
        None => conn
            .execute(
                "DELETE FROM blob_payload_costs
                 WHERE blob_id = (
                   SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2
                 )",
                params![oid, lang],
            )
            .expect("delete persisted payload cost"),
    });
}

#[cfg(test)]
#[test]
fn manifest_count_columns_match_the_persisted_schema_by_name() {
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let mut schema_columns = store.conn.execute(|conn| {
        conn.prepare(
            "SELECT name
             FROM pragma_table_info('resolution_fragment_interiors')
             WHERE name LIKE 'expected_%_count'
             ORDER BY cid",
        )
        .expect("prepare resolution manifest schema descriptor")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query resolution manifest schema descriptor")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("read resolution manifest schema descriptor")
    });
    let mut declared_columns = RESOLUTION_MANIFEST_COUNT_COLUMNS
        .iter()
        .map(|column| (*column).to_owned())
        .collect::<Vec<_>>();
    // Migration-added columns may occupy different physical positions. All
    // production queries bind these columns by name, not their schema cid.
    schema_columns.sort_unstable();
    declared_columns.sort_unstable();
    assert_eq!(schema_columns, declared_columns);
}

#[cfg(test)]
fn persisted_physical_logical_rows(store: &AnalyzerStore, keys: &[(Oid, &str)]) -> Vec<usize> {
    let keys = keys
        .iter()
        .map(|(oid, language)| (oid.to_string(), (*language).to_owned()))
        .collect::<Vec<_>>();
    store.conn.execute(move |conn| {
        let mut statement = conn
            .prepare_cached(persisted_blob_mutation_cost_fallback_sql())
            .expect("prepare physical cascade-row recomputation");
        keys.iter()
            .map(|(oid, language)| {
                let cascade =
                    persisted_blob_mutation_cost_fallback_statement(&mut statement, oid, language)
                        .expect("recompute persisted cascade rows");
                let payload_cost_rows = conn
                    .query_row(
                        "SELECT COUNT(*)
                         FROM blob_payload_costs AS costs
                         JOIN blobs AS blob ON blob.id = costs.blob_id
                         WHERE blob.blob_oid = ?1 AND blob.lang = ?2",
                        params![oid, language],
                        |row| row.get::<_, usize>(0),
                    )
                    .expect("count the persisted payload-cost row");
                assert_eq!(payload_cost_rows, 1);
                cascade.logical_rows
            })
            .collect()
    })
}

#[cfg(test)]
#[test]
fn primary_and_projection_publish_the_declared_family_bundle_atomically() {
    let temp = tempfile::tempdir().expect("test directory");
    let base = java_state(temp.path(), true);
    let projected = with_projection(&base);
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let generations = generations(&store);
    let published_oid = oid(b"rich primary and projection");
    let prepared = prepare_legacy_java(published_oid, projected, &generations, &[]);

    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        BindingFragmentId::unmounted(),
        crate::analyzer::resolution::test_shared_names(),
        Language::Java,
        &base.resolution_facts,
    );
    let ResolutionInteriorPreparation::Prepared(expected) =
        prepare_resolution_bundle_with_unit_keys(&lowered, None, &CancellationToken::default())
    else {
        panic!("uncancelled resolution preparation must finish")
    };
    assert_eq!(
        prepared.resolution.family_counts().len(),
        RESOLUTION_MANIFEST_COUNT_COLUMNS.len()
    );
    for family in [
        "expected_semantic_site_count",
        "expected_path_endpoint_header_count",
        "expected_declaration_visibility_property_count",
        "expected_member_scope_property_count",
        "expected_member_owner_property_count",
    ] {
        let index = RESOLUTION_MANIFEST_COUNT_COLUMNS
            .iter()
            .position(|column| *column == family)
            .expect("rich manifest family");
        assert!(
            prepared.resolution.family_counts()[index] > 0,
            "rich producer must exercise {family} insertion"
        );
    }
    assert_eq!(prepared.fragment_count(), 2);
    assert_eq!(prepared.resolution, *expected);
    assert_eq!(prepared.additional[0].resolution, *expected);
    let mut primary_manifest = ManifestSnapshot::expected(&prepared.resolution);
    let mut projection_manifest = ManifestSnapshot::expected(&prepared.additional[0].resolution);
    let primary_estimate = prepared.resolution.payload_bytes() + PRIMARY.len();
    let projection_estimate = prepared.additional[0].resolution.payload_bytes() + PROJECTION.len();
    let expected_rows = prepared.mutation_logical_rows();
    let expected_bytes = prepared.mutation_payload_bytes();

    let stats = persist_one(&store, prepared);

    assert_eq!(stats.transactions, 1);
    assert_eq!(stats.committed_blobs, 1);
    assert_eq!(stats.committed_fragments, 2);
    assert_eq!(stats.logical_rows, expected_rows);
    assert_eq!(stats.payload_bytes, expected_bytes);
    primary_manifest.payload_bytes = measured_resolution_payload(&store, published_oid, PRIMARY);
    projection_manifest.payload_bytes =
        measured_resolution_payload(&store, published_oid, PROJECTION);
    assert!(primary_estimate >= primary_manifest.payload_bytes);
    assert!(
        projection_estimate >= projection_manifest.payload_bytes,
        "prewrite budget includes the distinct storage alias length"
    );
    assert_eq!(
        manifest_snapshot(&store, published_oid, PRIMARY),
        primary_manifest
    );
    assert_eq!(
        manifest_snapshot(&store, published_oid, PROJECTION),
        projection_manifest
    );

    let primary_blob_id = store.conn.execute({
        let oid = published_oid.to_string();
        move |conn| {
            conn.query_row(
                "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
                params![oid, PRIMARY],
                |row| row.get::<_, i64>(0),
            )
            .expect("published primary blob id")
        }
    });
    // Nodes, reference sites and path bodies are interior detail. What the
    // publication owns for a reference is its semantic site, and the tier-1
    // root-route family is what a crate derivation reads back, so both are
    // sought by their primary key with no scan and no sorter.
    let plans = store.conn.execute(move |conn| {
        [
            (
                "resolution_semantic_sites",
                "SELECT source_site FROM resolution_semantic_sites
                 WHERE blob_id = ?1 AND source_site > -1
                 ORDER BY source_site LIMIT 256",
            ),
            (
                "resolution_root_route_segments",
                "SELECT path_key FROM resolution_root_route_segments
                 WHERE blob_id = ?1 AND path_key > -1
                 ORDER BY path_key LIMIT 256",
            ),
        ]
        .map(|(table, sql)| {
            let details = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .expect("prepare resolution endpoint query plan")
                .query_map([primary_blob_id], |row| row.get::<_, String>(3))
                .expect("query resolution endpoint plan")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("read resolution endpoint plan");
            (table, details)
        })
    });
    for (table, details) in plans {
        assert!(
            details
                .iter()
                .any(|detail| detail.contains(&format!("SEARCH {table} USING PRIMARY KEY"))),
            "expected a primary-key seek of {table}: {details:?}"
        );
        assert!(
            details
                .iter()
                .all(|detail| !detail.contains(&format!("SCAN {table}"))
                    && !detail.contains("USE TEMP B-TREE")),
            "endpoint lookup must seek without a sorter: {details:?}"
        );
    }

    store.conn.execute(move |conn| {
        conn.execute("DELETE FROM blobs WHERE id = ?1", [primary_blob_id])
            .expect("delete published primary blob");
        for table in [
            "resolution_fragment_interiors",
            "resolution_semantic_sites",
            "resolution_root_route_segments",
            "resolution_path_endpoint_headers",
            "resolution_member_owner_properties",
        ] {
            let count = conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = ?1"),
                    [primary_blob_id],
                    |row| row.get::<_, usize>(0),
                )
                .expect("query cascaded resolution family");
            assert_eq!(count, 0, "{table} must cascade from its blob");
        }
    });
}

#[cfg(test)]
#[test]
fn complete_analysis_repairs_legacy_and_optional_rows_once_with_directional_ownership() {
    let temp = tempfile::tempdir().expect("test directory");
    let state = java_state(temp.path(), false);
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let generations = generations(&store);

    for count in [300, 301] {
        let expected = (0..count)
            .map(|index| oid(format!("carrier-{count}-{index}")))
            .collect::<Vec<_>>();
        let mut requests = expected
            .iter()
            .copied()
            .map(|oid| CompleteAnalysisBlobRequest::new(oid, PRIMARY, [PROJECTION.to_owned()]))
            .collect::<Vec<_>>();
        requests.push(requests[17].clone());
        let missing = store
            .missing_published_complete_analysis_blob_keys_at_generations(
                &requests,
                &generations,
                Language::Java,
                None,
            )
            .expect("chunked complete-analysis carrier");
        assert_eq!(
            missing
                .iter()
                .map(|missing| missing.oid())
                .collect::<Vec<_>>(),
            expected,
            "the 300-row TEMP carrier boundary must preserve first-seen order and deduplicate"
        );
    }

    let legacy_oid = oid(b"legacy parsed only");
    store
        .register_blobs(&[legacy_oid], PRIMARY, generations[PRIMARY])
        .expect("register legacy parsed blob");
    let legacy_oid_text = legacy_oid.to_string();
    store.conn.execute(move |conn| {
        let blob_id = conn
            .query_row(
                "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java'",
                [&legacy_oid_text],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        conn.execute(
            "INSERT INTO blob_meta(
               blob_id, lang, contains_tests, content_package,
               stored_unit_count, range_count, signature_count,
               signature_metadata_count, supertype_count, child_count,
               import_statement_count, type_identifier_count, is_complete
             ) VALUES(?1, 'java', 0, '', 0, 0, 0, 0, 0, 0, 0, 0, 1)",
            [blob_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blob_payload_costs(blob_id, payload_bytes) VALUES(?1, 0)",
            [blob_id],
        )
        .unwrap();
    });
    let legacy_request = [CompleteAnalysisBlobRequest::new(
        legacy_oid,
        PRIMARY,
        Vec::new(),
    )];
    let missing = store
        .missing_published_complete_analysis_blob_keys_at_generations(
            &legacy_request,
            &generations,
            Language::Java,
            None,
        )
        .expect("legacy complete-analysis predicate");
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].oid(), legacy_oid);
    assert!(
        missing[0]
            .required_existing_additional_storage_languages()
            .is_empty()
    );
    persist_one(
        &store,
        prepare(legacy_oid, Arc::clone(&state), &generations, &[]),
    );
    assert!(
        store
            .missing_published_complete_analysis_blob_keys_at_generations(
                &legacy_request,
                &generations,
                Language::Java,
                None,
            )
            .unwrap()
            .is_empty()
    );

    let absent_optional_oid = oid(b"never materialized optional projection");
    persist_one(
        &store,
        prepare(absent_optional_oid, Arc::clone(&state), &generations, &[]),
    );
    let absent_optional_request = [CompleteAnalysisBlobRequest::new(
        absent_optional_oid,
        PRIMARY,
        [PROJECTION.to_owned()],
    )];
    assert!(
        store
            .missing_published_complete_analysis_blob_keys_at_generations(
                &absent_optional_request,
                &generations,
                Language::Java,
                None,
            )
            .unwrap()
            .is_empty(),
        "an optional projection that never existed is identical to its primary"
    );

    let optional_oid = oid(b"stale optional projection");
    persist_one(
        &store,
        prepare(optional_oid, with_projection(&state), &generations, &[]),
    );
    let optional_oid_text = optional_oid.to_string();
    store.conn.execute(move |conn| {
        conn.execute(
            "UPDATE resolution_fragment_interiors
             SET producer_epoch = 'legacy-resolution-bundle'
             WHERE blob_id = (
               SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java:projection'
             )",
            [&optional_oid_text],
        )
        .unwrap();
    });
    let owner_request =
        CompleteAnalysisBlobRequest::new(optional_oid, PRIMARY, [PROJECTION.to_owned()]);
    let missing = store
        .missing_published_complete_analysis_blob_keys_at_generations(
            std::slice::from_ref(&owner_request),
            &generations,
            Language::Java,
            None,
        )
        .unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].storage_language(), PRIMARY);
    assert_eq!(
        missing[0].required_existing_additional_storage_languages(),
        &[PROJECTION.to_owned()]
    );
    let repaired = prepare(
        optional_oid,
        Arc::clone(&state),
        &generations,
        missing[0].required_existing_additional_storage_languages(),
    );
    assert_eq!(repaired.fragment_count(), 2);
    assert_eq!(repaired.additional[0].lang(), PROJECTION);
    assert!(repaired.additional[0].state().source.is_empty());
    persist_one(&store, repaired);
    assert!(
        store
            .missing_published_complete_analysis_blob_keys_at_generations(
                std::slice::from_ref(&owner_request),
                &generations,
                Language::Java,
                None,
            )
            .unwrap()
            .is_empty(),
        "one catch-up publication must make the next build warm"
    );

    let optional_oid_text = optional_oid.to_string();
    store.conn.execute(move |conn| {
        conn.execute(
            "UPDATE resolution_fragment_interiors
             SET producer_epoch = 'legacy-resolution-bundle-again'
             WHERE blob_id = (
               SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'java:projection'
             )",
            [&optional_oid_text],
        )
        .unwrap();
    });
    let independent_request =
        CompleteAnalysisBlobRequest::new(optional_oid, PROJECTION, Vec::new());
    for requests in [
        vec![owner_request.clone(), independent_request.clone()],
        vec![independent_request.clone(), owner_request.clone()],
    ] {
        let missing = store
            .missing_published_complete_analysis_blob_keys_at_generations(
                &requests,
                &generations,
                Language::Java,
                None,
            )
            .unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].storage_language(), PROJECTION);
        assert!(
            missing[0]
                .required_existing_additional_storage_languages()
                .is_empty()
        );
    }
}

#[cfg(test)]
#[test]
fn production_writer_stale_generation_and_epoch_are_typed_terminal_failures() {
    let temp = tempfile::tempdir().expect("test directory");
    let state = java_state(temp.path(), false);
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let generations = generations(&store);
    let published_oid = oid(b"production stale writer");

    let stale_epoch = prepare(published_oid, Arc::clone(&state), &generations, &[]);
    store.conn.execute(|conn| {
        conn.execute(
            "UPDATE resolution_producer_epochs
             SET producer_epoch = 'future'
             WHERE lang = 'java'",
            [],
        )
        .expect("make producer epoch stale");
    });
    let (outcomes, stats) = store.persist_prepared_blobs_with_cancellation(
        vec![stale_epoch],
        &CancellationToken::default(),
        PersistBatchTargets::PRODUCTION,
    );
    assert!(
        outcomes[0]
            .error
            .as_ref()
            .is_some_and(|error| error.is_stale_resolution())
    );
    assert_eq!(stats.failed_transaction_attempts, 1);
    assert!(!store.contains_parsed_blob(published_oid, PRIMARY).unwrap());

    store
        .ensure_resolution_producer_epoch(PRIMARY, Language::Java)
        .expect("restore current producer epoch");
    let newer_generation = store
        .ensure_language_epoch_value(PRIMARY, "resolution-stale-writer-v2")
        .expect("advance current generation");
    assert_ne!(generations[PRIMARY], newer_generation);
    let stale_generation = prepare(published_oid, state, &generations, &[]);
    let (outcomes, stats) = store.persist_prepared_blobs_with_cancellation(
        vec![stale_generation],
        &CancellationToken::default(),
        PersistBatchTargets::PRODUCTION,
    );
    assert!(
        outcomes[0]
            .error
            .as_ref()
            .is_some_and(|error| error.is_stale_generation())
    );
    assert_eq!(stats.failed_transaction_attempts, 1);
    assert!(!store.contains_parsed_blob(published_oid, PRIMARY).unwrap());
}

#[cfg(test)]
#[test]
fn production_writer_duplicate_inputs_preserve_submission_order_and_reject_conflicts() {
    let temp = tempfile::tempdir().expect("test directory");
    let state = java_state(temp.path(), false);
    let rich_state = java_state(temp.path(), true);
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let generations = generations(&store);
    let duplicate_oid = oid(b"duplicate production input");
    let good_oid = oid(b"good production input");
    let (outcomes, stats) = store.persist_prepared_blobs(
        vec![
            prepare(duplicate_oid, Arc::clone(&state), &generations, &[]),
            prepare(good_oid, Arc::clone(&state), &generations, &[]),
            prepare_legacy_java(duplicate_oid, rich_state, &generations, &[]),
        ],
        PersistBatchTargets::PRODUCTION,
    );
    assert_eq!(
        outcomes
            .iter()
            .map(|outcome| outcome.prepared.oid())
            .collect::<Vec<_>>(),
        vec![duplicate_oid, good_oid, duplicate_oid]
    );
    assert!(outcomes[0].error.is_some());
    assert!(outcomes[2].error.is_some());
    assert!(
        outcomes[1].error.is_none(),
        "good input must survive bisection"
    );
    assert_eq!((stats.committed_blobs, stats.failed_blobs), (1, 2));
    assert!(!store.contains_parsed_blob(duplicate_oid, PRIMARY).unwrap());
    assert!(store.contains_parsed_blob(good_oid, PRIMARY).unwrap());
}

#[cfg(test)]
#[test]
fn production_writer_repairs_corrupt_payload_costs_on_retry() {
    let temp = tempfile::tempdir().expect("test directory");
    let state = java_state(temp.path(), false);
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let generation = store
        .ensure_language_epoch_value(PRIMARY, "resolution-payload-repair-v1")
        .expect("payload repair generation");
    let published_oid = oid(b"production payload repair");
    store
        .write_parsed_blob_at_generation(
            &crate::analyzer::store::test_blob_file(),
            published_oid,
            PRIMARY,
            generation,
            &JavaAdapter,
            &state,
        )
        .expect("initial production persistence");
    let expected_cost = payload_cost(&store, published_oid, PRIMARY);
    let expected_manifest = manifest_snapshot(&store, published_oid, PRIMARY);
    for corrupt in [Some(999_999usize), None] {
        rewrite_payload_cost(&store, published_oid, PRIMARY, corrupt);
        store
            .write_parsed_blob_at_generation(
                &crate::analyzer::store::test_blob_file(),
                published_oid,
                PRIMARY,
                generation,
                &JavaAdapter,
                &state,
            )
            .expect("retry production persistence");
        assert_eq!(payload_cost(&store, published_oid, PRIMARY), expected_cost);
        assert_eq!(
            manifest_snapshot(&store, published_oid, PRIMARY),
            expected_manifest
        );
    }
}

#[cfg(test)]
#[test]
fn production_writer_failed_and_cancelled_same_key_replacements_preserve_previous_bundle() {
    let temp = tempfile::tempdir().expect("test directory");
    let state = java_state(temp.path(), false);
    let rich_state = java_state(temp.path(), true);
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let generations = generations(&store);
    let published_oid = oid(b"production replacement rollback");
    persist_one(
        &store,
        prepare(published_oid, Arc::clone(&state), &generations, &[]),
    );
    let first_manifest = manifest_snapshot(&store, published_oid, PRIMARY);
    let first_payload_cost = payload_cost(&store, published_oid, PRIMARY);
    let targets = PersistBatchTargets {
        max_blobs: 1,
        max_rows: 1,
        max_payload_bytes: 1,
    };

    let mut failed_replacement =
        prepare_legacy_java(published_oid, Arc::clone(&rich_state), &generations, &[]);
    failed_replacement.inject_invalid_range_for_test();
    let (outcomes, stats) = store.persist_prepared_blobs(vec![failed_replacement], targets);
    assert!(outcomes[0].error.is_some());
    assert_eq!(stats.failed_blobs, 1);
    assert_eq!(
        manifest_snapshot(&store, published_oid, PRIMARY),
        first_manifest
    );
    assert_eq!(
        payload_cost(&store, published_oid, PRIMARY),
        first_payload_cost
    );

    let cancellation = CancellationToken::cancel_after_checks_for_test(4);
    let cancelled_replacement = prepare_legacy_java(published_oid, rich_state, &generations, &[]);
    let (outcomes, stats) = store.persist_prepared_blobs_with_cancellation(
        vec![cancelled_replacement],
        &cancellation,
        targets,
    );
    assert!(outcomes[0].error.is_some());
    assert!(cancellation.is_cancelled());
    assert_eq!(stats.failed_blobs, 1);
    assert_eq!(
        manifest_snapshot(&store, published_oid, PRIMARY),
        first_manifest
    );
    assert_eq!(
        payload_cost(&store, published_oid, PRIMARY),
        first_payload_cost
    );
}

#[cfg(test)]
#[test]
fn combined_writer_targets_groups_and_rolls_back_cancelled_or_failed_envelopes() {
    let temp = tempfile::tempdir().expect("test directory");
    let state = java_state(temp.path(), false);
    let projected = with_projection(&state);
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let generations = generations(&store);
    let two_fragment_limits = PersistBatchTargets {
        max_blobs: 2,
        max_rows: usize::MAX,
        max_payload_bytes: usize::MAX,
    };

    let (outcomes, stats) = store.persist_prepared_blobs(Vec::new(), two_fragment_limits);
    assert!(outcomes.is_empty());
    assert_eq!(stats, PersistBatchStats::default());

    let one_oid = oid(b"one fragment");
    let stats = persist_one(
        &store,
        prepare(one_oid, Arc::clone(&state), &generations, &[]),
    );
    assert_eq!((stats.transactions, stats.committed_fragments), (1, 1));

    let max_oid = oid(b"two fragment exact maximum");
    let (outcomes, stats) = store.persist_prepared_blobs(
        vec![prepare(max_oid, Arc::clone(&projected), &generations, &[])],
        two_fragment_limits,
    );
    assert!(outcomes[0].error.is_none());
    assert_eq!((stats.transactions, stats.committed_fragments), (1, 2));

    let (outcomes, stats) = store.persist_prepared_blobs(
        vec![
            prepare(
                oid(b"three fragments projected"),
                Arc::clone(&projected),
                &generations,
                &[],
            ),
            prepare(
                oid(b"three fragments primary"),
                Arc::clone(&state),
                &generations,
                &[],
            ),
        ],
        two_fragment_limits,
    );
    assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
    assert_eq!((stats.transactions, stats.committed_fragments), (2, 3));
    assert_eq!(stats.peak_batch_fragments, 2);

    let exact_oid = oid(b"exact row and byte caps");
    let exact = prepare(exact_oid, Arc::clone(&projected), &generations, &[]);
    let exact_expected_fragment_rows =
        vec![exact.logical_rows(), exact.additional[0].logical_rows()];
    let exact_expected_rows = exact.mutation_logical_rows();
    let exact_limits = PersistBatchTargets {
        max_blobs: exact.fragment_count(),
        max_rows: exact_expected_rows,
        max_payload_bytes: exact.mutation_payload_bytes(),
    };
    let (outcomes, stats) = store.persist_prepared_blobs(vec![exact], exact_limits);
    assert!(outcomes[0].error.is_none());
    assert_eq!(stats.transactions, 1);
    let physical_fragment_rows =
        persisted_physical_logical_rows(&store, &[(exact_oid, PRIMARY), (exact_oid, PROJECTION)]);
    assert_eq!(physical_fragment_rows, exact_expected_fragment_rows);
    let physical_rows = physical_fragment_rows
        .into_iter()
        .fold(0usize, usize::saturating_add);
    assert_eq!(physical_rows, exact_expected_rows);
    assert_eq!(stats.logical_rows, physical_rows);
    assert_eq!(stats.payload_bytes, exact_limits.max_payload_bytes);

    for (label, limits) in [
        (
            b"one fragment over".as_slice(),
            PersistBatchTargets {
                max_blobs: 1,
                ..exact_limits
            },
        ),
        (
            b"one row over".as_slice(),
            PersistBatchTargets {
                max_rows: exact_limits.max_rows - 1,
                ..exact_limits
            },
        ),
        (
            b"one byte over".as_slice(),
            PersistBatchTargets {
                max_payload_bytes: exact_limits.max_payload_bytes - 1,
                ..exact_limits
            },
        ),
    ] {
        let oversized_oid = oid(label);
        let peer_oid = oid([label, b"peer"].concat());
        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![
                prepare(oversized_oid, Arc::clone(&projected), &generations, &[]),
                prepare(peer_oid, Arc::clone(&state), &generations, &[]),
            ],
            limits,
        );
        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));
        assert_eq!(
            stats.transactions, 2,
            "oversized OID must not absorb its peer"
        );
        assert_eq!((stats.committed_fragments, stats.failed_fragments), (3, 0));
        assert_eq!(stats.peak_batch_fragments, 2);
        assert_eq!(stats.peak_batch_rows, exact_expected_rows);
        assert_eq!(
            stats.peak_batch_payload_bytes,
            exact_limits.max_payload_bytes
        );
        assert!(store.contains_parsed_blob(oversized_oid, PRIMARY).unwrap());
        assert!(
            store
                .contains_parsed_blob(oversized_oid, PROJECTION)
                .unwrap()
        );
        assert_eq!(
            persisted_physical_logical_rows(
                &store,
                &[(oversized_oid, PRIMARY), (oversized_oid, PROJECTION)]
            ),
            exact_expected_fragment_rows,
        );
    }

    let cancelled_oid = oid(b"cancelled combined envelope");
    let starts = store.parsed_blob_transaction_starts_for_test();
    let cancellation = CancellationToken::cancel_after_checks_for_test(4);
    let (mut outcomes, stats) = store.persist_prepared_blobs_with_cancellation(
        vec![prepare(
            cancelled_oid,
            Arc::clone(&projected),
            &generations,
            &[],
        )],
        &cancellation,
        PersistBatchTargets {
            max_blobs: 1,
            max_rows: 1,
            max_payload_bytes: 1,
        },
    );
    assert!(outcomes[0].error.is_some());
    assert!(cancellation.is_cancelled());
    assert_eq!(stats.failed_fragments, 2);
    assert_eq!(store.parsed_blob_transaction_starts_for_test(), starts + 1);
    assert!(!store.contains_parsed_blob(cancelled_oid, PRIMARY).unwrap());
    assert!(
        !store
            .contains_parsed_blob(cancelled_oid, PROJECTION)
            .unwrap()
    );
    let cancelled = outcomes.pop().expect("cancelled outcome").prepared;
    let retry = persist_one(&store, cancelled);
    assert_eq!(retry.committed_fragments, 2);

    let good_a_oid = oid(b"bisection good a");
    let bad_oid = oid(b"bisection bad combined envelope");
    let good_b_oid = oid(b"bisection good b");
    let mut bad = prepare(bad_oid, Arc::clone(&projected), &generations, &[]);
    bad.additional[0].inject_invalid_range_for_test();
    let (outcomes, stats) = store.persist_prepared_blobs(
        vec![
            prepare(good_a_oid, Arc::clone(&state), &generations, &[]),
            bad,
            prepare(good_b_oid, Arc::clone(&state), &generations, &[]),
        ],
        PersistBatchTargets::PRODUCTION,
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.error.is_some())
            .count(),
        1
    );
    assert_eq!((stats.committed_blobs, stats.failed_blobs), (2, 1));
    assert_eq!((stats.committed_fragments, stats.failed_fragments), (2, 2));
    assert!(store.contains_parsed_blob(good_a_oid, PRIMARY).unwrap());
    assert!(store.contains_parsed_blob(good_b_oid, PRIMARY).unwrap());
    assert!(!store.contains_parsed_blob(bad_oid, PRIMARY).unwrap());
    assert!(!store.contains_parsed_blob(bad_oid, PROJECTION).unwrap());
    let retry = persist_one(&store, prepare(bad_oid, projected, &generations, &[]));
    assert_eq!(retry.committed_fragments, 2);
}

#[cfg(test)]
/// A relation's rows are exactly the shared identities its read answers.
///
/// This is the contract the whole family rests on: a typed read opens the
/// blobs its relation names and no others, so a blob whose interior would have
/// answered and has no row is a wrong answer, and a blob with a row that
/// answers nothing is an interior produced for nothing. The oracle is the
/// interior itself. For each fixture blob, the persisted rows are compared
/// against what `PreloadedFactResolutionService` -- the same index the mounted
/// read consults, built from the same lowered fragment -- returns when it is
/// asked that relation's question about each shared identity in the blob's
/// catalog.
///
/// A fragment-local key never reaches a relation: `semantic_coordinates`
/// resolves it through the rebaser to the one mount that owns it. That is why
/// the sweep is over the shared slice of the catalog and why most relations
/// carry no rows at all.
#[test]
#[hardwon("dfb60686e6e4: persisted typed-fact membership drifted from the reader answer set")]
fn every_typed_relation_names_exactly_the_shared_identities_its_read_answers() {
    const RICH_SOURCE: &str = concat!(
        "pub mod inner {\n",
        "    pub struct Thing {\n        pub field: u32,\n    }\n",
        "    impl Thing {\n",
        "        pub fn make(value: u32) -> Self {\n            Self { field: value }\n        }\n",
        "        pub fn read(&self) -> u32 {\n            self.field\n        }\n",
        "    }\n",
        "    pub trait Read {\n        fn read(&self) -> u32;\n    }\n",
        "    impl Read for Thing {\n        fn read(&self) -> u32 {\n            self.field\n        }\n    }\n",
        "}\n",
        "use inner::{Read, Thing};\n",
        "type ItemAlias<T> = Option<T>;\n",
        "pub fn use_it(thing: &Thing, absent: Absent) -> u32 {\n",
        "    Read::read(thing) + Thing::make(1).read() + absent.shared_member()\n",
        "}\n",
        "pub fn use_alias(value: ItemAlias<Thing>) -> ItemAlias<Thing> { value }\n",
    );
    let mut sources = vec![
        ("src/rich.rs".to_owned(), RICH_SOURCE.to_owned()),
        (
            "src/route_holder.rs".to_owned(),
            ROUTE_ISOLATING_HOLDER.to_owned(),
        ),
        (
            "src/member_holder.rs".to_owned(),
            MEMBER_ISOLATING_HOLDER.to_owned(),
        ),
    ];
    for index in 0..4usize {
        sources.push((
            format!("src/declaring_{index:04}.rs"),
            format!(
                "pub struct S{index:04};
impl S{index:04} {{ pub fn shared_route(&self) -> usize {{ {index} }} }}
"
            ),
        ));
        sources.push((
            format!("src/calling_{index:04}.rs"),
            format!(
                "pub fn scale_{index:04}(value: Absent{index:04}) -> usize {{ value.shared_member() }}
"
            ),
        ));
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure the Rust parser");
    let mut checked = 0usize;
    let mut with_rows = std::collections::BTreeSet::new();
    for (path, source) in &sources {
        let file = ProjectFile::new(
            fixture_project_root("typed-relation-oracle-does-not-touch-disk"),
            path,
        );
        let tree = parser
            .parse(source, None)
            .expect("parse the oracle fixture");
        let parsed = brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
        let unit_keys = parsed_unit_keys(&parsed);
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(path.as_bytes()),
            crate::analyzer::resolution::test_shared_names(),
            Language::Rust,
            &parsed.resolution_facts,
        );
        let ResolutionInteriorPreparation::Prepared(prepared) =
            prepare_resolution_bundle_with_unit_keys(
                &lowered,
                Some(&unit_keys),
                &CancellationToken::default(),
            )
        else {
            panic!("uncancelled oracle preparation must finish for {path}");
        };
        let recorded = prepared
            .typed_fact_lookups()
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let shared = lowered
            .identities()
            .semantics()
            .iter()
            .filter_map(|(semantic, identity)| {
                identity
                    .shared_name()
                    .map(|name| (*semantic, lowered.identities().shared_name_digest(name)))
            })
            .collect::<Vec<_>>();
        assert!(
            !shared.is_empty(),
            "{path} must carry shared identities for the sweep to mean anything"
        );
        let (lexical, typed, _) = lowered.into_parts();
        let service = PreloadedFactResolutionService::from_lowered_fragments([lexical], [typed]);
        let cancellation = CancellationToken::default();
        let mut disagreements = Vec::new();
        for relation in TypedFactRelation::ALL {
            for (semantic, digest) in &shared {
                let answered =
                    typed_relation_answers(&service, *relation, *semantic, &cancellation);
                let written = recorded.contains(&(relation.code(), *digest));
                if answered != written {
                    disagreements.push((relation.label(), *semantic, answered, written));
                }
                if written {
                    with_rows.insert(relation.label());
                }
                checked += 1;
            }
        }
        assert!(
            disagreements.is_empty(),
            "in {path} a relation's rows must be exactly the shared identities its \
             read answers (relation, identity, interior answers, row written): \
             {disagreements:?}"
        );
    }
    eprintln!(
        "{checked} (relation, shared identity) pairs checked over {} blobs; relations with \
         rows: {with_rows:?}",
        sources.len()
    );
    assert!(
        checked > 0 && !with_rows.is_empty(),
        "the oracle fixtures must exercise at least one relation"
    );
}

#[cfg(test)]
/// Does this blob's interior answer this relation's question about this
/// identity?
///
/// One arm per relation, over the same reads `resolution_typed.rs` composes
/// membership for, so a relation added there without a writer loop fails to
/// compile here.
fn typed_relation_answers(
    service: &PreloadedFactResolutionService,
    relation: TypedFactRelation,
    semantic: SemanticId,
    cancellation: &CancellationToken,
) -> bool {
    macro_rules! answered {
        ($method:ident, $request:expr) => {{
            let mut rows = 0usize;
            let mut sink = |page: &[_]| {
                rows += page.len();
                Ok(true)
            };
            let mut visitor = TypedFactPageVisitor::new(&mut sink);
            let request = [$request];
            // A Rust reference context read reports a missing row as a store
            // error rather than an empty page, which is the same answer for
            // this question: the interior holds nothing under the identity.
            let outcome =
                service.$method(TypedFactRequest::new(&request), cancellation, &mut visitor);
            outcome.is_ok() && rows > 0
        }};
    }
    match relation {
        TypedFactRelation::RustReferenceContext => {
            answered!(visit_rust_reference_context_pages, semantic)
        }
        TypedFactRelation::RustDeclarationAuthority => {
            answered!(visit_rust_declaration_authority_pages, semantic)
        }
        TypedFactRelation::TypedFrontierSlot => answered!(visit_typed_frontier_pages, semantic),
        TypedFactRelation::TypeIdentityObservationReference => {
            answered!(
                visit_type_identity_observation_pages_for_references,
                semantic
            )
        }
        TypedFactRelation::TypeFrontierCompletionFrontier => {
            answered!(visit_type_frontier_completion_pages, semantic)
        }
        TypedFactRelation::TypeTransferSourceSlot => {
            answered!(visit_type_transfer_pages_from_sources, semantic)
        }
        TypedFactRelation::TypeTransferTargetSlot => {
            answered!(visit_type_transfer_pages_to_targets, semantic)
        }
        TypedFactRelation::TypeProductionOutput => {
            answered!(visit_type_production_pages_for_outputs, semantic)
        }
        TypedFactRelation::TypeComponentContainer => {
            answered!(visit_type_component_pages_for_containers, semantic)
        }
        TypedFactRelation::DeclaredTypeArgumentOwner => {
            answered!(visit_declared_type_argument_pages_for_owners, semantic)
        }
        TypedFactRelation::TypeArgumentApplication => {
            answered!(visit_type_argument_pages_for_applications, semantic)
        }
        TypedFactRelation::GenericTypeAliasDefinition => {
            answered!(
                visit_generic_type_alias_parameter_pages_for_definitions,
                semantic
            )
        }
        TypedFactRelation::GenericFormalOwner => {
            answered!(visit_generic_formal_pages_for_owners, semantic)
        }

        TypedFactRelation::GenericFormalDefaultOwner => {
            answered!(visit_generic_formal_default_pages_for_owners, semantic)
        }
        TypedFactRelation::UnderlyingTypeDefinition => {
            answered!(visit_underlying_type_pages_for_definitions, semantic)
        }
        TypedFactRelation::IntrinsicSeedSlot => {
            answered!(visit_intrinsic_seed_pages_for_slots, semantic)
        }
        TypedFactRelation::IntrinsicSeedTypeIdentity => {
            answered!(visit_intrinsic_seed_pages_for_type_identities, semantic)
        }
        TypedFactRelation::BindingProjectionReference => {
            answered!(visit_binding_projection_pages_for_references, semantic)
        }
        TypedFactRelation::BindingProjectionOutputSlot => {
            answered!(visit_binding_projection_pages_for_outputs, semantic)
        }
        TypedFactRelation::QualifiedRouteReference => {
            answered!(visit_qualified_route_pages_for_references, semantic)
        }
        TypedFactRelation::QualifiedRouteQualifierSlot => {
            answered!(visit_qualified_route_pages_for_qualifier_slots, semantic)
        }
        // The completion-lookup index and the slot-lookup index hold the same
        // lookups, which is why one relation serves both reads and the route
        // inventory; probing either proves the row set.
        TypedFactRelation::QualifiedRouteLookup => {
            answered!(visit_qualified_route_pages_for_lookups, semantic)
        }
        TypedFactRelation::QualifiedRouteGapReason => {
            answered!(visit_qualified_route_pages_for_gap_reasons, semantic)
        }
        TypedFactRelation::DeclarationTypeDefinition => {
            answered!(visit_declaration_type_pages_for_definitions, semantic)
        }
        TypedFactRelation::DeclarationTypeSlot => {
            answered!(visit_declaration_type_pages_for_slots, semantic)
        }
        TypedFactRelation::DeclarationVisibilityDefinition => {
            answered!(visit_declaration_visibility_pages_for_definitions, semantic)
        }
        TypedFactRelation::MemberScopeDefinition => {
            answered!(visit_member_scope_pages_for_definitions, semantic)
        }
        TypedFactRelation::MemberOwnerDefinition => {
            answered!(visit_member_owner_pages_for_definitions, semantic)
        }
        TypedFactRelation::MemberOwnerOwnerDefinition => {
            answered!(visit_member_owner_pages_for_owners, semantic)
        }
        TypedFactRelation::DeferredMemberOwnerDefinition => {
            answered!(visit_deferred_member_owner_pages_for_definitions, semantic)
        }
        TypedFactRelation::DeferredMemberOwnerLookup => answered!(
            visit_deferred_member_owner_pages_for_lookup_names,
            DeferredMemberOwnerLookupName::new(semantic)
        ),
        TypedFactRelation::ConstructionRequirementDefinition => {
            answered!(
                visit_construction_requirement_pages_for_definitions,
                semantic
            )
        }
        TypedFactRelation::SupertypeDefinition => {
            answered!(visit_supertype_pages_for_definitions, semantic)
        }
        TypedFactRelation::SupertypeReference => {
            answered!(visit_supertype_pages_for_references, semantic)
        }
        TypedFactRelation::SupertypeFrontier => {
            answered!(visit_supertype_pages_for_frontiers, semantic)
        }
        TypedFactRelation::DefinitionPropertyGapReason => {
            answered!(visit_definition_property_gap_pages_for_reasons, semantic)
        }
        TypedFactRelation::DefinitionPropertyGapDefinition => {
            answered!(
                visit_definition_property_gap_pages_for_definitions,
                semantic
            )
        }
        TypedFactRelation::CallApplicabilityCalleeReference => {
            answered!(
                visit_call_applicability_pages_for_callee_references,
                semantic
            )
        }
        TypedFactRelation::CallApplicabilityGapReason => {
            answered!(visit_call_applicability_pages_for_gap_reasons, semantic)
        }
        TypedFactRelation::CallableSignatureDefinition => {
            answered!(visit_callable_signature_pages_for_definitions, semantic)
        }
        TypedFactRelation::GapReasonProvenanceReason => {
            answered!(visit_gap_reason_provenance_pages_for_reasons, semantic)
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[path = "resolution_publication_tests.rs"]
#[doc(hidden)]
pub mod selected_publication;

// This oracle discovers the persisted variable-width columns from SQLite's
// schema, independently of the production manifest family/column inventory.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn measured_resolution_payload(store: &AnalyzerStore, oid: Oid, lang: &str) -> usize {
    let oid = oid.to_string();
    let lang = lang.to_owned();
    store.conn.execute(move |conn| {
        let blob_id: i64 = conn
            .query_row(
                "SELECT id FROM blobs WHERE blob_oid=?1 AND lang=?2",
                params![oid, lang],
                |row| row.get(0),
            )
            .unwrap();
        let names = conn
            .prepare(
                "SELECT name FROM sqlite_schema
            WHERE (type='table' AND name GLOB 'resolution_*')
               OR name='resolution_declaration_visibility_properties'",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let mut bytes = 0usize;
        for name in names {
            let columns = conn
                .prepare("SELECT name,type FROM pragma_table_info(?1)")
                .unwrap()
                .query_map([&name], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            if !columns.iter().any(|(column, _)| column == "blob_id") {
                continue;
            }
            for (column, kind) in columns {
                if !matches!(kind.as_str(), "TEXT" | "BLOB") || column == "publication_state" {
                    continue;
                }
                let sql = format!(
                    "SELECT COALESCE(SUM(length(CAST(\"{}\" AS BLOB))),0)
                    FROM \"{}\" WHERE blob_id=?1",
                    column.replace('"', "\"\""),
                    name.replace('"', "\"\"")
                );
                bytes += conn
                    .query_row(&sql, [blob_id], |row| row.get::<_, usize>(0))
                    .unwrap();
            }
        }
        bytes
    })
}

#[cfg(test)]
#[test]
fn rust_first_tranche_survives_common_lowering_and_bundle_preparation() {
    let source = "use engine::Thing as LocalThing;\npub fn callee(value: i32) -> i32 { value }\nfn caller(input: i32) -> i32 { let local = input; callee(local) }\n";
    let file = ProjectFile::new(
        fixture_project_root("selected-rust-context-does-not-touch-disk"),
        "lib.rs",
    );
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure Rust parser");
    let tree = parser.parse(source, None).expect("parse Rust fixture");
    let parsed = brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
    let unit_keys = parsed_unit_keys(&parsed);
    let facts = parsed.resolution_facts;

    assert!(!facts.identifiers.is_empty());
    assert!(!facts.binders.is_empty());
    assert_eq!(facts.root_imports.len(), 1);
    // Root exports retain every named declaration as a candidate endpoint;
    // terminal visibility is applied by the selected resolver.  The fixture
    // has both the public callee and the private caller.
    assert_eq!(facts.root_exports.len(), 2);
    assert_eq!(facts.calls.len(), 1);
    // `callee(local)` writes one actual; `callee` and `caller` each declare
    // one parameter.
    assert_eq!(facts.call_arguments.len(), 1);
    assert_eq!(facts.callable_parameters.len(), 2);
    assert!(
        facts
            .type_slots
            .iter()
            .any(|slot| slot.role == ResolutionTypeSlotRole::CallResult)
    );
    let mut point_gaps = facts
        .gaps
        .iter()
        .map(|gap| {
            let site = facts.sites[gap.site.index()];
            (
                &source[site.start_byte..site.end_byte],
                gap.kind,
                site.start_byte,
                site.end_byte,
            )
        })
        .collect::<Vec<_>>();
    point_gaps.sort_by_key(|(_, kind, start_byte, end_byte)| (*start_byte, *end_byte, *kind));
    assert_eq!(
        point_gaps
            .iter()
            .map(|(spelling, kind, _, _)| (*spelling, *kind))
            .collect::<Vec<_>>(),
        // Both parameter lists and the argument list are exact, so only the
        // callee's own obligation remains.
        vec![
            ("caller", ResolutionGapKind::UnsupportedVisibility),
            ("callee", ResolutionGapKind::UnsupportedCallApplicability),
        ],
        "every retained Rust applicability gap must identify its source site"
    );
    assert!(
        facts.reference_enumeration_gaps.is_empty(),
        "unexpected enumeration gaps: {:?}",
        facts.reference_enumeration_gaps
    );
    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        BindingFragmentId::for_test(b"rust-first-resolution-tranche"),
        crate::analyzer::resolution::test_shared_names(),
        Language::Rust,
        &facts,
    );
    assert!(!lowered.lexical().nodes().is_empty());
    assert!(!lowered.lexical().paths().is_empty());
    assert!(!lowered.lexical().semantics().is_empty());
    assert_eq!(lowered.lexical().gaps().len(), 2);
    assert!(lowered.lexical().gaps().iter().all(|gap| {
        matches!(
            gap.origin(),
            LoweringGapOrigin::Extracted(
                ResolutionGapKind::UnsupportedCallApplicability
                    | ResolutionGapKind::UnsupportedVisibility
            )
        )
    }));
    assert_eq!(
        lowered
            .lexical()
            .gaps()
            .iter()
            .filter(|gap| matches!(gap.frontier(), LoweringCoverageFrontier::Type { .. }))
            .count(),
        1,
        "only the gap on a real type slot retains typed coverage"
    );
    assert_eq!(
        lowered
            .lexical()
            .gaps()
            .iter()
            .filter(|gap| { matches!(gap.frontier(), LoweringCoverageFrontier::Reference { .. }) })
            .count(),
        1,
        "the callee applicability gap retains one positioned reference frontier"
    );
    assert!(!lowered.lexical().gaps().iter().any(|gap| {
        matches!(
            gap.frontier(),
            LoweringCoverageFrontier::Candidate {
                direction: LoweredCandidateDirection::Forward,
                ..
            }
        )
    }));
    let mut lowered_gap_sites = lowered
        .lexical()
        .gaps()
        .iter()
        .map(|gap| {
            let site = facts.sites[gap.site().index()];
            &source[site.start_byte..site.end_byte]
        })
        .collect::<Vec<_>>();
    lowered_gap_sites.sort_unstable();
    assert_eq!(
        lowered_gap_sites,
        vec!["callee", "caller"],
        "lowered coverage keeps positioned and real-slot gap rows"
    );

    let ResolutionInteriorPreparation::Prepared(prepared) =
        prepare_resolution_bundle_with_unit_keys(
            &lowered,
            Some(&unit_keys),
            &CancellationToken::default(),
        )
    else {
        panic!("uncancelled Rust first-tranche preparation must finish");
    };
    for family in [
        "expected_semantic_site_count",
        "expected_path_endpoint_header_count",
    ] {
        let index = RESOLUTION_MANIFEST_COUNT_COLUMNS
            .iter()
            .position(|column| *column == family)
            .unwrap_or_else(|| panic!("manifest has {family}"));
        assert!(prepared.family_counts()[index] > 0, "{family}");
    }
}

#[cfg(test)]
#[test]
fn unresolved_expression_macro_does_not_duplicate_reverse_gap_candidate() {
    let source = "fn caller() { external_macro!(); }\n";
    let file = ProjectFile::new(
        fixture_project_root("unresolved-expression-macro-reverse-gap-candidate"),
        "lib.rs",
    );
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure Rust parser");
    let tree = parser.parse(source, None).expect("parse Rust fixture");
    let parsed = brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
    let source_facts = parsed
        .source_facts
        .as_ref()
        .expect("Rust parser publishes canonical source facts");
    assert_eq!(source_facts.rust_items.macro_inputs.len(), 1);
    let (macro_site, _) = source_facts.rust_items.macro_inputs[0]
        .native_frontier
        .expect("unresolved expression macro has a native frontier");
    assert!(parsed.resolution_facts.gaps.iter().any(|gap| {
        gap.site == macro_site && gap.kind == ResolutionGapKind::UnsupportedExpression
    }));

    let unit_keys = parsed_unit_keys(&parsed);
    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        BindingFragmentId::for_test(b"unresolved-expression-macro-reverse-gap-candidate"),
        crate::analyzer::resolution::test_shared_names(),
        Language::Rust,
        &parsed.resolution_facts,
    );
    assert!(
        lowered
            .common()
            .rust_reverse_gap_candidates
            .iter()
            .any(|candidate| candidate.site == macro_site)
    );
    let ResolutionInteriorPreparation::Prepared(prepared) =
        prepare_resolution_bundle_with_source_facts(
            &lowered,
            &unit_keys,
            Some(source_facts),
            Some(source),
            &CancellationToken::default(),
        )
        .expect("prepare unresolved expression macro resolution bundle")
    else {
        panic!("uncancelled unresolved macro preparation must finish");
    };
    let count_index = RESOLUTION_MANIFEST_COUNT_COLUMNS
        .iter()
        .position(|column| *column == "expected_rust_reverse_gap_candidate_count")
        .expect("Rust reverse gap candidate family");
    assert!(
        prepared.family_counts()[count_index] > 0,
        "the unresolved macro frontier retains a reverse gap candidate"
    );
}

#[cfg(test)]
#[test]
fn rust_m6a_first_tranche_facts_all_prepare() {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .expect("configure Rust parser");
    for (path, source) in brokk_bifrost_rust::resolution_spike_fixture::M6A_RUST_WORKSPACE_FILES
        .iter()
        .filter(|(path, _)| path.ends_with(".rs"))
    {
        let file = ProjectFile::new(
            fixture_project_root("selected-rust-context-does-not-touch-disk"),
            *path,
        );
        let tree = parser.parse(source, None).expect("parse Rust spike file");
        let parsed = brokk_bifrost_rust::declarations::parse_rust_file(&file, source, &tree);
        let unit_keys = parsed_unit_keys(&parsed);
        let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
            BindingFragmentId::for_test(path.as_bytes()),
            crate::analyzer::resolution::test_shared_names(),
            Language::Rust,
            &parsed.resolution_facts,
        );
        assert!(
            matches!(
                prepare_resolution_bundle_with_unit_keys(
                    &lowered,
                    Some(&unit_keys),
                    &CancellationToken::default(),
                ),
                ResolutionInteriorPreparation::Prepared(_)
            ),
            "{path}"
        );
    }
}

#[cfg(test)]
#[test]
fn complete_analysis_queries_seek_persistent_authority_tables() {
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let request = CompleteAnalysisBlobRequest::new(
        oid(b"complete analysis query plan"),
        PRIMARY,
        [PROJECTION.to_owned()],
    );
    let conn = store.conn.lock().expect("store mutex");
    sync_requested_parsed_blobs(
        &conn,
        &[(request.oid(), request.storage_language().to_owned())],
    )
    .expect("sync requested primary");
    sync_requested_analysis_projections(&conn, std::slice::from_ref(&request))
        .expect("sync requested projections");

    let explain = |sql: &str| {
        conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("prepare complete-analysis plan")
            .query_map([Language::Java.config_label()], |row| {
                row.get::<_, String>(3)
            })
            .expect("query complete-analysis plan")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("read complete-analysis plan")
    };
    let missing_plan = explain(MISSING_PUBLISHED_COMPLETE_ANALYSIS_SQL);
    let projection_plan = explain(REQUIRED_EXISTING_ANALYSIS_PROJECTIONS_SQL);

    assert_bounded_complete_analysis_plan(&missing_plan);
    assert_bounded_complete_analysis_plan(&projection_plan);

    for (alias, index) in [
        ("primary_epoch", "PRIMARY KEY"),
        ("primary_resolution_epoch", "PRIMARY KEY"),
        ("primary_blob", "idx_blobs_lang_generation"),
        ("primary_meta", "PRIMARY KEY"),
        ("primary_interior", "PRIMARY KEY"),
        ("projection", "PRIMARY KEY"),
        ("independent", "PRIMARY KEY"),
        ("projection_epoch", "PRIMARY KEY"),
        ("projection_resolution_epoch", "PRIMARY KEY"),
        ("projection_meta", "PRIMARY KEY"),
        ("projection_interior", "PRIMARY KEY"),
    ] {
        assert_plan_search(&missing_plan, alias, index);
    }
    assert_plan_search(&missing_plan, "projection_blob", "sqlite_autoindex_blobs_1");
    assert_plan_search(&missing_plan, "projection_blob", "(blob_oid=? AND lang=?)");
    assert!(
        missing_plan
            .iter()
            .any(|detail| detail.contains("CORRELATED SCALAR SUBQUERY")),
        "optional projection validation must remain a per-request indexed probe: {missing_plan:#?}"
    );

    for (alias, index) in [
        ("owner", "PRIMARY KEY"),
        ("independent", "PRIMARY KEY"),
        ("projection_epoch", "PRIMARY KEY"),
        ("projection_resolution_epoch", "PRIMARY KEY"),
        ("projection_meta", "PRIMARY KEY"),
        ("projection_interior", "PRIMARY KEY"),
    ] {
        assert_plan_search(&projection_plan, alias, index);
    }
    assert_plan_search(
        &projection_plan,
        "projection_blob",
        "sqlite_autoindex_blobs_1",
    );
    assert_plan_search(
        &projection_plan,
        "projection_blob",
        "(blob_oid=? AND lang=?)",
    );
}

#[cfg(test)]
#[test]
fn stale_generation_reclamation_cost_plan_uses_gc_order_and_keyed_probes() {
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let conn = store.conn.lock().expect("store mutex");
    let plan = conn
        .prepare(&format!(
            "EXPLAIN QUERY PLAN {}",
            stale_generation_blob_costs_sql()
        ))
        .expect("prepare stale-generation GC plan")
        .query_map([], |row| row.get::<_, String>(3))
        .expect("query stale-generation GC plan")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("read stale-generation GC plan");

    let scans = plan
        .iter()
        .filter_map(|detail| {
            detail
                .split_once("SCAN ")
                .and_then(|(_, tail)| tail.split_ascii_whitespace().next())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        scans,
        vec!["blobs"],
        "GC may scan only the ordered blob inventory: {plan:#?}"
    );
    assert!(
        plan.iter().any(|detail| {
            detail.contains("SCAN blobs USING COVERING INDEX idx_blobs_lang_generation")
        }),
        "GC must consume stale blobs in its indexed order: {plan:#?}"
    );
    for alias in [
        "epochs",
        "meta",
        "costs",
        "manifest",
        "reference_manifest",
        "interior",
    ] {
        assert_plan_search(&plan, alias, "PRIMARY KEY");
    }
    // Schema 117 left one `facts` alias in the reclamation cost: the canonical
    // source-fact manifest. The four retired `structural_fact_*` families each
    // had one of the other probes.
    assert_eq!(
        plan.iter()
            .filter(|detail| detail.contains("SEARCH facts USING PRIMARY KEY"))
            .count(),
        1,
        "the canonical source-fact family must be a keyed correlated probe: {plan:#?}"
    );
    assert!(
        plan.iter()
            .all(|detail| { !detail.contains("AUTOMATIC") && !detail.contains("USE TEMP B-TREE") }),
        "GC must not synthesize an index or sort its ordered inventory: {plan:#?}"
    );
}

#[cfg(test)]
use super::js_ts_resolution_producer_support::*;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod rust_root_test_support {
    use super::*;

    use crate::CancellationToken;

    use crate::analyzer::java::JavaAdapter;

    use crate::analyzer::store::file_state::FileState;

    use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;

    use crate::hash::HashMap;

    use git2::Oid;

    use std::sync::Arc;

    pub(super) const PRIMARY: &str = "java";
    #[cfg(test)]
    pub(super) const PROJECTION: &str = "java:projection";
    #[cfg(test)]
    pub(super) fn generations(store: &AnalyzerStore) -> HashMap<String, GenerationId> {
        let mut generations = HashMap::default();
        for language in [PRIMARY, PROJECTION] {
            generations.insert(
                language.to_owned(),
                store
                    .ensure_language_epoch_value(language, "resolution-producer-test-v1")
                    .expect("test generation"),
            );
        }
        generations
    }
    pub(super) fn prepare_with_adapter<A: LanguageAdapter>(
        oid: Oid,
        state: Arc<FileState>,
        generations: &HashMap<String, GenerationId>,
        required_projections: &[String],
        adapter: &A,
    ) -> PreparedParsedBlob {
        let file = crate::analyzer::store::test_blob_file();
        let syntax = crate::analyzer::tree_sitter_analyzer::reparse_retained_source(
            adapter, &file, &state, None,
        );
        let syntax = match syntax {
            crate::analyzer::store::file_state::PreparedSyntaxPreparation::Complete(Some(tree)) => {
                tree
            }
            _ => panic!("test source must parse within its budget"),
        };
        match AnalyzerStore::prepare_parsed_blob_at_generations(
            &file,
            &syntax,
            oid,
            PRIMARY,
            generations,
            adapter,
            state,
            required_projections,
            &CancellationToken::default(),
        )
        .expect("prepare combined parsed and resolution bundle")
        {
            PreparedParsedBlobPreparation::Prepared(prepared) => *prepared,
            PreparedParsedBlobPreparation::Cancelled => panic!("uncancelled preparation cancelled"),
        }
    }
    #[doc(hidden)]
    pub fn prepare(
        oid: Oid,
        state: Arc<FileState>,
        generations: &HashMap<String, GenerationId>,
        required_projections: &[String],
    ) -> PreparedParsedBlob {
        prepare_with_adapter(oid, state, generations, required_projections, &JavaAdapter)
    }
    /// Declares a member under `shared_route` and calls it through a receiver, so
    /// it is the one blob that holds a qualified route under the name.
    #[doc(hidden)]
    pub const ROUTE_ISOLATING_HOLDER: &str = concat!(
        "pub struct Router;\n",
        "impl Router { pub fn shared_route(&self) -> usize { 0 } }\n",
        "pub fn hold(value: Router) -> usize { value.shared_route() }\n",
    );
    /// Declares a member under `shared_member` and never calls it, so it is the
    /// one blob that declares a deferred member owner under the name.
    #[doc(hidden)]
    pub const MEMBER_ISOLATING_HOLDER: &str = concat!(
        "pub struct Owner;\n",
        "impl Owner { pub fn shared_member(&self) -> usize { 0 } }\n",
    );
}

#[cfg(test)]
use crate::analyzer::store::resolution_producer_tests_go_support::go_extraction_support_10::*;
