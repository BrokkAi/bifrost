use std::{path::PathBuf, sync::Arc};

use git2::{ObjectType, Oid};
use rusqlite::{params, params_from_iter};
use tree_sitter::Parser;

use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionGapKind, ResolutionNamespace, ResolutionTypeSlotRole,
};

use crate::CancellationToken;
use crate::analyzer::cpp::CppAdapter;
use crate::analyzer::go::GoAdapter;
use crate::analyzer::java::JavaAdapter;
use crate::analyzer::resolution::{
    BindingFragmentId, DeferredMemberOwnerLookupName, LoweredCandidateDirection,
    LoweringCoverageFrontier, LoweringGapOrigin, PreloadedFactResolutionService,
    SelectedTypedFactSource, SemanticId, TypedFactPageVisitor, TypedFactRequest,
    rich_java_resolution_facts_for_test,
};
use crate::analyzer::rust::RustAdapter;
use crate::analyzer::store::resolution::{
    PreparedResolutionBundle, RESOLUTION_MANIFEST_COUNT_COLUMNS, TypedFactRelation,
    resolution_bundle_epoch,
};
use crate::analyzer::store::resolution_prepare::{
    ResolutionInteriorPreparation, prepare_resolution_bundle_with_unit_keys,
};
use crate::analyzer::store::test_adapters::LegacyJavaFixtureAdapter;
use crate::analyzer::tree_sitter_analyzer::{FileState, LanguageAdapter, ParsedFile};
use crate::analyzer::typescript::TypescriptAdapter;
use crate::analyzer::{CodeUnit, Language, ProjectFile};
use crate::hash::HashMap;

use super::*;

const PRIMARY: &str = "java";
const PROJECTION: &str = "java:projection";

fn fixture_project_root(name: &str) -> PathBuf {
    std::env::current_dir()
        .expect("current directory is available for an absolute fixture root")
        .join(name)
}

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

#[derive(Debug, PartialEq, Eq)]
struct ManifestSnapshot {
    semantic_language: String,
    producer_epoch: String,
    interior_digest: [u8; 32],
    publication_state: String,
    family_counts: [usize; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()],
    logical_rows: usize,
    payload_bytes: usize,
}

impl ManifestSnapshot {
    fn expected(bundle: &PreparedResolutionBundle) -> Self {
        Self {
            semantic_language: bundle.semantic_language().config_label().to_owned(),
            producer_epoch: bundle.producer_epoch().to_owned(),
            interior_digest: bundle.interior_digest(),
            publication_state: "complete".to_owned(),
            family_counts: bundle.family_counts(),
            logical_rows: bundle.logical_rows(),
            payload_bytes: bundle.payload_bytes(),
        }
    }
}

fn oid(label: impl AsRef<[u8]>) -> Oid {
    Oid::hash_object(ObjectType::Blob, label.as_ref()).expect("test blob oid")
}

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

fn parsed_fixture_state<A: LanguageAdapter>(
    adapter: &A,
    relative_path: &str,
    source: &str,
) -> Arc<FileState> {
    let file = ProjectFile::new(
        std::env::current_dir()
            .expect("resolve producer fixture root")
            .join("resolution-producer-fixture-does-not-touch-disk"),
        relative_path,
    );
    let mut parser = Parser::new();
    parser
        .set_language(&adapter.parser_language_for_file(&file))
        .expect("configure producer fixture grammar");
    let tree = parser
        .parse(source, None)
        .expect("parse producer fixture source");
    let mut parsed: ParsedFile = adapter.parse_file(&file, source, &tree);
    parsed.add_file_scope(&file, source);
    let contains_tests = adapter.contains_tests(&file, source, &tree, &parsed);
    let declarations = parsed.declarations().clone();
    Arc::new(FileState {
        source: source.to_owned(),
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
        parse_complete: true,
        additional_projections: Vec::new(),
    })
}

#[test]
fn canonical_source_publication_reopens_shared_native_and_structural_rows() {
    let temp = tempfile::tempdir().expect("persistent source-facts store");
    let db = temp.path().join("source-facts.db");
    let source = "pub fn target() {}\npub fn caller() { target(); }\n";
    let content_oid = oid(source.as_bytes());
    let state = parsed_fixture_state(&RustAdapter, "src/lib.rs", source);
    let canonical = state.source_facts.as_ref().expect("Rust canonical facts");
    let expected = crate::analyzer::structural::facts::FileFacts::from_source_and_rows(
        source.to_owned(),
        canonical.occurrences.clone(),
        canonical.structural.clone(),
    )
    .persisted_rows()
    .unwrap();
    let version = crate::analyzer::structural::facts::STRUCTURAL_FACTS_VERSION;
    let work_items = canonical.structural.work_item_count();
    let generation;
    {
        let store = AnalyzerStore::open_persistent(&db).unwrap();
        generation = store
            .ensure_language_epoch_value("rust", "canonical-source-test-v1")
            .unwrap();
        store
            .write_parsed_blob_at_generation(content_oid, "rust", generation, &RustAdapter, &state)
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

        let mut failed = prepare_parsed_blob(
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
    let sql = AnalyzerStore::blobs_with_rust_facts_sql(oids.len());
    let mut parameters = vec![
        rusqlite::types::Value::Text("rust".to_owned()),
        rusqlite::types::Value::Integer(generation.get()),
    ];
    parameters.extend(
        oids.iter()
            .map(|oid| rusqlite::types::Value::Text(oid.to_string())),
    );
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
            .write_parsed_blob_at_generation(content_oid, "rust", generation, &RustAdapter, &state)
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

fn with_projection(state: &Arc<FileState>) -> Arc<FileState> {
    let mut projection = state.as_ref().clone();
    projection.source.clear();
    projection.additional_projections.clear();
    let mut primary = state.as_ref().clone();
    primary.additional_projections = vec![(PROJECTION, Arc::new(projection))];
    Arc::new(primary)
}

fn generations(store: &AnalyzerStore) -> HashMap<String, GenerationId> {
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

fn prepare_with_adapter<A: LanguageAdapter>(
    oid: Oid,
    state: Arc<FileState>,
    generations: &HashMap<String, GenerationId>,
    required_projections: &[String],
    adapter: &A,
) -> PreparedParsedBlob {
    match AnalyzerStore::prepare_parsed_blob_at_generations(
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

fn prepare(
    oid: Oid,
    state: Arc<FileState>,
    generations: &HashMap<String, GenerationId>,
    required_projections: &[String],
) -> PreparedParsedBlob {
    prepare_with_adapter(oid, state, generations, required_projections, &JavaAdapter)
}

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

fn assert_plan_search(plan: &[String], alias: &str, index: &str) {
    assert!(
        plan.iter().any(|detail| {
            detail.contains(&format!("SEARCH {alias} ")) && detail.contains(index)
        }),
        "complete-analysis query must seek {alias} through {index}: {plan:#?}"
    );
}

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

fn manifest_snapshot(store: &AnalyzerStore, oid: Oid, lang: &str) -> ManifestSnapshot {
    let count_columns = RESOLUTION_MANIFEST_COUNT_COLUMNS
        .iter()
        .map(|column| format!("interior.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT interior.semantic_language, interior.producer_epoch,
                interior.interior_digest, interior.publication_state,
                interior.logical_rows, interior.payload_bytes, {count_columns}
         FROM blobs
         JOIN resolution_fragment_interiors AS interior ON interior.blob_id = blobs.id
         WHERE blobs.blob_oid = ?1 AND blobs.lang = ?2"
    );
    let oid = oid.to_string();
    let lang = lang.to_owned();
    store.conn.execute(move |conn| {
        conn.query_row(&sql, params![oid, lang], |row| {
            let digest = row.get::<_, Vec<u8>>(2)?;
            let mut family_counts = [0; RESOLUTION_MANIFEST_COUNT_COLUMNS.len()];
            for (index, count) in family_counts.iter_mut().enumerate() {
                *count = row.get(6 + index)?;
            }
            Ok(ManifestSnapshot {
                semantic_language: row.get(0)?,
                producer_epoch: row.get(1)?,
                interior_digest: digest
                    .try_into()
                    .expect("resolution interior digest is exactly 32 bytes"),
                publication_state: row.get(3)?,
                logical_rows: row.get(4)?,
                payload_bytes: row.get(5)?,
                family_counts,
            })
        })
        .expect("persisted resolution manifest")
    })
}

fn persist_one(store: &AnalyzerStore, prepared: PreparedParsedBlob) -> PersistBatchStats {
    let (outcomes, stats) =
        store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].error.is_none(), "{:#?}", outcomes[0].error);
    stats
}

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

#[test]
fn go_method_owner_frontier_survives_common_lowering_and_bundle_preparation() {
    let source = "package p\nfunc (value *Remote) Method() *Remote { return value }\n";
    let file = ProjectFile::new(
        fixture_project_root("selected-go-context-does-not-touch-disk"),
        "method.go",
    );
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("configure Go parser");
    let tree = parser.parse(source, None).expect("parse Go method fixture");
    let facts =
        brokk_bifrost_go::declarations::parse_go_file(&file, source, &tree).resolution_facts;
    assert_eq!(facts.deferred_member_owners.len(), 1);

    let lowered = crate::analyzer::resolution::lower_resolution_facts_for_selection(
        BindingFragmentId::for_test(b"go-deferred-owner-m6a"),
        crate::analyzer::resolution::test_shared_names(),
        Language::Go,
        &facts,
    );
    assert_eq!(lowered.common().deferred_member_owners.len(), 1);
    let ResolutionInteriorPreparation::Prepared(prepared) =
        prepare_resolution_bundle_with_unit_keys(&lowered, None, &CancellationToken::default())
    else {
        panic!("uncancelled Go deferred-owner preparation must finish");
    };
    // The deferred owner and the frontier it names are both interior detail
    // now; what must survive preparation is the declaration the owner belongs
    // to, which is the tier-1 semantic site.
    let family = RESOLUTION_MANIFEST_COUNT_COLUMNS
        .iter()
        .position(|column| *column == "expected_semantic_site_count")
        .expect("semantic site manifest family");
    assert!(prepared.family_counts()[family] > 0);
}

#[test]
fn go_reverse_lookup_headers_include_if_condition_call_callees() {
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral Go resolution store");
    let source = "package pkg\n\ntype Widget struct{}\nfunc New() Widget { return Widget{} }\nfunc use() { if New().Name() == \"\" {} }\n";
    let content = oid(source);
    persist_alias_fixture(&store, content, "go", &GoAdapter, "pkg/pkg_test.go", source);
    let content = content.to_string();
    let names: Vec<String> = store
        .conn
        .execute(move |connection| {
            let mut statement = connection.prepare(
                "SELECT DISTINCT identity.spelling
                 FROM main.blobs AS blob
                 JOIN main.resolution_reference_lookup_identities AS lookup
                   ON lookup.blob_id=blob.id
                 JOIN main.resolution_identities AS identity
                   ON identity.id=lookup.identity_id
                 WHERE blob.blob_oid=?1 AND blob.lang='go'
                   AND identity.spelling='New'
                 ORDER BY identity.spelling",
            )?;
            statement
                .query_map([content], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .expect("read persisted Go lookup-header spellings");
    assert!(
        names.iter().any(|spelling| spelling == "New"),
        "nested `New()` needs a persisted package-reference lookup header: {names:?}"
    );
}

#[test]
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

fn persist_alias_fixture<A: LanguageAdapter>(
    store: &AnalyzerStore,
    oid: Oid,
    storage_language: &str,
    adapter: &A,
    relative_path: &str,
    source: &str,
) -> ManifestSnapshot {
    let generation = store
        .ensure_language_epoch_value(storage_language, "resolution-alias-test-v1")
        .expect("alias generation");
    let state = parsed_fixture_state(adapter, relative_path, source);
    store
        .write_parsed_blob_at_generation(oid, storage_language, generation, adapter, &state)
        .expect("persist alias fixture");
    let first = manifest_snapshot(store, oid, storage_language);
    assert_eq!(
        first.semantic_language,
        adapter.language().config_label(),
        "storage alias must retain semantic language metadata"
    );
    assert!(store.content_row_count(oid, storage_language).unwrap() > 0);
    store
        .write_parsed_blob_at_generation(oid, storage_language, generation, adapter, &state)
        .expect("repeat alias fixture persistence");
    assert_eq!(manifest_snapshot(store, oid, storage_language), first);
    assert!(store.contains_parsed_blob(oid, storage_language).unwrap());
    first
}

#[test]
fn production_writer_persists_storage_alias_metadata_digest_and_idempotence() {
    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let typescript = persist_alias_fixture(
        &store,
        oid(b"typescript tsx storage alias"),
        "typescript:tsx",
        &TypescriptAdapter,
        "src/Model.tsx",
        "export class Model { value = 1; }\n",
    );
    let cpp = persist_alias_fixture(
        &store,
        oid(b"cpp c storage alias"),
        "cpp:c",
        &CppAdapter,
        "src/model.c",
        "struct Model { int value; };\n",
    );
    assert_eq!(typescript.semantic_language, "typescript");
    assert_eq!(cpp.semantic_language, "cpp");
    assert_eq!(
        typescript.producer_epoch,
        resolution_bundle_epoch(Language::TypeScript)
    );
    assert_eq!(cpp.producer_epoch, resolution_bundle_epoch(Language::Cpp));
    assert_ne!(typescript.interior_digest, cpp.interior_digest);
}

#[test]
fn production_writer_seals_common_visibility_for_a_non_java_fragment() {
    use brokk_bifrost_core::analyzer::resolution_facts::{
        ResolutionDeclarationVisibilityFact, ResolutionSiteKind,
        ResolutionVisibilityEligibilityFact,
    };
    use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

    let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
    let generation = store
        .ensure_language_epoch_value("go", "resolution-go-visibility-test-v1")
        .expect("Go generation");
    let oid = oid(b"non-java visibility insertion");
    let mut state = parsed_fixture_state(
        &GoAdapter,
        "src/visibility.go",
        "package demo\ntype Owner struct {}\n",
    );
    // Exercise the common writer independently of Go's visibility extraction,
    // while retaining the real declaration's source identity and bridges.
    let facts = &mut Arc::make_mut(&mut state).resolution_facts;
    let declaration = facts
        .sites
        .iter()
        .find(|site| site.kind == ResolutionSiteKind::TypeDeclaration)
        .expect("parsed Go type declaration")
        .id;
    facts
        .visibility_eligibilities
        .push(ResolutionVisibilityEligibilityFact { declaration });
    facts
        .declaration_visibilities
        .push(ResolutionDeclarationVisibilityFact {
            declaration,
            visibility: DeclaredVisibility::Public,
        });
    store
        .write_parsed_blob_at_generation(oid, "go", generation, &GoAdapter, &state)
        .expect("persist Go visibility fixture");
    let counts = store.conn.execute({
        let oid = oid.to_string();
        move |conn| {
            conn.query_row(
                "SELECT interior.expected_declaration_visibility_property_count,
                        (SELECT COUNT(*) FROM resolution_declaration_visibility_properties AS property
                         WHERE property.blob_id = interior.blob_id)
                 FROM blobs AS blob
                 JOIN resolution_fragment_interiors AS interior ON interior.blob_id = blob.id
                 WHERE blob.blob_oid = ?1 AND blob.lang = 'go'",
                [oid],
                |row| {
                    Ok((
                        row.get::<_, usize>(0)?,
                        row.get::<_, usize>(1)?,
                    ))
                },
            )
            .expect("query persisted Go visibility family")
        }
    });
    assert!(counts.0 > 0, "Go fixture must publish visibility metadata");
    assert_eq!(counts.0, counts.1);
}

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
        .write_parsed_blob_at_generation(published_oid, PRIMARY, generation, &JavaAdapter, &state)
        .expect("initial production persistence");
    let expected_cost = payload_cost(&store, published_oid, PRIMARY);
    let expected_manifest = manifest_snapshot(&store, published_oid, PRIMARY);
    for corrupt in [Some(999_999usize), None] {
        rewrite_payload_cost(&store, published_oid, PRIMARY, corrupt);
        store
            .write_parsed_blob_at_generation(
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
    let expected = super::resolution::PERSISTED_RESOLUTION_TABLES
        .iter()
        .map(|name| (*name).to_owned())
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
            "expected_type_component_count",
            "resolution_type_components",
        ),
        (
            "expected_underlying_type_count",
            "resolution_underlying_types",
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
        super::resolution_manifest::BODY_MANIFEST_COLUMNS.len()
    );
    assert!(
        super::resolution_manifest::BODY_MANIFEST_COLUMNS
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

/// Declares a member under `shared_route` and calls it through a receiver, so
/// it is the one blob that holds a qualified route under the name.
const ROUTE_ISOLATING_HOLDER: &str = concat!(
    "pub struct Router;\n",
    "impl Router { pub fn shared_route(&self) -> usize { 0 } }\n",
    "pub fn hold(value: Router) -> usize { value.shared_route() }\n",
);

/// Declares a member under `shared_member` and never calls it, so it is the
/// one blob that declares a deferred member owner under the name.
const MEMBER_ISOLATING_HOLDER: &str = concat!(
    "pub struct Owner;\n",
    "impl Owner { pub fn shared_member(&self) -> usize { 0 } }\n",
);

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
    crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
        Language::Rust,
        ResolutionNamespace::Callable,
        spelling,
    )
    .name_digest()
}

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
        "pub fn use_it(thing: &Thing, absent: Absent) -> u32 {\n",
        "    Read::read(thing) + Thing::make(1).read() + absent.shared_member()\n",
        "}\n",
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
        TypedFactRelation::TypeComponentContainer => {
            answered!(visit_type_component_pages_for_containers, semantic)
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
#[test]
fn a_qualified_route_lookup_names_the_blobs_that_hold_a_route_not_those_that_mention_it() {
    let digest = shared_callable_identity("shared_route");
    let rows = [8usize, 24].map(|files| {
        let store = persist_rust_scale_workspace(files, ROUTE_ISOLATING_HOLDER, |index| {
            format!("pub struct S{index:04};\nimpl S{index:04} {{ pub fn shared_route(&self) -> usize {{ {index} }} }}\n")
        });
        (
            files,
            blobs_holding_relation(&store, TypedFactRelation::QualifiedRouteLookup, digest),
        )
    });
    // Measured here: (8 files, 1 route blob) and (24, 1). Every file declares
    // a member spelled `shared_route`, which puts the Callable lookup identity
    // in its catalog, so the file count is what these two reads opened before;
    // only the holder writes a call through a receiver, which is what makes a
    // route.
    eprintln!("qualified route lookup blobs (files, route): {rows:?}");
    assert_eq!(
        rows[0].1, rows[1].1,
        "the route relation must not grow with the workspace: {rows:?}"
    );
    assert_eq!(rows[0].1, 1, "one blob holds the route: {rows:?}");
}

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

#[path = "resolution_publication_tests.rs"]
mod selected_publication;

// This oracle discovers the persisted variable-width columns from SQLite's
// schema, independently of the production manifest family/column inventory.
fn measured_resolution_payload(store: &AnalyzerStore, oid: Oid, lang: &str) -> usize {
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
