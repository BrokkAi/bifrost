use crate::analyzer::store::file_state::FileState;
pub use crate::analyzer::store::test_blob_oid as oid_for;
use crate::analyzer::store::*;
use crate::analyzer::store_bridge::AnalyzerStoreEngineExt;
use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
use crate::analyzer::tree_sitter_analyzer::ParsedFile;
use crate::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;
use crate::analyzer::{ProjectFile, SignatureMetadata};
use crate::hash::HashMap;
use brokk_bifrost_core::cache_db::OPTIONAL_FACT_KIND_SIGNATURE_METADATA_SIGNATURE;
pub use brokk_bifrost_store::analyzer::store::test_support::*;
use rusqlite::params;
use std::sync::Arc;
use tree_sitter::Parser;
#[doc(hidden)]
/// Write `metadata` as the signature rows of one unit of `file`, then read
/// them back through every reader the store has.
///
/// The queries decode this table positionally from one shared column
/// list, so a round trip that exercises only one does not cover the
/// other readers.
pub fn assert_signature_metadata_round_trips<A: LanguageAdapter>(
    adapter: &A,
    lang: &str,
    file: &ProjectFile,
    metadata: &[SignatureMetadata],
) {
    let source = file.read_to_string().unwrap();
    let oid = oid_for(source.as_bytes());
    let mut state = parse_state(adapter, file);
    let target = state
        .signature_metadata
        .iter()
        .find(|(_, entries)| !entries.is_empty())
        .map(|(unit, _)| unit.clone())
        .expect("fixture should produce signature metadata");
    let mut projected_metadata = metadata.to_vec();
    if let Some(shape) = state.signature_metadata[&target][0].java_type_constructor_shape() {
        for alternative in &mut projected_metadata {
            *alternative = alternative.clone().with_java_type_constructor_shape(shape);
        }
    }
    if adapter.declaration_visibility_facts_version().is_some() {
        let link = state
            .source_declaration_metadata
            .iter()
            .find(|link| link.unit == target)
            .expect("actual Java metadata has a canonical declaration link")
            .clone();
        let visibility = state
            .source_facts
            .as_ref()
            .unwrap()
            .declaration_visibilities
            .as_ref()
            .unwrap()
            .iter()
            .find(|fact| fact.declaration == link.declaration)
            .unwrap()
            .visibility;
        for alternative in &mut projected_metadata {
            *alternative = alternative
                .clone()
                .with_source_declared_visibility(visibility);
        }
    }
    replace_test_metadata_bridges(&mut state, &target, metadata.len());
    state
        .source_declaration_metadata
        .retain(|link| link.unit == target);
    let metadata = projected_metadata.as_slice();
    let signatures = state
        .signatures
        .get_mut(&target)
        .expect("metadata target should have a signature");
    signatures.clear();
    signatures.extend([
        metadata[2].label().to_string(),
        metadata[0].label().to_string(),
    ]);
    state.signature_metadata.clear();
    state.signature_metadata_signature_ordinals.clear();
    state
        .signature_metadata
        .insert(target.clone(), metadata.to_vec());
    assert_eq!(
        metadata.len(),
        3,
        "pair test needs three metadata alternatives"
    );
    let expected_pairs = (0..metadata.len())
        .map(|ordinal| match ordinal {
            0 | 1 => 1,
            _ => 0,
        })
        .collect::<Vec<_>>();
    state
        .signature_metadata_signature_ordinals
        .insert(target.clone(), expected_pairs.clone());
    let state = Arc::new(state);

    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store
        .ensure_language_epoch_value(lang, "signature-metadata-round-trip")
        .unwrap();
    store
        .write_parsed_blob_at_generation(
            &crate::analyzer::store::test_blob_file(),
            oid,
            lang,
            generation,
            adapter,
            state.as_ref(),
        )
        .unwrap();
    let conn = store.read_conn().unwrap();
    let pair_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM unit_signature_metadata_signatures
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
            params![oid.to_string(), lang],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pair_count, i64::try_from(metadata.len()).unwrap());
    let manifest_count: i64 = conn
        .query_row(
            "SELECT row_count FROM blob_optional_fact_manifest
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)
                   AND fact_kind = ?3",
            params![
                oid.to_string(),
                lang,
                OPTIONAL_FACT_KIND_SIGNATURE_METADATA_SIGNATURE
            ],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(manifest_count, pair_count);
    drop(conn);

    let limited = store
        .signature_metadata_for_unit_limited(oid, lang, generation, &target, usize::MAX)
        .unwrap();
    assert!(limited.complete, "{lang}: bounded read must complete");
    assert_eq!(limited.rows, metadata, "{lang}: bounded per-unit reader");

    assert_eq!(
        store
            .signature_metadata_for_unit(oid, lang, generation, &target)
            .unwrap(),
        metadata,
        "{lang}: unbounded per-unit reader"
    );

    let hydrated = store
        .hydrate_file_state_with_source(oid, lang, generation, adapter, file, &source)
        .unwrap()
        .expect("single-file hydration");
    assert_eq!(
        hydrated.signature_metadata.get(&target).map(Vec::as_slice),
        Some(metadata),
        "{lang}: single-file hydration reader"
    );
    assert_eq!(
        hydrated
            .signature_metadata_signature_ordinals
            .get(&target)
            .map(Vec::as_slice),
        Some(expected_pairs.as_slice()),
        "{lang}: single-file metadata/signature pair reader"
    );

    let bulk = store
        .hydrate_file_states(
            &[(file.clone(), oid)],
            lang,
            adapter,
            &HashMap::from_iter([(file.clone(), source.clone())]),
        )
        .unwrap();
    assert_eq!(
        bulk.get(file)
            .expect("bulk hydration")
            .signature_metadata
            .get(&target)
            .map(Vec::as_slice),
        Some(metadata),
        "{lang}: bulk hydration reader"
    );
    assert_eq!(
        bulk.get(file)
            .expect("bulk hydration")
            .signature_metadata_signature_ordinals
            .get(&target)
            .map(Vec::as_slice),
        Some(expected_pairs.as_slice()),
        "{lang}: bulk metadata/signature pair reader"
    );

    // The usage-fact projection selects the first metadata row paired with
    // signature ordinal zero, and only for units in declarations.
    let usage_row = store
        .usage_fact_rows_by_lang(lang)
        .unwrap()
        .into_iter()
        .find(|row| row.candidate.short_name == target.short_name())
        .expect("usage-fact row for the target unit");
    let first_signature_metadata_ordinal = expected_pairs
        .iter()
        .position(|&signature_ordinal| signature_ordinal == 0)
        .expect("fixture should pair the first signature");
    assert_eq!(
        usage_row.signature_metadata.as_ref(),
        metadata.get(first_signature_metadata_ordinal),
        "{lang}: usage-fact projection reader"
    );
}
#[doc(hidden)]
pub fn assert_round_trip<A: LanguageAdapter>(adapter: &A, lang: &str, file: &ProjectFile) {
    let source = file.read_to_string().unwrap();
    let oid = oid_for(source.as_bytes());
    let parsed = parse_state(adapter, file);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, lang, adapter, &parsed)
        .unwrap();
    let hydrated = store
        .hydrate_file_state(oid, lang, adapter, file)
        .unwrap()
        .unwrap();
    assert_file_state_equivalent(&parsed, &hydrated);
    assert!(hydrated.source.is_empty());
    assert!(hydrated.parse_errors.is_none());
}
#[doc(hidden)]
pub fn assert_direct_prepared_parity<A: LanguageAdapter>(
    adapter: &A,
    lang: &str,
    file: &ProjectFile,
) {
    let source = file.read_to_string().unwrap();
    let oid = oid_for(source.as_bytes());
    let parsed = Arc::new(parse_state(adapter, file));
    let direct = AnalyzerStore::open_ephemeral().unwrap();
    direct
        .write_parsed_blob(oid, lang, adapter, parsed.as_ref())
        .unwrap();
    let prepared_store = AnalyzerStore::open_ephemeral().unwrap();
    let prepared = AnalyzerStore::prepare_parsed_blob(
        oid,
        lang,
        GenerationId::BOOTSTRAP,
        adapter,
        Arc::clone(&parsed),
    )
    .unwrap();
    let (outcomes, stats) =
        prepared_store.persist_prepared_blobs(vec![prepared], PersistBatchTargets::PRODUCTION);
    assert_eq!(stats.transactions, 1);
    assert_eq!(stats.committed_blobs, 1);
    assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));

    let direct_state = direct
        .hydrate_file_state(oid, lang, adapter, file)
        .unwrap()
        .unwrap();
    let prepared_state = prepared_store
        .hydrate_file_state(oid, lang, adapter, file)
        .unwrap()
        .unwrap();
    assert_file_state_equivalent(parsed.as_ref(), &direct_state);
    assert_file_state_equivalent(parsed.as_ref(), &prepared_state);
    assert_file_state_equivalent(&direct_state, &prepared_state);
    let bulk_states = prepared_store
        .hydrate_file_states(
            &[(file.clone(), oid)],
            lang,
            adapter,
            &HashMap::from_iter([(file.clone(), source)]),
        )
        .unwrap();
    assert_eq!(
        bulk_states
            .get(file)
            .expect("prepared blob should bulk hydrate")
            .scala_exports,
        parsed.scala_exports
    );
    assert_eq!(
        direct.content_row_count(oid, lang).unwrap(),
        prepared_store.content_row_count(oid, lang).unwrap()
    );
}
#[doc(hidden)]
pub fn assert_deleting_side_table_marks_incomplete<A: LanguageAdapter>(
    adapter: &A,
    lang: &str,
    file: &ProjectFile,
    table: &str,
) {
    let source = file.read_to_string().unwrap();
    let oid = oid_for(source.as_bytes());
    let parsed = parse_state(adapter, file);
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, lang, adapter, &parsed)
        .unwrap();

    {
        let conn = store.conn.lock().unwrap();
        let count_sql = format!(
            "SELECT COUNT(*) FROM {table} WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)"
        );
        let count: usize = conn
            .query_row(&count_sql, params![oid.to_string(), lang], |row| row.get(0))
            .unwrap();
        assert!(
            count > 0,
            "fixture should persist at least one {table} row for {lang}"
        );
        let delete_sql = format!(
            "DELETE FROM {table} WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)"
        );
        let corruption_setup = match table {
            "import_statements" => {
                Some("DROP TRIGGER import_statements_no_delete_after_source_seal;")
            }
            "unit_cpp_class_templates" => Some(
                "DROP TRIGGER unit_cpp_class_templates_no_delete_after_seal;
                     DROP TRIGGER unit_cpp_class_template_parameters_no_delete_after_seal;
                     DROP TRIGGER unit_cpp_class_template_alias_components_no_delete_after_seal;
                     DROP TRIGGER unit_cpp_class_template_expressions_no_delete_after_seal;
                     DROP TRIGGER unit_cpp_class_template_terms_no_delete_after_seal;",
            ),
            "unit_signatures" => Some(
                "DROP TRIGGER unit_signatures_no_delete_after_pair_seal;
                     DROP TRIGGER unit_signature_metadata_signatures_no_delete_after_seal;",
            ),
            "unit_signature_metadata" => Some(
                "DROP TRIGGER unit_signature_metadata_no_delete_after_pair_seal;
                     DROP TRIGGER unit_signature_metadata_signatures_no_delete_after_seal;
                     DROP TRIGGER unit_signature_parameters_no_delete_after_seal;
                     DROP TRIGGER source_declaration_metadata_bridges_no_delete_after_seal;",
            ),
            "unit_signature_metadata_signatures" => {
                Some("DROP TRIGGER unit_signature_metadata_signatures_no_delete_after_seal;")
            }
            _ => None,
        };
        if let Some(corruption_setup) = corruption_setup {
            assert!(
                conn.execute(&delete_sql, params![oid.to_string(), lang])
                    .is_err()
            );
            // Bypass only the tested immutability guards to model external
            // cache damage, then exercise the independent read validation.
            conn.execute_batch(corruption_setup).unwrap();
        }
        if table == "unit_signature_metadata" {
            // Metadata bridges have a deferred NO ACTION foreign key, so
            // remove those links before damaging their referenced rows.
            conn.execute(
                "DELETE FROM source_declaration_metadata_bridges
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)",
                params![oid.to_string(), lang],
            )
            .unwrap();
        }
        conn.execute(&delete_sql, params![oid.to_string(), lang])
            .unwrap_or_else(|error| panic!("injecting {table} corruption for {lang}: {error}"));
    }

    assert!(!store.contains_parsed_blob(oid, lang).unwrap());
    assert_eq!(
        store
            .missing_parsed_blob_keys(&[(oid, lang.to_string())])
            .unwrap(),
        vec![(oid, lang.to_string())]
    );
    assert!(
        store
            .hydrate_file_state(oid, lang, adapter, file)
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .hydrate_file_states(&[(file.clone(), oid)], lang, adapter, &HashMap::default())
            .unwrap()
            .contains_key(file)
    );
}
#[doc(hidden)]
pub fn parse_state<A: LanguageAdapter>(adapter: &A, file: &ProjectFile) -> FileState {
    let source = file.read_to_string().unwrap();
    let mut parser = Parser::new();
    parser
        .set_language(&adapter.parser_language())
        .expect("set parser language");
    let tree = parser.parse(source.as_str(), None).expect("parse file");
    let mut parsed: ParsedFile = adapter.parse_file(file, &source, &tree);
    parsed.add_file_scope(file, &source);
    let contains_tests = adapter.contains_tests(file, &source, &tree, &parsed);
    TreeSitterAnalyzer::<A>::file_state_from_parsed(
        source,
        parsed,
        contains_tests,
        Some(Vec::new()),
        true,
    )
}
#[doc(hidden)]
pub fn assert_prior_parsed_blob_invalidated<A: LanguageAdapter>(
    adapter: &A,
    state: &FileState,
    prior_epoch: &str,
) {
    let language = adapter.language();
    let language_key = language.config_label();
    let oid = oid_for(state.source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let prior_generation = store
        .ensure_language_epoch_value(language_key, prior_epoch)
        .unwrap();
    store
        .write_parsed_blob_at_generation(
            &crate::analyzer::store::test_blob_file(),
            oid,
            language_key,
            prior_generation,
            adapter,
            state,
        )
        .unwrap();
    assert!(store.contains_parsed_blob(oid, language_key).unwrap());

    let current_generation = store
        .ensure_language_epoch(language, &adapter.parser_language())
        .unwrap();

    assert_ne!(current_generation, prior_generation);
    assert!(!store.contains_parsed_blob(oid, language_key).unwrap());
    assert_eq!(
        store
            .missing_parsed_blob_keys(&[(oid, language_key.to_string())])
            .unwrap(),
        vec![(oid, language_key.to_string())]
    );
}
#[doc(hidden)]
/// Every `short_name` the store holds for one parsed blob.
pub fn persisted_short_names<A: LanguageAdapter>(
    adapter: &A,
    lang: &str,
    file: &ProjectFile,
) -> Vec<String> {
    let state = parse_state(adapter, file);
    let oid = oid_for(state.source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store
        .ensure_language_epoch_value(lang, "short-name-vocabulary-pin-v1")
        .unwrap();
    store
        .write_parsed_blob_at_generation(
            &crate::analyzer::store::test_blob_file(),
            oid,
            lang,
            generation,
            adapter,
            &state,
        )
        .unwrap();
    let conn = store.conn.lock().unwrap();
    let mut statement = conn
            .prepare("SELECT short_name FROM code_units WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)")
            .unwrap();
    let names: Vec<String> = statement
        .query_map(params![oid.to_string(), lang], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<String>>>()
        .unwrap();
    assert!(
        !names.is_empty(),
        "the {lang} fixture must persist declarations for the pin to mean anything"
    );
    names
}
