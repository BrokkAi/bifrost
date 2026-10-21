pub use super::test_blob_oid as oid_for;
use crate::analyzer::store_bridge::AnalyzerStoreEngineExt;

use super::*;

use crate::analyzer::model::StructuredTypeIdentityBuilder;

use crate::analyzer::model::StructuredTypeName;

use crate::analyzer::tree_sitter_analyzer::ParsedFile;

use crate::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

use tree_sitter::Parser;

#[doc(hidden)]
pub fn blob_id(conn: &Connection, oid: Oid) -> i64 {
    conn.query_row(
        "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
        [oid.to_string()],
        |row| row.get(0),
    )
    .expect("published Rust blob id")
}

/// One `SignatureMetadata` with every field carrying a non-default value.
///
/// The round-trip test below is only as strong as this value is complete:
/// a field that stays at its default here would round-trip through a
/// column that the encoder never writes and the decoder never reads.
#[doc(hidden)]
pub fn fully_populated_signature_metadata() -> SignatureMetadata {
    let named = |path: &str| {
        StructuredTypeName::new(vec![path.to_string()], vec!["outer".to_string()], true)
            .expect("structured type name")
    };
    let mut builder = StructuredTypeIdentityBuilder::default();
    let key = builder.named(named("String")).unwrap();
    let value = builder.named(named("Widget")).unwrap();
    let map = builder.map(key, value).unwrap();
    let base = builder.named(named("Registry")).unwrap();
    let generic = builder.generic(base, vec![map]).unwrap();
    let return_type_identity = builder.finish(generic).expect("return identity");

    let mut underlying = StructuredTypeIdentityBuilder::default();
    let element = underlying.named(named("Operation")).unwrap();
    let pointer = underlying.pointer(element).unwrap();
    let array = underlying.array(pointer).unwrap();
    let underlying_type_identity = underlying.finish(array).expect("underlying identity");

    let mut receiver = StructuredTypeIdentityBuilder::default();
    let receiver_named = receiver.named(named("Receiver")).unwrap();
    let receiver_slice = receiver.slice(receiver_named).unwrap();
    let extension_receiver_type_identity = receiver.finish(receiver_slice).expect("receiver");

    // Two declared results, so the round trip pins the positional column
    // rather than only the single `return_type_identity` beside it. A
    // reader that dropped this column would still decode every other
    // field, which is exactly how it went unnoticed the first time.
    let mut first_result = StructuredTypeIdentityBuilder::default();
    let first_named = first_result.named(named("Tx")).unwrap();
    let first_pointer = first_result.pointer(first_named).unwrap();
    let first_result_identity = first_result.finish(first_pointer).expect("first result");
    let mut second_result = StructuredTypeIdentityBuilder::default();
    let second_named = second_result.named(named("error")).unwrap();
    let second_result_identity = second_result.finish(second_named).expect("second result");

    SignatureMetadata::new(
        "fn build(first: String, second: Widget) -> Registry<Map<String, Widget>>",
        vec![
            ParameterMetadata::new("first: String", 9, 22).with_name("first"),
            ParameterMetadata::new("second: Widget", 24, 38).with_name("second"),
        ],
    )
    .with_return_type_text(Some("Registry<Map<String, Widget>>"))
    .with_return_type_identity(Some(return_type_identity))
    .with_parameter_type_identities(vec![Some(first_result_identity.clone()), None])
    .with_result_type_identities(vec![first_result_identity, second_result_identity])
    .with_callable_override_modifier(CallableOverrideModifier::Override)
    .with_underlying_type_identity(Some(underlying_type_identity))
    .with_declaration_only(true)
    .with_callable_arity(CallableArity::new(2, 3, true))
    // The recorded builder, so the round trip pins the flag column beside
    // the list. `bare` beside this row is the unrecorded reading, which is
    // what a row written before #1651 reads back as.
    .with_recorded_type_parameters(vec!["T".to_string(), "U".to_string()])
    .with_bare_return_type_parameter(Some("T"))
    .with_callable_linkage(CallableLinkage::External)
    .with_dispatch_extensibility(DispatchExtensibility::Closed)
    .with_extension_receiver_type(Some("Receiver"))
    .with_extension_receiver_type_identity(Some(extension_receiver_type_identity))
    .with_extension_receiver_is_unconstrained_type_parameter(true)
    .with_field_modifiers(true, true)
    .with_field_initializer(true)
    .with_cpp_field_linkage(CppFieldLinkage::InternalUnlessExternalPeer)
    .with_companion_object(true)
    .with_callable_modifiers(true, true, DeclaredVisibility::PackagePrivate)
    .with_callable_parameter_types(vec!["String".to_string(), "Widget".to_string()])
    .with_callable_native(true)
    .with_class_like_kind(brokk_bifrost_core::analyzer::model::ClassLikeKind::Interface)
    .with_class_like_static(true)
}

#[doc(hidden)]
pub fn replace_test_metadata_bridges(state: &mut FileState, target: &CodeUnit, count: usize) {
    let original = state
        .source_declaration_metadata
        .iter()
        .filter(|link| link.unit == *target && link.metadata_ordinal == 0)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        !original.is_empty(),
        "fixture metadata needs source declarations"
    );
    state
        .source_declaration_metadata
        .retain(|link| link.unit != *target);
    for link in original {
        state
            .source_declaration_metadata
            .extend((0..count).map(|metadata_ordinal| {
                let mut alternative = link.clone();
                alternative.metadata_ordinal = metadata_ordinal;
                alternative
            }));
    }
}

/// Write `metadata` as the signature rows of one unit of `file`, then read
/// them back through every reader the store has.
///
/// The queries decode this table positionally from one shared column
/// list, so a round trip that exercises only one does not cover the
/// other readers.
#[doc(hidden)]
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
pub fn assert_file_state_equivalent(expected: &FileState, actual: &FileState) {
    assert_eq!(actual.package_name, expected.package_name);
    assert_eq!(actual.completeness, expected.completeness);
    assert_eq!(
        actual.top_level_declarations,
        expected.top_level_declarations
    );
    assert_eq!(actual.declarations, expected.declarations);
    assert_eq!(actual.scala_exports, expected.scala_exports);
    assert_eq!(
        actual.definition_lookup_units,
        expected.definition_lookup_units
    );
    assert_eq!(actual.imports, expected.imports);
    assert_eq!(
        non_empty_vec_entries(&actual.raw_supertypes),
        non_empty_vec_entries(&expected.raw_supertypes)
    );
    assert_eq!(
        non_empty_vec_entries(&actual.supertype_lookup_paths),
        non_empty_vec_entries(&expected.supertype_lookup_paths)
    );
    assert_eq!(actual.type_identifiers, expected.type_identifiers);
    assert_eq!(actual.signatures, expected.signatures);
    assert_eq!(actual.signature_metadata, expected.signature_metadata);
    assert_eq!(
        actual.signature_metadata_signature_ordinals,
        expected.signature_metadata_signature_ordinals
    );
    assert_eq!(
        actual.materialization_records,
        expected.materialization_records
    );
    assert_eq!(actual.cpp_template_metadata, expected.cpp_template_metadata);
    assert_eq!(actual.ranges, expected.ranges);
    assert_eq!(
        non_empty_vec_entries(&actual.children),
        non_empty_vec_entries(&expected.children)
    );
    assert_eq!(actual.type_aliases, expected.type_aliases);
    assert_eq!(
        actual.ruby_method_dispatch_modes,
        expected.ruby_method_dispatch_modes
    );
    assert_eq!(actual.scala_traits, expected.scala_traits);
    assert_eq!(actual.contains_tests, expected.contains_tests);
    assert_eq!(actual.test_region_units, expected.test_region_units);
    assert!(actual.source.is_empty());
    assert!(actual.parse_errors.is_none());
}

#[doc(hidden)]
pub fn non_empty_vec_entries<T: Clone>(
    map: &HashMap<CodeUnit, Vec<T>>,
) -> HashMap<CodeUnit, Vec<T>> {
    map.iter()
        .filter(|(_, values)| !values.is_empty())
        .map(|(unit, values)| (unit.clone(), values.clone()))
        .collect()
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

/// Every `short_name` the store holds for one parsed blob.
#[doc(hidden)]
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

#[doc(hidden)]
pub fn assert_rust_source_read_cancellation_retries<T>(
    mut read: impl FnMut(&dyn Fn() -> bool) -> Option<T>,
    minimum_checkpoints: usize,
    check_retry: impl FnOnce(&T, &T),
) {
    let checks = std::cell::Cell::new(0usize);
    let complete = read(&|| {
        checks.set(checks.get() + 1);
        true
    })
    .expect("complete Rust source-fact read");
    let total_checks = checks.get();
    assert!(
        total_checks > minimum_checkpoints,
        "Rust source-fact read had too few checkpoints: {total_checks}"
    );

    let cancelled_checks = std::cell::Cell::new(0usize);
    assert!(
        read(&|| {
            cancelled_checks.set(cancelled_checks.get() + 1);
            cancelled_checks.get() < total_checks
        })
        .is_none(),
        "cancelled Rust source-fact read returned partial rows"
    );
    assert!(
        cancelled_checks.get() >= total_checks,
        "cancelled Rust source-fact read skipped checkpoints"
    );

    let retried = read(&|| true).expect("retry Rust source-fact read");
    check_retry(&complete, &retried);
}
