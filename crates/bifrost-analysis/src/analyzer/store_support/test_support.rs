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
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
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
        .signature_metadata_for_unit_limited(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
            generation,
            &target,
            usize::MAX,
        )
        .unwrap();
    assert!(limited.complete, "{lang}: bounded read must complete");
    assert_eq!(limited.rows, metadata, "{lang}: bounded per-unit reader");

    assert_eq!(
        store
            .signature_metadata_for_unit(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
                generation,
                &target
            )
            .unwrap(),
        metadata,
        "{lang}: unbounded per-unit reader"
    );

    let hydrated = store
        .hydrate_file_state_with_source(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
            generation,
            adapter,
            file,
            &source,
        )
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
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
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
        .write_parsed_blob(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
            adapter,
            &parsed,
        )
        .unwrap();
    let hydrated = store
        .hydrate_file_state(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
            adapter,
            file,
        )
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
        .write_parsed_blob(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
            adapter,
            parsed.as_ref(),
        )
        .unwrap();
    let prepared_store = AnalyzerStore::open_ephemeral().unwrap();
    let prepared = AnalyzerStore::prepare_parsed_blob(
        &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
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
        .hydrate_file_state(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
            adapter,
            file,
        )
        .unwrap()
        .unwrap();
    let prepared_state = prepared_store
        .hydrate_file_state(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
            adapter,
            file,
        )
        .unwrap()
        .unwrap();
    assert_file_state_equivalent(parsed.as_ref(), &direct_state);
    assert_file_state_equivalent(parsed.as_ref(), &prepared_state);
    assert_file_state_equivalent(&direct_state, &prepared_state);
    let bulk_states = prepared_store
        .hydrate_file_states(
            &[(file.clone(), oid)],
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
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
        direct
            .content_row_count(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang))
            .unwrap(),
        prepared_store
            .content_row_count(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang))
            .unwrap()
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
        .write_parsed_blob(
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
            adapter,
            &parsed,
        )
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

    assert!(
        !store
            .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang))
            .unwrap()
    );
    assert_eq!(
        store
            .missing_parsed_blob_keys(&[brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang)])
            .unwrap(),
        vec![brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang)]
    );
    assert!(
        store
            .hydrate_file_state(
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
                adapter,
                file
            )
            .unwrap()
            .is_none()
    );
    assert!(
        !store
            .hydrate_file_states(
                &[(file.clone(), oid)],
                &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
                adapter,
                &HashMap::default()
            )
            .unwrap()
            .contains_key(file)
    );
}
#[doc(hidden)]
#[track_caller]
pub fn parse_state<A: LanguageAdapter>(adapter: &A, file: &ProjectFile) -> FileState {
    let source = file.read_to_string().unwrap();
    file_state_from_source_with_grammar(
        adapter,
        file,
        source,
        adapter.parser_language(),
        "set parser language",
        "parse file",
    )
}

#[track_caller]
fn file_state_from_source_with_grammar<A: LanguageAdapter>(
    adapter: &A,
    file: &ProjectFile,
    source: String,
    language: tree_sitter::Language,
    configure_message: &str,
    parse_message: &str,
) -> FileState {
    let mut parser = Parser::new();
    parser.set_language(&language).expect(configure_message);
    let preprocessor = adapter.preprocess(file, &source);
    if let Some(ranges) = preprocessor.as_ref().and_then(|p| p.included_ranges()) {
        parser.set_included_ranges(ranges).expect(configure_message);
    }
    let tree = parser.parse(&source, None).expect(parse_message);
    let mut parsed: ParsedFile = adapter
        .parse_file_preprocessed(file, &source, &tree, preprocessor.as_deref())
        .0;
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
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, language_key),
            prior_generation,
            adapter,
            state,
        )
        .unwrap();
    assert!(
        store
            .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                oid,
                language_key
            ))
            .unwrap()
    );

    let current_generation = store
        .ensure_language_epoch(language, &adapter.parser_language())
        .unwrap();

    assert_ne!(current_generation, prior_generation);
    assert!(
        !store
            .contains_parsed_blob(&brokk_bifrost_core::gitblob::BlobKey::unvaried(
                oid,
                language_key
            ))
            .unwrap()
    );
    assert_eq!(
        store
            .missing_parsed_blob_keys(&[brokk_bifrost_core::gitblob::BlobKey::unvaried(
                oid,
                language_key
            )])
            .unwrap(),
        vec![brokk_bifrost_core::gitblob::BlobKey::unvaried(
            oid,
            language_key
        )]
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
            &brokk_bifrost_core::gitblob::BlobKey::unvaried(oid, lang),
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
#[track_caller]
pub fn file_state_from_source<A: LanguageAdapter>(
    adapter: &A,
    file: &ProjectFile,
    source: &str,
) -> FileState {
    file_state_from_source_with_grammar(
        adapter,
        file,
        source.to_owned(),
        adapter.parser_language_for_file(file),
        "configure source fixture grammar",
        "parse source fixture",
    )
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod operation_fixture_support {
    use crate::CancellationToken;
    use crate::analyzer::resolution::{BindingFragmentId, SelectedResolutionMountOrdinal};
    use crate::analyzer::store::resolution_lexical::SelectedResolutionLexicalSource;
    use brokk_bifrost_core::analyzer::project::AsProject;

    use crate::analyzer::resolution::{
        LoweredResolutionFactsWithIdentityCatalog, LoweredSemanticRole, SelectedSemanticLocator,
    };

    use crate::analyzer::store::file_state::FileState;
    use crate::analyzer::store::resolution_operation::*;
    use crate::analyzer::store::resolution_selection::{
        SelectedResolutionContentMountRequest, SelectedResolutionLanguage,
        SelectedResolutionOverlayMask,
    };
    use crate::analyzer::store::{
        AnalyzerStore, GenerationId, Result, WorkspaceFileRow, WorkspaceId, WorkspaceSnapshotId,
        WorkspaceSnapshots,
    };
    use crate::analyzer::tree_sitter_analyzer::LanguageAdapter;
    use crate::analyzer::{Language, Project, ProjectFile, TestProject};
    use brokk_bifrost_core::analyzer::project::WorkspaceOverlayContent;
    use brokk_bifrost_core::analyzer::resolution_facts::{
        FileResolutionFacts, ResolutionIdentifierRole, ResolutionNamespace, ResolutionSiteId,
    };

    use git2::Oid;
    use rusqlite::params;

    use std::collections::BTreeSet;
    use std::path::Path;

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    #[doc(hidden)]
    pub fn persist_test_workspace_snapshot(
        store: &AnalyzerStore,
        workspace_id: &WorkspaceId,
        language: &str,
        generation: GenerationId,
        file_versions: Vec<(String, String, String)>,
    ) -> WorkspaceSnapshots {
        let writer_workspace_id = workspace_id.as_str().to_owned();
        let writer_language = language.to_owned();
        let generation_value = generation.get();
        store.conn.execute(move |conn| {
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO workspace_revisions(workspace_id, lang, generation, revision)
             VALUES(?1, ?2, ?3, 1)",
                params![writer_workspace_id, writer_language, generation_value],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO workspace_heads(workspace_id, lang, generation, revision)
             VALUES(?1, ?2, ?3, 1)",
                params![writer_workspace_id, writer_language, generation_value],
            )
            .unwrap();
            for (path, blob_oid, projection_digest) in file_versions {
                tx.execute(
                    "INSERT INTO workspace_file_versions(
                   workspace_id, lang, generation, rel_path, blob_oid,
                   projection_digest, valid_from
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1)",
                    params![
                        writer_workspace_id,
                        writer_language,
                        generation_value,
                        path,
                        blob_oid,
                        projection_digest,
                    ],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        });

        let mut snapshots = WorkspaceSnapshots::default();
        snapshots.insert(
            language.to_owned(),
            WorkspaceSnapshotId {
                workspace_id: workspace_id.clone(),
                lang: language.to_owned(),
                generation,
                revision: 1,
            },
        );
        snapshots
    }
    #[doc(hidden)]
    pub fn selected_operation_input<'project, 'selection>(
        project: &'project dyn Project,
        workspace_id: &'selection WorkspaceId,
        snapshots: &'selection WorkspaceSnapshots,
        languages: &'selection [SelectedResolutionLanguage],
        overlay_masks: &'selection [SelectedResolutionOverlayMask],
        content_mounts: Vec<SelectedResolutionContentMountRequest>,
    ) -> SelectedResolutionOperationInput<'project, 'selection> {
        SelectedResolutionOperationInput::new(
            project,
            workspace_id,
            snapshots,
            languages,
            overlay_masks,
        )
        .with_content_mounts(content_mounts)
    }
    #[doc(hidden)]
    pub fn open_ready_operation<'store, 'project, 'selection>(
        store: &'store AnalyzerStore,
        input: SelectedResolutionOperationInput<'project, 'selection>,
        cancellation: &CancellationToken,
    ) -> SelectedResolutionOperation<'store, 'project> {
        match store
            .open_selected_resolution_operation(input, cancellation)
            .expect("open selected resolution test operation")
        {
            SelectedResolutionOperationOpenOutcome::Ready(operation) => *operation,
            outcome => panic!("selected resolution test operation must be Ready: {outcome:?}"),
        }
    }
    #[doc(hidden)]
    pub fn content_mount_request(
        publication: crate::analyzer::store::resolution_publication::ResolutionContentWitness,
        path: &str,
        blob_oid: Oid,
    ) -> SelectedResolutionContentMountRequest {
        SelectedResolutionContentMountRequest::new(
            publication,
            WorkspaceFileRow {
                rel_path: path.to_owned(),
                blob_oid,
            },
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
    #[doc(hidden)]
    pub fn counterfactual_content_mount(
        content: SelectedResolutionContentMountRequest,
        original: &str,
    ) -> SelectedResolutionContentMountRequest {
        content.with_counterfactual_base_content_digest(
            brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(original.as_bytes()),
        )
    }
    #[derive(Clone)]
    #[doc(hidden)]
    pub struct MutableGenerationProject {
        project_reads: brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot,
        delegate: TestProject,
        generation: Arc<AtomicU64>,
        overlay_content: Arc<Mutex<Option<Arc<WorkspaceOverlayContent>>>>,
    }
    impl MutableGenerationProject {
        #[doc(hidden)]
        pub fn new(root: &Path, language: Language) -> Self {
            Self {
                delegate: TestProject::new(root, language),
                project_reads:
                    brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot::default(),
                generation: Arc::new(AtomicU64::new(0)),
                overlay_content: Arc::new(Mutex::new(None)),
            }
        }

        #[doc(hidden)]
        pub fn generation_handle(&self) -> Arc<AtomicU64> {
            Arc::clone(&self.generation)
        }

        #[doc(hidden)]
        pub fn advance(&self) {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }

        #[doc(hidden)]
        pub fn set_overlay_content(&self, file: ProjectFile, content: &str) {
            let digest =
                brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(content.as_bytes());
            let overlay = Arc::new(WorkspaceOverlayContent::new([(
                file,
                digest,
                git2::Oid::hash_object(git2::ObjectType::Blob, content.as_bytes())
                    .expect("hashing installed fixture overlay"),
            )]));
            *self
                .overlay_content
                .lock()
                .expect("operation test overlay lock") = Some(overlay);
        }
    }
    impl Project for MutableGenerationProject {
        fn project_read_slot(
            &self,
        ) -> Option<&brokk_bifrost_core::analyzer::project_reads::ProjectReadSlot> {
            Some(&self.project_reads)
        }
        fn install_read_recorder(
            &self,
            capability: brokk_bifrost_core::analyzer::project_reads::ReadCapability,
        ) -> bool {
            self.delegate.install_read_recorder(capability.clone());
            self.project_reads.install(capability);
            true
        }
        fn ignore_rules_digest(&self) -> std::io::Result<[u8; 32]> {
            let _read = self.project_reads.ignore_rules(self.as_project());
            self.delegate.ignore_rules_digest()
        }

        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.project_reads
                .languages(self.as_project(), || self.delegate.analyzer_languages())
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            let _project_read = self.project_reads.inventory(self.as_project());
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            let _project_read = brokk_bifrost_core::analyzer::project_reads::listing_read(self);
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            let _project_read = self.project_reads.path(self.as_project(), rel_path);
            self.delegate.file_by_rel_path(rel_path)
        }

        fn analysis_generation(&self) -> u64 {
            self.generation.load(Ordering::SeqCst)
        }

        fn overlay_content(&self) -> Option<Arc<WorkspaceOverlayContent>> {
            let _project_read = self.project_reads.overlays(self.as_project());
            let answer = {
                self.overlay_content
                    .lock()
                    .expect("operation test overlay lock")
                    .clone()
            };
            brokk_bifrost_core::analyzer::project_reads::publish_overlays(&answer);
            answer
        }
    }
    #[doc(hidden)]
    pub fn parsed_operation_state<A: LanguageAdapter>(
        project_root: &Path,
        relative_path: &str,
        source: &str,
        adapter: &A,
    ) -> (Arc<FileState>, FileResolutionFacts) {
        let file = ProjectFile::new(project_root.to_path_buf(), relative_path);
        file.write(source).expect("write operation source");
        parsed_operation_source_state(project_root, relative_path, source, adapter)
    }
    /// Parse unsaved content without replacing the selected disk baseline.
    #[doc(hidden)]
    pub fn parsed_operation_source_state<A: LanguageAdapter>(
        project_root: &Path,
        relative_path: &str,
        source: &str,
        adapter: &A,
    ) -> (Arc<FileState>, FileResolutionFacts) {
        let file = ProjectFile::new(project_root.to_path_buf(), relative_path);
        let state = Arc::new(super::file_state_from_source(adapter, &file, source));
        let facts = state.resolution_facts.clone();
        (state, facts)
    }
    #[doc(hidden)]
    pub fn site_for_identifier(
        facts: &FileResolutionFacts,
        spelling: &str,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> ResolutionSiteId {
        try_site_for_identifier(facts, spelling, role, namespace)
            .unwrap_or_else(|| panic!("fixture identifier {role:?} {namespace:?} {spelling:?}"))
    }
    #[doc(hidden)]
    pub fn try_site_for_identifier(
        facts: &FileResolutionFacts,
        spelling: &str,
        role: ResolutionIdentifierRole,
        namespace: ResolutionNamespace,
    ) -> Option<ResolutionSiteId> {
        facts
            .identifiers_named(spelling, role, namespace)
            .into_iter()
            .next()
            .map(|identifier| identifier.site)
    }
    #[doc(hidden)]
    pub fn locator(
        path: &str,
        site: ResolutionSiteId,
        role: LoweredSemanticRole,
    ) -> SelectedSemanticLocator {
        SelectedSemanticLocator::new("java", path, site, role)
    }
    #[doc(hidden)]
    pub fn semantic_at(
        artifact: &LoweredResolutionFactsWithIdentityCatalog,
        site: ResolutionSiteId,
        role: LoweredSemanticRole,
    ) -> crate::analyzer::resolution::SemanticId {
        crate::analyzer::resolution::test_support::lowered_semantic_at(
            artifact.lexical().semantics(),
            site,
            role,
        )
    }
    /// The mount coverage lookup a test operation's context set is built against.
    #[doc(hidden)]
    pub fn mount_lookup(
        mounts: &[SelectedResolutionOperationMount],
    ) -> impl Fn(BindingFragmentId) -> Result<Option<(SelectedResolutionMountOrdinal, Language)>> + '_
    {
        |fragment| {
            Ok(mounts
                .iter()
                .find(|mount| mount.fragment() == fragment)
                .map(|mount| (mount.ordinal(), mount.semantic_language())))
        }
    }
    #[doc(hidden)]
    pub fn assert_store_error_contains<T>(result: Result<T>, needle: &str) {
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("expected store error containing {needle:?}"),
        };
        assert!(
            error.to_string().contains(needle),
            "unexpected store error: {error}"
        );
    }
    #[doc(hidden)]
    pub fn with_operation_lexical<T>(
        operation: &SelectedResolutionOperation<'_, '_>,
        inspect: impl FnOnce(
            &SelectedResolutionLexicalSource<'_, '_>,
            &SelectedResolutionLexicalSource<'_, '_>,
        ) -> T,
    ) -> T {
        let source = operation.ready.lexical_source();
        inspect(&source, &source)
    }

    #[doc(hidden)]
    pub fn assert_empty_context_metrics(metrics: &SelectedResolutionContextMetrics) {
        assert_eq!(metrics, &SelectedResolutionContextMetrics);
    }
}

#[cfg(test)]
mod overlay_input_tests {
    use super::operation_fixture_support::MutableGenerationProject;
    use crate::analyzer::{Language, MultiAnalyzer, Project, ProjectFile, capture_query_reads};

    #[test]
    fn overlay_content_only_projects_explicit_fixture_inputs() {
        let root = std::env::temp_dir();
        let project = MutableGenerationProject::new(&root, Language::Rust);
        let file = ProjectFile::new(&root, "input.rs");
        project.set_overlay_content(file.clone(), "first");
        let before = project.overlay_content().unwrap();
        let analyzer = MultiAnalyzer::default();
        let (_, reads) = capture_query_reads(&analyzer, || {
            assert_eq!(
                project.overlay_content().unwrap().entries(),
                before.entries()
            );
            project.set_overlay_content(file, "second");
            assert_ne!(
                project.overlay_content().unwrap().entries(),
                before.entries()
            );
        });
        assert!(reads.keys().is_empty());
    }
}
