#[cfg(test)]
mod rust_departing_tests_tests {

    use brokk_bifrost_analysis::analyzer::store::ActiveSearchBlob;

    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;

    use std::sync::Arc;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

    use brokk_bifrost_analysis::analyzer::store::GenerationId;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

    use git2::Oid;

    use brokk_bifrost_core::analyzer::model::PackageAnchor;

    use std::path::Path;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::store::RelationalUnitFq;

    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId;

    use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;

    use brokk_bifrost_analysis::analyzer::store::Result;

    use brokk_bifrost_core::analyzer::rust_facts::RustUsageFacts;

    use brokk_bifrost_core::analyzer::rust_facts::RustVisibility;

    use brokk_bifrost_analysis::analyzer::store::SEARCH_CANDIDATE_KEY_BATCH_SIZE;

    use brokk_bifrost_analysis::analyzer::store::SearchCandidateKey;

    use brokk_bifrost_core::analyzer::model::StructuredImportPathKind;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceAnchorRow;

    use brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow;

    use brokk_bifrost_analysis::analyzer::store::candidate_rows_for_identifier_languages_limited;

    use brokk_bifrost_analysis::analyzer::store::chunk_params;

    use brokk_bifrost_analysis::analyzer::store::chunk_placeholders;

    use brokk_bifrost_core::analyzer::rust_facts::encode_rust_cfg_condition;

    use brokk_bifrost_core::analyzer::rust_facts::encode_rust_visibility;

    use brokk_bifrost_analysis::analyzer::store::epoch;

    use brokk_bifrost_analysis::analyzer::store::hydrate_unit_fq;

    use brokk_bifrost_analysis::analyzer::store::import_infos_bulk_sql;

    use brokk_bifrost_analysis::analyzer::store::import_path_children_sql;

    use brokk_bifrost_analysis::analyzer::store::limited_identifier_candidate_sql;

    use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

    use rusqlite::params;

    use rusqlite::params_from_iter;

    use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

    use brokk_bifrost_analysis::analyzer::store::persisted_unit_fq;

    use brokk_bifrost_analysis::analyzer::store::read_import_infos;

    use brokk_bifrost_analysis::analyzer::store::read_import_infos_bulk;

    use brokk_bifrost_analysis::analyzer::store::read_rust_usage_facts;

    use brokk_bifrost_analysis::analyzer::store::read_rust_usage_facts_bulk;

    use brokk_bifrost_analysis::analyzer::store::read_rust_usage_facts_bulk_with_session;

    use brokk_bifrost_analysis::analyzer::store::read_unit_rows_while;

    use brokk_bifrost_analysis::analyzer::store::rust_import_module_segments_sql;

    use brokk_bifrost_analysis::analyzer::store::rust_import_targets_sql;

    use brokk_bifrost_core::analyzer::fq_name::segment_interner;

    use brokk_bifrost_analysis::analyzer::store::segment_kind_sql;

    use brokk_bifrost_analysis::analyzer::store::source_facts;

    use brokk_bifrost_analysis::analyzer::store::test_support::assert_prior_parsed_blob_invalidated;

    use brokk_bifrost_core::test_support::write_file;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;
    #[test]
    fn explicit_root_rust_unit_persists_full_identity_despite_empty_qualifier() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/tools/clippy/tests/ui/from_over_into.rs",
            "struct ExplicitPaths;\n",
        );
        let unit = CodeUnit::with_signature(
            file.clone(),
            CodeUnitType::Function,
            "",
            "ExplicitPaths.into",
            Some(
                "impl core::convert::Into<bool> for crate::ExplicitPaths::fn into(self) -> bool { ... }"
                    .to_string(),
            ),
            false,
        );
        let adapter = RustAdapter;
        let content_qualifier = adapter.storage_content_qualifier(&unit, "");

        assert!(content_qualifier.is_empty());
        let persisted = persisted_unit_fq(&adapter, &unit, &content_qualifier).unwrap();
        assert_eq!(persisted.anchor, None);
        let interner = segment_interner();
        let segments = persisted
            .tail
            .segments()
            .iter()
            .map(|&id| {
                let (text, kind) = interner.resolve(id);
                (kind, text.to_string())
            })
            .collect::<Vec<_>>();
        let relational = RelationalUnitFq::new(
            persisted.anchor,
            persisted.package_tail_segments,
            persisted.tail.len(),
            segments
                .iter()
                .map(|(kind, segment)| segment_kind_sql(*kind).len() + segment.len())
                .sum(),
            segments,
        );
        let (hydrated_fq, hydrated_package_segment_count) =
            hydrate_unit_fq(&adapter, Some(&relational), &content_qualifier, &file).unwrap();
        assert_eq!(hydrated_fq, unit.fq().clone());
        assert_eq!(hydrated_package_segment_count, 0);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#4510: STAT4 recompiled the cached identifier-candidate query for distinct names"
    )]
    #[test]
    fn limited_identifier_candidate_query_does_not_reprepare_for_distinct_names() {
        use rusqlite::StatementStatus;

        const IDENTIFIERS: usize = 1_024;
        let temp = tempfile::TempDir::new().unwrap();
        let source = (0..IDENTIFIERS)
            .map(|index| format!("pub struct Module{index:04};\n"))
            .collect::<String>();
        let rust_file = write_file(temp.path(), "src/lib.rs", &source);
        let java_source = (0..IDENTIFIERS)
            .map(|index| format!("class Module{index:04} {{}}\n"))
            .collect::<String>();
        let java_file = write_file(temp.path(), "src/Library.java", &java_source);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(
                oid_for(rust_file.read_to_string().unwrap().as_bytes()),
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &rust_file),
            )
            .unwrap();
        store
            .write_parsed_blob(
                oid_for(java_file.read_to_string().unwrap().as_bytes()),
                "java",
                &JavaAdapter,
                &parse_state(&JavaAdapter, &java_file),
            )
            .unwrap();
        store.refresh_planner_statistics().unwrap();

        let sql = limited_identifier_candidate_sql();
        let langs = vec!["rust".to_string(), "java".to_string()];
        let mut conn = store.read_conn().unwrap();
        let tx = conn.transaction().unwrap();
        for index in 0..IDENTIFIERS {
            let identifier = format!("Module{index:04}");
            let rows =
                candidate_rows_for_identifier_languages_limited(&tx, &langs, &identifier, &sql, 3)
                    .unwrap();
            assert!(rows.complete, "{identifier} candidate query was incomplete");
            assert_eq!(rows.rows.len(), 2, "{identifier} candidate count");
            assert_eq!(
                rows.rows
                    .iter()
                    .map(|candidate| candidate.lang.as_str())
                    .collect::<Vec<_>>(),
                ["rust", "java"],
                "{identifier} candidate language order"
            );
        }
        tx.commit().unwrap();

        let statement = conn.prepare_cached(&sql).unwrap();
        assert_eq!(
            statement.get_status(StatementStatus::Run),
            IDENTIFIERS as i32,
            "one cached statement must execute once per requested identifier"
        );
        assert_eq!(
            statement.get_status(StatementStatus::RePrepare),
            0,
            "temp-table request values must not trigger STAT4 statement re-preparation"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2911: type aliases gained their own type identity, which stale cache rows could not represent"
    )]
    #[test]
    fn rust_type_alias_identity_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "tags.rs",
            "pub mod tags {\n    pub type MaxVal = u32;\n    pub const MaxVal: u32 = 1;\n}\n",
        );
        let state = Arc::new(parse_state(&RustAdapter, &file));
        let alias = state
            .declarations
            .iter()
            .find(|unit| unit.short_name() == "tags.MaxVal" && unit.is_class())
            .expect("the current walk mints the alias as a type declaration");
        assert!(
            state
                .declarations
                .iter()
                .any(|unit| unit.short_name() == "tags.MaxVal" && unit.is_field()),
            "the const keeps its own field declaration beside {alias:?}: {:?}",
            state.declarations
        );
        let prior_epoch = epoch::rust_epoch_before_type_alias_type_identity();
        assert_prior_parsed_blob_invalidated(&RustAdapter, state.as_ref(), &prior_epoch);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "6dc4d18752fb: recovered macro fragment bindings change persisted Rust resolution facts"
    )]
    #[test]
    fn rust_recovered_macro_fragment_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "issue_70446.rs",
            r#"//@ check-pass

macro_rules! foo {
    ($(: $p:path)? $(: $l:lifetime)? ) => { bar! {$(: $p)? $(: $l)? } };
}

macro_rules! bar {
    ($(: $p:path)? $(: $l:lifetime)? ) => {};
}

foo! {: 'a }

fn main() {}
"#,
        );
        let state = Arc::new(parse_state(&RustAdapter, &file));
        let prior_epoch = epoch::rust_epoch_before_recovered_macro_fragment_bindings();
        assert_prior_parsed_blob_invalidated(&RustAdapter, state.as_ref(), &prior_epoch);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#4458: stale Rust cache rows retained cfg_attr transformation boundaries"
    )]
    #[test]
    fn rust_cfg_attr_item_boundary_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "lib.rs",
            "#[cfg_attr(test, track_caller)]\npub fn visit() {}\n",
        );
        let state = Arc::new(parse_state(&RustAdapter, &file));
        let prior_epoch = epoch::rust_epoch_before_cfg_attr_effective_item_attributes();
        assert_prior_parsed_blob_invalidated(&RustAdapter, state.as_ref(), &prior_epoch);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#4458: reference impl receivers change persisted Rust resolution facts"
    )]
    #[test]
    fn rust_reference_impl_member_owner_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "reference_impl.rs",
            "pub struct Widget; impl Hook for &mut Widget { fn call(self) { self.ping(); } }\n",
        );
        let state = Arc::new(parse_state(&RustAdapter, &file));
        let prior_epoch = epoch::rust_epoch_before_reference_impl_member_owners();
        assert_prior_parsed_blob_invalidated(&RustAdapter, state.as_ref(), &prior_epoch);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#4458: derive-helper boundaries change persisted Rust resolution facts"
    )]
    #[test]
    fn rust_derive_helper_attribute_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "lib.rs",
            "#[derive(Parser)]\n#[command(name = \"tool\")]\npub struct Args;\n",
        );
        let state = Arc::new(parse_state(&RustAdapter, &file));
        let prior_epoch = epoch::rust_epoch_before_conditional_derive_helper_attributes();
        assert_prior_parsed_blob_invalidated(&RustAdapter, state.as_ref(), &prior_epoch);
    }

    #[test]
    fn active_symbol_candidate_scan_batches_languages() {
        let temp = tempfile::TempDir::new().unwrap();
        let java_file = write_file(
            temp.path(),
            "java/Service.java",
            "package java; class Service { void run() {} }\n",
        );
        let rust_file = write_file(temp.path(), "rust/service.rs", "pub fn run() {}\n");
        let java_oid = oid_for(java_file.read_to_string().unwrap().as_bytes());
        let rust_oid = oid_for(rust_file.read_to_string().unwrap().as_bytes());
        let store = AnalyzerStore::open_persistent(&temp.path().join("cache.db")).unwrap();
        store
            .write_parsed_blob(
                java_oid,
                "java",
                &JavaAdapter,
                &parse_state(&JavaAdapter, &java_file),
            )
            .unwrap();
        store
            .write_parsed_blob(
                rust_oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &rust_file),
            )
            .unwrap();

        let languages = vec!["java".to_string(), "rust".to_string()];
        let generations = HashMap::from_iter([
            ("java".to_string(), GenerationId::BOOTSTRAP),
            ("rust".to_string(), GenerationId::BOOTSTRAP),
        ]);
        let rows = store
            .search_candidate_name_rows_for_langs(
                &languages,
                &generations,
                &[
                    ActiveSearchBlob::unfiltered(java_oid),
                    ActiveSearchBlob::unfiltered(rust_oid),
                ],
                Some(&[vec!["run".to_string()], vec!["Service".to_string()]]),
                None,
            )
            .unwrap();

        assert!(rows.complete);
        assert!(
            rows.rows
                .iter()
                .any(|row| row.lang_index == 0 && row.blob_oid == java_oid)
        );
        assert!(
            rows.rows
                .iter()
                .any(|row| row.lang_index == 1 && row.blob_oid == rust_oid)
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2785: by-key hydration crossed blob or language boundaries and skipped padded batches"
    )]
    #[test]
    fn search_candidate_key_hydration_preserves_multi_blob_language_parity() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let java_alpha = write_file(
            root,
            "java/Alpha.java",
            "package demo; class Alpha { int value; }\n",
        );
        let java_beta = write_file(
            root,
            "java/Beta.java",
            "package demo; class Beta { void run() {} int other; }\n",
        );
        let rust_gamma = write_file(root, "rust/gamma.rs", "pub struct Gamma;\n");
        let java_alpha_oid = oid_for(java_alpha.read_to_string().unwrap().as_bytes());
        let java_beta_oid = oid_for(java_beta.read_to_string().unwrap().as_bytes());
        let rust_gamma_oid = oid_for(rust_gamma.read_to_string().unwrap().as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(
                java_alpha_oid,
                "java",
                &JavaAdapter,
                &parse_state(&JavaAdapter, &java_alpha),
            )
            .unwrap();
        store
            .write_parsed_blob(
                java_beta_oid,
                "java",
                &JavaAdapter,
                &parse_state(&JavaAdapter, &java_beta),
            )
            .unwrap();
        store
            .write_parsed_blob(
                rust_gamma_oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &rust_gamma),
            )
            .unwrap();

        let languages = vec!["java".to_string(), "rust".to_string()];
        let generations = HashMap::from_iter([
            ("java".to_string(), GenerationId::BOOTSTRAP),
            ("rust".to_string(), GenerationId::BOOTSTRAP),
        ]);
        let java_baseline = store.search_candidate_rows_by_lang("java").unwrap();
        let rust_baseline = store.search_candidate_rows_by_lang("rust").unwrap();
        let alpha = java_baseline
            .iter()
            .find(|row| row.candidate.short_name == "Alpha")
            .expect("Alpha declaration");
        let beta = java_baseline
            .iter()
            .find(|row| row.candidate.short_name == "Beta")
            .expect("Beta declaration");
        let alpha_keys = java_baseline
            .iter()
            .filter(|row| row.candidate.blob_oid == java_alpha_oid)
            .map(|row| row.candidate.unit_key)
            .collect::<HashSet<_>>();
        let beta_only_unit_key = java_baseline
            .iter()
            .filter(|row| row.candidate.blob_oid == java_beta_oid)
            .map(|row| row.candidate.unit_key)
            .find(|unit_key| !alpha_keys.contains(unit_key))
            .expect("Beta fixture must have a unit key absent from Alpha");
        let gamma = rust_baseline
            .iter()
            .find(|row| row.candidate.short_name == "Gamma")
            .expect("Gamma declaration");

        let requested = vec![
            SearchCandidateKey {
                lang_index: 0,
                blob_oid: java_alpha_oid,
                unit_key: alpha.candidate.unit_key,
            },
            SearchCandidateKey {
                lang_index: 0,
                blob_oid: java_beta_oid,
                unit_key: beta.candidate.unit_key,
            },
            SearchCandidateKey {
                lang_index: 1,
                blob_oid: rust_gamma_oid,
                unit_key: gamma.candidate.unit_key,
            },
            // A valid unit key from another blob must not cross the blob
            // boundary, and a nonexistent key must remain a near miss.
            SearchCandidateKey {
                lang_index: 0,
                blob_oid: java_alpha_oid,
                unit_key: beta_only_unit_key,
            },
            SearchCandidateKey {
                lang_index: 0,
                blob_oid: java_alpha_oid,
                unit_key: i64::MAX,
            },
            // The OID exists, but only for Rust; the language scope must
            // prevent this request from reaching the Rust declaration.
            SearchCandidateKey {
                lang_index: 0,
                blob_oid: rust_gamma_oid,
                unit_key: gamma.candidate.unit_key,
            },
        ];
        // More than one fixed-arity batch must remain equivalent to one
        // request. These missing keys exercise the padded 400-tuple query and
        // ensure near misses do not cause declaration-range over-reading.
        let mut requested = requested;
        requested.extend((0..401).map(|index| SearchCandidateKey {
            lang_index: 0,
            blob_oid: java_alpha_oid,
            unit_key: i64::MIN + i64::from(index),
        }));
        assert!(requested.len() > SEARCH_CANDIDATE_KEY_BATCH_SIZE);
        let hydrated = store
            .search_candidate_rows_for_keys(&languages, &generations, &requested, None)
            .unwrap();
        assert!(hydrated.complete);

        let expected = [alpha, beta, gamma]
            .into_iter()
            .map(|row| {
                (
                    row.candidate.blob_oid,
                    row.candidate.lang.clone(),
                    row.candidate.unit_key,
                )
            })
            .collect::<HashSet<_>>();
        let actual = hydrated
            .rows
            .iter()
            .map(|row| {
                (
                    row.candidate.blob_oid,
                    row.candidate.lang.clone(),
                    row.candidate.unit_key,
                )
            })
            .collect::<HashSet<_>>();
        assert_eq!(actual, expected);
        assert_eq!(hydrated.rows.len(), expected.len());
        for row in &hydrated.rows {
            let baseline = java_baseline
                .iter()
                .chain(rust_baseline.iter())
                .find(|candidate| {
                    candidate.candidate.blob_oid == row.candidate.blob_oid
                        && candidate.candidate.lang == row.candidate.lang
                        && candidate.candidate.unit_key == row.candidate.unit_key
                })
                .expect("hydrated row must have a baseline projection");
            assert_eq!(row, baseline, "by-key hydration changed projection fields");
            assert!(
                row.primary_range.is_some(),
                "fixture should retain declaration range"
            );
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "65984c3656f2: imports nested in Rust inline modules were absent from persisted facts"
    )]
    #[test]
    fn rust_nested_import_epoch_invalidates_prior_parsed_blobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "lib.rs",
            "pub fn run() {}\n\n#[cfg(test)]\nmod tests {\n    use crate::run;\n}\n",
        );
        let mut state = parse_state(&RustAdapter, &file);
        assert!(
            state
                .imports
                .iter()
                .any(|import| import.raw_snippet.contains("use crate::run")),
            "the current walk records the import written inside `mod tests`: {:?}",
            state.imports
        );
        // Before this epoch the walk collected only the file's top-level `use`
        // declarations, so an import written inside an inline module was absent
        // from the persisted family the coarse file graph reads.
        state
            .imports
            .retain(|import| !import.raw_snippet.contains("use crate::run"));
        assert!(state.imports.is_empty());
        state
            .source_facts
            .as_mut()
            .expect("Rust producer source facts")
            .generic_imports
            .clear();
        let state = Arc::new(state);
        let oid = oid_for(state.source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let prior_epoch = epoch::rust_epoch_before_nested_and_extern_crate_import_facts();
        let prior_generation = store
            .ensure_language_epoch_value("rust", &prior_epoch)
            .unwrap();
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "rust",
                prior_generation,
                &RustAdapter,
                state.as_ref(),
            )
            .unwrap();
        assert!(store.contains_parsed_blob(oid, "rust").unwrap());

        let current_generation = store
            .ensure_language_epoch(Language::Rust, &tree_sitter_rust::LANGUAGE.into())
            .unwrap();

        assert_ne!(current_generation, prior_generation);
        assert!(!store.contains_parsed_blob(oid, "rust").unwrap());
        assert_eq!(
            store
                .missing_parsed_blob_keys(&[(oid, "rust".to_string())])
                .unwrap(),
            vec![(oid, "rust".to_string())]
        );
    }

    /// The relational anchor, package boundary, and content-stable tail for
    /// the unit whose rendered name is `fq_name`.
    fn persisted_unit_row<A: LanguageAdapter>(
        adapter: &A,
        state: &FileState,
        fq_name: &str,
    ) -> (Option<PackageAnchor>, usize, String) {
        let unit = state
            .declarations
            .iter()
            .find(|unit| unit.fq_name() == fq_name)
            .unwrap_or_else(|| panic!("fixture must declare {fq_name}: {:?}", state.declarations));
        let content_qualifier = adapter.storage_content_qualifier(unit, &state.content_qualifier);
        let persisted = persisted_unit_fq(adapter, unit, &content_qualifier).unwrap();
        let interner = segment_interner();
        let tail = persisted.tail.display(interner);
        (persisted.anchor, persisted.package_tail_segments, tail)
    }

    /// A crate-root-qualified impl owner (`use crate::JsError; impl T for
    /// JsError`) has a package that is neither the file's own nor foreign: it
    /// is the crate root. Persisting it in full would bake the extracting
    /// mount's directory names into a content-addressed row, and treating it as
    /// the file's own package would be wrong wherever those differ. It must
    /// persist as a crate-root anchor plus a package-free tail, and hydrate
    /// with each mount's own crate root.
    #[test]
    fn identical_rust_crate_impl_blob_hydrates_with_live_crate_roots() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let _ = write_file(root, "src/lib.rs", "pub struct JsError;\n");
        let _ = write_file(root, "crates/webidl/src/lib.rs", "pub struct JsError;\n");
        let content = "use crate::JsError;\n\npub trait WasmDescribe {\n    fn describe();\n}\n\nimpl WasmDescribe for JsError {\n    fn describe() {}\n}\n";
        let file_a = write_file(root, "src/describe.rs", content);
        let file_b = write_file(root, "crates/webidl/src/describe.rs", content);
        let oid = oid_for(content.as_bytes());
        let adapter = RustAdapter;
        let state = parse_state(&adapter, &file_a);

        let (anchor, boundary_in_tail, tail) =
            persisted_unit_row(&adapter, &state, "JsError.describe");
        assert_eq!(anchor, Some(PackageAnchor::CrateRoot));
        assert_eq!(boundary_in_tail, 0);
        assert_eq!(tail, "JsError.describe");

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &adapter, &state)
            .unwrap();
        let workspace_files = [&file_a, &file_b]
            .into_iter()
            .map(|file| WorkspaceFileRow {
                rel_path: brokk_bifrost_core::path_utils::rel_path_string(file),
                blob_oid: oid,
            })
            .collect::<Vec<_>>();
        let anchors = [&file_a, &file_b]
            .into_iter()
            .map(|file| {
                WorkspaceAnchorRow::new(
                    brokk_bifrost_core::path_utils::rel_path_string(file),
                    PackageAnchor::CrateRoot,
                    adapter
                        .resolve_package_anchor(PackageAnchor::CrateRoot, "", file)
                        .unwrap()
                        .display_native(Language::Rust, segment_interner()),
                )
            })
            .collect::<Vec<_>>();
        let mut packages = anchors
            .iter()
            .map(|anchor| anchor.package_name.clone())
            .collect::<Vec<_>>();
        packages.sort();
        packages.dedup();
        store
            .sync_workspace_snapshot(
                "rust",
                GenerationId::BOOTSTRAP,
                &workspace_files,
                &[],
                &packages,
                &[],
                &[],
                &anchors,
            )
            .unwrap();
        let hydrated_a = store
            .hydrate_file_state(oid, "rust", &adapter, &file_a)
            .unwrap()
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "rust", &adapter, &file_b)
            .unwrap()
            .unwrap();

        assert!(
            hydrated_a
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "JsError.describe")
        );
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "crates.webidl.src.JsError.describe"),
            "{:?}",
            hydrated_b.declarations
        );
        let mounted_names = {
            let conn = store.conn.lock().expect("store mutex");
            let mut statement = conn
                .prepare(
                    "SELECT prefix, tail, rel_path
                     FROM live_definition_exact_names
                     WHERE lang = 'rust' AND tail = 'JsError.describe'
                     ORDER BY rel_path",
                )
                .unwrap();
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(
            mounted_names,
            [
                (
                    "crates.webidl.src".to_string(),
                    "JsError.describe".to_string(),
                    "crates/webidl/src/describe.rs".to_string(),
                ),
                (
                    String::new(),
                    "JsError.describe".to_string(),
                    "src/describe.rs".to_string(),
                ),
            ]
        );
    }

    /// The same impl-bearing blob mounted at two directory depths must hydrate
    /// with per-mount package prefixes: an own-module impl stores only the
    /// declaration tail, never the directory names it was extracted under.
    #[test]
    fn identical_rust_impl_blob_hydrates_with_live_module_packages() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let content = "pub struct Client;\n\nimpl Client {\n    pub fn connect(&self) {}\n}\n";
        let file_a = write_file(root, "alpha/src/service.rs", content);
        let file_b = write_file(root, "beta/nested/src/service.rs", content);
        let oid = oid_for(content.as_bytes());
        let adapter = RustAdapter;
        let state = parse_state(&adapter, &file_a);

        let (anchor, boundary_in_tail, tail) =
            persisted_unit_row(&adapter, &state, "alpha.src.service.Client.connect");
        assert_eq!(anchor, Some(PackageAnchor::OwnModule { pop: 0 }));
        assert_eq!(boundary_in_tail, 0);
        assert_eq!(tail, "Client.connect");

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &adapter, &state)
            .unwrap();
        let hydrated_a = store
            .hydrate_file_state(oid, "rust", &adapter, &file_a)
            .unwrap()
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "rust", &adapter, &file_b)
            .unwrap()
            .unwrap();

        assert!(
            hydrated_a
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "alpha.src.service.Client.connect")
        );
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "beta.nested.src.service.Client.connect"),
            "{:?}",
            hydrated_b.declarations
        );
    }

    /// `super` pops the LEXICAL package, which inside an inline `mod` starts
    /// with a content-written component. Only the pops that survive past those
    /// components cross the file-package boundary, so this owner resolves back
    /// to the file's own module with an effective pop of zero. Counting the
    /// `super` naively would anchor one level up and push the file's
    /// path-derived final component (`b`) into the content-addressed tail.
    #[test]
    fn inline_module_super_impl_owner_persists_no_path_derived_segments() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let content = "mod m {\n    use super::T;\n\n    pub trait X {\n        fn f();\n    }\n\n    impl X for T {\n        fn f() {}\n    }\n}\n";
        let file = write_file(root, "src/a/b.rs", content);
        let adapter = RustAdapter;
        let state = parse_state(&adapter, &file);

        let (anchor, boundary_in_tail, tail) = persisted_unit_row(&adapter, &state, "a.b.T.f");
        assert_eq!(anchor, Some(PackageAnchor::OwnModule { pop: 0 }));
        assert_eq!(boundary_in_tail, 0);
        assert_eq!(tail, "T.f");
    }

    /// An import and the `impl` it feeds can sit in different lexical scopes: a
    /// file-level `use super::T` resolves against the file's package while an
    /// `impl` inside `mod m` resolves against `<file>.m`. The anchor is derived
    /// from the package the owner actually ends up with, so the two scopes
    /// disagreeing cannot produce an anchor that fails to place its own package
    /// (the debug assertions this suite runs under would abort if it did).
    #[test]
    fn file_level_import_feeding_an_inline_module_impl_stays_placeable() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let content = "use super::T;\n\nmod m {\n    pub trait X {\n        fn f();\n    }\n\n    impl X for T {\n        fn f() {}\n    }\n}\n";
        let file_a = write_file(root, "src/a/b.rs", content);
        let file_b = write_file(root, "crates/z/src/a/b.rs", content);
        let oid = oid_for(content.as_bytes());
        let adapter = RustAdapter;
        let state = parse_state(&adapter, &file_a);

        // The file-level binding is not in scope inside `mod m` (the module
        // body gets its own binder), so this owner resolves as a bare local
        // name under the inline module and keeps `m` in the content tail.
        let (anchor, boundary_in_tail, tail) = persisted_unit_row(&adapter, &state, "a.b.m.T.f");
        assert_eq!(anchor, Some(PackageAnchor::OwnModule { pop: 0 }));
        assert_eq!(boundary_in_tail, 0);
        assert_eq!(tail, "m.T.f");

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &adapter, &state)
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "rust", &adapter, &file_b)
            .unwrap()
            .unwrap();
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "crates.z.src.a.b.m.T.f"),
            "{:?}",
            hydrated_b.declarations
        );
    }

    /// `impl crate::foo::Bar` names a module below the crate root, so the
    /// crate-root anchor leaves a source-written `foo` package segment inside
    /// the persisted tail. The package boundary is one segment past the anchor,
    /// and that offset must survive the round trip at a mount whose crate root
    /// has a different depth.
    #[test]
    fn crate_rooted_module_impl_owner_persists_a_package_segment_in_its_tail() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let _ = write_file(root, "crates/webidl/src/lib.rs", "pub mod foo;\n");
        let _ = write_file(root, "src/lib.rs", "pub mod foo;\n");
        let content = "use crate::foo::Bar;\n\npub trait X {\n    fn f();\n}\n\nimpl X for Bar {\n    fn f() {}\n}\n";
        let file_a = write_file(root, "crates/webidl/src/generator.rs", content);
        let file_b = write_file(root, "src/generator.rs", content);
        let oid = oid_for(content.as_bytes());
        let adapter = RustAdapter;
        let state = parse_state(&adapter, &file_a);

        let (anchor, boundary_in_tail, tail) =
            persisted_unit_row(&adapter, &state, "crates.webidl.src.foo.Bar.f");
        assert_eq!(anchor, Some(PackageAnchor::CrateRoot));
        assert_eq!(boundary_in_tail, 1);
        assert_eq!(tail, "foo.Bar.f");

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &adapter, &state)
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "rust", &adapter, &file_b)
            .unwrap()
            .unwrap();
        let member = hydrated_b
            .declarations
            .iter()
            .find(|unit| unit.fq_name() == "foo.Bar.f")
            .unwrap_or_else(|| panic!("{:?}", hydrated_b.declarations));
        assert_eq!(member.package_name(), "foo");
    }

    /// A file-level `use super::T` genuinely crosses the file-package boundary,
    /// so the owner anchors one module above the file and hydrates against the
    /// live mount's parent package rather than the extraction-time one.
    #[test]
    fn cross_file_super_impl_owner_persists_a_popped_own_module_anchor() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let content =
            "use super::T;\n\npub trait X {\n    fn f();\n}\n\nimpl X for T {\n    fn f() {}\n}\n";
        let file_a = write_file(root, "src/a/b.rs", content);
        let file_b = write_file(root, "crates/z/src/a/b.rs", content);
        let oid = oid_for(content.as_bytes());
        let adapter = RustAdapter;
        let state = parse_state(&adapter, &file_a);

        let (anchor, boundary_in_tail, tail) = persisted_unit_row(&adapter, &state, "a.T.f");
        assert_eq!(anchor, Some(PackageAnchor::OwnModule { pop: 1 }));
        assert_eq!(boundary_in_tail, 0);
        assert_eq!(tail, "T.f");

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &adapter, &state)
            .unwrap();
        let hydrated_b = store
            .hydrate_file_state(oid, "rust", &adapter, &file_b)
            .unwrap()
            .unwrap();
        assert!(
            hydrated_b
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "crates.z.src.a.T.f"),
            "{:?}",
            hydrated_b.declarations
        );
    }

    /// An impl owner rooted in another crate has no placeable anchor: its
    /// package is not derived from this file's path at any depth. It keeps its
    /// complete persisted name, and because the anchor came from the adapter
    /// default rather than the extractor, that fallback is silent (a debug
    /// build would abort here if it were treated as an extractor bug).
    #[test]
    fn foreign_crate_impl_owner_persists_its_complete_name() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path();
        let content = "pub trait Local {\n    fn f();\n}\n\nimpl Local for serde::Value {\n    fn f() {}\n}\n";
        let file = write_file(root, "src/model.rs", content);
        let oid = oid_for(content.as_bytes());
        let adapter = RustAdapter;
        let state = parse_state(&adapter, &file);

        let (anchor, _, tail) = persisted_unit_row(&adapter, &state, "serde.Value.f");
        assert_eq!(anchor, None);
        assert_eq!(tail, "serde.Value.f");

        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &adapter, &state)
            .unwrap();
        let hydrated = store
            .hydrate_file_state(oid, "rust", &adapter, &file)
            .unwrap()
            .unwrap();
        assert!(
            hydrated
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "serde.Value.f"),
            "{:?}",
            hydrated.declarations
        );
    }

    /// SQL hydration retains the producer's import interpretation independently
    /// of the rendered snippet consumed by display clients.
    #[test]
    fn hydrated_rust_import_binder_uses_structured_form_not_display_text() {
        let source =
            "extern crate serde as serialization;\nuse crate::model::{Thing as Local, lower};\n";
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let imports =
            brokk_bifrost_rust::imports::rust_import_projection(tree.root_node(), source, "")
                .into_iter()
                .map(|projected| projected.import.info)
                .collect::<Vec<_>>();
        // Publish through production: a structured import path is stored in
        // the canonical `source_import_*` families, which the hydrator reads
        // back through the `source_import_lexical_*` projections.
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "src/lib.rs", source);
        let oid = oid_for(source.as_bytes());
        let state = parse_state(&RustAdapter, &file);
        assert_eq!(state.imports, imports);
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        let conn = store.conn.lock().expect("store mutex");
        let mut hydrated = read_import_infos(&conn, &oid.to_string(), "rust").unwrap();
        assert_eq!(hydrated, imports);
        let mut binder = brokk_bifrost_core::analyzer::usages::model::ImportBinder::empty();
        for import in &mut hydrated {
            import.raw_snippet = "use wrong::DisplayOnly;".to_string();
            brokk_bifrost_rust::lexical_scope::insert_rust_import_binding(&mut binder, import);
        }
        assert!(!binder.bindings.contains_key("serialization"));
        assert!(!binder.bindings.contains_key("DisplayOnly"));
        let local = &binder.bindings["Local"];
        assert_eq!(local.module_specifier, "crate::model");
        assert_eq!(local.imported_name.as_deref(), Some("Thing"));
        // The existing parser renders grouped leaves as normalized imports;
        // preserve the incumbent lowercase namespace interpretation.
        let lower = &binder.bindings["lower"];
        assert_eq!(lower.module_specifier, "crate::model::lower");
        assert!(lower.imported_name.is_none());
        assert_eq!(binder.bindings.len(), 2);
    }

    #[test]
    fn rust_fact_tables_record_exports_imports_modules_and_occurrences() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_fixture_store(temp.path(), "src/lib.rs", RUST_USAGE_FACT_FIXTURE);
        let facts = store.rust_usage_facts(oid, "rust").unwrap();

        let exports: Vec<_> = facts
            .exports
            .iter()
            .map(|export| {
                (
                    export.exported_name.as_deref(),
                    export.source_path.as_str(),
                    export.imported_name.as_deref(),
                    export.is_glob,
                )
            })
            .collect();
        assert_eq!(
            exports,
            vec![
                (Some("Exported"), "alpha", Some("Exported"), false),
                (Some("Alias"), "beta", Some("Renamed"), false),
                (None, "gamma", None, true),
            ],
            "private and non-root `use` declarations are not exports: {:?}",
            facts.exports
        );

        let imports: Vec<_> = facts
            .import_targets
            .iter()
            .map(|target| {
                (
                    target
                        .module_path
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    target.bound_name.as_deref(),
                    target.is_glob,
                    target.is_extern_crate,
                    target.is_macro_use,
                    target.owner_module.as_str(),
                    target.local_extent.is_some(),
                )
            })
            .collect();
        assert_eq!(
            imports,
            vec![
                (
                    Vec::<&str>::new(),
                    Some("facade"),
                    false,
                    true,
                    true,
                    "",
                    false
                ),
                (
                    vec!["alpha"],
                    Some("Exported"),
                    false,
                    false,
                    false,
                    "",
                    false
                ),
                (vec!["beta"], Some("Alias"), false, false, false, "", false),
                (vec!["gamma"], None, true, false, false, "", false),
                (
                    vec!["delta"],
                    Some("Private"),
                    false,
                    false,
                    false,
                    "",
                    false
                ),
                (
                    vec!["crate"],
                    Some("Scoped"),
                    false,
                    false,
                    false,
                    "inline",
                    false,
                ),
                (
                    vec!["crate"],
                    Some("Local"),
                    false,
                    false,
                    false,
                    "inline",
                    true,
                ),
            ],
            "import rows were {:?}",
            facts.import_targets
        );
        assert_eq!(facts.import_targets[1].visibility, RustVisibility::Public);
        assert_eq!(facts.import_targets[4].visibility, RustVisibility::Private);

        let modules: Vec<_> = facts
            .modules
            .iter()
            .map(|module| (module.module_name.as_str(), module.is_inline))
            .collect();
        assert_eq!(
            modules,
            vec![("", true), ("detached", false), ("inline", true)],
            "module rows were {:?}",
            facts.modules
        );
        assert_eq!(facts.modules[0].start_byte, 0);
        assert_eq!(facts.modules[0].end_byte, RUST_USAGE_FACT_FIXTURE.len());

        let mask = |name: &str| {
            facts
                .identifier_occurrences
                .iter()
                .find(|occurrence| occurrence.identifier == name)
                .map(|occurrence| occurrence.context_mask)
        };
        assert_eq!(
            mask("helper"),
            Some(brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_CODE)
        );
        assert_eq!(
            mask("in_a_comment"),
            Some(brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_COMMENT)
        );
        assert_eq!(
            mask("in_a_string"),
            Some(brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_STRING)
        );

        // The include edge records the literal as written and its last
        // component, never the resolved target: two byte-identical files at
        // different paths share this row set, so resolution is the reader's.
        let edges: Vec<_> = facts
            .include_edges
            .iter()
            .map(|edge| (edge.relative_path.as_str(), edge.file_name.as_str()))
            .collect();
        assert_eq!(edges, vec![("generated/table.rs", "table.rs")]);
        let bindings: Vec<_> = facts.include_edges[0]
            .host_bindings
            .iter()
            .map(|binding| {
                (
                    binding.local_name.as_str(),
                    binding.module_specifier.as_str(),
                    binding.imported_name.as_deref(),
                    binding.kind,
                )
            })
            .collect();
        assert_eq!(
            bindings,
            vec![
                (
                    "*",
                    "gamma",
                    None,
                    brokk_bifrost_core::analyzer::rust_facts::RustIncludeBindingKind::Glob
                ),
                (
                    "Alias",
                    "beta",
                    Some("Renamed"),
                    brokk_bifrost_core::analyzer::rust_facts::RustIncludeBindingKind::Named
                ),
                (
                    "Exported",
                    "alpha",
                    Some("Exported"),
                    brokk_bifrost_core::analyzer::rust_facts::RustIncludeBindingKind::Named
                ),
                (
                    "Private",
                    "delta",
                    Some("Private"),
                    brokk_bifrost_core::analyzer::rust_facts::RustIncludeBindingKind::Named
                ),
                (
                    "facade",
                    "facade",
                    None,
                    brokk_bifrost_core::analyzer::rust_facts::RustIncludeBindingKind::Namespace
                ),
            ],
            "only the root-scope bindings reach a root-scope include: {:?}",
            facts.include_edges[0].host_bindings
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "3bb3fbdffb31: selected Rust inverse reads lost canonical import occurrence locations"
    )]
    #[test]
    fn canonical_import_locations_reopen_and_seek_exact_ordinals() {
        let mut source = String::from(
            "extern crate serde as serialization;\nuse crate::model::{Thing as Local, *};\nmod nested { use crate::Nested; }\nfn f() { use crate::LocalOnly; }\n",
        );
        for index in 0..128 {
            source.push_str(&format!("use crate::model::Thing as Alias{index};\n"));
        }
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", &source)
            .build();
        let file = fixture.file("src/lib.rs");
        let state = parse_state(&RustAdapter, &file);
        let oid = oid_for(source.as_bytes());
        let db_path = fixture.root().join("import-locations.db");
        let store = AnalyzerStore::open_persistent(&db_path).unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "canonical-import-location-test")
            .unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        let requested = [0, 1, 2, 3, 4, 132].into_iter().collect();
        let cancellation = CancellationToken::new();
        let check_locations = |store: &AnalyzerStore| {
            let locations = store
                .load_rust_import_source_locations(oid, generation, &requested, &cancellation)
                .unwrap()
                .unwrap();
            // The projection carries the path's target token only. An `as`
            // alias is the name a use declaration binds, not a naming of the
            // imported item (the Rust Reference, use declarations), so the
            // selected reference index has no edge to place at it.
            assert_eq!(locations[&0].target.unwrap().text(&source), "serde");
            assert_eq!(locations[&1].target.unwrap().text(&source), "Thing");
            assert!(locations[&2].target.is_none());
            assert!(!locations[&3].root_owned);
            assert!(!locations[&4].root_owned);
            assert_eq!(locations[&132].target.unwrap().text(&source), "Thing");
            let facts = store.rust_usage_facts(oid, "rust").unwrap();
            assert_eq!(facts.import_targets, state.rust_usage_facts.import_targets);
        };
        check_locations(&store);
        store.refresh_planner_statistics().unwrap();
        check_locations(&store);
        drop(store);
        let reopened = AnalyzerStore::open_persistent(&db_path).unwrap();
        check_locations(&reopened);
        let absent = [1000].into_iter().collect();
        assert!(
            reopened
                .load_rust_import_source_locations(oid, generation, &absent, &cancellation)
                .unwrap()
                .is_none()
        );
        cancellation.cancel();
        assert!(
            reopened
                .load_rust_import_source_locations(oid, generation, &requested, &cancellation)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn primary_route_only_module_properties_survive_reopen_without_display_links() {
        use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, RustDeclarationKind};
        let source = r#"
#[cfg(feature = "outer")]
fn gated() { pub(crate) mod local {} }
#[cfg(feature = "one")]
pub mod repeated;
#[cfg(not(feature = "one"))]
mod repeated;
pub(crate) mod inline { mod nested; }
"#;
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let file = fixture.file("src/lib.rs");
        let state = parse_state(&RustAdapter, &file);
        let facts = state.source_facts.as_ref().unwrap();
        let local = facts
            .rust_declaration_properties
            .iter()
            .find(|property| {
                if property.kind != RustDeclarationKind::InlineModule {
                    return false;
                }
                let declaration = facts.occurrences.declaration(property.declaration);
                let name = facts
                    .occurrences
                    .occurrence(declaration.name.unwrap())
                    .range;
                &source[name.start_byte..name.end_byte] == "local"
            })
            .expect("route-only primary module has a canonical source declaration")
            .clone();
        assert_eq!(local.visibility, RustVisibility::Crate);
        assert_eq!(
            local.cfg_condition,
            RustCfgCondition::Atom("feature = \"outer\"".into()),
            "the retained local module carries its enclosing function predicate"
        );
        assert!(
            !state
                .source_declaration_units
                .iter()
                .any(|(id, _)| *id == local.declaration)
        );
        assert!(
            facts
                .native_declaration_sources
                .iter()
                .any(|(_, id)| *id == local.declaration)
        );
        let expected = state.rust_usage_facts.module_routes.clone();
        let local_scope = expected
            .scopes
            .iter()
            .find(|scope| scope.module_name == "local")
            .unwrap();
        assert_eq!(local_scope.visibility, local.visibility);
        assert!(local_scope.resolution_scope.is_some());
        let oid = oid_for(source.as_bytes());
        let path = fixture.root().join("primary-module-properties.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        drop(state);
        drop(store);
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        assert_eq!(
            store.rust_usage_facts(oid, "rust").unwrap().module_routes,
            expected
        );
        let persisted = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT property.visibility, property.cfg_condition,
                    (SELECT COUNT(*) FROM source_declaration_units AS bridge
                     WHERE bridge.blob_id = property.blob_id
                       AND bridge.declaration_id = property.declaration_id)
             FROM source_rust_declaration_properties AS property
             JOIN blobs ON blobs.id = property.blob_id
             WHERE blobs.blob_oid = ?1 AND blobs.lang = 'rust' AND property.declaration_id = ?2",
                params![oid.to_string(), i64::from(local.declaration.get())],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            persisted,
            (
                encode_rust_visibility(&local.visibility),
                encode_rust_cfg_condition(&local.cfg_condition),
                0
            )
        );
    }

    #[test]
    fn shared_embedded_module_properties_reopen_with_fifo_routes_and_exact_links() {
        use brokk_bifrost_core::analyzer::rust_facts::RustDeclarationKind;
        use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;

        let source = r#"
macro_rules! discard { ($($tokens:tt)*) => {}; }
outer! { pub mod first; nested! { pub(crate) mod deep; } }
discard! { pub mod hidden { mod child; } }
outer! { mod first; }
mod primary;
"#;
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let mut state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let facts = state.source_facts.as_ref().unwrap();
        let modules = facts
            .rust_declaration_properties
            .iter()
            .filter(|property| {
                matches!(
                    property.kind,
                    RustDeclarationKind::InlineModule | RustDeclarationKind::ExternalModule
                )
            })
            .map(|property| {
                let declaration = facts.occurrences.declaration(property.declaration);
                let name = facts.occurrences.occurrence(declaration.name.unwrap());
                (
                    source[name.range.start_byte..name.range.end_byte].to_owned(),
                    property.declaration,
                    name.provenance,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(modules.len(), 6, "exact module properties: {modules:?}");
        for (name, id, provenance) in &modules {
            let links = state
                .source_declaration_units
                .iter()
                .filter(|(declaration, _)| declaration == id)
                .count();
            assert_eq!(
                links,
                usize::from(!matches!(name.as_str(), "hidden" | "child")),
                "display admission for {name} / {id:?}"
            );
            if name != "primary" {
                assert_eq!(*provenance, SourceOccurrenceProvenance::Embedded);
                assert!(
                    !facts
                        .native_declaration_sources
                        .iter()
                        .any(|(_, declaration)| declaration == id)
                );
            }
        }
        let first = modules
            .iter()
            .filter(|(name, _, _)| name == "first")
            .map(|(_, id, _)| *id)
            .collect::<Vec<_>>();
        assert_eq!(first.len(), 2);
        assert_ne!(first[0], first[1]);
        let routes = state.rust_usage_facts.module_routes.clone();
        assert_eq!(
            routes
                .routes
                .iter()
                .map(|route| route.module_name.as_str())
                .collect::<Vec<_>>(),
            ["primary", "first", "child", "first", "deep"]
        );
        let child = routes
            .routes
            .iter()
            .find(|route| route.module_name == "child")
            .unwrap();
        assert_eq!(routes.scopes[child.scope].module_name, "hidden");
        let inventory = state.rust_usage_facts.modules.clone();
        let canonical = state
            .source_facts
            .as_ref()
            .unwrap()
            .rust_modules
            .as_ref()
            .unwrap()
            .clone();
        // The DTOs are consumer views, not writable source authority. Even
        // replacing whole collections must not change canonical publication.
        state.rust_usage_facts.modules.clear();
        state.rust_usage_facts.module_routes.scopes.clear();
        state.rust_usage_facts.module_routes.routes.clear();
        let oid = oid_for(source.as_bytes());
        let path = fixture.root().join("shared-embedded-modules.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        drop(state);
        drop(store);
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        assert_eq!(
            store.rust_usage_facts(oid, "rust").unwrap().modules,
            inventory
        );
        assert_eq!(
            store.rust_usage_facts(oid, "rust").unwrap().module_routes,
            routes
        );
        let conn = store.read_conn().unwrap();
        let root: u32 = conn
            .query_row(
                "SELECT root_occurrence_id FROM source_rust_module_manifests
             WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust')",
                [oid.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(root, canonical.root.get());
        let links = conn.prepare(
            "SELECT declaration_id, body_occurrence_id, module_name FROM source_rust_module_declarations
             WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust')
             ORDER BY declaration_id"
        ).unwrap().query_map([oid.to_string()], |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Option<u32>>(1)?, row.get::<_, String>(2)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let mut expected_links = canonical
            .declarations
            .iter()
            .map(|row| {
                (
                    row.declaration.get(),
                    row.body.map(|id| id.get()),
                    row.name.clone(),
                )
            })
            .collect::<Vec<_>>();
        expected_links.sort_unstable_by_key(|row| row.0);
        assert_eq!(links, expected_links);
        let gates = conn.prepare(
            "SELECT route_ordinal, gate_ordinal, invocation_occurrence_id FROM source_rust_module_route_gates
             WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust')
             ORDER BY route_ordinal, gate_ordinal"
        ).unwrap().query_map([oid.to_string()], |row| Ok((row.get::<_, usize>(0)?, row.get::<_, usize>(1)?, row.get::<_, u32>(2)?)))
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        let expected_gates = canonical
            .routes
            .iter()
            .enumerate()
            .flat_map(|(route, row)| {
                row.gates
                    .iter()
                    .enumerate()
                    .map(move |(gate, id)| (route, gate, id.get()))
            })
            .collect::<Vec<_>>();
        assert_eq!(gates, expected_gates);
        drop(conn);
        for (name, id, _) in modules {
            let links: i64 = store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM source_declaration_units AS bridge
                         WHERE bridge.blob_id = property.blob_id
                           AND bridge.declaration_id = property.declaration_id)
                     FROM source_rust_declaration_properties AS property
                     JOIN blobs ON blobs.id = property.blob_id
                     WHERE blobs.blob_oid = ?1 AND blobs.lang = 'rust'
                       AND property.declaration_id = ?2",
                    params![oid.to_string(), i64::from(id.get())],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                links,
                i64::from(!matches!(name.as_str(), "hidden" | "child"))
            );
        }
    }

    #[test]
    fn canonical_module_publication_requires_source_facts_and_repairs_missing_witness() {
        let source = "#[macro_use] mod inline { pub mod leaf; } outer! { mod gated; }";
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let expected = state.rust_usage_facts.clone();
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("rust").unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        let mut missing = state.clone();
        missing.source_facts.as_mut().unwrap().rust_modules = None;
        let error = store
            .write_parsed_blob(oid, "rust", &RustAdapter, &missing)
            .unwrap_err();
        assert!(
            error.to_string().contains("canonical module source facts"),
            "{error}"
        );
        assert_eq!(store.rust_usage_facts(oid, "rust").unwrap(), expected);
        store.delete_rust_facts_for_test("rust");
        assert!(
            store
                .blobs_with_rust_facts("rust", generation, &[oid])
                .unwrap()
                .is_empty()
        );
        assert!(store.rust_usage_facts(oid, "rust").is_err());
        {
            let conn = store.read_conn().unwrap();
            assert!(read_rust_usage_facts_bulk(&conn, "rust", &[oid.to_string()]).is_err());
        }
        assert!(
            store
                .rust_module_route_facts_while("rust", generation, &[oid], &|| true)
                .unwrap()
                .unwrap()
                .is_empty()
        );
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        assert_eq!(store.rust_usage_facts(oid, "rust").unwrap(), expected);
        assert_eq!(
            store
                .blobs_with_rust_facts("rust", generation, &[oid])
                .unwrap(),
            [oid].into_iter().collect()
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "9fba40a6cb46: stale Rust macro DTOs overrode canonical declaration identities and route ranges"
    )]
    #[test]
    fn canonical_rust_macro_properties_ignore_stale_dto_and_reopen_exact_links() {
        let source = "#[macro_export]\nmacro_rules! public_macro { () => {}; }\nmacro_rules! private_macro { () => {}; }\nmod nested { macro_rules! local_macro { () => {}; } }\n";
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let file = fixture.file("src/lib.rs");
        let mut state = parse_state(&RustAdapter, &file);
        let expected = state.rust_usage_facts.module_routes.item_macros.clone();
        assert_eq!(expected.len(), 3);
        assert!(expected[0].exported);
        assert!(!expected[1].exported);
        assert_ne!(expected[0].declaration, expected[1].declaration);
        assert_eq!(expected[0].scope_start, expected[1].scope_start);
        assert!(expected[2].scope_start > expected[1].scope_start);
        assert!(expected[2].scope_end < expected[1].scope_end);
        let source_facts = state.source_facts.as_ref().unwrap();
        for definition in &expected {
            let declaration = source_facts.occurrences.declaration(definition.declaration);
            let declaration_occurrence =
                source_facts.occurrences.occurrence(declaration.occurrence);
            let macro_fact = source_facts
                .rust_items
                .macro_definitions
                .iter()
                .find(|fact| fact.declaration == definition.declaration)
                .unwrap();
            let context = source_facts.occurrences.occurrence(macro_fact.context);
            assert_eq!(
                definition.visible_after,
                declaration_occurrence.range.end_byte
            );
            assert_eq!(definition.scope_start, context.range.start_byte);
            assert_eq!(definition.scope_end, context.range.end_byte);
        }
        for definition in &mut state.rust_usage_facts.module_routes.item_macros {
            definition.exported = !definition.exported;
            definition.visible_after = usize::MAX;
            definition.scope_start = usize::MAX;
            definition.scope_end = usize::MAX;
        }
        let oid = oid_for(source.as_bytes());
        let path = fixture.root().join("macro-declarations.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let mut invalid = state.clone();
        invalid.rust_usage_facts.module_routes.item_macros[0].declaration =
            brokk_bifrost_core::analyzer::source_facts::SourceDeclarationId::new(u32::MAX);
        assert!(
            store
                .write_parsed_blob(oid, "rust", &RustAdapter, &invalid)
                .is_err()
        );
        assert_eq!(
            store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
                    [oid.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "invalid macro identity must roll back the entire publication"
        );
        drop(invalid);
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        drop(state);
        drop(store);
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        assert_eq!(
            store
                .rust_usage_facts(oid, "rust")
                .unwrap()
                .module_routes
                .item_macros,
            expected
        );
        let generation = store.current_generation("rust").unwrap();
        let routes = store
            .rust_module_route_facts_while("rust", generation, &[oid], &|| true)
            .unwrap()
            .unwrap();
        assert_eq!(routes[&oid].item_macros, expected);
        let conn = store.read_conn().unwrap();
        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(source_rust_item_macros)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            !columns.iter().any(|column| matches!(
                column.as_str(),
                "exported" | "visible_after" | "scope_start" | "scope_end"
            )),
            "{columns:?}"
        );
        drop(conn);
        // Simulate a legacy or damaged publication without bypassing either
        // typed reader: NULL is unavailable, never a private/non-macro result.
        store.conn.execute(|conn| {
            conn.execute_batch(
                "DROP TRIGGER source_rust_declaration_properties_no_update_after_seal;
                 UPDATE source_rust_declaration_properties SET declaration_kind = NULL, macro_exported = NULL;",
            ).unwrap();
        });
        assert!(store.rust_usage_facts(oid, "rust").is_err());
        let generation = store.current_generation("rust").unwrap();
        assert!(
            store
                .rust_declaration_properties(oid, generation, &RustAdapter, &file, &|| true)
                .is_err()
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "9fba40a6cb46: persisted macro scope trusted stale context instead of canonical source identity"
    )]
    #[test]
    fn canonical_rust_macro_scope_requires_source_context_and_repairs() {
        let source = "mod nested { macro_rules! local_macro { () => {}; } }\n";
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let file = fixture.file("src/lib.rs");
        let state = parse_state(&RustAdapter, &file);
        let expected = state.rust_usage_facts.module_routes.item_macros.clone();
        assert_eq!(expected.len(), 1);
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        store.conn.execute(|conn| {
            conn.execute_batch(
                "DROP TRIGGER source_rust_macro_definitions_no_update_after_seal;
                 UPDATE source_rust_macro_definitions SET context_occurrence_id = NULL;",
            )
            .unwrap();
        });
        assert!(store.rust_usage_facts(oid, "rust").is_err());
        let generation = store.current_generation("rust").unwrap();
        assert!(
            store
                .rust_module_route_facts_while("rust", generation, &[oid], &|| true)
                .is_err()
        );
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        assert_eq!(
            store
                .rust_usage_facts(oid, "rust")
                .unwrap()
                .module_routes
                .item_macros,
            expected
        );
    }

    #[test]
    fn canonical_rust_declaration_properties_reopen_preserve_alternatives_and_fail_closed() {
        use brokk_bifrost_core::analyzer::rust_facts::{RustCfgCondition, RustDeclarationBoundary};
        let source = r#"
pub struct Unit;
#[non_exhaustive]
pub struct Restricted(pub usize, pub(crate) usize);
pub struct Named { pub field: usize }
pub trait Owner { fn defaulted() {} }
impl Unit { pub fn inherent() {} }
pub fn outer() { const LOCAL: u8 = 0; }
macro_rules! replay { ($($item:item)*) => { $($item)* }; }
replay! {
    #[cfg(feature = "x")]
    pub fn repeated() {}
    #[cfg(not(feature = "x"))]
    pub fn repeated() {}
}
"#;
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let file = fixture.file("src/lib.rs");
        let state = parse_state(&RustAdapter, &file);
        let facts = state.source_facts.as_ref().unwrap();
        let local_property = facts
            .rust_declaration_properties
            .iter()
            .find(|property| {
                property.nearest_declaration_boundary
                    == RustDeclarationBoundary::LocalBlockOrFunction
            })
            .expect("the native-only local constant has a source property")
            .clone();
        let mut expected = state
            .source_declaration_units
            .iter()
            .map(|(id, unit)| {
                let property = facts
                    .rust_declaration_properties
                    .iter()
                    .find(|property| property.declaration == *id)
                    .unwrap();
                (unit.clone(), property.clone())
            })
            .collect::<Vec<_>>();
        expected.sort_by_key(|(_, property)| property.declaration.get());
        let oid = oid_for(source.as_bytes());
        let path = fixture.root().join("declaration-properties.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "declaration-property-test")
            .unwrap();
        let mut invalid = state.clone();
        let invalid_property = &mut invalid
            .source_facts
            .as_mut()
            .unwrap()
            .rust_declaration_properties[0];
        invalid_property.has_impl_or_trait_ancestor = false;
        invalid_property.nearest_declaration_boundary = RustDeclarationBoundary::Impl;
        assert!(
            store
                .write_parsed_blob(oid, "rust", &RustAdapter, &invalid)
                .is_err()
        );
        assert_eq!(
            store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
                    [oid.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "invalid ancestry must roll back the complete blob"
        );
        drop(invalid);
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        drop(state);
        drop(store);

        let store = AnalyzerStore::open_persistent(&path).unwrap();
        let read = || {
            store
                .rust_declaration_properties(oid, generation, &RustAdapter, &file, &|| true)
                .unwrap()
                .unwrap()
        };
        let actual = read();
        assert_eq!(actual, expected);
        // The display declaration walk does not admit function-body items.
        // Their canonical native source rows still survive ordinary publication.
        let local_boundary = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT property.has_impl_or_trait_ancestor, property.nearest_declaration_boundary
             FROM source_rust_declaration_properties AS property
             JOIN blobs ON blobs.id = property.blob_id
             WHERE blobs.blob_oid = ?1 AND blobs.lang = 'rust' AND property.declaration_id = ?2",
                params![oid.to_string(), i64::from(local_property.declaration.get())],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, i64>(1)?)),
            )
            .unwrap();
        assert_eq!(local_boundary, (false, 1));
        {
            let conn = store.read_conn().unwrap();
            let checks = std::cell::Cell::new(0);
            assert!(
                read_unit_rows_while(
                    &conn,
                    &oid.to_string(),
                    "rust",
                    &RustAdapter,
                    &file,
                    &|| {
                        checks.set(checks.get() + 1);
                        true
                    }
                )
                .unwrap()
                .is_some()
            );
            // Exercise cancellation throughout raw rows, FQ segments, and
            // mounted CodeUnit construction, including the final checkpoint.
            for stop in 1..=checks.get() {
                let step = std::cell::Cell::new(0);
                assert!(
                    read_unit_rows_while(
                        &conn,
                        &oid.to_string(),
                        "rust",
                        &RustAdapter,
                        &file,
                        &|| {
                            step.set(step.get() + 1);
                            step.get() < stop
                        }
                    )
                    .unwrap()
                    .is_none(),
                    "unit hydration ignored cancellation at {stop}"
                );
            }
        }
        let repeated: Vec<_> = actual
            .iter()
            .filter(|(unit, _)| unit.identifier() == "repeated")
            .collect();
        assert_eq!(repeated.len(), 2);
        assert_eq!(repeated[0].0, repeated[1].0);
        assert_ne!(repeated[0].1.declaration, repeated[1].1.declaration);
        assert!(matches!(
            repeated[0].1.cfg_condition,
            RustCfgCondition::Atom(_)
        ));
        assert!(
            repeated[0]
                .1
                .cfg_condition
                .proven_mutually_exclusive(&repeated[1].1.cfg_condition)
        );
        let property = |name| {
            &actual
                .iter()
                .find(|(unit, _)| unit.identifier() == name)
                .unwrap_or_else(|| panic!("missing property for {name} in {actual:?}"))
                .1
        };
        for (name, ancestor, boundary) in [
            ("Unit", false, RustDeclarationBoundary::ModuleOrFile),
            ("defaulted", true, RustDeclarationBoundary::Trait),
            ("inherent", true, RustDeclarationBoundary::Impl),
            ("repeated", false, RustDeclarationBoundary::ModuleOrFile),
        ] {
            assert_eq!(
                property(name).has_impl_or_trait_ancestor,
                ancestor,
                "{name}"
            );
            assert_eq!(
                property(name).nearest_declaration_boundary,
                boundary,
                "{name}"
            );
        }
        assert!(
            property("Unit")
                .value_constructor
                .as_ref()
                .unwrap()
                .field_visibilities
                .is_empty()
        );
        assert!(property("Named").value_constructor.is_none());
        let restricted = property("Restricted").value_constructor.as_ref().unwrap();
        assert!(restricted.non_exhaustive);
        assert_eq!(
            restricted.field_visibilities,
            [RustVisibility::Public, RustVisibility::Crate]
        );
        let remounted = store
            .rust_declaration_properties(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/copied.rs"),
                &|| true,
            )
            .unwrap()
            .unwrap();
        for ((original_unit, original), (mounted_unit, mounted)) in actual.iter().zip(&remounted) {
            assert_eq!(original, mounted);
            assert_ne!(original_unit.source(), mounted_unit.source());
        }
        assert!(
            store
                .rust_declaration_properties(oid, generation, &RustAdapter, &file, &|| false)
                .unwrap()
                .is_none()
        );
        let steps = std::cell::Cell::new(0);
        assert!(
            store
                .rust_declaration_properties(oid, generation, &RustAdapter, &file, &|| {
                    steps.set(steps.get() + 1);
                    steps.get() < 3
                })
                .unwrap()
                .is_none()
        );
        let damaged_declaration = i64::from(property("Unit").declaration.get());
        store.conn.execute(move |conn| {
            conn.execute_batch(
                "DROP TRIGGER source_rust_declaration_properties_no_delete_after_seal",
            )
            .unwrap();
            conn.execute(
                "DELETE FROM source_rust_declaration_properties WHERE declaration_id = ?1",
                [damaged_declaration],
            )
            .unwrap();
        });
        assert!(
            store
                .rust_declaration_properties(oid, generation, &RustAdapter, &file, &|| true)
                .is_err()
        );
        let repaired = parse_state(&RustAdapter, &file);
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &repaired)
            .unwrap();
        assert_eq!(read(), expected);
        store.conn.execute(|conn| {
            conn.execute_batch(
                "DROP TRIGGER source_rust_declaration_properties_no_update_after_seal",
            )
            .unwrap();
        });
        for column in ["has_impl_or_trait_ancestor", "nearest_declaration_boundary"] {
            store.conn.execute(move |conn| {
                conn.execute(
                    &format!("UPDATE source_rust_declaration_properties SET {column} = NULL"),
                    [],
                )
                .unwrap();
            });
            assert!(
                store
                    .rust_declaration_properties(oid, generation, &RustAdapter, &file, &|| true)
                    .is_err(),
                "legacy NULL {column} must remain unavailable"
            );
            store
                .write_parsed_blob(oid, "rust", &RustAdapter, &repaired)
                .unwrap();
            assert_eq!(read(), expected);
        }
        store
            .ensure_language_epoch_value("rust", "new-declaration-property-test")
            .unwrap();
        assert!(
            store
                .rust_declaration_properties(oid, generation, &RustAdapter, &file, &|| true)
                .is_err()
        );
    }

    #[test]
    fn embedded_rust_declaration_identities_survive_store_reopen() {
        let source = "macro_rules! replay { ($($item:item)*) => { $($item)* }; }\nreplay! { pub struct Item { pub field: usize } pub fn repeated() {} pub fn repeated() {} }\n";
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let facts = state.source_facts.as_ref().unwrap();
        let expected = state.source_declaration_units.iter()
            .filter_map(|(id, unit)| {
                let declaration = facts.occurrences.declaration(*id);
                let occurrence = facts.occurrences.occurrence(declaration.occurrence);
                (occurrence.provenance == brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded)
                    .then(|| (i64::from(id.get()), unit.identifier().to_owned(),
                        occurrence.range.start_byte as i64, occurrence.range.end_byte as i64))
            }).collect::<Vec<_>>();
        assert_eq!(expected.len(), 4);
        let repeated = expected
            .iter()
            .filter(|row| row.1 == "repeated")
            .collect::<Vec<_>>();
        assert_eq!(repeated.len(), 2);
        assert_ne!(repeated[0].0, repeated[1].0);
        assert_ne!(repeated[0].2, repeated[1].2);
        let oid = oid_for(source.as_bytes());
        let path = fixture.root().join("embedded-declarations.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        drop(state);
        drop(store);

        let reopened = AnalyzerStore::open_persistent(&path).unwrap();
        let conn = reopened.read_conn().unwrap();
        let actual = conn.prepare(
            "SELECT declaration.declaration_id, unit.identifier, occurrence.start_byte, occurrence.end_byte
             FROM blobs AS blob
             JOIN source_declarations AS declaration ON declaration.blob_id = blob.id
             JOIN source_occurrences AS occurrence
               ON occurrence.blob_id = declaration.blob_id
              AND occurrence.occurrence_id = declaration.occurrence_id
             JOIN source_declaration_units AS link
               ON link.blob_id = declaration.blob_id
              AND link.declaration_id = declaration.declaration_id
             JOIN code_units AS unit ON unit.blob_id = link.blob_id AND unit.unit_key = link.unit_key
             WHERE blob.blob_oid = ?1 AND blob.lang = 'rust' AND occurrence.provenance = 'embedded'
             ORDER BY declaration.declaration_id"
        ).unwrap().query_map([oid.to_string()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
            .unwrap().collect::<rusqlite::Result<Vec<(i64, String, i64, i64)>>>().unwrap();
        assert_eq!(actual, expected);
    }

    /// The items of a same-file, arguments-only passthrough invocation are
    /// declared once, against the identity declaration replay gave them, and
    /// bridged to a native definition site. Their access authority names the
    /// module that holds the invocation: replay parses the invocation's
    /// arguments as their own tree, whose root is a file-root context whose
    /// parent is the invocation's context, and that root is not a module. The
    /// projection continues through it to the enclosing module, which is a
    /// primary context, so the primary-module requirement holds for an
    /// embedded declaration exactly as it does for a primary one.
    #[test]
    fn bridged_macro_items_take_the_module_that_holds_their_invocation() {
        let source = "macro_rules! replay { ($($item:item)*) => { $($item)* }; }\npub mod inner {\n    replay! { pub fn nested() {} }\n}\nreplay! { pub fn top() {} }\n";
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let oid = oid_for(source.as_bytes());
        let path = fixture.root().join("bridged-macro-items.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        drop(state);
        let conn = store.read_conn().unwrap();
        let actual = conn
            .prepare(
                "SELECT unit.identifier, occurrence.provenance, module_unit.identifier
                 FROM blobs AS blob
                 JOIN resolution_rust_declaration_authorities AS authority
                   ON authority.blob_id = blob.id
                 JOIN source_native_declaration_bridges AS bridge
                   ON bridge.blob_id = authority.blob_id
                  AND bridge.declaration_id = authority.declaration
                 JOIN source_declarations AS declaration
                   ON declaration.blob_id = authority.blob_id
                  AND declaration.declaration_id = authority.declaration
                 JOIN source_occurrences AS occurrence
                   ON occurrence.blob_id = declaration.blob_id
                  AND occurrence.occurrence_id = declaration.occurrence_id
                 JOIN source_declaration_units AS link
                   ON link.blob_id = authority.blob_id
                  AND link.declaration_id = authority.declaration
                 JOIN code_units AS unit
                   ON unit.blob_id = link.blob_id AND unit.unit_key = link.unit_key
                 LEFT JOIN source_declaration_units AS module_link
                   ON module_link.blob_id = authority.blob_id
                  AND module_link.declaration_id = authority.module_declaration
                 LEFT JOIN code_units AS module_unit
                   ON module_unit.blob_id = module_link.blob_id
                  AND module_unit.unit_key = module_link.unit_key
                 WHERE blob.blob_oid = ?1 AND blob.lang = 'rust'
                   AND unit.identifier IN ('nested', 'top')
                 ORDER BY unit.identifier",
            )
            .unwrap()
            .query_map([oid.to_string()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<(String, String, Option<String>)>>>()
            .unwrap();
        assert_eq!(
            actual,
            [
                (
                    "nested".to_owned(),
                    "embedded".to_owned(),
                    Some("inner".to_owned())
                ),
                ("top".to_owned(), "embedded".to_owned(), None),
            ]
        );
    }

    #[test]
    fn raw_embedded_imports_survive_store_reopen_without_projection_membership() {
        use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;

        let source = r#"
wrap! {
    use crate::{First as Alias, Other};
    mod inside {
        use crate::Thing as Nested;
        extern crate dep as renamed;
    }
}
helper::wrap! {
    use crate::{Hidden, HiddenOther};
    extern crate rejected as hidden_dep;
}
"#;
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let file = fixture.file("src/lib.rs");
        let state = parse_state(&RustAdapter, &file);
        let source_facts = state.source_facts.as_ref().unwrap();
        let expected_imports = source_facts.imports.clone();
        let expected_generic = state.imports.clone();
        let expected_generic_ids = source_facts
            .generic_imports
            .iter()
            .map(|id| i64::from(id.get()))
            .collect::<Vec<_>>();
        assert_eq!(
            source_facts
                .generic_imports
                .iter()
                .map(|id| expected_imports[id.index()].identifier.as_deref())
                .collect::<Vec<_>>(),
            [Some("First"), Some("Other")]
        );
        let embedded_import_indices = expected_imports
            .iter()
            .enumerate()
            .filter_map(|(index, import)| {
                (source_facts
                    .occurrences
                    .occurrence(import.declaration)
                    .provenance
                    == SourceOccurrenceProvenance::Embedded)
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(embedded_import_indices.len(), expected_imports.len());
        let source_only_import_indices = embedded_import_indices
            .iter()
            .copied()
            .filter(|index| !expected_generic_ids.contains(&i64::try_from(*index).unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(source_only_import_indices.len(), 5);
        let source_only = |identifier: &str| {
            source_only_import_indices
                .iter()
                .map(|index| &expected_imports[*index])
                .find(|import| import.identifier.as_deref() == Some(identifier))
                .unwrap_or_else(|| panic!("source-only import {identifier}"))
        };
        let nested = source_only("Thing");
        assert_eq!(nested.alias.as_deref(), Some("Nested"));
        let dependency = source_only("dep");
        assert_eq!(dependency.alias.as_deref(), Some("renamed"));
        assert_eq!(
            dependency.path.as_ref().unwrap().kind,
            Some(StructuredImportPathKind::ExternCrate)
        );
        let hidden = source_only("Hidden");
        let hidden_other = source_only("HiddenOther");
        assert_eq!(hidden.alias, None);
        assert_eq!(hidden_other.alias, None);
        assert_eq!(hidden.declaration, hidden_other.declaration);
        let rejected = source_only("rejected");
        assert_eq!(rejected.alias.as_deref(), Some("hidden_dep"));
        assert_eq!(
            rejected.path.as_ref().unwrap().kind,
            Some(StructuredImportPathKind::ExternCrate)
        );

        let expected_rows = expected_imports
            .iter()
            .enumerate()
            .map(|(index, import)| {
                (
                    i64::try_from(index).unwrap(),
                    import.statement.clone(),
                    i64::from(import.is_wildcard),
                    i64::from(import.is_global),
                    import.identifier.clone(),
                    import.alias.clone(),
                    import
                        .path
                        .as_ref()
                        .and_then(|path| path.kind)
                        .map(|kind| kind.persist_tag().to_owned()),
                    i64::from(import.declaration.get()),
                    import.target.map(|id| i64::from(id.get())),
                    import.alias_occurrence.map(|id| i64::from(id.get())),
                )
            })
            .collect::<Vec<_>>();
        let expected_raw_provenance = embedded_import_indices
            .iter()
            .map(|index| {
                let import = &expected_imports[*index];
                (
                    i64::try_from(*index).unwrap(),
                    "embedded".to_string(),
                    import.target.map(|id| {
                        assert_eq!(
                            source_facts.occurrences.occurrence(id).provenance,
                            SourceOccurrenceProvenance::Embedded
                        );
                        "embedded".to_string()
                    }),
                    import.alias_occurrence.map(|id| {
                        assert_eq!(
                            source_facts.occurrences.occurrence(id).provenance,
                            SourceOccurrenceProvenance::Embedded
                        );
                        "embedded".to_string()
                    }),
                )
            })
            .collect::<Vec<_>>();
        let expected_usage = state.rust_usage_facts.clone();
        let oid = oid_for(source.as_bytes());
        let path = fixture.root().join("raw-embedded-imports.db");
        let store = AnalyzerStore::open_persistent(&path).unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        drop(state);
        drop(store);

        let reopened = AnalyzerStore::open_persistent(&path).unwrap();
        let conn = reopened.read_conn().unwrap();
        let actual_rows = conn
            .prepare(
                "SELECT import_id, statement, is_wildcard, is_global, identifier, alias,
                        path_kind, declaration_occurrence_id, target_occurrence_id,
                        alias_occurrence_id
                 FROM source_imports
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust')
                 ORDER BY import_id",
            )
            .unwrap()
            .query_map([oid.to_string()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(actual_rows, expected_rows);

        let actual_raw_provenance = conn
            .prepare(
                "SELECT import.import_id, declaration.provenance,
                        target.provenance, alias.provenance
                 FROM source_imports AS import
                 JOIN source_occurrences AS declaration
                   ON declaration.blob_id = import.blob_id
                  AND declaration.occurrence_id = import.declaration_occurrence_id
                 LEFT JOIN source_occurrences AS target
                   ON target.blob_id = import.blob_id
                  AND target.occurrence_id = import.target_occurrence_id
                 LEFT JOIN source_occurrences AS alias
                   ON alias.blob_id = import.blob_id
                  AND alias.occurrence_id = import.alias_occurrence_id
                 WHERE import.blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust')
                   AND declaration.provenance = 'embedded'
                 ORDER BY import.import_id",
            )
            .unwrap()
            .query_map([oid.to_string()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(actual_raw_provenance, expected_raw_provenance);

        let persisted_generic_ids = conn
            .prepare(
                "SELECT source_import_id FROM import_statements
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust')
                 ORDER BY ordinal",
            )
            .unwrap()
            .query_map([oid.to_string()], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(persisted_generic_ids, expected_generic_ids);
        let persisted_target_ids = conn
            .prepare(
                "SELECT source_import_id FROM rust_import_targets
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust')
                   AND source_import_id IS NOT NULL
                 ORDER BY source_import_id",
            )
            .unwrap()
            .query_map([oid.to_string()], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let persisted_export_ids = conn
            .prepare(
                "SELECT source_import_id FROM rust_exports
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust')
                   AND source_import_id IS NOT NULL
                 ORDER BY source_import_id",
            )
            .unwrap()
            .query_map([oid.to_string()], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(persisted_target_ids.is_empty());
        assert!(persisted_export_ids.is_empty());
        drop(conn);
        assert_eq!(
            read_import_infos(&reopened.read_conn().unwrap(), &oid.to_string(), "rust").unwrap(),
            expected_generic
        );
        assert_eq!(
            reopened.rust_usage_facts(oid, "rust").unwrap(),
            expected_usage
        );
    }

    #[test]
    fn canonical_import_local_scope_is_preserved_and_publication_validated() {
        let source = "fn local() { use crate::Thing; }\n";
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store
            .ensure_language_epoch_value("rust", "missing-import-scope")
            .unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        let facts = store.rust_usage_facts(oid, "rust").unwrap();
        assert_eq!(facts.import_targets, state.rust_usage_facts.import_targets);
        assert_eq!(facts.import_targets.len(), 1);
        assert!(facts.import_targets[0].local_extent.is_some());
        let locations = store
            .load_rust_import_source_locations(
                oid,
                generation,
                &[0].into_iter().collect(),
                &CancellationToken::new(),
            )
            .unwrap()
            .unwrap();
        assert!(!locations[&0].root_owned);
        assert_eq!(locations[&0].target.unwrap().text(source), "Thing");

        // Reopen only inside this rolled-back fixture transaction to exercise
        // the publication boundary with otherwise valid production rows.
        let mut conn = store.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute_batch(
            "DROP TRIGGER source_fact_manifests_no_reopen;
             UPDATE source_fact_manifests SET publication_state = 'building';",
        )
        .unwrap();
        let blob_id: i64 = tx
            .query_row(
                "SELECT blob_id FROM source_rust_import_contexts",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let error = tx
            .execute(
                "UPDATE source_rust_import_contexts SET local_scope_start_byte = NULL
                 WHERE blob_id = ?1",
                [blob_id],
            )
            .expect_err("a present local scope requires its inline span");
        assert!(
            error.to_string().contains("CHECK constraint failed"),
            "{error}"
        );
        assert!(
            error.to_string().contains("local_scope_start_byte"),
            "{error}"
        );
        tx.rollback().unwrap();
    }

    #[brokk_bifrost_test_macros::hardwon(
        "440ca895ccfb: missing canonical Rust import segments were accepted as complete authority"
    )]
    #[test]
    fn missing_canonical_import_segments_fail_and_republication_recovers() {
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", "use crate::model::Thing as Local;\n")
            .build();
        let file = fixture.file("src/lib.rs");
        let state = parse_state(&RustAdapter, &file);
        let oid = oid_for(b"use crate::model::Thing as Local;\n");
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        {
            // Deliberate damaged-cache input, impossible through the sealed writer.
            let conn = store.conn.lock().unwrap();
            conn.execute_batch("DROP TRIGGER source_import_segments_no_delete_after_seal")
                .unwrap();
            conn.execute("DELETE FROM source_import_segments", [])
                .unwrap();
        }
        let error = store.rust_usage_facts(oid, "rust").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("segments disagree with lookup header"),
            "{error}"
        );
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        assert_eq!(
            store.rust_usage_facts(oid, "rust").unwrap(),
            state.rust_usage_facts
        );
    }

    #[test]
    fn canonical_import_properties_ignore_stale_dtos_and_store_once() {
        let source = "pub use crate::model::Public as Exported;\nfn local() { use crate::LocalOnly; mod inner { use crate::Inside; } }\nextern crate serde as serialization;\nmod nested { use crate::model::{Thing as Local, *}; }\n";
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", source)
            .build();
        let file = fixture.file("src/lib.rs");
        let mut state = parse_state(&RustAdapter, &file);
        let expected = state.imports.clone();
        let source_facts = state
            .source_facts
            .as_ref()
            .expect("Rust producer source facts");
        let expected_source_imports = source_facts.imports.clone();
        let expected_generic_imports = source_facts.generic_imports.clone();
        let expected_import_contexts = source_facts.rust_import_contexts.clone();
        let expected_rust_facts = state.rust_usage_facts.clone();
        assert_eq!(expected.len(), 4);
        assert_eq!(expected_source_imports.len(), 6);
        assert_eq!(expected_generic_imports.len(), expected.len());
        assert_eq!(expected_import_contexts.len(), 5);
        assert!(
            expected
                .iter()
                .any(|import| !import.path.as_ref().unwrap().lexical_scopes.is_empty())
        );
        // Consumer DTO ranges and duplicated semantic fields are no longer
        // publication inputs. Deliberately make them unusable while preserving
        // the producer's exact source-import ids and owner extensions.
        for import in &mut state.imports {
            import.raw_snippet = "stale display statement".to_string();
            import.is_wildcard = !import.is_wildcard;
            import.is_global = !import.is_global;
            import.identifier = Some("stale_identifier".to_string());
            import.alias = Some("stale_alias".to_string());
            let path = import.path.as_mut().unwrap();
            path.declaration_start_byte = usize::MAX;
            path.kind = Some(StructuredImportPathKind::ExternCrate);
            path.segments = vec!["stale".to_string()];
            path.lexical_prefixes = vec!["stale_prefix".to_string()];
            path.lexical_scopes.clear();
            import.binder_span = None;
        }
        for target in &mut state.rust_usage_facts.import_targets {
            target.native_scope = None;
            target.module_path = vec!["stale_module".to_string()];
            target.bound_name = Some("stale_bound".to_string());
            target.imported_name = Some("stale_imported".to_string());
            target.is_glob = !target.is_glob;
            target.leading_absolute = !target.leading_absolute;
            target.is_extern_crate = !target.is_extern_crate;
            target.owner_module = "stale_owner".to_string();
            target.owner_start = usize::MAX;
            target.owner_end = usize::MAX;
            target.local_extent = Some((usize::MAX, usize::MAX));
            target.visibility = RustVisibility::InPath(vec!["stale".to_string()]);
            target.cfg_condition =
                brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Unknown;
        }
        for export in &mut state.rust_usage_facts.exports {
            export.exported_name = Some("stale_exported".to_string());
            export.source_path = "stale_source".to_string();
            export.imported_name = Some("stale_imported".to_string());
            export.is_glob = !export.is_glob;
        }
        let oid = oid_for(source.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        let conn = store.read_conn().unwrap();
        assert_eq!(
            read_import_infos(&conn, &oid.to_string(), "rust").unwrap(),
            expected
        );
        drop(conn);
        assert_eq!(
            store.rust_usage_facts(oid, "rust").unwrap(),
            expected_rust_facts,
            "Rust projections are rehydrated from canonical source-import properties"
        );

        let conn = store.read_conn().unwrap();
        let blob_id: i64 = conn
            .query_row(
                "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
                [oid.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        let (generic_rows, stale_generic_rows): (i64, i64) = conn
            .query_row(
                "SELECT count(*), count(*) FILTER (WHERE source_import_id IS NOT NULL
                    AND statement IS NULL AND is_wildcard IS NULL AND is_global IS NULL
                    AND identifier IS NULL AND alias IS NULL AND path_kind IS NULL
                    AND declaration_start_byte IS NULL AND binder_start IS NULL
                    AND binder_end IS NULL)
                 FROM import_statements WHERE blob_id = ?1",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(generic_rows, expected.len() as i64);
        assert_eq!(stale_generic_rows, generic_rows);
        let generic_source_ids = conn
            .prepare(
                "SELECT source_import_id FROM import_statements
                 WHERE blob_id = ?1 ORDER BY ordinal",
            )
            .unwrap()
            .query_map([blob_id], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            generic_source_ids,
            expected_generic_imports
                .iter()
                .map(|id| i64::from(id.get()))
                .collect::<Vec<_>>()
        );
        let canonical_rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM source_imports WHERE blob_id = ?1",
                [blob_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(canonical_rows, expected_source_imports.len() as i64);
        let stored_context_count: i64 = conn
            .query_row(
                "SELECT rust_import_context_count FROM source_fact_manifests WHERE blob_id = ?1",
                [blob_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_context_count, expected_import_contexts.len() as i64);

        let mut expected_context_rows = expected_import_contexts
            .iter()
            .map(|context| {
                (
                    i64::from(context.declaration.get()),
                    context.owner_module.clone(),
                    context.owner_scope.map(|id| i64::from(id.get())),
                    context.local_scope.map(|id| i64::from(id.get())),
                    encode_rust_visibility(&context.visibility),
                    encode_rust_cfg_condition(&context.cfg_condition),
                )
            })
            .collect::<Vec<_>>();
        expected_context_rows.sort_by_key(|row| row.0);
        let actual_context_rows = conn
            .prepare(
                "SELECT declaration_occurrence_id, owner_module,
                        owner_scope_occurrence_id, local_scope_occurrence_id,
                        visibility, cfg_condition
                 FROM source_rust_import_contexts
                 WHERE blob_id = ?1 ORDER BY declaration_occurrence_id",
            )
            .unwrap()
            .query_map([blob_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<(i64, String, Option<i64>, Option<i64>, String, String)>>>();
        assert_eq!(actual_context_rows.unwrap(), expected_context_rows);
        let local_declaration = expected_source_imports
            .iter()
            .find(|import| import.statement.contains("use crate::LocalOnly"))
            .expect("local import source fact")
            .declaration;
        let root_declaration = expected_source_imports
            .iter()
            .find(|import| import.statement.contains("use crate::model::Public"))
            .expect("root import source fact")
            .declaration;
        let inner_declaration = expected_source_imports
            .iter()
            .find(|import| import.statement.contains("use crate::Inside"))
            .expect("function-nested module import source fact")
            .declaration;
        let bounds = conn
            .prepare(
                "SELECT context.declaration_occurrence_id,
                        declaration.start_byte, declaration.end_byte,
                        owner.start_byte, owner.end_byte,
                        local.start_byte, local.end_byte
                 FROM source_rust_import_contexts AS context
                 JOIN source_occurrences AS declaration
                   ON declaration.blob_id = context.blob_id
                  AND declaration.occurrence_id = context.declaration_occurrence_id
                 LEFT JOIN source_occurrences AS owner
                   ON owner.blob_id = context.blob_id
                  AND owner.occurrence_id = context.owner_scope_occurrence_id
                 LEFT JOIN source_occurrences AS local
                   ON local.blob_id = context.blob_id
                  AND local.occurrence_id = context.local_scope_occurrence_id
                 WHERE context.blob_id = ?1
                   AND context.declaration_occurrence_id IN (?2, ?3, ?4)
                 ORDER BY context.declaration_occurrence_id",
            )
            .unwrap()
            .query_map(
                rusqlite::params![
                    blob_id,
                    i64::from(root_declaration.get()),
                    i64::from(local_declaration.get()),
                    i64::from(inner_declaration.get()),
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                    ))
                },
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(bounds.len(), 3);
        let root_bounds = bounds
            .iter()
            .find(|row| row.0 == i64::from(root_declaration.get()))
            .unwrap();
        assert!(root_bounds.1 >= 0 && root_bounds.2 as usize <= source.len());
        assert!(root_bounds.3.is_none() && root_bounds.5.is_none());
        let local_bounds = bounds
            .iter()
            .find(|row| row.0 == i64::from(local_declaration.get()))
            .unwrap();
        assert!(local_bounds.3.is_none() && local_bounds.4.is_none());
        assert!(local_bounds.5.unwrap() <= local_bounds.1);
        assert!(local_bounds.2 <= local_bounds.6.unwrap());
        let inner_bounds = bounds
            .iter()
            .find(|row| row.0 == i64::from(inner_declaration.get()))
            .unwrap();
        assert!(inner_bounds.3.unwrap() <= inner_bounds.1);
        assert!(inner_bounds.2 <= inner_bounds.4.unwrap());
        assert!(inner_bounds.5.unwrap() <= inner_bounds.1);
        assert!(inner_bounds.2 <= inner_bounds.6.unwrap());

        let (target_rows, canonical_target_headers): (i64, i64) = conn
            .query_row(
                "SELECT count(*), count(*) FILTER (WHERE source_import_id IS NOT NULL
                    AND module_path IS NOT NULL
                    AND ((SELECT is_wildcard FROM source_imports
                          WHERE source_imports.blob_id = rust_import_targets.blob_id
                            AND source_imports.import_id = rust_import_targets.source_import_id) = 1
                         AND bound_name IS NULL
                         OR (SELECT is_wildcard FROM source_imports
                             WHERE source_imports.blob_id = rust_import_targets.blob_id
                               AND source_imports.import_id = rust_import_targets.source_import_id) = 0
                         AND bound_name IS NOT NULL)
                    AND imported_name IS NULL AND is_glob IS NULL
                    AND leading_absolute IS NULL AND is_extern_crate IS NULL
                    AND declaration_occurrence_id IS NULL AND target_occurrence_id IS NULL
                    AND alias_occurrence_id IS NULL
                    AND source_context_occurrence_id IS NOT NULL
                    AND owner_module IS NULL AND owner_start IS NULL AND owner_end IS NULL
                    AND local_start IS NULL AND local_end IS NULL
                    AND visibility IS NULL AND cfg_condition IS NULL)
                 FROM rust_import_targets WHERE blob_id = ?1",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(target_rows, expected_rust_facts.import_targets.len() as i64);
        assert_eq!(canonical_target_headers, target_rows);
        let target_source_ids = conn
            .prepare(
                "SELECT source_import_id FROM rust_import_targets
                 WHERE blob_id = ?1 ORDER BY ordinal",
            )
            .unwrap()
            .query_map([blob_id], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            target_source_ids,
            expected_rust_facts
                .import_targets
                .iter()
                .map(|target| {
                    i64::from(
                        target
                            .source_import_id
                            .expect("Rust target has canonical source-import id")
                            .get(),
                    )
                })
                .collect::<Vec<_>>()
        );
        let target_context_ids = conn
            .prepare(
                "SELECT source_import_id, source_context_occurrence_id
                 FROM rust_import_targets
                 WHERE blob_id = ?1 ORDER BY ordinal",
            )
            .unwrap()
            .query_map([blob_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            target_context_ids,
            expected_rust_facts
                .import_targets
                .iter()
                .map(|target| {
                    let source_import = &expected_source_imports[target
                        .source_import_id
                        .expect("Rust target has canonical source-import id")
                        .index()];
                    (
                        i64::from(target.source_import_id.unwrap().get()),
                        i64::from(source_import.declaration.get()),
                    )
                })
                .collect::<Vec<_>>()
        );

        let (export_rows, canonical_exports): (i64, i64) = conn
            .query_row(
                "SELECT count(*), count(*) FILTER (WHERE source_import_id IS NOT NULL
                    AND exported_name IS NOT NULL AND source_path IS NULL
                    AND imported_name IS NULL AND is_glob IS NULL)
                 FROM rust_exports WHERE blob_id = ?1",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(export_rows, expected_rust_facts.exports.len() as i64);
        assert_eq!(canonical_exports, export_rows);
        let export_source_ids = conn
            .prepare(
                "SELECT source_import_id FROM rust_exports
                 WHERE blob_id = ?1 ORDER BY ordinal",
            )
            .unwrap()
            .query_map([blob_id], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            export_source_ids,
            expected_rust_facts
                .exports
                .iter()
                .map(|export| {
                    i64::from(
                        export
                            .source_import_id
                            .expect("Rust export has canonical source-import id")
                            .get(),
                    )
                })
                .collect::<Vec<_>>()
        );

        let (canonical_segments, canonical_scopes, canonical_prefixes): (i64, i64, i64) = conn
            .query_row(
                "SELECT
                    (SELECT count(*) FROM source_import_segments WHERE blob_id = ?1),
                    (SELECT count(*) FROM source_import_scopes WHERE blob_id = ?1),
                    (SELECT count(*) FROM source_import_prefixes WHERE blob_id = ?1)",
                [blob_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            canonical_segments as usize,
            expected_source_imports
                .iter()
                .map(|import| import.path.as_ref().map_or(0, |path| path.segments.len()))
                .sum::<usize>()
        );
        assert_eq!(
            canonical_scopes as usize,
            expected_source_imports
                .iter()
                .map(|import| import
                    .path
                    .as_ref()
                    .map_or(0, |path| path.lexical_scopes.len()))
                .sum::<usize>()
        );
        assert_eq!(
            canonical_prefixes as usize,
            expected_source_imports
                .iter()
                .map(|import| import
                    .path
                    .as_ref()
                    .map_or(0, |path| path.lexical_prefixes.len()))
                .sum::<usize>()
        );
    }

    #[test]
    fn canonical_generic_import_batches_seek_900_oids_before_and_after_statistics() {
        const SOURCE: &str = "mod nested { use crate::model::Thing as Local; mod leaf; }\npub struct Tuple(pub usize, usize);\n#[macro_export]\nmacro_rules! exported { () => {}; }\nouter! { mod gated; }\n";
        let fixture = crate::inline_project::InlineTestProject::new()
            .file("src/lib.rs", SOURCE)
            .build();
        let file = fixture.file("src/lib.rs");
        let state = parse_state(&RustAdapter, &file);
        assert_eq!(state.imports.len(), 1);
        assert!(
            state
                .imports
                .first()
                .and_then(|import| import.path.as_ref())
                .is_some_and(|path| !path.lexical_scopes.is_empty())
        );
        assert!(
            state
                .source_facts
                .as_ref()
                .is_some_and(|facts| facts.generic_imports.len() == state.imports.len())
        );

        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("rust").unwrap();
        let oids: Vec<_> = (0..4096)
            .map(|index| oid_for(format!("canonical generic import plan blob {index}").as_bytes()))
            .collect();
        let requested: Vec<_> = oids.iter().take(900).map(ToString::to_string).collect();
        let prepared = oids
            .iter()
            .map(|oid| {
                AnalyzerStore::prepare_parsed_blob(
                    *oid,
                    "rust",
                    generation,
                    &RustAdapter,
                    Arc::new(state.clone()),
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let (outcomes, stats) =
            store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
        assert_eq!(stats.committed_blobs, oids.len());
        assert_eq!(
            stats.failed_blobs, 0,
            "persisted canonical import rows: {stats:?}"
        );
        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));

        let placeholders = chunk_placeholders(&requested);
        assert_eq!(requested.len(), 900);

        let check_plan = |label: &str, plan: &[String]| {
            assert!(
                plan.iter().any(|detail| {
                    detail.contains("SEARCH keys USING COVERING INDEX sqlite_autoindex_blobs_1")
                }),
                "{label} must seek requested parent blobs: {plan:#?}"
            );
            // Canonical import spans live on the import and lexical-scope
            // rows. Each relation must be reached by an equality seek rather
            // than scanning the publication or decoding its occurrence arena.
            let seeks = |alias: &str| {
                plan.iter().any(|detail| {
                    detail.starts_with(&format!("SEARCH {alias} USING")) && detail.contains("=?")
                })
            };
            assert!(
                seeks("import")
                    || seeks("import_statements")
                    || seeks("imports")
                    || seeks("scope")
                    || seeks("facts"),
                "{label} must seek canonical import rows by parent key: {plan:#?}"
            );
            assert!(
                plan.iter().any(|detail| {
                    (detail.starts_with("SEARCH source USING")
                        || detail.starts_with("SEARCH scope USING"))
                        && detail.contains("blob_id=? AND import_id=?")
                }),
                "{label} must seek inline spans by canonical import key: {plan:#?}"
            );
            assert!(
                plan.iter().all(|detail| {
                    (!detail.starts_with("SCAN ") || detail.starts_with("SCAN CONSTANT ROW"))
                        && !detail.contains("MATERIALIZE")
                }),
                "{label} must not scan or materialize unbounded canonical rows: {plan:#?}"
            );
        };

        let check = |store: &AnalyzerStore| {
            let routes = store
                .rust_module_route_facts_while("rust", generation, &oids[..400], &|| true)
                .unwrap()
                .unwrap();
            assert_eq!(routes.len(), 400);
            assert!(
                routes
                    .values()
                    .all(|route| route.item_macros.len() == 1 && route.item_macros[0].exported)
            );
            let properties = store
                .rust_declaration_properties(oids[0], generation, &RustAdapter, &file, &|| true)
                .unwrap()
                .unwrap();
            assert_eq!(properties.len(), 5);
            assert_eq!(
                properties
                    .iter()
                    .find(|(unit, _)| unit.identifier() == "Tuple")
                    .unwrap()
                    .1
                    .value_constructor
                    .as_ref()
                    .unwrap()
                    .field_visibilities,
                [RustVisibility::Public, RustVisibility::Private]
            );
            let conn = store.read_conn().unwrap();
            let blob_id: i64 = conn
                .query_row(
                    "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
                    [&requested[0]],
                    |row| row.get(0),
                )
                .unwrap();
            for (label, sql) in [
                (
                    "source_rust_declaration_properties",
                    source_facts::RUST_DECLARATION_PROPERTIES_SQL,
                ),
                (
                    "source_rust_constructor_fields",
                    source_facts::RUST_CONSTRUCTOR_FIELDS_SQL,
                ),
                (
                    "source_declaration_units",
                    source_facts::SOURCE_DECLARATION_UNITS_SQL,
                ),
            ] {
                let plan = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                    .unwrap()
                    .query_map([blob_id], |row| row.get::<_, String>(3))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(
                    plan.iter()
                        .any(|line| line.contains(&format!("SEARCH {label} USING PRIMARY KEY"))),
                    "{label}: {plan:?}"
                );
                assert!(
                    plan.iter()
                        .all(|line| !line.starts_with("SCAN ") && !line.contains("MATERIALIZE")),
                    "{label}: {plan:?}"
                );
            }
            let property_manifest_plan = conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {}",
                    source_facts::RUST_DECLARATION_PROPERTY_MANIFEST_SQL
                ))
                .unwrap()
                .query_map(
                    params![
                        requested[0],
                        generation.get(),
                        source_facts::SOURCE_FACTS_VERSION
                    ],
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                property_manifest_plan
                    .iter()
                    .all(|line| !line.starts_with("SCAN ") && !line.contains("MATERIALIZE")),
                "declaration publication must seek populated rows: {property_manifest_plan:?}"
            );
            let hydrated = read_import_infos_bulk(&conn, "rust", &requested).unwrap();
            assert_eq!(hydrated.len(), requested.len());
            assert!(hydrated.values().all(|imports| {
                imports.len() == 1
                    && imports[0]
                        .path
                        .as_ref()
                        .is_some_and(|path| path.lexical_scopes.len() == 1)
            }));
            let rust_facts = read_rust_usage_facts_bulk(&conn, "rust", &requested).unwrap();
            assert_eq!(rust_facts.len(), requested.len());
            assert!(rust_facts.values().all(|facts| {
                facts.import_targets.len() == 1
                    && facts.import_targets[0].module_path
                        == ["crate".to_owned(), "model".to_owned()]
                    && facts.import_targets[0].source_import_id.is_some()
            }));

            let params = chunk_params("rust", &requested);
            let readiness_plan = conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN SELECT keys.blob_oid FROM blobs AS keys
                 JOIN blob_meta AS meta ON meta.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
                   AND NOT EXISTS (SELECT 1 FROM rust_published_fact_blobs AS ready
                                   WHERE ready.blob_id = keys.id)"
                ))
                .unwrap()
                .query_map(params_from_iter(params.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                readiness_plan
                    .iter()
                    .all(|line| !line.starts_with("SCAN ") && !line.contains("MATERIALIZE")),
                "canonical module readiness must remain selected-blob bounded: {readiness_plan:#?}"
            );
            let macro_plan = conn
                .prepare(&format!(
                "EXPLAIN QUERY PLAN SELECT keys.blob_oid, facts.macro_name, facts.visible_after,
                    facts.scope_start, facts.scope_end, facts.passthrough,
                    facts.exported, facts.declaration_id
                 FROM blobs AS keys JOIN rust_item_macros AS facts ON facts.blob_id = keys.id
                 WHERE keys.lang = ? AND keys.blob_oid IN ({placeholders})
                 ORDER BY keys.blob_oid, facts.ordinal"
            ))
                .unwrap()
                .query_map(params_from_iter(params.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            // Declaration/context spans are inline; occurrence joins are gone.
            for table in ["macro", "property", "declaration", "definition", "context"] {
                assert!(
                    macro_plan
                        .iter()
                        .any(|line| line.contains(&format!("SEARCH {table} USING PRIMARY KEY"))),
                    "{macro_plan:?}"
                );
            }
            assert!(
                macro_plan
                    .iter()
                    .all(|line| !line.starts_with("SCAN ") && !line.contains("MATERIALIZE")),
                "{macro_plan:?}"
            );
            assert!(
                rust_facts
                    .values()
                    .all(|facts| facts.module_routes.item_macros.len() == 1
                        && facts.module_routes.item_macros[0].exported)
            );
            // The route reader uses exact 400-OID batches, unlike the
            // primitive reader's padded arity ladder.
            let route_placeholders = std::iter::repeat_n("?", 400).collect::<Vec<_>>().join(", ");
            let mut route_params = vec![
                rusqlite::types::Value::Text("rust".into()),
                rusqlite::types::Value::Integer(generation.get()),
            ];
            route_params.extend(
                requested[..400]
                    .iter()
                    .cloned()
                    .map(rusqlite::types::Value::Text),
            );
            let route_plan = conn.prepare(&format!(
                "EXPLAIN QUERY PLAN SELECT keys.blob_oid, facts.macro_name, facts.visible_after,
                     facts.scope_start, facts.scope_end, facts.passthrough, facts.exported, facts.declaration_id
                 FROM rust_published_fact_blobs AS keys
                 JOIN rust_item_macros AS facts ON facts.blob_id = keys.blob_id AND facts.lang = keys.lang
                 WHERE keys.lang = ?1 AND keys.generation = ?2 AND keys.blob_oid IN ({route_placeholders})
                 ORDER BY keys.blob_oid, facts.ordinal"
            )).unwrap().query_map(params_from_iter(route_params.iter()), |row| row.get::<_, String>(3))
                .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            for table in ["macro", "property", "declaration", "definition", "context"] {
                assert!(
                    route_plan
                        .iter()
                        .any(|line| line.contains(&format!("SEARCH {table} USING PRIMARY KEY"))),
                    "{route_plan:?}"
                );
            }
            assert!(
                route_plan
                    .iter()
                    .all(|line| !line.starts_with("SCAN ") && !line.contains("MATERIALIZE")),
                "{route_plan:?}"
            );
            for (table, fields, order) in [
                (
                    "rust_modules",
                    "facts.module_name, facts.is_inline, facts.start_byte, facts.end_byte, facts.cfg_condition",
                    "facts.ordinal",
                ),
                (
                    "rust_module_scopes",
                    "facts.parent_ordinal, facts.module_name, facts.path_attribute, facts.visibility, facts.imports_macros, facts.resolution_scope, facts.body_start, facts.body_end",
                    "facts.ordinal",
                ),
                (
                    "rust_module_routes",
                    "facts.scope_ordinal, facts.module_name, facts.path_attribute, facts.visibility, facts.imports_macros, facts.test_gated, facts.cfg_condition, facts.declaration_start, facts.declaration_end",
                    "facts.ordinal",
                ),
                (
                    "rust_module_route_gates",
                    "facts.route_ordinal, facts.macro_name, facts.invocation_start",
                    "facts.route_ordinal, facts.gate_ordinal",
                ),
            ] {
                let sql = format!(
                    "SELECT keys.blob_oid, {fields} FROM rust_published_fact_blobs AS keys
                     JOIN {table} AS facts ON facts.blob_id = keys.blob_id AND facts.lang = keys.lang
                     WHERE keys.lang = ?1 AND keys.generation = ?2 AND keys.blob_oid IN ({route_placeholders})
                     ORDER BY keys.blob_oid, {order}"
                );
                let plan = conn
                    .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                    .unwrap()
                    .query_map(params_from_iter(route_params.iter()), |row| {
                        row.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(
                    plan.iter()
                        .all(|line| !line.starts_with("SCAN ") && !line.contains("MATERIALIZE")),
                    "selected canonical {table} rows must use bounded index seeks: {plan:#?}"
                );
                let rows = conn
                    .prepare(&sql)
                    .unwrap()
                    .query_map(params_from_iter(route_params.iter()), |row| {
                        row.get::<_, String>(0)
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(
                    rows.len() >= 400,
                    "{table} must exercise populated rows, got {rows:?}"
                );
            }
            let location_plan = conn
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN {}",
                    source_facts::IMPORT_SOURCE_LOCATIONS_SQL
                ))
                .unwrap()
                .query_map(
                    params![requested[0], 0, source_facts::SOURCE_FACTS_VERSION],
                    |row| row.get::<_, String>(3),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            // The helper selects one import, walks its blob arena once, and
            // retains at most the declaration and target occurrences. Scans
            // of those bounded CTEs do not become per-occurrence arena joins.
            assert!(
                location_plan.iter().all(|detail| {
                    !detail.starts_with("SCAN ")
                        || [
                            "SCAN requested",
                            "SCAN imports",
                            "SCAN declaration",
                            "SCAN target",
                            "SCAN entry VIRTUAL TABLE",
                        ]
                        .iter()
                        .any(|prefix| detail.starts_with(prefix))
                }),
                "exact import locations must keep persistent rows keyed: {location_plan:#?}"
            );
            assert_eq!(
                location_plan
                    .iter()
                    .filter(|detail| detail.starts_with("SCAN entry VIRTUAL TABLE"))
                    .count(),
                1,
                "exact import locations decode one arena: {location_plan:#?}"
            );
            for (table, key) in [
                ("arena", "blob_id=?"),
                ("source", "blob_id=? AND import_id=?"),
                ("target", "blob_id=? AND ordinal=?"),
                ("context", "blob_id=? AND declaration_occurrence_id=?"),
            ] {
                assert!(
                    location_plan.iter().any(|detail| detail
                        .contains(&format!("SEARCH {table} USING PRIMARY KEY ({key})"))),
                    "exact import locations must seek {table}: {location_plan:#?}"
                );
            }
            assert!(
                location_plan
                    .iter()
                    .any(|detail| detail.contains("SEARCH keys USING")
                        && detail.contains("blob_oid=? AND lang=?")),
                "{location_plan:#?}"
            );
            assert!(
                location_plan
                    .iter()
                    .all(|detail| !detail.contains("MATERIALIZE")
                        || detail == "MATERIALIZE requested"
                        || detail == "MATERIALIZE source_occurrences"),
                "{location_plan:#?}"
            );
            let target_sql = rust_import_targets_sql(&placeholders);
            let target_plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {target_sql}"))
                .unwrap()
                .query_map(params_from_iter(params.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                target_plan
                    .iter()
                    .any(|detail| detail.contains("SEARCH context USING PRIMARY KEY")),
                "Rust target hydration must seek each declaration context: {target_plan:#?}"
            );
            assert!(
                target_plan.iter().all(|detail| {
                    (!detail.starts_with("SCAN ") || detail.starts_with("SCAN CONSTANT ROW"))
                        && !detail.contains("MATERIALIZE")
                }),
                "Rust target hydration must not scan or materialize source rows: {target_plan:#?}"
            );
            let import_sql = import_infos_bulk_sql(&placeholders);
            let import_plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {import_sql}"))
                .unwrap()
                .query_map(params_from_iter(params.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            check_plan("canonical import statement batch", &import_plan);

            let scope_sql = import_path_children_sql(
                "source_import_lexical_scopes",
                "start_byte, end_byte",
                "scope_ordinal",
                &placeholders,
            );
            let scope_plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {scope_sql}"))
                .unwrap()
                .query_map(params_from_iter(params.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            check_plan("canonical lexical-scope batch", &scope_plan);

            let rust_segment_sql = rust_import_module_segments_sql(&placeholders);
            let rust_segment_plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {rust_segment_sql}"))
                .unwrap()
                .query_map(params_from_iter(params.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                rust_segment_plan.iter().any(|detail| {
                    detail.contains("SEARCH source_rust_import_module_segments")
                        || detail.contains("SEARCH segments")
                        || detail.contains("SEARCH segment")
                }),
                "canonical Rust segment batch must seek the source segment view: {rust_segment_plan:#?}"
            );
            assert!(
                rust_segment_plan.iter().all(|detail| {
                    (!detail.starts_with("SCAN ") || detail.starts_with("SCAN CONSTANT ROW"))
                        && !detail.contains("MATERIALIZE")
                }),
                "canonical Rust segment batch must not scan or materialize unbounded rows: {rust_segment_plan:#?}"
            );
        };

        check(&store);
        store.refresh_planner_statistics().unwrap();
        check(&store);
    }

    #[test]
    fn canonical_import_segment_batches_seek_before_and_after_statistics() {
        // Schema 117 stores an import's module path once, in the canonical
        // `source_import_segments` family that `rust_import_targets` points at,
        // so this pin publishes real blobs rather than assembling the rows by
        // hand: the canonical chain a Rust target depends on spans the source
        // manifest, its occurrences, its imports and the Rust module and item
        // manifests.
        const SOURCE: &str = "use crate::model::Target;\nfn consume(value: Target) {}\n";
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "src/lib.rs", SOURCE);
        let state = Arc::new(parse_state(&RustAdapter, &file));
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let generation = store.current_generation("rust").unwrap();
        let oids: Vec<_> = (0..1_200)
            .map(|index| oid_for(format!("import blob {index}").as_bytes()))
            .collect();
        let requested: Vec<_> = oids.iter().take(900).map(ToString::to_string).collect();
        let prepared = oids
            .iter()
            .map(|oid| {
                AnalyzerStore::prepare_parsed_blob(
                    *oid,
                    "rust",
                    generation,
                    &RustAdapter,
                    Arc::clone(&state),
                )
            })
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let (outcomes, stats) =
            store.persist_prepared_blobs(prepared, PersistBatchTargets::PRODUCTION);
        assert_eq!(stats.committed_blobs, oids.len());
        assert_eq!(stats.failed_blobs, 0, "persisted import blobs: {stats:?}");
        assert!(outcomes.iter().all(|outcome| outcome.error.is_none()));

        let check = || {
            let conn = store.read_conn().unwrap();
            let sql = rust_import_module_segments_sql(&chunk_placeholders(&requested));
            let params = chunk_params("rust", &requested);
            let plan = conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map(params_from_iter(params.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter()
                    .any(|detail| detail.contains("SEARCH segment USING PRIMARY KEY")),
                "{plan:?}"
            );
            assert!(
                !plan.iter().any(|detail| detail.starts_with("SCAN ")),
                "{plan:?}"
            );
            let rows = read_rust_usage_facts_bulk(&conn, "rust", &requested).unwrap();
            assert_eq!(rows.len(), requested.len());
            for oid in &requested {
                assert_eq!(
                    rows[oid].import_targets[0].module_path,
                    ["crate".to_owned(), "model".to_owned()]
                );
            }
            let plan = conn.prepare(
                "EXPLAIN QUERY PLAN SELECT blob_id FROM rust_import_targets WHERE module_path = ?1"
            ).unwrap().query_map(["crate::model"], |row| row.get::<_, String>(3)).unwrap()
                .collect::<rusqlite::Result<Vec<_>>>().unwrap();
            assert!(
                plan.iter()
                    .any(|detail| detail.contains("idx_rust_import_targets_module")),
                "{plan:?}"
            );
            assert!(
                !plan.iter().any(|detail| detail.starts_with("SCAN ")),
                "{plan:?}"
            );
        };
        check();
        store.refresh_planner_statistics().unwrap();
        check();
    }

    #[test]
    fn rust_absolute_import_targets_round_trip_per_leaf() {
        const SOURCE: &str =
            "use {route::relative, ::route::absolute};\nuse ::route::group::{named, *};\n";
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "src/lib.rs", SOURCE);
        let oid = oid_for(SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &parse_state(&RustAdapter, &file))
            .unwrap();

        let facts = store.rust_usage_facts(oid, "rust").unwrap();
        assert_eq!(
            facts
                .import_targets
                .iter()
                .map(|target| (
                    target
                        .module_path
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    target.imported_name.as_deref(),
                    target.leading_absolute,
                    target.is_glob,
                ))
                .collect::<Vec<_>>(),
            vec![
                (vec!["route"], Some("relative"), false, false),
                (vec!["route"], Some("absolute"), true, false),
                (vec!["route", "group"], Some("named"), true, false),
                (vec!["route", "group"], None, true, true),
            ]
        );

        let conn = store.conn.lock().unwrap();
        let persisted = conn
            .prepare(
                "SELECT leading_absolute FROM source_rust_import_targets
                 WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust')
                 ORDER BY ordinal",
            )
            .unwrap()
            .query_map([oid.to_string()], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(persisted, vec![0, 1, 1, 1]);
    }

    #[test]
    fn rust_fact_tables_answer_the_inverted_name_lookups() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_fixture_store(temp.path(), "src/lib.rs", RUST_USAGE_FACT_FIXTURE);

        assert_eq!(store.rust_export_blobs("rust", "Alias").unwrap(), vec![oid]);
        assert!(
            store
                .rust_export_blobs("rust", "Private")
                .unwrap()
                .is_empty(),
            "a private import must not answer an export lookup"
        );
        assert_eq!(
            store.rust_import_target_blobs("rust", "delta").unwrap(),
            vec![oid]
        );
        assert_eq!(
            store
                .rust_module_import_candidate_blobs("rust", "delta")
                .unwrap(),
            vec![oid]
        );
        assert_eq!(
            store
                .rust_identifier_occurrence_blobs("rust", "helper")
                .unwrap(),
            vec![(
                oid,
                brokk_bifrost_core::analyzer::rust_facts::RUST_OCCURRENCE_CODE
            )]
        );
        assert!(
            store
                .rust_identifier_occurrence_blobs("rust", "HELPER")
                .unwrap()
                .is_empty(),
            "identifier lookups are case-sensitive"
        );
        assert!(
            store
                .rust_identifier_occurrence_blobs("java", "helper")
                .unwrap()
                .is_empty(),
            "identifier lookups are scoped to one language"
        );
    }

    #[test]
    fn rust_fact_rows_cascade_with_their_blob() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_fixture_store(temp.path(), "src/lib.rs", RUST_USAGE_FACT_FIXTURE);
        let count = |store: &AnalyzerStore| {
            let conn = store.conn.lock().unwrap();
            [
                "rust_exports",
                "rust_import_targets",
                "rust_modules",
                "rust_identifier_occurrences",
                "rust_module_scopes",
                "rust_module_routes",
                "rust_module_route_gates",
                "rust_item_macros",
                "rust_include_edges",
                "rust_include_host_bindings",
            ]
            .into_iter()
            .map(|table| {
                conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)"),
                    params![oid.to_string(), "rust"],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap()
            })
            .sum::<usize>()
        };

        assert!(count(&store) > 0, "fixture must persist fact rows");
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
                params![oid.to_string(), "rust"],
            )
            .unwrap();
        }
        assert_eq!(
            count(&store),
            0,
            "deleting the blob must cascade every rust_* fact row away"
        );
    }

    #[test]
    fn rust_fact_rows_are_stable_across_a_re_analysis_of_the_same_content() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_fixture_store(temp.path(), "src/lib.rs", RUST_USAGE_FACT_FIXTURE);
        let first = store.rust_usage_facts(oid, "rust").unwrap();

        // Same bytes at a different path: the content key is unchanged, so the
        // second analysis must produce byte-identical rows. Nothing persisted
        // here may be path-derived.
        let moved = write_file(temp.path(), "src/other/lib.rs", RUST_USAGE_FACT_FIXTURE);
        store
            .write_parsed_blob(
                oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &moved),
            )
            .unwrap();
        let second = store.rust_usage_facts(oid, "rust").unwrap();

        assert_eq!(first, second);

        let route_file = write_file(temp.path(), "src/lib.rs", RUST_MODULE_ROUTE_FIXTURE);
        let route_oid = oid_for(RUST_MODULE_ROUTE_FIXTURE.as_bytes());
        store
            .write_parsed_blob(
                route_oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &route_file),
            )
            .unwrap();
        let first_routes = store
            .rust_usage_facts(route_oid, "rust")
            .unwrap()
            .module_routes;
        assert!(
            !first_routes.routes.is_empty(),
            "fixture must persist route rows"
        );

        let moved_route_file = write_file(
            temp.path(),
            "src/deep/nested/mod.rs",
            RUST_MODULE_ROUTE_FIXTURE,
        );
        store
            .write_parsed_blob(
                route_oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &moved_route_file),
            )
            .unwrap();
        assert_eq!(
            store
                .rust_usage_facts(route_oid, "rust")
                .unwrap()
                .module_routes,
            first_routes
        );
    }

    #[test]
    fn rust_module_route_tables_record_scopes_routes_gates_and_item_macros() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_fixture_store(temp.path(), "src/lib.rs", RUST_MODULE_ROUTE_FIXTURE);
        let routes = store.rust_usage_facts(oid, "rust").unwrap().module_routes;

        let scopes: Vec<_> = routes
            .scopes
            .iter()
            .map(|scope| {
                (
                    scope.parent,
                    scope.module_name.as_str(),
                    scope.path_attribute.as_deref(),
                    scope.imports_macros,
                )
            })
            .collect();
        assert_eq!(
            scopes,
            vec![
                (None, "", None, true),
                (Some(0), "scope", Some("elsewhere"), false),
            ],
            "scopes were {:?}",
            routes.scopes
        );
        assert_eq!(routes.scopes[0].body_start, 0);
        assert_eq!(
            routes.scopes[0].body_end,
            RUST_MODULE_ROUTE_FIXTURE.len(),
            "the root scope spans the whole source"
        );
        assert_eq!(
            routes
                .scopes
                .iter()
                .map(|scope| scope.resolution_scope.map(ResolutionScopeId::get))
                .collect::<Vec<_>>(),
            vec![Some(0), Some(1)],
            "common-resolution attachment scopes must survive the store round trip"
        );

        let described: Vec<_> = routes
            .routes
            .iter()
            .map(|route| {
                (
                    route.scope,
                    route.module_name.as_str(),
                    route.path_attribute.as_deref(),
                    route.imports_macros,
                    route.test_gated,
                    encode_rust_cfg_condition(&route.cfg_condition),
                    route
                        .gates
                        .iter()
                        .map(|gate| gate.macro_name.as_str())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            described,
            vec![
                (0, "plain", None, false, false, "always".to_string(), vec![]),
                (
                    0,
                    "macro_source",
                    None,
                    true,
                    false,
                    "always".to_string(),
                    vec![]
                ),
                (
                    0,
                    "gated",
                    None,
                    false,
                    true,
                    "atom test".to_string(),
                    vec![]
                ),
                (
                    0,
                    "relocated",
                    Some("custom/target.rs"),
                    false,
                    false,
                    "always".to_string(),
                    vec![]
                ),
                (1, "deep", None, false, false, "always".to_string(), vec![]),
                (
                    0,
                    "replayed",
                    None,
                    false,
                    false,
                    "always".to_string(),
                    vec!["replay"]
                ),
            ],
            "routes were {:?}",
            routes.routes
        );
        assert_eq!(
            routes
                .item_macros
                .iter()
                .map(|definition| {
                    (
                        definition.name.as_str(),
                        definition.passthrough,
                        definition.exported,
                    )
                })
                .collect::<Vec<_>>(),
            vec![("replay", true, true)],
            "item macros were {:?}",
            routes.item_macros
        );
        let gate = &routes.routes[5].gates[0];
        assert_eq!(
            RUST_MODULE_ROUTE_FIXTURE
                .get(gate.invocation_start..)
                .map(|rest| rest.starts_with("replay! { mod replayed; }")),
            Some(true),
            "the gate points at the invocation that produced the route"
        );
    }

    #[test]
    fn rust_module_route_rows_cascade_with_their_blob() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_fixture_store(temp.path(), "src/lib.rs", RUST_MODULE_ROUTE_FIXTURE);
        let counts = |store: &AnalyzerStore| {
            let conn = store.conn.lock().unwrap();
            [
                "rust_module_scopes",
                "rust_module_routes",
                "rust_module_route_gates",
                "rust_item_macros",
            ]
            .map(|table| {
                conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2)"),
                    params![oid.to_string(), "rust"],
                    |row| row.get::<_, usize>(0),
                )
                .unwrap()
            })
        };

        assert!(
            counts(&store).iter().all(|count| *count > 0),
            "every module-route table must carry rows for this fixture: {:?}",
            counts(&store)
        );
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
                params![oid.to_string(), "rust"],
            )
            .unwrap();
        }
        assert_eq!(counts(&store), [0, 0, 0, 0]);
    }

    /// The Cargo-route build reads every live blob at once, and that batched
    /// read must agree with the per-blob one it replaces column for column.
    #[test]
    fn batched_module_route_facts_match_the_per_blob_read() {
        let temp = tempfile::TempDir::new().unwrap();
        let (store, oid) = rust_fixture_store(temp.path(), "src/lib.rs", RUST_MODULE_ROUTE_FIXTURE);
        let other = write_file(temp.path(), "src/plain.rs", "mod leaf;\n");
        let other_oid = oid_for(b"mod leaf;\n");
        store
            .write_parsed_blob(
                other_oid,
                "rust",
                &RustAdapter,
                &parse_state(&RustAdapter, &other),
            )
            .unwrap();
        let absent = oid_for(b"pub struct NeverAnalyzed;\n");
        let generation = store.current_generation("rust").unwrap();

        let batched = store
            .rust_module_route_facts_while("rust", generation, &[oid, other_oid, absent], &|| true)
            .unwrap()
            .expect("uninterrupted route read");

        assert_eq!(batched.len(), 2, "an unanalyzed blob contributes no entry");
        let checkpoints = std::cell::Cell::new(0);
        let cancelled = store
            .rust_module_route_facts_while("rust", generation, &[oid, other_oid, absent], &|| {
                let visited = checkpoints.get();
                checkpoints.set(visited + 1);
                visited < 2
            })
            .unwrap();
        assert!(
            cancelled.is_none(),
            "cancelled route rows must not escape as a partial map"
        );
        let retried = store
            .rust_module_route_facts_while("rust", generation, &[oid, other_oid, absent], &|| true)
            .unwrap()
            .expect("retry after dropping the cancelled read transaction");
        assert_eq!(retried, batched);
        for key in [oid, other_oid] {
            assert_eq!(
                batched.get(&key),
                Some(&store.rust_usage_facts(key, "rust").unwrap().module_routes),
                "batched and per-blob reads disagree for {key}"
            );
        }
    }

    /// Compare the Rust usage-fact bulk reader with the analyzer's original
    /// pre-persistence values, rather than another store decoder, so every
    /// family and each family's persisted order are covered independently. A
    /// registered blob with no fact rows remains absent from the bulk map and
    /// hydrates through the scalar facade as the default value.
    #[test]
    fn batched_rust_usage_facts_match_analyzer_all_families_and_empty_rows() {
        let temp = tempfile::TempDir::new().unwrap();
        let first_file = write_file(temp.path(), "src/facts.rs", RUST_USAGE_FACT_FIXTURE);
        let route_file = write_file(temp.path(), "src/routes.rs", RUST_MODULE_ROUTE_FIXTURE);
        let first_oid = oid_for(RUST_USAGE_FACT_FIXTURE.as_bytes());
        let route_oid = oid_for(RUST_MODULE_ROUTE_FIXTURE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let first_state = parse_state(&RustAdapter, &first_file);
        let expected_first = first_state.rust_usage_facts.clone();
        store
            .write_parsed_blob(first_oid, "rust", &RustAdapter, &first_state)
            .unwrap();
        let route_state = parse_state(&RustAdapter, &route_file);
        let expected_route = route_state.rust_usage_facts.clone();
        store
            .write_parsed_blob(route_oid, "rust", &RustAdapter, &route_state)
            .unwrap();

        let empty_oid = oid_for(b"a registered Rust blob with no fact rows");
        let generation = store.current_generation("rust").unwrap();
        store
            .register_blobs(&[empty_oid], "rust", generation)
            .unwrap();

        let requested = [
            first_oid.to_string(),
            route_oid.to_string(),
            empty_oid.to_string(),
        ];
        let conn = store.conn.lock().unwrap();
        let bulk = read_rust_usage_facts_bulk(&conn, "rust", &requested).unwrap();
        assert_eq!(bulk.get(&first_oid.to_string()), Some(&expected_first));
        assert_eq!(bulk.get(&route_oid.to_string()), Some(&expected_route));
        assert!(!bulk.contains_key(&empty_oid.to_string()));
        assert_eq!(
            read_rust_usage_facts(&conn, &empty_oid.to_string(), "rust").unwrap(),
            RustUsageFacts::default(),
            "a zero-row blob must hydrate as the empty fact value"
        );

        let repeated = [
            first_oid.to_string(),
            first_oid.to_string(),
            route_oid.to_string(),
            empty_oid.to_string(),
        ];
        let repeated_bulk = read_rust_usage_facts_bulk(&conn, "rust", &repeated).unwrap();
        assert_eq!(
            repeated_bulk, bulk,
            "duplicate OIDs must not duplicate facts"
        );
    }

    #[test]
    fn batched_rust_usage_facts_session_stop_discards_partial_map() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(temp.path(), "src/facts.rs", RUST_USAGE_FACT_FIXTURE);
        let oid = oid_for(RUST_USAGE_FACT_FIXTURE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &parse_state(&RustAdapter, &file))
            .unwrap();

        let requested = [oid.to_string()];
        let conn = store.conn.lock().unwrap();
        let session = ResolutionSession::bounded(
            brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget {
                max_scope_nodes: 1,
                ..Default::default()
            },
            None,
        );
        let stopped =
            read_rust_usage_facts_bulk_with_session(&conn, "rust", &requested, Some(&session))
                .unwrap();
        assert!(
            stopped.is_none(),
            "a stopped bulk read must expose no partial map"
        );
        assert!(matches!(
            session.finish(()),
            brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution::Exceeded { .. }
        ));
    }

    /// The fixture the `rust_*` fact-table tests share: one file that
    /// re-exports, imports (named, glob, aliased, function-local), declares an
    /// inline and a file module, and mentions identifiers in code, a comment,
    /// and a string.
    const RUST_USAGE_FACT_FIXTURE: &str = "\
#[macro_use]
extern crate facade;
pub use alpha::Exported;
pub use beta::Renamed as Alias;
pub use gamma::*;
use delta::Private;
mod detached;
mod inline {
    use crate::Scoped;
    pub fn helper() {
        use crate::Local;
        let _ = \"in_a_string\";
    }
}
include!(\"generated/table.rs\");
// in_a_comment
";

    /// The module-route fixture (issue #1793): a file whose declarations cover
    /// every column the Cargo route index reads -- an inline scope with a
    /// `#[path]`, a `#[macro_use]` declaration, a bare `#[cfg(test)]` gate, a
    /// `#[path]` on a declaration, an item macro definition, and a declaration
    /// that only exists inside that macro's expansion.
    const RUST_MODULE_ROUTE_FIXTURE: &str = "\
#[macro_export]
macro_rules! replay {
    ($($item:item)*) => { $($item)* };
}
mod plain;
#[macro_use]
mod macro_source;
#[cfg(test)]
mod gated;
#[path = \"custom/target.rs\"]
mod relocated;
#[path = \"elsewhere\"]
mod scope {
    mod deep;
}
replay! { mod replayed; }
";

    fn rust_fixture_store(temp: &Path, rel_path: &str, fixture: &str) -> (AnalyzerStore, Oid) {
        let file = write_file(temp, rel_path, fixture);
        let oid = oid_for(fixture.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &parse_state(&RustAdapter, &file))
            .unwrap();
        (store, oid)
    }

    /// Every `short_name` the store holds for one parsed blob.
    fn persisted_short_names<A: LanguageAdapter>(
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
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
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

    /// The storage contract issue #1748's structural-miss filter rests on,
    /// pinned end to end rather than inferred from the renderer.
    ///
    /// `definition_candidate_short_names` drops a lookup spelling that carries
    /// a separator `absent_segment_separators` reports for the adapter's
    /// language, on the ground that no stored `short_name` for that language
    /// can contain one. This asserts the property against rows the store wrote,
    /// over the Rust shapes most likely to smuggle a path separator into a name -- nested
    /// inline modules, a generic inherent impl, a qualified trait impl, and an
    /// associated const.
    ///
    /// If a future extractor or schema change starts persisting `::`-bearing
    /// rust short names, the filter would begin dropping spellings that can
    /// match. This fails first, and says so.
    #[test]
    fn short_name_vocabulary_excludes_separators_absent_from_the_renderer() {
        let temp = tempfile::TempDir::new().unwrap();
        let file = write_file(
            temp.path(),
            "src/lib.rs",
            "pub mod outer {\n\
             \x20   pub mod inner {\n\
             \x20       pub struct Widget<T> { pub value: T }\n\
             \x20       impl<T: core::fmt::Debug> Widget<T> {\n\
             \x20           pub const LIMIT: usize = 4;\n\
             \x20           pub fn make(value: T) -> Self { Widget { value } }\n\
             \x20       }\n\
             \x20       impl<T> core::default::Default for Widget<T>\n\
             \x20       where T: core::default::Default {\n\
             \x20           fn default() -> Self { Widget { value: T::default() } }\n\
             \x20       }\n\
             \x20   }\n\
             }\n\
             pub fn top() -> usize { outer::inner::Widget::<usize>::LIMIT }\n",
        );

        let names = persisted_short_names(&RustAdapter, "rust", &file);
        let absent =
            brokk_bifrost_core::analyzer::fq_name::absent_segment_separators(Language::Rust);
        assert_eq!(
            &["::"],
            absent,
            "rust has no `::` rendering rule, so `::` is the separator the filter drops"
        );
        let offenders: Vec<&String> = names
            .iter()
            .filter(|name| absent.iter().any(|separator| name.contains(separator)))
            .collect();
        assert!(
            offenders.is_empty(),
            "persisted rust short names must not contain {absent:?}; offenders: {offenders:?} \
             out of {names:?}"
        );
    }
}
