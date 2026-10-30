#[cfg(test)]
mod tests {
    use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ByteBounded;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerBuildTierAccess;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerRuntimeState;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::AnalyzerStoreContext;

    use std::sync::Arc;

    use std::sync::atomic::AtomicUsize;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BLOCKING_ANALYSIS_OBSERVED_ABORT;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BLOCKING_ANALYSIS_READY;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BLOCK_UNTIL_BUILD_ABORT_PATH;

    use std::collections::BTreeSet;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BoundedFileCache;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BoundedParse;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildAbort;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgress;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BuildProgressPhase;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::BulkFileStateSource;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::CACHE_ORDER_COMPACT_FACTOR;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::COMPLETE_FILE_PARSE_BUDGET;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

    use brokk_bifrost_analysis::analyzer::store::CompleteAnalysisBlobRequest;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::DirtyFileStateStatus;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ENCLOSING_CODE_UNIT_INDEX_MIN_DECLARATIONS;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FORCED_PARSE_TIMEOUT_PATHS;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileStateCacheKey;

    use brokk_bifrost_core::analyzer::fq_name::FqName;

    use brokk_bifrost_analysis::analyzer::store::GenerationId;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::IMPORT_INFO_STORE_ENTRY_OVERHEAD_BYTES;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::IMPORT_INFO_STORE_MAX_BYTES;

    use brokk_bifrost_core::analyzer::model::ImportInfo;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ImportInfoStore;

    use brokk_bifrost_analysis::analyzer::i_analyzer::InformationTier;

    use std::time::Instant;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

    use brokk_bifrost_analysis::analyzer::store::liveness::LivePathEntry;

    use brokk_bifrost_analysis::analyzer::store::liveness::LivePathMap;

    use std::sync::Mutex;

    use std::sync::OnceLock;

    use std::sync::atomic::Ordering;

    use brokk_bifrost_core::analyzer::project::OverlayRevision;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PANICKING_ANALYSIS_PATH;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PREPARATION_FAILURE_PATH;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PREPARED_FAILURE_PATH;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PREPARED_SYNTAX_BYTES_PER_SOURCE_BYTE;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PREPARED_SYNTAX_STORE_ENTRY_OVERHEAD_BYTES;

    use brokk_bifrost_core::analyzer::model::PackageAnchor;

    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;

    use tree_sitter::Parser;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchStats;

    use brokk_bifrost_analysis::analyzer::store::PersistBatchTargets;

    use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSourceOrigin;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PreparedSyntaxCacheFlavor;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PreparedSyntaxCacheKey;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PreparedSyntaxLimitedOutcome;

    use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxSource;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::PreparedSyntaxStore;

    use brokk_bifrost_core::analyzer::project::Project;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::project::ProjectSourceSnapshot;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::QueryReadCache;

    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::RetainedImportInfos;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::RevisionBlobIdentities;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::STORE_WRITE_IMMEDIATE_RETRIES;

    use brokk_bifrost_analysis::analyzer::i_analyzer::SearchSymbolPatternBatch;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::SegmentedFileStateCache;

    use brokk_bifrost_core::analyzer::model::SignatureMetadata;

    use brokk_bifrost_analysis::analyzer::source_admission::SourceAdmissionPolicy;

    use tree_sitter::Tree;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::WorkspaceBuildSnapshot;

    use brokk_bifrost_core::analyzer::tree_walk::collect_parse_errors;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context;

    use brokk_bifrost_core::analyzer::tree_walk::expanded_comment_start;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::file_state_cache_budget_bytes;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::file_state_cache_ceiling_bytes;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::merge_dirty_relational_value;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::parse_complete_file_with_tree_ranges;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::set_parser_for_file;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_shared_store;

    use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::store_context_from_store;

    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;

    use brokk_bifrost_cpp_analysis::analyzer::cpp::source_storage::CanonicalCppSourceFacts;

    use brokk_bifrost_csharp_analysis::analyzer::csharp::adapter::CSharpAdapter;

    use brokk_bifrost_go_analysis::analyzer::go::adapter::GoAdapter;

    use brokk_bifrost_go_analysis::analyzer::go::source_storage::CanonicalGoSourceFacts;

    use brokk_bifrost_jvm_analysis::analyzer::java::adapter::JavaAdapter;

    use brokk_bifrost_jvm_analysis::analyzer::java::source_facts::JavaSourceFacts;

    use brokk_bifrost_js_ts_analysis::analyzer::javascript::JavascriptAdapter;

    use brokk_bifrost_js_ts_analysis::analyzer::js_ts::source_storage::CanonicalJsTsSourceFacts;

    use brokk_bifrost_php_analysis::analyzer::php::source_storage::CanonicalPhpSourceFacts;

    use brokk_bifrost_python_analysis::analyzer::python::adapter::PythonAdapter;

    use brokk_bifrost_ruby_analysis::analyzer::ruby::source_facts::RubySourceFacts;

    use brokk_bifrost_rust_analysis::analyzer::rust::adapter::RustAdapter;

    use brokk_bifrost_jvm_analysis::analyzer::scala::adapter::ScalaAdapter;

    use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

    use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

    use brokk_bifrost_js_ts_analysis::analyzer::typescript::TypescriptAdapter;

    use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

    use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

    use brokk_bifrost_jvm_analysis::analyzer::java::JavaAnalyzer;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::project::OverlayProject;

    use brokk_bifrost_core::analyzer::project::TestProject;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;
    use git2::{ObjectType, Oid};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Barrier, Condvar, RwLock};

    fn cache_key(name: &str) -> FileStateCacheKey {
        FileStateCacheKey {
            oid: Oid::zero(),
            rel_path: PathBuf::from(name),
            admission_policy: SourceAdmissionPolicy::current(),
        }
    }

    fn singleton_generation_map(
        language: &str,
        generation: GenerationId,
    ) -> Arc<HashMap<String, GenerationId>> {
        let mut generations = HashMap::default();
        generations.insert(language.to_owned(), generation);
        Arc::new(generations)
    }

    #[test]
    fn expanded_comment_start_walks_attached_lines_with_mixed_endings() {
        let source = "// license\r\n\r\n// docs\n#[attr]\rfn work() {}";
        let declaration = source.find("fn work").unwrap();

        assert_eq!(
            expanded_comment_start(Language::Rust, source, declaration),
            source.find("// docs").unwrap()
        );
    }

    #[test]
    fn expanded_comment_start_keeps_inline_comment_boundary() {
        let source = "const pi = \"pi\"; // nearby\nfn work() {}";
        let declaration = source.find("fn work").unwrap();

        assert_eq!(
            expanded_comment_start(Language::Rust, source, declaration),
            source.find("// nearby").unwrap()
        );
    }

    #[test]
    fn expanded_comment_start_ignores_non_boundary_offsets() {
        let source = "// docs\nfn café() {}";
        let non_boundary = source.find('é').unwrap() + 1;

        assert_eq!(
            expanded_comment_start(Language::Rust, source, non_boundary),
            non_boundary
        );
        assert_eq!(
            expanded_comment_start(Language::Rust, source, source.len() + 1),
            source.len()
        );
    }

    #[test]
    fn relational_batch_deduplicates_with_one_snapshot_and_point_is_arity_one() {
        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionLookup,
            RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
            RelationalName, RelationalPointOutcome,
        };

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/Widget.java");
        file.write("package demo; public class Widget {}\n")
            .expect("write Java fixture");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        let widget = analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_class() && unit.identifier() == "Widget")
            .expect("fixture declares demo.Widget");
        let exact = RelationalDefinitionRequest {
            ordinal: 11,
            language_scope: DefinitionLanguageScope::Language(Language::Java),
            name: RelationalName::stable(widget.fq().clone()),
            query: RelationalDefinitionQuery::ExactName,
        };
        let duplicate = RelationalDefinitionRequest {
            ordinal: 3,
            ..exact.clone()
        };
        let normalized = RelationalDefinitionRequest {
            ordinal: 7,
            name: RelationalName::stable(analyzer.adapter.normalize_fq_name(widget.fq())),
            query: RelationalDefinitionQuery::NormalizedName,
            ..exact.clone()
        };
        let rendered_name = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Java,
            "demo.Widget",
            brokk_bifrost_core::analyzer::fq_name::segment_interner(),
        );
        let rendered_exact = RelationalDefinitionRequest {
            ordinal: 13,
            name: RelationalName::stable(rendered_name.clone()),
            ..exact.clone()
        };
        let rendered_normalized = RelationalDefinitionRequest {
            ordinal: 17,
            name: RelationalName::stable(rendered_name),
            query: RelationalDefinitionQuery::NormalizedName,
            ..exact.clone()
        };

        let outcome = analyzer.batch(
            &[
                exact.clone(),
                duplicate,
                normalized.clone(),
                rendered_exact,
                rendered_normalized,
            ],
            &CancellationToken::new(),
        );
        let RelationalBatchOutcome::Complete(results) = outcome else {
            panic!("relational batch should complete: {outcome:?}");
        };
        assert_eq!(
            results
                .iter()
                .map(|result| result.ordinal)
                .collect::<Vec<_>>(),
            [11, 3, 7, 13, 17],
            "fanout preserves caller order and ordinals"
        );
        for result in &results {
            let RelationalDefinitionValue::Definitions(definitions) = &result.value else {
                panic!("name lookup must return definitions")
            };
            assert_eq!(definitions, std::slice::from_ref(&widget));
        }
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (1, 1, 4),
            "five inputs contain four distinct structured and rendered questions in one reader snapshot"
        );

        let point = analyzer.point(&exact, &CancellationToken::new());
        let RelationalPointOutcome::Complete(point_result) = point else {
            panic!("point lookup should complete: {point:?}");
        };
        assert_eq!(point_result, results[0]);
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (2, 2, 5),
            "point delegates through one additional arity-one batch"
        );

        let cancellation = CancellationToken::cancel_after_checks_for_test(4);
        assert_eq!(
            analyzer.batch(&[exact.clone(), normalized], &cancellation),
            RelationalBatchOutcome::Cancelled,
            "a stopped batch must not publish the completed prefix"
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (3, 3, 7)
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            analyzer.batch(std::slice::from_ref(&exact), &cancellation),
            RelationalBatchOutcome::Cancelled
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (3, 3, 7),
            "pre-cancelled batches publish no prefix and open no reader"
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_live_unit_count_queries_for_test(),
            0,
            "small relational batches never consult workspace cardinality"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2588: batching dominant definition queries had to preserve point-query answers while fixing a severe policy-preparation regression"
    )]
    #[test]
    fn relational_batch_set_queries_preserve_point_results() {
        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionLookup,
            RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
            RelationalName,
        };

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/Widget.java");
        file.write("package demo; public class Widget { public void run() {} }\n")
            .expect("write Java fixture");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        let declarations = analyzer.get_all_declarations();
        let widget = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.identifier() == "Widget")
            .cloned()
            .expect("fixture declares demo.Widget");
        let run = declarations
            .iter()
            .find(|unit| unit.is_function() && unit.identifier() == "run")
            .cloned()
            .expect("fixture declares Widget.run");
        let scope = DefinitionLanguageScope::Language(Language::Java);
        let mut requests = Vec::new();
        for index in 0..64usize {
            let fq = if index == 0 {
                widget.fq().clone()
            } else {
                brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
                    Language::Java,
                    &format!("demo.MissingExact{index}"),
                    brokk_bifrost_core::analyzer::fq_name::segment_interner(),
                )
            };
            requests.push(RelationalDefinitionRequest {
                ordinal: requests.len(),
                language_scope: scope.clone(),
                name: RelationalName::stable(fq),
                query: RelationalDefinitionQuery::ExactName,
            });
        }
        for index in 0..64usize {
            let fq = if index == 0 {
                analyzer.adapter.normalize_fq_name(widget.fq())
            } else {
                brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
                    Language::Java,
                    &format!("demo.MissingNormalized{index}"),
                    brokk_bifrost_core::analyzer::fq_name::segment_interner(),
                )
            };
            requests.push(RelationalDefinitionRequest {
                ordinal: requests.len(),
                language_scope: scope.clone(),
                name: RelationalName::stable(fq),
                query: RelationalDefinitionQuery::NormalizedName,
            });
        }
        for index in 0..64usize {
            requests.push(RelationalDefinitionRequest {
                ordinal: requests.len(),
                language_scope: scope.clone(),
                name: RelationalName::stable(widget.fq().clone()),
                query: RelationalDefinitionQuery::StructuralMembers {
                    identifier: if index == 0 {
                        "run".to_string()
                    } else {
                        format!("missingMember{index}")
                    },
                },
            });
        }

        let RelationalBatchOutcome::Complete(results) =
            analyzer.batch(&requests, &CancellationToken::new())
        else {
            panic!("set-shaped relational batch should complete")
        };
        assert_eq!(results.len(), requests.len());
        for (index, result) in results.iter().enumerate() {
            assert_eq!(result.ordinal, index);
            let RelationalDefinitionValue::Definitions(definitions) = &result.value else {
                panic!("set query returned the wrong value shape")
            };
            match index {
                0 | 64 => assert_eq!(definitions, std::slice::from_ref(&widget)),
                128 => assert_eq!(definitions, std::slice::from_ref(&run)),
                _ => assert!(definitions.is_empty(), "unexpected definitions at {index}"),
            }
        }
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_live_unit_count_queries_for_test(),
            1,
            "all qualifying set-query shapes share one workspace cardinality read"
        );

        // The same contract for a language whose declarations include
        // path-derived module units. A Python file `pkg/service.py` is the
        // module `pkg.service` although no line in it says so, and that unit
        // exists only in `workspace_file_path_symbol_rows`, never in
        // `code_units`. Before Part 2 of the issue #2588 plan, every set
        // executor returned early for such a language, so these requests were
        // always answered one at a time. Now the batch answers them, and it has
        // to return the same units the point path returns: a batch that
        // forgets the path half silently drops every module.
        let python_temp = tempfile::tempdir().expect("temp dir");
        let python_root = python_temp
            .path()
            .canonicalize()
            .expect("canonical temp dir");
        ProjectFile::new(python_root.clone(), "pkg/service.py")
            .write("class Service:\n    def run(self):\n        pass\n")
            .expect("write Python fixture");
        let python_project: Arc<dyn Project> =
            Arc::new(TestProject::new(&python_root, Language::Python));
        let python_analyzer = TreeSitterAnalyzer::new(python_project, PythonAdapter::default());
        let module = python_analyzer
            .get_all_declarations()
            .into_iter()
            .find(|unit| unit.is_module() && unit.identifier() == "service")
            .expect("fixture declares the path-derived module pkg.service");
        let python_scope = DefinitionLanguageScope::Language(Language::Python);
        let module_name = RelationalName::stable(module.fq().clone());
        let package_name = RelationalName::stable(
            brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
                Language::Python,
                "pkg",
                brokk_bifrost_core::analyzer::fq_name::segment_interner(),
            ),
        );
        let missing_module = |index: usize| {
            RelationalName::stable(
                brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
                    Language::Python,
                    &format!("pkg.missing{index}"),
                    brokk_bifrost_core::analyzer::fq_name::segment_interner(),
                ),
            )
        };
        // A set executor only claims a shape once the batch holds
        // `SET_QUERY_MIN_REQUESTS` (64) *distinct* requests of it, so each
        // batch below asks one answerable question and 63 unanswerable ones,
        // exactly as the Java batches above do.
        let path_shapes: [(&str, RelationalDefinitionQuery); 3] = [
            ("exact name", RelationalDefinitionQuery::ExactName),
            ("normalized name", RelationalDefinitionQuery::NormalizedName),
            (
                "structural members",
                RelationalDefinitionQuery::StructuralMembers {
                    identifier: "service".to_string(),
                },
            ),
        ];
        for (case_name, shape) in path_shapes {
            let answerable = match &shape {
                RelationalDefinitionQuery::StructuralMembers { .. } => package_name.clone(),
                _ => module_name.clone(),
            };
            let point = RelationalDefinitionRequest {
                ordinal: 0,
                language_scope: python_scope.clone(),
                name: answerable.clone(),
                query: shape.clone(),
            };
            let RelationalBatchOutcome::Complete(point_results) =
                python_analyzer.batch(std::slice::from_ref(&point), &CancellationToken::new())
            else {
                panic!("one-request relational batch should complete")
            };
            let RelationalDefinitionValue::Definitions(point_definitions) = &point_results[0].value
            else {
                panic!("path query returned the wrong value shape")
            };
            assert_eq!(
                point_definitions,
                std::slice::from_ref(&module),
                "the point path must answer {case_name} with the path-derived module"
            );

            let batched = (0..64usize)
                .map(|index| RelationalDefinitionRequest {
                    ordinal: index,
                    language_scope: python_scope.clone(),
                    name: match (&shape, index) {
                        (_, 0) => answerable.clone(),
                        (RelationalDefinitionQuery::StructuralMembers { .. }, _) => {
                            package_name.clone()
                        }
                        _ => missing_module(index),
                    },
                    query: match (&shape, index) {
                        (RelationalDefinitionQuery::StructuralMembers { .. }, 0) => shape.clone(),
                        (RelationalDefinitionQuery::StructuralMembers { .. }, _) => {
                            RelationalDefinitionQuery::StructuralMembers {
                                identifier: format!("missing{index}"),
                            }
                        }
                        _ => shape.clone(),
                    },
                })
                .collect::<Vec<_>>();
            let RelationalBatchOutcome::Complete(batched_results) =
                python_analyzer.batch(&batched, &CancellationToken::new())
            else {
                panic!("set-shaped relational batch should complete")
            };
            assert_eq!(batched_results.len(), 64);
            for (index, result) in batched_results.iter().enumerate() {
                let RelationalDefinitionValue::Definitions(definitions) = &result.value else {
                    panic!("path set query returned the wrong value shape")
                };
                if index == 0 {
                    assert_eq!(
                        definitions, point_definitions,
                        "the batched path must answer {case_name} exactly as the point path does"
                    );
                } else {
                    assert!(
                        definitions.is_empty(),
                        "{case_name} answered an unanswerable request at {index}"
                    );
                }
            }
        }
    }

    #[test]
    fn relational_callable_pairs_preserve_shared_labels_and_synthetic_metadata() {
        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionLookup,
            RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
            RelationalName,
        };
        let source = "interface Dual { void run() {} }\nclass Dual { void run() {} Object make() { return new Object() { void inside() {} }; } }\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("Dual.java", source)
            .build();
        let file = fixture.file("Dual.java");
        let mut parser = Parser::new();
        parser.set_language(&JavaAdapter.parser_language()).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let parsed = JavaAdapter.parse_file(&file, source, &tree);
        let state = TreeSitterAnalyzer::<JavaAdapter>::file_state_from_parsed(
            source.to_owned(),
            parsed,
            false,
            None,
            true,
        );
        let run = state
            .signature_metadata
            .keys()
            .find(|unit| unit.is_function() && unit.identifier() == "run")
            .unwrap()
            .clone();
        assert_eq!(state.signature_metadata[&run].len(), 2);
        assert_eq!(state.signatures[&run].len(), 1);
        assert_eq!(
            state.signature_metadata_signature_ordinals[&run],
            vec![0, 0]
        );
        let synthetic = state
            .signature_metadata
            .keys()
            .find(|unit| unit.is_synthetic() && unit.is_class())
            .unwrap()
            .clone();
        assert!(
            state
                .source_declaration_metadata
                .iter()
                .all(|link| link.unit != synthetic)
        );

        let state = Arc::new(state);
        let requests = [run.clone(), synthetic.clone()]
            .into_iter()
            .enumerate()
            .map(|(ordinal, unit)| RelationalDefinitionRequest {
                ordinal,
                language_scope: DefinitionLanguageScope::Language(Language::Java),
                name: RelationalName::stable(unit.fq().clone()),
                query: RelationalDefinitionQuery::CallableFacts,
            })
            .collect::<Vec<_>>();
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
        let outcome = analyzer.batch(&requests, &CancellationToken::new());
        let RelationalBatchOutcome::Complete(results) = outcome else {
            panic!("paired callable query must complete: {outcome:?}");
        };
        for (request, result) in requests.iter().zip(&results) {
            let mut dirty = RelationalDefinitionValue::CallableFacts(Vec::new());
            merge_dirty_relational_value(
                &JavaAdapter,
                request,
                std::slice::from_ref(&state),
                &HashSet::from_iter([file.clone()]),
                &mut dirty,
            );
            assert_eq!(
                result.value, dirty,
                "persisted and producer-owned callable pairs must agree"
            );
        }
        let RelationalDefinitionValue::CallableFacts(run_facts) = &results[0].value else {
            panic!("run must return callable facts");
        };
        assert_eq!(run_facts.len(), 2);
        assert!(
            run_facts
                .iter()
                .all(|fact| fact.signature_ordinal == 0 && fact.metadata.is_some())
        );
        let RelationalDefinitionValue::CallableFacts(synthetic_facts) = &results[1].value else {
            panic!("synthetic class must retain its metadata");
        };
        assert_eq!(synthetic_facts.len(), 1);
        assert_eq!(synthetic_facts[0].declaration, synthetic);
        assert!(synthetic_facts[0].metadata.is_some());

        let mut divergent = Arc::into_inner(state).expect("test owns its only state handle");
        divergent
            .signatures
            .get_mut(&run)
            .unwrap()
            .insert(0, "plain signature".to_owned());
        for ordinal in divergent
            .signature_metadata_signature_ordinals
            .get_mut(&run)
            .unwrap()
        {
            *ordinal += 1;
        }
        let expected_metadata = divergent.signature_metadata[&run].clone();
        let mut dirty = RelationalDefinitionValue::CallableFacts(Vec::new());
        merge_dirty_relational_value(
            &JavaAdapter,
            &requests[0],
            &[Arc::new(divergent)],
            &HashSet::from_iter([file]),
            &mut dirty,
        );
        let RelationalDefinitionValue::CallableFacts(facts) = dirty else {
            panic!("dirty callable query must retain its shape");
        };
        assert_eq!(facts.len(), 3);
        assert_eq!(facts[0].signature_ordinal, 0);
        assert_eq!(facts[0].signature, "plain signature");
        assert!(facts[0].metadata.is_none());
        for (fact, expected) in facts[1..].iter().zip(expected_metadata) {
            assert_eq!(fact.signature_ordinal, 1);
            assert_eq!(fact.signature, "void run()");
            assert_eq!(fact.metadata, Some(expected));
        }
    }

    #[test]
    fn relational_batch_executes_every_supported_view_shape() {
        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, PackageRelationKind, PackageRelationValue,
            RelationalBatchOutcome, RelationalDefinitionLookup, RelationalDefinitionQuery,
            RelationalDefinitionRequest, RelationalDefinitionValue, RelationalName,
        };

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "Nested.cs");
        file.write(
            "namespace Demo { class Outer { public class Nested<T> { public int Run(int x) { return x; } } } }\n",
        )
        .expect("write C# fixture");
        let root_file = ProjectFile::new(root.clone(), "Root.cs");
        root_file
            .write("class Root {}\n")
            .expect("write root-package C# fixture");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::CSharp));
        let analyzer = TreeSitterAnalyzer::new(project, CSharpAdapter);
        let declarations = analyzer.get_all_declarations();
        let nested = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.identifier().starts_with("Nested"))
            .cloned()
            .expect("fixture declares Nested<T>");
        let run = declarations
            .iter()
            .find(|unit| unit.is_function() && unit.identifier() == "Run")
            .cloned()
            .expect("fixture declares Run");
        let root_class = declarations
            .iter()
            .find(|unit| unit.is_class() && unit.identifier() == "Root")
            .cloned()
            .expect("fixture declares a root-package type");
        let nested_owner = nested.fq().parent().expect("nested owner");
        let package = nested.package_fq();
        let mut package_types = declarations
            .iter()
            .filter(|unit| unit.is_class() && unit.package_fq() == package)
            .cloned()
            .collect::<Vec<_>>();
        package_types.sort();
        let nested_leaf = nested.fq().suffix_from(nested.fq().len() - 1);
        let scope = DefinitionLanguageScope::Language(Language::CSharp);
        let request = |ordinal, name, query| RelationalDefinitionRequest {
            ordinal,
            language_scope: scope.clone(),
            name,
            query,
        };
        let requests = vec![
            request(
                1,
                RelationalName::stable(nested.fq().clone()),
                RelationalDefinitionQuery::ExactName,
            ),
            request(
                2,
                RelationalName::stable(analyzer.adapter.normalize_fq_name(nested.fq())),
                RelationalDefinitionQuery::NormalizedName,
            ),
            request(
                3,
                RelationalName::stable(nested_owner.clone()),
                RelationalDefinitionQuery::StructuralChildren,
            ),
            request(
                4,
                RelationalName::stable(nested_owner),
                RelationalDefinitionQuery::StructuralMembers {
                    identifier: nested.identifier().to_string(),
                },
            ),
            request(
                5,
                RelationalName::stable(package.clone()),
                RelationalDefinitionQuery::VisibleMembers {
                    identifier: nested.identifier().to_string(),
                },
            ),
            request(
                6,
                RelationalName::stable(nested_leaf),
                RelationalDefinitionQuery::Identifier {
                    file: Some(file.clone()),
                },
            ),
            request(
                7,
                RelationalName::stable(package.clone()),
                RelationalDefinitionQuery::PackageTypes {
                    simple_name: "Nested".to_string(),
                },
            ),
            request(
                8,
                RelationalName::stable(package.clone()),
                RelationalDefinitionQuery::PackageTypesInPackage,
            ),
            request(
                9,
                RelationalName::stable(package.clone()),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Exists),
            ),
            request(
                10,
                RelationalName::stable(package),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Files),
            ),
            request(
                11,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Children),
            ),
            request(
                12,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::PackageRelation(PackageRelationKind::Descendants),
            ),
            request(
                13,
                RelationalName::stable(run.fq().clone()),
                RelationalDefinitionQuery::CallableFacts,
            ),
            request(
                14,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::StructuralChildren,
            ),
            request(
                15,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::PackageTypes {
                    simple_name: "Root".to_string(),
                },
            ),
            request(
                16,
                RelationalName::stable(FqName::new()),
                RelationalDefinitionQuery::PackageTypesInPackage,
            ),
            request(
                17,
                RelationalName::stable(
                    brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
                        Language::CSharp,
                        "Nested`",
                        brokk_bifrost_core::analyzer::fq_name::segment_interner(),
                    ),
                ),
                RelationalDefinitionQuery::IdentifierPrefix { file: None },
            ),
        ];

        let outcome = analyzer.batch(&requests, &CancellationToken::new());
        let RelationalBatchOutcome::Complete(results) = outcome else {
            panic!("all relational view shapes should complete: {outcome:?}");
        };
        for ordinal in 1..=7 {
            let RelationalDefinitionValue::Definitions(definitions) = &results[ordinal - 1].value
            else {
                panic!("request {ordinal} must return definitions")
            };
            assert_eq!(
                definitions,
                std::slice::from_ref(&nested),
                "request {ordinal}"
            );
        }
        assert_eq!(
            results[7].value,
            RelationalDefinitionValue::Definitions(package_types)
        );
        assert_eq!(
            results[8].value,
            RelationalDefinitionValue::PackageRelation(PackageRelationValue::Exists(true))
        );
        assert_eq!(
            results[9].value,
            RelationalDefinitionValue::PackageRelation(PackageRelationValue::Files(vec![
                file.clone()
            ]))
        );
        for result in &results[10..=11] {
            assert_eq!(
                result.value,
                RelationalDefinitionValue::PackageRelation(PackageRelationValue::Packages(vec![
                    "Demo".to_string()
                ]))
            );
        }
        let RelationalDefinitionValue::CallableFacts(facts) = &results[12].value else {
            panic!("callable request must return facts")
        };
        assert!(!facts.is_empty());
        assert!(facts.iter().all(|fact| fact.declaration == run));
        assert!(facts.iter().all(|fact| fact.metadata.is_some()));
        for result in &results[13..=15] {
            assert_eq!(
                result.value,
                RelationalDefinitionValue::Definitions(vec![root_class.clone()]),
                "root package is a valid structural and package query subject"
            );
        }
        assert_eq!(
            results[16].value,
            RelationalDefinitionValue::Definitions(vec![nested.clone()]),
            "the C# arity-free identifier spelling must use the indexed decoration range"
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .relational_batch_counts_for_test(),
            (1, 1, requests.len())
        );
    }

    #[test]
    fn bounded_file_cache_respects_capacity_under_interleaved_touches() {
        let mut cache: BoundedFileCache<u32> = BoundedFileCache::new(2);
        cache.insert(cache_key("a"), Arc::new(1));
        cache.insert(cache_key("b"), Arc::new(2));
        // Interleave touches (get) with a fresh insert; capacity must never
        // be exceeded no matter how many stale `order` duplicates a touch
        // leaves behind.
        assert!(cache.get(&cache_key("a")).is_some());
        assert!(cache.get(&cache_key("a")).is_some());
        assert!(cache.get(&cache_key("b")).is_some());
        cache.insert(cache_key("c"), Arc::new(3));
        assert_eq!(cache.len(), 2, "capacity must be respected after eviction");
    }

    #[test]
    fn bounded_file_cache_compacts_stale_order_duplicates() {
        let mut cache: BoundedFileCache<u32> = BoundedFileCache::new(2);
        cache.insert(cache_key("a"), Arc::new(1));
        cache.insert(cache_key("b"), Arc::new(2));
        // Touch "a" far past the compaction threshold; `order` must not grow
        // without bound even though `entries` stays fixed at capacity.
        for _ in 0..(CACHE_ORDER_COMPACT_FACTOR * 10) {
            assert!(cache.get(&cache_key("a")).is_some());
        }
        assert!(
            cache.order.len()
                <= cache.capacity * CACHE_ORDER_COMPACT_FACTOR + CACHE_ORDER_COMPACT_FACTOR,
            "order should be compacted instead of growing unboundedly, got {}",
            cache.order.len()
        );
        assert_eq!(cache.len(), 2);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#1707: cold FileState scans evicted repeatedly reused entries and made Phalcon probes stall for hours"
    )]
    #[test]
    fn segmented_file_state_cache_keeps_reused_states_through_a_cold_scan() {
        let state = Arc::new(empty_file_state("x".repeat(512), false));
        let weight = state.estimated_retained_bytes();
        let mut cache = SegmentedFileStateCache::new(weight.saturating_mul(4));
        let hot_a = cache_key("hot-a");
        let hot_b = cache_key("hot-b");
        cache.insert(hot_a.clone(), Arc::clone(&state));
        cache.insert(hot_b.clone(), Arc::clone(&state));
        assert!(cache.get(&hot_a).is_some());
        assert!(cache.get(&hot_b).is_some());

        for index in 0..4 {
            cache.insert(cache_key(&format!("cold-{index}")), Arc::clone(&state));
        }

        assert!(cache.contains(&hot_a), "a second use protects hot state a");
        assert!(cache.contains(&hot_b), "a second use protects hot state b");
        assert!(cache.retained_bytes() <= cache.max_bytes);
        assert_eq!(cache.stats().promotions, 2);
        assert!(cache.stats().evictions > 0);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#1707: file-state caching grew beyond the documented corpus-wide byte ceiling"
    )]
    #[test]
    fn file_state_cache_budget_tracks_corpus_with_a_hard_ceiling() {
        let config = AnalyzerConfig::default();
        let ceiling = file_state_cache_ceiling_bytes(&config);
        assert_eq!(
            file_state_cache_budget_bytes(&config, None),
            ceiling,
            "an unavailable corpus estimate must preserve the safe ceiling"
        );
        assert_eq!(
            file_state_cache_budget_bytes(&config, Some(100 * 1024 * 1024)),
            40 * 1024 * 1024,
            "the target is ten percent of the expanded persisted corpus"
        );
        assert_eq!(
            file_state_cache_budget_bytes(&config, Some(usize::MAX)),
            ceiling,
            "a whale corpus cannot exceed the configured ceiling"
        );
    }

    #[derive(Clone)]
    struct CountingOverlayProject {
        delegate: TestProject,
        listing_failed: Arc<std::sync::atomic::AtomicBool>,
        source: Arc<RwLock<(String, u64)>>,
        reads: Arc<AtomicUsize>,
        replacement: Arc<RwLock<Option<String>>>,
        reads_after_arm: Arc<AtomicUsize>,
    }

    impl CountingOverlayProject {
        fn new(root: impl Into<std::path::PathBuf>, source: impl Into<String>) -> Self {
            Self {
                delegate: TestProject::new(root, Language::Rust),
                listing_failed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                source: Arc::new(RwLock::new((source.into(), 1))),
                reads: Arc::new(AtomicUsize::new(0)),
                replacement: Arc::new(RwLock::new(None)),
                reads_after_arm: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn set_source(&self, source: impl Into<String>) {
            let mut current = self.source.write().expect("source lock poisoned");
            current.0 = source.into();
            current.1 = current
                .1
                .checked_add(1)
                .expect("test overlay revision space exhausted");
        }

        fn reset_reads(&self) {
            self.reads.store(0, Ordering::Relaxed);
        }

        fn read_count(&self) -> usize {
            self.reads.load(Ordering::Relaxed)
        }

        fn arm_source_swap(&self, replacement: impl Into<String>) {
            *self
                .replacement
                .write()
                .expect("replacement source lock poisoned") = Some(replacement.into());
            self.reads_after_arm.store(0, Ordering::Release);
        }
    }

    impl Project for CountingOverlayProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            if self.listing_failed.load(Ordering::Relaxed) {
                return Err(std::io::Error::other(
                    "injected source inventory listing failure",
                ));
            }
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, _file: &ProjectFile) -> std::io::Result<String> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            if let Some(replacement) = self
                .replacement
                .read()
                .expect("replacement source lock poisoned")
                .as_ref()
                && self.reads_after_arm.fetch_add(1, Ordering::AcqRel) > 0
            {
                return Ok(replacement.clone());
            }
            Ok(self.source.read().expect("source lock poisoned").0.clone())
        }

        fn read_source_snapshot(
            &self,
            _file: &ProjectFile,
        ) -> std::io::Result<ProjectSourceSnapshot> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            if let Some(replacement) = self
                .replacement
                .read()
                .expect("replacement source lock poisoned")
                .as_ref()
                && self.reads_after_arm.fetch_add(1, Ordering::AcqRel) > 0
            {
                return Ok(ProjectSourceSnapshot::overlay(
                    replacement.clone(),
                    OverlayRevision::from_monotonic_counter(2),
                ));
            }
            let current = self.source.read().expect("source lock poisoned");
            Ok(ProjectSourceSnapshot::overlay(
                current.0.clone(),
                OverlayRevision::from_monotonic_counter(current.1),
            ))
        }

        fn has_overlay(&self, _file: &ProjectFile) -> bool {
            true
        }
    }

    /// Keeps the workspace listing stable while removing a configuration file
    /// immediately before a generation's source reconciliation. This models a
    /// manifest disappearing after the immutable inventory was captured,
    /// without depending on platform-specific permission behavior.
    #[derive(Clone)]
    struct ConfigurationCaptureFailureProject {
        delegate: TestProject,
        files: BTreeSet<ProjectFile>,
        manifest: ProjectFile,
        fail_next_capture: Arc<AtomicBool>,
    }

    impl ConfigurationCaptureFailureProject {
        fn new(delegate: TestProject, manifest: ProjectFile) -> Self {
            let files = delegate
                .all_files()
                .expect("configuration fixture workspace listing");
            Self {
                delegate,
                files,
                manifest,
                fail_next_capture: Arc::new(AtomicBool::new(false)),
            }
        }

        fn fail_next_capture(&self) {
            assert!(
                !self.fail_next_capture.swap(true, Ordering::AcqRel),
                "only one configuration capture failure may be armed"
            );
        }
    }

    impl Project for ConfigurationCaptureFailureProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            Ok(self.files.clone())
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files_from(&self.files, language)
        }

        fn analyzable_files_from(
            &self,
            files: &BTreeSet<ProjectFile>,
            language: Language,
        ) -> std::io::Result<BTreeSet<ProjectFile>> {
            if self.fail_next_capture.swap(false, Ordering::AcqRel) {
                std::fs::remove_file(self.manifest.abs_path())
                    .expect("armed configuration capture failure should remove manifest");
            }
            self.delegate.analyzable_files_from(files, language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }
    }

    /// Changes the source after the reusable-identity probe, but returns no
    /// overlay from that probe. The following source lookup sees the changed
    /// bytes as an overlay. This is deterministic and exercises the identity
    /// pairing that a concurrent file/overlay transition would require.
    struct ProbeReplacementProject {
        delegate: TestProject,
        source: RwLock<String>,
        replacement: String,
        arm_probe: AtomicBool,
        replaced: AtomicBool,
    }

    impl ProbeReplacementProject {
        fn new(
            root: impl Into<std::path::PathBuf>,
            source: impl Into<String>,
            replacement: impl Into<String>,
        ) -> Self {
            Self {
                delegate: TestProject::new(root, Language::Rust),
                source: RwLock::new(source.into()),
                replacement: replacement.into(),
                arm_probe: AtomicBool::new(false),
                replaced: AtomicBool::new(false),
            }
        }

        fn arm_probe(&self) {
            assert!(!self.arm_probe.swap(true, Ordering::AcqRel));
        }

        fn was_replaced(&self) -> bool {
            self.replaced.load(Ordering::Acquire)
        }

        fn current_source(&self) -> String {
            self.source
                .read()
                .expect("probe source lock poisoned")
                .clone()
        }
    }

    impl Project for ProbeReplacementProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, _file: &ProjectFile) -> std::io::Result<String> {
            Ok(self.current_source())
        }

        fn read_source_snapshot(
            &self,
            _file: &ProjectFile,
        ) -> std::io::Result<ProjectSourceSnapshot> {
            let source = self.current_source();
            if self.replaced.load(Ordering::Acquire) {
                Ok(ProjectSourceSnapshot::overlay(
                    source,
                    OverlayRevision::from_monotonic_counter(1),
                ))
            } else {
                Ok(ProjectSourceSnapshot::disk(source))
            }
        }

        fn has_overlay(&self, _file: &ProjectFile) -> bool {
            if self.arm_probe.swap(false, Ordering::AcqRel) {
                *self.source.write().expect("probe source lock poisoned") =
                    self.replacement.clone();
                self.replaced.store(true, Ordering::Release);
                false
            } else {
                self.replaced.load(Ordering::Acquire)
            }
        }
    }

    #[test]
    fn structural_facts_miss_rekeys_after_probe_source_changes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        let source_before_probe = "fn before_probe() {}\n";
        let source_after_probe = "fn after_probe() {}\n";
        file.write(source_before_probe)
            .expect("write initial Rust source");

        let project = Arc::new(ProbeReplacementProject::new(
            &root,
            source_before_probe,
            source_after_probe,
        ));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);
        let provider = analyzer
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("Rust structural provider");
        let before_oid = analyzer
            .content_oid_of(&file, source_before_probe)
            .expect("the fixture source names its bytes");
        assert_eq!(
            analyzer.reusable_live_oid(&file),
            Some(before_oid),
            "the fixture must admit the old identity before the source transition"
        );

        project.arm_probe();
        let facts = provider
            .structural_facts(&file)
            .expect("facts after the source transition");
        assert!(
            project.was_replaced(),
            "the probe must install the replacement"
        );
        assert_eq!(facts.source(), source_after_probe);

        let materializations =
            provider.structural_extraction_count() + provider.structural_hydration_count();
        let repeated = provider
            .structural_facts(&file)
            .expect("repeated facts after the source transition");
        assert!(Arc::ptr_eq(&facts, &repeated));
        assert_eq!(
            provider.structural_extraction_count() + provider.structural_hydration_count(),
            materializations,
            "the replacement bytes must be retained under their actual content key"
        );
    }

    /// Records the thread each overlay OID read is billed to.
    #[derive(Clone)]
    struct OverlayReadThreadProject {
        delegate: TestProject,
        read_threads: Arc<Mutex<Vec<String>>>,
    }

    impl Project for OverlayReadThreadProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            self.read_threads
                .lock()
                .expect("overlay read thread log poisoned")
                .push(
                    std::thread::current()
                        .name()
                        .unwrap_or("<unnamed>")
                        .to_string(),
                );
            self.delegate.read_source(file)
        }

        fn has_overlay(&self, _file: &ProjectFile) -> bool {
            true
        }
    }

    /// Every overlay OID read fails, naming the file that failed.
    #[derive(Clone)]
    struct FailingOverlayProject {
        delegate: TestProject,
    }

    impl Project for FailingOverlayProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            Err(std::io::Error::other(format!(
                "{} overlay OID failure",
                file.rel_path().display()
            )))
        }

        fn has_overlay(&self, _file: &ProjectFile) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct BlockingParseProject {
        delegate: TestProject,
        blocked_file: PathBuf,
        blocked_parse_started: std::sync::mpsc::SyncSender<()>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    impl Project for BlockingParseProject {
        fn root(&self) -> &Path {
            self.delegate.root()
        }

        fn analyzer_languages(&self) -> BTreeSet<Language> {
            self.delegate.analyzer_languages()
        }

        fn all_files(&self) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.all_files()
        }

        fn analyzable_files(&self, language: Language) -> std::io::Result<BTreeSet<ProjectFile>> {
            self.delegate.analyzable_files(language)
        }

        fn file_by_rel_path(&self, rel_path: &Path) -> Option<ProjectFile> {
            self.delegate.file_by_rel_path(rel_path)
        }

        fn read_source(&self, file: &ProjectFile) -> std::io::Result<String> {
            if file.rel_path() == self.blocked_file {
                self.blocked_parse_started
                    .send(())
                    .expect("blocked parse observer should remain connected");
                let (released, wake) = &*self.release;
                let mut released = released.lock().expect("parse release mutex poisoned");
                while !*released {
                    released = wake.wait(released).expect("parse release mutex poisoned");
                }
            }
            self.delegate.read_source(file)
        }
    }

    /// The multi-file hashing burst runs on the process-shared dedicated build
    /// pool, so it is billed neither to the calling thread nor to a global-pool
    /// worker that an interactive request would otherwise be waiting for
    /// (#2115). The pool's width is a process setting, so the burst's own
    /// concurrency is not something one `AnalyzerConfig` can assert; that it
    /// runs off the caller and off the global pool is.
    #[test]
    fn live_oid_resolution_hashes_overlays_on_the_dedicated_build_pool() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let first = temp_file(&root, "src/First.java");
        let first_source = "package demo; class First {}\n";
        first.write(first_source).expect("first Java source");
        let second = temp_file(&root, "src/Second.java");
        let second_source = "package demo; class Second {}\n";
        second.write(second_source).expect("second Java source");

        let read_threads = Arc::new(Mutex::new(Vec::new()));
        let project = OverlayReadThreadProject {
            delegate: TestProject::new(&root, Language::Java),
            read_threads: Arc::clone(&read_threads),
        };
        let store_context = ephemeral_store_context(&project).unwrap();

        let resolved = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[first.clone(), second.clone()],
            &store_context,
            true,
        )
        .expect("both overlay identities resolve");

        for (file, source) in [(&first, first_source), (&second, second_source)] {
            let expected =
                Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("overlay OID");
            assert_eq!(resolved.get(file), Some(&expected));
        }

        let read_threads = read_threads.lock().expect("read thread log poisoned");
        assert_eq!(
            read_threads.len(),
            2,
            "both overlays hashed: {read_threads:?}"
        );
        assert!(
            read_threads
                .iter()
                .all(|name| name.starts_with("bifrost-index-build-")),
            "overlay hashing escaped the dedicated build pool: {read_threads:?}"
        );
    }

    /// A failed plan reports the first *input's* error, not the first error the
    /// burst happened to produce, so the same edit always reports the same file.
    #[test]
    fn live_oid_resolution_reports_the_first_input_error() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let first = temp_file(&root, "src/First.java");
        first.write("first\n").expect("first source");
        let expected_first_error = format!("{} overlay OID failure", first.rel_path().display());
        let second = temp_file(&root, "src/Second.java");
        second.write("second\n").expect("second source");

        let project = FailingOverlayProject {
            delegate: TestProject::new(&root, Language::Java),
        };
        let store_context = ephemeral_store_context(&project).unwrap();

        let error = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[first, second],
            &store_context,
            true,
        )
        .expect_err("both overlay reads fail");

        assert_eq!(error, expected_first_error);
    }

    #[test]
    fn empty_live_oid_planning_preserves_refresh_and_replace_semantics() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/Existing.java");
        let source = "package demo; class Existing {}\n";
        file.write(source).expect("existing Java source");
        let project = TestProject::new(&root, Language::Java);
        let store_context = ephemeral_store_context(&project).unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("source OID");
        store_context
            .live_paths
            .refresh([LivePathEntry::overlay(file.clone(), oid)]);

        let refreshed = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[],
            &store_context,
            false,
        )
        .expect("empty refresh");
        assert!(refreshed.is_empty());
        assert_eq!(
            store_context.live_paths.snapshot().oid_for_path(&file),
            Some(oid)
        );

        let replaced = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[],
            &store_context,
            true,
        )
        .expect("empty replacement");
        assert!(replaced.is_empty());
        assert_eq!(
            store_context.live_paths.snapshot().oid_for_path(&file),
            None
        );
    }

    #[test]
    fn indexed_source_match_is_anchored_to_the_analyzer_generation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/Widget.java");
        let indexed = "package demo; class Widget {}\n";
        let later = "package demo; class Widget { void later() {} }\n";
        file.write(indexed).expect("indexed Java source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        analyzer.blob_oids.entries.invalidate(&file);
        analyzer.reset_blob_hash_count_for_test();
        for _ in 0..16 {
            assert!(analyzer.indexed_source_matches(&file, indexed));
        }
        assert_eq!(
            analyzer.blob_hash_count_for_test(),
            1,
            "repeated checks of unchanged indexed source should hash its blob once"
        );
        let indexed_identity = analyzer.language_content_identity();

        file.write(later).expect("later Java source");
        let stale_query = analyzer.clone();
        stale_query
            .fetch_file_state_from_current_source(&file)
            .expect("stale query observes and parses the later source");
        let later_oid = Oid::hash_object(ObjectType::Blob, later.as_bytes()).expect("later OID");
        assert_eq!(
            analyzer.live_snapshot().oid_for_path(&file),
            Some(later_oid),
            "the query must exercise a refresh of the shared live projection"
        );
        assert!(analyzer.indexed_source_matches(&file, indexed));
        assert!(
            !analyzer.indexed_source_matches(&file, later),
            "a refreshed live projection must not redefine what this generation indexed"
        );
        let hashes_after_edit = analyzer.blob_hash_count_for_test();
        for _ in 0..16 {
            assert!(!analyzer.indexed_source_matches(&file, later));
        }
        assert_eq!(
            analyzer.blob_hash_count_for_test(),
            hashes_after_edit,
            "repeated checks must reuse the changed source identity too"
        );
        assert_eq!(
            analyzer.language_content_identity(),
            indexed_identity,
            "query hydration must not move the analyzer generation's cache identity"
        );
    }

    #[test]
    fn incremental_update_retains_unmodified_identity_from_the_prior_generation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let first = temp_file(&root, "src/First.java");
        let second = temp_file(&root, "src/Second.java");
        let first_indexed = "package demo; class First {}\n";
        let first_later = "package demo; class First { void later() {} }\n";
        let second_indexed = "package demo; class Second {}\n";
        let second_later = "package demo; class Second { void later() {} }\n";
        first.write(first_indexed).expect("indexed first source");
        second.write(second_indexed).expect("indexed second source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        second.write(second_later).expect("later second source");
        analyzer
            .clone()
            .fetch_file_state_from_current_source(&second)
            .expect("stale query observes the later second source");
        first.write(first_later).expect("later first source");

        let updated = analyzer.update(&BTreeSet::from([first.clone()]));
        assert!(updated.indexed_source_matches(&first, first_later));
        assert!(updated.indexed_source_matches(&second, second_indexed));
        assert!(
            !updated.indexed_source_matches(&second, second_later),
            "updating another file must not bless a stale query's observation as indexed"
        );

        let fully_updated = updated.update(&BTreeSet::from([second.clone()]));
        assert!(fully_updated.indexed_source_matches(&second, second_later));
    }

    #[test]
    fn revision_supplied_blob_ids_replace_hashing_the_exported_bytes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        // `src/First.java` sorts first, so it is the entry the sampled debug
        // assertion checks, and its inventory id must therefore be the honest
        // hash of what is on disk. `src/Second.java` carries the proof: its
        // inventory id names bytes the file does not hold, so a resolution that
        // hashed the file would report the disk id instead.
        let first = temp_file(&root, "src/First.java");
        first.write("class First {}\n").expect("first source");
        let first_oid =
            Oid::hash_object(ObjectType::Blob, b"class First {}\n").expect("first blob id");
        let second = temp_file(&root, "src/Second.java");
        second.write("class OnDisk {}\n").expect("second source");
        let second_disk_oid =
            Oid::hash_object(ObjectType::Blob, b"class OnDisk {}\n").expect("disk blob id");
        let second_revision_oid =
            Oid::hash_object(ObjectType::Blob, b"class InTheRevision {}\n").expect("revision id");

        let project = TestProject::new(&root, Language::Java);
        let mut store_context = ephemeral_store_context(&project).unwrap();
        store_context.revision_blobs = Some(Arc::new(RevisionBlobIdentities::new(
            vec![
                (first.rel_path().to_path_buf(), first_oid),
                (second.rel_path().to_path_buf(), second_revision_oid),
            ],
            Vec::new(),
        )));

        let resolved = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[first.clone(), second.clone()],
            &store_context,
            true,
        )
        .expect("revision identities resolve");

        assert_eq!(resolved.get(&first), Some(&first_oid));
        assert_eq!(
            resolved.get(&second),
            Some(&second_revision_oid),
            "the revision's inventory decides identity; hashing would have reported \
             {second_disk_oid}"
        );
        // The identity is also what every later query reads, without a stat.
        assert_eq!(
            store_context
                .live_paths
                .snapshot()
                .validated_oid_for_path(&second),
            Some(second_revision_oid)
        );
    }

    /// The sampled re-hash is the only thing standing between a mis-assembled
    /// inventory and facts published under the wrong content key, so prove it
    /// fires. Debug-only: the assertion is compiled out of a release build by
    /// design, and this test would then never panic.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "exported bytes hash differently")]
    fn a_sampled_revision_blob_id_that_disagrees_with_the_export_is_rejected() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let only = temp_file(&root, "src/Only.java");
        only.write("class Only {}\n").expect("only source");
        let wrong = Oid::hash_object(ObjectType::Blob, b"class Other {}\n").expect("wrong blob id");

        let project = TestProject::new(&root, Language::Java);
        let mut store_context = ephemeral_store_context(&project).unwrap();
        store_context.revision_blobs = Some(Arc::new(RevisionBlobIdentities::new(
            vec![(only.rel_path().to_path_buf(), wrong)],
            Vec::new(),
        )));

        let _ = TreeSitterAnalyzer::<JavaAdapter>::resolve_live_oids(
            &project,
            &[only],
            &store_context,
            true,
        );
    }

    #[test]
    fn persisted_epoch_publication_failure_is_returned_from_analyzer_construction() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let db = root.join("analyzer.db");
        let store =
            Arc::new(AnalyzerStore::open_persistent(&db).expect("initialize persistent store"));
        let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db)
            .expect("open test connection");
        conn.execute_batch(
            "CREATE TRIGGER fail_epoch_publication
             BEFORE INSERT ON analysis_epochs
             BEGIN
                 SELECT RAISE(FAIL, 'forced epoch publication failure');
             END;",
        )
        .expect("install epoch failure trigger");
        drop(conn);

        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store_context = AnalyzerStoreContext {
            store,
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(
                project.root(),
            ),
            _projection_lease: None,
            gc: Arc::new(
                brokk_bifrost_analysis::analyzer::store::gc::AnalyzerGcCoordinator::default(),
            ),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
            structural_facts: Arc::new(OnceLock::new()),
            cancellation: brokk_bifrost_core::cancellation::CancellationToken::default(),
        };

        let error = match TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig::default(),
            store_context,
            None,
        ) {
            Ok(_) => panic!("epoch publication failure should be returned"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("publishing analyzer epochs"));
        assert!(
            error
                .to_string()
                .contains("forced epoch publication failure")
        );
    }

    #[test]
    fn reconcile_persists_fast_parse_before_blocked_slow_parse_is_released() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let fast = temp_file(&root, "src/Fast.java");
        fast.write("package demo; class Fast {}\n")
            .expect("fast Java source");
        let slow = temp_file(&root, "src/Slow.java");
        slow.write("package demo; class Slow {}\n")
            .expect("slow Java source");

        let (blocked_parse_started_tx, blocked_parse_started_rx) = std::sync::mpsc::sync_channel(1);
        let (persisted_tx, persisted_rx) = std::sync::mpsc::sync_channel(1);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let project: Arc<dyn Project> = Arc::new(BlockingParseProject {
            delegate: TestProject::new(&root, Language::Java),
            blocked_file: slow.rel_path().to_path_buf(),
            blocked_parse_started: blocked_parse_started_tx,
            release: Arc::clone(&release),
        });
        let store_context = ephemeral_store_context(project.as_ref()).unwrap();
        let store = Arc::clone(&store_context.store);
        let progress: BuildProgress = Arc::new(move |event| {
            if event.phase == BuildProgressPhase::Persist && event.completed > 0 {
                let _ = persisted_tx.try_send(());
            }
        });

        let build = std::thread::spawn(move || {
            TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                project,
                JavaAdapter,
                AnalyzerConfig {
                    parallelism: Some(2),
                    ..AnalyzerConfig::default()
                },
                store_context,
                Some(progress),
            )
        });

        blocked_parse_started_rx
            .recv()
            .expect("slow parse should reach the injected block");
        persisted_rx
            .recv()
            .expect("fast parse should persist while slow parse is blocked");
        let persistence_starts_before_release = store.parsed_blob_transaction_starts_for_test();
        {
            let (released, wake) = &*release;
            *released.lock().expect("parse release mutex poisoned") = true;
            wake.notify_all();
        }
        build
            .join()
            .expect("analyzer build should finish")
            .expect("analyzer epochs should initialize");

        assert!(
            persistence_starts_before_release > 0,
            "the real reconcile pipeline should start persisting the prepared fast blob while the unrelated slow parser remains blocked"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2326: cold workspace construction serialized per-file Rust persistence and spent about ten seconds reconciling"
    )]
    #[test]
    fn reconcile_batches_257_small_files_into_two_transactions() {
        const FILES: usize = 257;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for index in 0..FILES {
            let file = temp_file(&root, &format!("src/Type{index}.java"));
            file.write(format!("package demo; class Type{index} {{}}\n"))
                .expect("Java source");
        }
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store_context = ephemeral_store_context(project.as_ref()).unwrap();
        let store = Arc::clone(&store_context.store);

        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            store_context,
            None,
        )
        .expect("analyzer epochs should initialize");

        assert_eq!(store.parsed_blob_transaction_starts_for_test(), 2);
        assert_eq!(analyzer.state.persistence_stats.transactions, 2);
        assert_eq!(analyzer.state.persistence_stats.committed_blobs, FILES);
        assert_eq!(analyzer.state.persistence_stats.failed_blobs, 0);
        assert!(analyzer.state.persistence_stats.peak_in_flight_items > 0);
        assert!(
            analyzer.state.persistence_stats.peak_in_flight_items
                <= analyzer
                    .state
                    .persistence_stats
                    .configured_max_in_flight_items
        );
        assert!(
            analyzer
                .state
                .persistence_stats
                .peak_in_flight_payload_bytes
                > 0
        );
    }

    #[test]
    fn preparation_failure_reaches_terminal_persist_progress_and_dirty_fallback() {
        const SHARED_SOURCE: &str = "int shared;\n";
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let bad = temp_file(&root, "src/Bad.h");
        bad.write(SHARED_SOURCE).expect("C++ header");
        let seed = temp_file(&root, "src/Seed.c");
        seed.write(SHARED_SOURCE).expect("C source");
        let seed_project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Cpp));
        let seed_analyzer = TreeSitterAnalyzer::new(seed_project, CppAdapter);
        let store = Arc::clone(&seed_analyzer.store_context.store);
        let shared_oid = Oid::hash_object(ObjectType::Blob, SHARED_SOURCE.as_bytes()).unwrap();
        assert!(store.contains_parsed_blob(shared_oid, "cpp").unwrap());
        assert!(store.contains_parsed_blob(shared_oid, "cpp:c").unwrap());

        std::fs::remove_file(seed.abs_path()).expect("remove independent C owner");
        for name in ["GoodA", "GoodB"] {
            let file = temp_file(&root, &format!("src/{name}.h"));
            file.write(format!("int {name};\n")).expect("C++ header");
        }
        store
            .ensure_language_epoch_value("cpp:c", "stale-optional-preparation-failure")
            .expect("advance the optional projection generation");
        *PREPARATION_FAILURE_PATH
            .lock()
            .expect("preparation failure path mutex poisoned") = Some(bad.abs_path().to_path_buf());
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Cpp));
        let events = Arc::new(Mutex::new(Vec::new()));
        let progress_events = Arc::clone(&events);
        let progress: BuildProgress = Arc::new(move |event| {
            progress_events
                .lock()
                .expect("progress event mutex poisoned")
                .push(event);
        });

        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            CppAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            seed_analyzer.store_context.clone(),
            Some(progress),
        )
        .expect("analyzer epochs should initialize");
        *PREPARATION_FAILURE_PATH
            .lock()
            .expect("preparation failure path mutex poisoned") = None;

        assert_eq!(analyzer.state.persistence_stats.committed_blobs, 2);
        assert_eq!(analyzer.state.persistence_stats.failed_blobs, 1);
        assert_eq!(analyzer.state.persistence_stats.committed_fragments, 2);
        assert_eq!(analyzer.state.persistence_stats.failed_fragments, 2);
        let dirty = analyzer.state.dirty_snapshot();
        assert_eq!(dirty.len(), 1);
        let (dirty_key, dirty_state) = dirty.iter().next().unwrap();
        assert_eq!(dirty_key.rel_path, bad.rel_path());
        assert!(dirty_state.state.additional_projections.is_empty());
        assert_eq!(
            dirty_state
                .required_existing_additional_storage_languages
                .as_ref(),
            &["cpp:c".to_owned()]
        );
        let events = events.lock().expect("progress event mutex poisoned");
        let final_persist = events
            .iter()
            .rev()
            .find(|event| event.phase == BuildProgressPhase::Persist)
            .expect("persist progress event");
        assert_eq!(final_persist.completed, 3);
        assert_eq!(final_persist.total, 3);
        drop(events);

        let request = [CompleteAnalysisBlobRequest::new(
            shared_oid,
            "cpp",
            ["cpp:c".to_owned()],
        )];
        let dirty_key = dirty_key.clone();
        analyzer
            .state
            .dirty_file_states
            .lock()
            .expect("dirty file-state mutex poisoned")
            .get_mut(&dirty_key)
            .expect("failed preparation must remain dirty")
            .next_retry_at = Instant::now();
        let starts = store.parsed_blob_transaction_starts_for_test();

        let retried = analyzer
            .retry_dirty_file_state(&dirty_key, "cpp")
            .expect("dirty state remains available during retry");

        assert!(retried.additional_projections.is_empty());
        assert_eq!(store.parsed_blob_transaction_starts_for_test(), starts + 1);
        assert!(analyzer.state.dirty_snapshot().is_empty());
        assert!(store.contains_parsed_blob(shared_oid, "cpp").unwrap());
        assert!(store.contains_parsed_blob(shared_oid, "cpp:c").unwrap());
        assert!(
            store
                .missing_published_complete_analysis_blob_keys_at_generations(
                    &request,
                    analyzer.store_context.generations.as_ref(),
                    Language::Cpp,
                    None,
                )
                .unwrap()
                .is_empty(),
            "retry must make the current primary and required optional projection warm"
        );
    }

    /// Issue #2359. On microsoft/PowerToys a Cpp build worker panicked within
    /// seconds and the process then outlived a 1872-second timeout, because
    /// `std::thread::scope` joins every sibling before the panic can leave the
    /// fan-out and nothing told those siblings to stop.
    ///
    /// The fixture makes that shape deterministic: one language panics on its
    /// only file, the other blocks on its only file until the build abort
    /// reaches it. The sibling records that it observed the abort; this proves
    /// the synchronization contract directly without a wall-clock assertion
    /// that becomes flaky when the full test binary is CPU-saturated. Its
    /// 30-second internal safety timeout still prevents a broken signal from
    /// wedging the test process.
    #[test]
    fn a_panicking_build_worker_aborts_the_whole_build_promptly() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let panicking = temp_file(&root, "src/panics.cpp");
        panicking
            .write("void init_settings() {}\n")
            .expect("cpp source");
        let blocking = temp_file(&root, "src/blocks.py");
        blocking
            .write("def work():\n    return 1\n")
            .expect("py source");
        *PANICKING_ANALYSIS_PATH
            .lock()
            .expect("panicking analysis path mutex poisoned") = Some(panicking.abs_path());
        *BLOCK_UNTIL_BUILD_ABORT_PATH
            .lock()
            .expect("block until build abort path mutex poisoned") = Some(blocking.abs_path());
        BLOCKING_ANALYSIS_OBSERVED_ABORT.store(false, Ordering::Release);
        *BLOCKING_ANALYSIS_READY
            .0
            .lock()
            .expect("blocking analysis ready mutex poisoned") = false;

        let project: Arc<dyn Project> = Arc::new(TestProject::with_languages(
            &root,
            BTreeSet::from([Language::Cpp, Language::Python]),
        ));
        // Two workers, not two thread pools the width of the machine: the
        // fixture needs one file in flight per language, and a CPU spike inside
        // a 1900-test binary perturbs timing-sensitive neighbours.
        let config = AnalyzerConfig {
            parallelism: Some(1),
            ..AnalyzerConfig::default()
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            brokk_bifrost_analysis::analyzer::workspace::WorkspaceAnalyzer::build_persisted(
                project, config,
            )
        }));

        *PANICKING_ANALYSIS_PATH
            .lock()
            .expect("panicking analysis path mutex poisoned") = None;
        *BLOCK_UNTIL_BUILD_ABORT_PATH
            .lock()
            .expect("block until build abort path mutex poisoned") = None;

        let payload = outcome
            .err()
            .expect("a panicking worker must fail the build");
        let message = payload
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_else(|| "non-string panic payload".to_string());
        assert!(
            message.contains("injected analysis panic"),
            "the original panic message must survive propagation: {message}"
        );
        assert!(
            BLOCKING_ANALYSIS_OBSERVED_ABORT.load(Ordering::Acquire),
            "the blocked sibling must observe the shared build abort"
        );
    }

    #[test]
    fn reconcile_keeps_only_irreducible_prepared_failure_dirty() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let good_a = temp_file(&root, "src/GoodA.java");
        good_a
            .write("package demo; class GoodA {}\n")
            .expect("good Java source");
        let bad = temp_file(&root, "src/Bad.java");
        bad.write("package demo; class Bad {}\n")
            .expect("bad Java source");
        let good_b = temp_file(&root, "src/GoodB.java");
        good_b
            .write("package demo; class GoodB {}\n")
            .expect("good Java source");
        *PREPARED_FAILURE_PATH
            .lock()
            .expect("prepared failure path mutex poisoned") = Some(bad.abs_path().to_path_buf());

        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new_with_config(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(3),
                ..AnalyzerConfig::default()
            },
        );
        *PREPARED_FAILURE_PATH
            .lock()
            .expect("prepared failure path mutex poisoned") = None;

        let dirty = analyzer.state.dirty_snapshot();
        assert_eq!(dirty.len(), 1);
        let (dirty_key, dirty_state) = dirty.iter().next().unwrap();
        assert_eq!(dirty_key.rel_path, bad.rel_path());
        assert_eq!(dirty_state.attempts, STORE_WRITE_IMMEDIATE_RETRIES + 1);
        for file in [&good_a, &good_b] {
            let source = file.read_to_string().unwrap();
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            assert!(
                analyzer
                    .store_context
                    .store
                    .contains_parsed_blob(oid, "java")
                    .unwrap()
            );
        }
        let bad_oid =
            Oid::hash_object(ObjectType::Blob, bad.read_to_string().unwrap().as_bytes()).unwrap();
        assert!(
            !analyzer
                .store_context
                .store
                .contains_parsed_blob(bad_oid, "java")
                .unwrap()
        );
    }

    fn parse_javascript(source: &str) -> Tree {
        brokk_bifrost_js_ts::test_support::parse_javascript(source)
    }

    fn empty_file_state(source: impl Into<String>, contains_tests: bool) -> FileState {
        FileState {
            source: source.into(),
            package_name: String::new(),
            content_qualifier: String::new(),
            top_level_declarations: Vec::new(),
            declarations: HashSet::default(),
            definition_lookup_units: HashSet::default(),
            imports: Vec::new(),
            scala_exports: HashMap::default(),
            rust_usage_facts: Default::default(),
            resolution_facts: Default::default(),
            source_facts: None,
            source_declaration_units: Vec::new(),
            source_declaration_metadata: Vec::new(),
            raw_supertypes: HashMap::default(),
            supertype_lookup_paths: HashMap::default(),
            type_identifiers: HashSet::default(),
            signatures: HashMap::default(),
            signature_metadata: HashMap::default(),
            signature_metadata_signature_ordinals: HashMap::default(),
            cpp_template_metadata: HashMap::default(),
            ruby_method_dispatch_modes: HashMap::default(),
            ranges: HashMap::default(),
            children: HashMap::default(),
            scala_traits: HashSet::default(),
            type_aliases: HashSet::default(),
            contains_tests,
            test_region_units: HashSet::default(),
            materialization_records: Vec::new(),
            parse_errors: None,
            completeness: brokk_bifrost_core::analyzer::model::ParseCompleteness::Complete,
            parse_complete: true,
            additional_projections: Vec::new(),
        }
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2883: file-state assembly dropped parsed resolution facts before the resolver consumed them"
    )]
    #[test]
    fn parsed_resolution_facts_survive_file_state_assembly() {
        use brokk_bifrost_core::analyzer::resolution_facts::{
            FileResolutionFacts, ResolutionNameFact, ResolutionNameId,
        };

        let expected = FileResolutionFacts {
            names: vec![ResolutionNameFact {
                id: ResolutionNameId::new(0),
                spelling: "Widget".to_string(),
            }],
            ..FileResolutionFacts::default()
        };
        let mut parsed = ParsedFile::new(String::new());
        parsed.resolution_facts = expected.clone();

        let state = TreeSitterAnalyzer::<JavaAdapter>::file_state_from_parsed(
            String::new(),
            parsed,
            false,
            None,
            true,
        );

        assert_eq!(state.resolution_facts, expected);
        assert!(state.estimated_retained_bytes() >= std::mem::size_of::<FileState>());
    }

    fn temp_file(root: &Path, rel_path: &str) -> ProjectFile {
        ProjectFile::new(root.to_path_buf(), rel_path)
    }

    /// #2883: only an open buffer can override a persisted row, so the
    /// authoritative read walks the live snapshot's overlay set instead of
    /// every cached file state. The buffer's declaration must still win, and
    /// the walk must materialize that one state -- with no buffer open it must
    /// materialize none at all, however many states the analyzer has cached.
    #[brokk_bifrost_test_macros::hardwon(
        "#2883: every relational batch deep-cloned cached file states and reselected workspace snapshots"
    )]
    #[test]
    fn authoritative_reads_cost_the_open_buffers_not_the_cached_file_states() {
        const FILE_COUNT: usize = 8;

        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let files = (0..FILE_COUNT)
            .map(|index| {
                let file = temp_file(&root, &format!("src/file{index}.rs"));
                file.write(format!("pub fn disk_{index}() {{}}\n"))
                    .expect("rust source");
                file
            })
            .collect::<Vec<_>>();
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&overlay) as Arc<dyn Project>, RustAdapter);
        for file in &files {
            analyzer.fetch_file_state(file).expect("warm file state");
        }

        analyzer.reset_authoritative_file_state_reads_for_test();
        let on_disk = analyzer.get_all_declarations();
        assert!(
            !on_disk
                .iter()
                .any(|unit| unit.fq_name().ends_with("buffer_only")),
            "the fixture declares this name only in the buffer: {on_disk:?}"
        );
        assert_eq!(
            analyzer.authoritative_file_state_reads_for_test(),
            0,
            "with no buffer open a read must materialize none of the {FILE_COUNT} cached states"
        );

        assert!(overlay.set(files[0].abs_path(), "pub fn buffer_only() {}\n".to_owned()));
        analyzer.reset_authoritative_file_state_reads_for_test();
        let with_buffer = analyzer.get_all_declarations();

        assert!(
            with_buffer
                .iter()
                .any(|unit| unit.fq_name().ends_with("buffer_only") && unit.source() == &files[0]),
            "the open buffer's declaration must override the disk row: {with_buffer:?}"
        );
        assert_eq!(
            analyzer.authoritative_file_state_reads_for_test(),
            1,
            "one open buffer is one materialized file state"
        );
    }

    #[test]
    fn parse_error_collection_skips_error_descendants_iteratively() {
        let tree = parse_javascript("function broken( { const value = ; }\n");
        let mut errors = Vec::new();

        collect_parse_errors(tree.root_node(), &mut errors);

        assert!(!errors.is_empty(), "expected parse errors");
        for index in 0..errors.len() {
            for other in 0..errors.len() {
                if index == other {
                    continue;
                }
                let left = &errors[index].range;
                let right = &errors[other].range;
                assert!(
                    !(left.start_byte <= right.start_byte
                        && right.end_byte <= left.end_byte
                        && (left.start_byte, left.end_byte) != (right.start_byte, right.end_byte)),
                    "error descendant should have been skipped: {errors:?}"
                );
            }
        }
    }

    #[test]
    fn cpp_tree_range_parse_matches_search_and_resets_between_files() {
        let project = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
            .file("probe.cpp", "int value;")
            .build();
        let file = project.file("probe.cpp");
        let mut parser = Parser::new();
        let masked = "#define APPLY(x) do { /* macro comment */ x; } while (0)\nint caller() { return 1; }\n";
        let ordinary = "// ordinary comment\nint final_value() { return 2; }\n";
        for source in [masked, ordinary, "int malformed( {", masked, ordinary] {
            assert!(set_parser_for_file(&mut parser, &CppAdapter, &file, source));
            let BoundedParse::Complete(tree) = parse_complete_file_with_tree_ranges(
                &mut parser,
                &CppAdapter,
                source,
                None,
                Instant::now() + COMPLETE_FILE_PARSE_BUDGET,
                SourceAdmissionPolicy::current(),
            ) else {
                panic!("C++ fixture should finish parsing");
            };
            let search_tree =
                brokk_bifrost_analysis::analyzer::usages::get_definition::parse_tree_for_language(
                    &file,
                    Language::Cpp,
                    source,
                )
                .expect("search tree");
            let rows = |tree: &Tree| {
                let mut nodes = vec![tree.root_node()];
                let mut rows = Vec::new();
                while let Some(node) = nodes.pop() {
                    rows.push((
                        node.kind().to_owned(),
                        node.range(),
                        node.is_missing(),
                        node.is_error(),
                    ));
                    let mut cursor = node.walk();
                    nodes.extend(node.children(&mut cursor));
                }
                rows
            };
            assert_eq!(rows(&tree), rows(&search_tree));
            if source == ordinary {
                assert!(!tree.root_node().has_error());
                assert_eq!(tree.root_node().end_byte(), source.len());
            }
        }
    }

    #[test]
    fn tree_range_reparse_preserves_cancellation_rejection_and_deadline() {
        struct RangeAdapter {
            cancellation: Option<CancellationToken>,
        }
        impl StoreLanguageAdapter for RangeAdapter {
            fn language(&self) -> Language {
                Language::Cpp
            }
        }
        impl LanguageAdapter for RangeAdapter {
            fn query_directory(&self) -> &'static str {
                CppAdapter.query_directory()
            }
            fn file_extension(&self) -> &'static str {
                "cpp"
            }
            fn extract_call_receiver(&self, reference: &str) -> Option<String> {
                CppAdapter.extract_call_receiver(reference)
            }
            fn parse_file(&self, file: &ProjectFile, source: &str, tree: &Tree) -> ParsedFile {
                CppAdapter.parse_file(file, source, tree)
            }
            fn parser_included_ranges_from_tree(
                &self,
                _source: &str,
                tree: &Tree,
                _should_stop: &mut dyn FnMut() -> bool,
            ) -> std::ops::ControlFlow<(), Option<Vec<tree_sitter::Range>>> {
                if let Some(cancellation) = &self.cancellation {
                    cancellation.cancel();
                }
                // Overlapping ranges must be rejected, never answered with
                // the successful initial tree that the hook just received.
                std::ops::ControlFlow::Continue(Some(vec![
                    tree.root_node().range(),
                    tree.root_node().range(),
                ]))
            }
        }
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .unwrap();
        let token = CancellationToken::new();
        let adapter = RangeAdapter {
            cancellation: Some(token.clone()),
        };
        assert!(matches!(
            parse_complete_file_with_tree_ranges(
                &mut parser,
                &adapter,
                "int value;",
                Some(&token),
                Instant::now() + COMPLETE_FILE_PARSE_BUDGET,
                SourceAdmissionPolicy::current(),
            ),
            BoundedParse::Cancelled
        ));
        assert!(matches!(
            parse_complete_file_with_tree_ranges(
                &mut parser,
                &RangeAdapter { cancellation: None },
                "int value;",
                None,
                Instant::now() + COMPLETE_FILE_PARSE_BUDGET,
                SourceAdmissionPolicy::current(),
            ),
            BoundedParse::Rejected
        ));
        assert!(matches!(
            parse_complete_file_with_tree_ranges(
                &mut parser,
                &CppAdapter,
                "int value;",
                None,
                Instant::now(),
                SourceAdmissionPolicy::current(),
            ),
            BoundedParse::TimedOut
        ));
    }

    fn analyzer_over_rust_fixture(
        fixture: &crate::inline_project::BuiltInlineTestProject,
    ) -> TreeSitterAnalyzer<RustAdapter> {
        let project = fixture.project_dyn();
        let store = AnalyzerStore::open_ephemeral().expect("ephemeral store");
        TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            RustAdapter,
            AnalyzerConfig::default(),
            store_context_from_store(project.as_ref(), store, false),
            None,
        )
        .expect("analyzer over the fixture")
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#6650: a source refused by admission cleared graph readiness for the whole inventory"
    )]
    fn refused_source_is_recorded_without_clearing_graph_readiness() {
        let blob = format!("pub const DATA: &str = \"{}\";\n", "A".repeat(20_000));
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub fn ok() {}\n")
            .file("src/blob.rs", blob.as_str())
            .build();
        let analyzer = analyzer_over_rust_fixture(&fixture);
        // A refused file is not indexed, so the absence of a declaration is
        // still unprovable. It is recorded with its reason, so graph readiness
        // holds and the exclusion is named instead of hiding every file.
        assert!(!analyzer.workspace_package_inventory_complete());
        assert!(analyzer.indexed_source_inventory_complete());
        let refusals = analyzer
            .selected_source_admission_refusals()
            .expect("recorded refusals")
            .into_iter()
            .map(|row| {
                (
                    row.file.rel_path().to_path_buf(),
                    serde_json::from_str::<serde_json::Value>(&row.reason).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let observed = blob.lines().map(str::len).max().unwrap();
        assert_eq!(
            refusals,
            [(
                std::path::PathBuf::from("src/blob.rs"),
                serde_json::json!({"code": "structural_line", "limit": 16000, "observed": observed})
            )]
        );
    }

    #[test]
    fn timed_out_source_is_not_a_refusal_and_clears_graph_readiness() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/lib.rs", "pub fn ok() {}\n")
            .file("src/slow.rs", "pub fn slow() {}\n")
            .build();
        *FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned") =
            vec![fixture.file("src/slow.rs").abs_path()];
        let analyzer = analyzer_over_rust_fixture(&fixture);
        FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned")
            .clear();
        // A parse that did not finish is transient: nothing is recorded and
        // the inventory is neither indexed nor accounted for.
        assert!(!analyzer.indexed_source_inventory_complete());
        assert!(
            analyzer
                .selected_source_admission_refusals()
                .expect("recorded refusals")
                .is_empty()
        );
    }

    #[test]
    fn parse_timeout_stays_transient_and_same_content_recovers_on_retry_and_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let retry = ProjectFile::new(root.clone(), "src/Retry.java");
        let reopen = ProjectFile::new(root.clone(), "src/Reopen.java");
        let healthy = ProjectFile::new(root.clone(), "src/Healthy.java");
        let retry_source = format!(
            "package demo; class Retry {{\n{}\n}}\n",
            "int generatedField;\n".repeat(10_000)
        );
        let reopen_source = format!(
            "package demo; class Reopen {{\n{}\n}}\n",
            "int generatedField;\n".repeat(10_000)
        );
        let healthy_source = "package demo; class Healthy {}\n";
        retry.write(&retry_source).expect("retry fixture");
        reopen.write(&reopen_source).expect("reopen fixture");
        healthy.write(healthy_source).expect("healthy fixture");

        *FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned") =
            vec![retry.abs_path(), reopen.abs_path()];

        let db = root.join("analyzer.db");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Java));
        let store = Arc::new(AnalyzerStore::open_persistent(&db).expect("persistent store"));
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(
                project.root(),
            ),
            _projection_lease: None,
            gc: Arc::new(
                brokk_bifrost_analysis::analyzer::store::gc::AnalyzerGcCoordinator::default(),
            ),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
            structural_facts: Arc::new(OnceLock::new()),
            cancellation: brokk_bifrost_core::cancellation::CancellationToken::default(),
        };
        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            store_context,
            None,
        )
        .expect("initial timed-out reconciliation");
        FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned")
            .clear();

        assert_eq!(
            analyzer.state.dirty_snapshot().len(),
            2,
            "both timed-out states must remain transient and retryable"
        );
        for (file, source, missing_name) in [
            (&retry, retry_source.as_str(), "Retry"),
            (&reopen, reopen_source.as_str(), "Reopen"),
        ] {
            let state = analyzer
                .fetch_file_state(file)
                .expect("timed-out state remains available in memory");
            assert_eq!(state.source, source, "fixture bytes must participate");
            assert!(!state.parse_complete);
            assert_eq!(state.declarations.len(), 1);
            assert!(state.declarations.iter().all(CodeUnit::is_file_scope));
            assert!(
                !analyzer
                    .get_declarations(file)
                    .iter()
                    .any(|declaration| declaration.short_name() == missing_name)
            );
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            assert!(
                !store.contains_parsed_blob(oid, "java").unwrap(),
                "a timeout marker must not be published as a complete blob"
            );
        }

        let healthy_state = analyzer
            .fetch_file_state(&healthy)
            .expect("healthy peer state");
        assert_eq!(healthy_state.source, healthy_source);
        assert!(healthy_state.parse_complete);
        assert!(
            analyzer
                .get_declarations(&healthy)
                .iter()
                .any(|declaration| declaration.short_name() == "Healthy")
        );
        let healthy_oid = Oid::hash_object(ObjectType::Blob, healthy_source.as_bytes()).unwrap();
        assert!(store.contains_parsed_blob(healthy_oid, "java").unwrap());

        let retry_oid = Oid::hash_object(ObjectType::Blob, retry_source.as_bytes()).unwrap();
        let retry_generation = analyzer.store_context.generations["java"];
        let partial_retry_state = analyzer
            .fetch_file_state(&retry)
            .expect("partial retry state");
        let preparation_error = AnalyzerStore::prepare_parsed_blob(
            retry_oid,
            "java",
            retry_generation,
            &JavaAdapter,
            Arc::clone(&partial_retry_state),
        )
        .expect_err("prepared persistence must reject an incomplete parser result");
        assert!(
            preparation_error
                .to_string()
                .contains("timed-out file analysis")
        );
        let direct_error = store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                retry_oid,
                "java",
                retry_generation,
                &JavaAdapter,
                partial_retry_state.as_ref(),
            )
            .expect_err("the direct write path must enforce the same completeness invariant");
        assert!(direct_error.to_string().contains("timed-out file analysis"));
        assert!(!store.contains_parsed_blob(retry_oid, "java").unwrap());

        let retried = analyzer.update(&BTreeSet::from([retry.clone()]));
        let retried_state = retried.fetch_file_state(&retry).expect("retried state");
        assert!(retried_state.parse_complete);
        let retried_declarations = retried.get_declarations(&retry);
        assert!(
            retried_declarations
                .iter()
                .any(|declaration| declaration.short_name() == "Retry")
        );
        assert!(store.contains_parsed_blob(retry_oid, "java").unwrap());

        drop(retried);
        drop(analyzer);
        drop(store);

        let reopened_store =
            Arc::new(AnalyzerStore::open_persistent(&db).expect("reopen persistent store"));
        let reopened_context = AnalyzerStoreContext {
            store: Arc::clone(&reopened_store),
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(
                project.root(),
            ),
            _projection_lease: None,
            gc: Arc::new(
                brokk_bifrost_analysis::analyzer::store::gc::AnalyzerGcCoordinator::default(),
            ),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
            structural_facts: Arc::new(OnceLock::new()),
            cancellation: brokk_bifrost_core::cancellation::CancellationToken::default(),
        };
        let reopened = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            JavaAdapter,
            AnalyzerConfig {
                parallelism: Some(1),
                ..AnalyzerConfig::default()
            },
            reopened_context,
            None,
        )
        .expect("reopen reparses the still-missing same-content blob");

        let reopened_state = reopened
            .fetch_file_state(&reopen)
            .expect("reopened complete state");
        assert_eq!(reopened_state.source, reopen_source);
        assert!(reopened_state.parse_complete);
        assert!(
            reopened
                .get_declarations(&reopen)
                .iter()
                .any(|declaration| declaration.short_name() == "Reopen")
        );
        for (file, source) in [(&retry, retry_source.as_str()), (&healthy, healthy_source)] {
            let state = reopened
                .fetch_file_state(file)
                .expect("reopened complete peer state");
            assert_eq!(state.source, source);
            assert!(state.parse_complete);
        }
        assert_eq!(
            reopened.get_declarations(&retry),
            retried_declarations,
            "same-content update and persisted reopen must converge"
        );
        let reopen_oid = Oid::hash_object(ObjectType::Blob, reopen_source.as_bytes()).unwrap();
        assert!(
            reopened_store
                .contains_parsed_blob(reopen_oid, "java")
                .unwrap()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3673: cold exact lookup must retain the selected manifest after a disk edit"
    )]
    fn python_retained_exact_lookup_keeps_selected_configuration() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file(
                "pyproject.toml",
                "[tool.setuptools.packages.find]\nwhere = ['source']\n",
            )
            .file("source/pkg/model.py", "class Widget:\n    pass\n")
            .build();
        let retained = TreeSitterAnalyzer::new(fixture.project_dyn(), PythonAdapter::default());
        std::fs::write(
            fixture.root().join("pyproject.toml"),
            "[tool.setuptools.packages.find]\nwhere = ['.']\n",
        )
        .unwrap();
        let names = retained.get_definitions("pkg.model.Widget");
        assert_eq!(names.len(), 1, "{names:?}");
        assert_eq!(names[0].fq_name(), "pkg.model.Widget");
        assert!(
            retained
                .get_definitions("source.pkg.model.Widget")
                .is_empty()
        );
        let fresh = TreeSitterAnalyzer::new(fixture.project_dyn(), PythonAdapter::default());
        let names = fresh.get_definitions("source.pkg.model.Widget");
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(fresh.get_definitions("pkg.model.Widget").is_empty());
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#3673: request root reprojection must not replace the live workspace head"
    )]
    fn python_request_root_projection_keeps_the_live_workspace_head() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Python)
            .file("source/pkg/model.py", "class Widget:\n    pass\n")
            .build();
        let disk = TreeSitterAnalyzer::new(fixture.project_dyn(), PythonAdapter::default());
        let original = disk.selected_workspace_snapshots();
        let original_python = original.get("python").expect("Python workspace snapshot");
        let overlay = OverlayProject::new(fixture.project_dyn());
        assert!(overlay.set(
            fixture.root().join("pyproject.toml"),
            "[tool.setuptools.packages.find]\nwhere = ['source']\n".to_string()
        ));
        let request = disk
            .clone_with_project(Arc::new(overlay.snapshot()))
            .reproject_workspace();
        let current = disk
            .store_context
            .store
            .workspace_snapshots_for_langs(
                &disk.store_context.workspace_id,
                &["python".to_string()],
                disk.store_context.generations.as_ref(),
            )
            .unwrap();
        assert_eq!(current.get("python"), Some(original_python));
        assert_ne!(
            request.store_context.workspace_id,
            disk.store_context.workspace_id
        );
        let projected_definitions = request.get_definitions("pkg.model.Widget");
        assert_eq!(projected_definitions.len(), 1, "{projected_definitions:?}");
        let original_definitions = disk.get_definitions("source.pkg.model.Widget");
        assert_eq!(original_definitions.len(), 1, "{original_definitions:?}");
        let request_id = request.store_context.workspace_id.clone();
        drop(request);
        let remaining = disk
            .store_context
            .store
            .workspace_snapshots_for_langs(
                &request_id,
                &["python".to_string()],
                disk.store_context.generations.as_ref(),
            )
            .unwrap();
        assert!(remaining.is_empty(), "{remaining:?}");
        assert_eq!(
            disk.get_definitions("source.pkg.model.Widget"),
            original_definitions
        );
    }

    #[test]
    fn prepared_source_above_batch_targets_publishes_queryable_facts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = "class Published:\n    pass\n".to_string();
        let file = ProjectFile::new(root, "published.py");
        let adapter = PythonAdapter::for_test_file(&file);
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            adapter.parser_language_for_file(&file),
        );
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let parsed = Arc::new(
            TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
                &mut parser,
                &adapter,
                &file,
                source,
            )
            .expect("python file parses")
            .state,
        );
        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            "python",
            GenerationId::BOOTSTRAP,
            &adapter,
            Arc::clone(&parsed),
        )
        .unwrap();
        let expected_rows = prepared.mutation_logical_rows();
        let expected_bytes = prepared.mutation_payload_bytes();
        let store = AnalyzerStore::open_ephemeral().unwrap();

        let (outcomes, stats) = store.persist_prepared_blobs(
            vec![prepared],
            PersistBatchTargets {
                max_blobs: 1,
                max_rows: 1,
                max_payload_bytes: 1,
            },
        );

        assert!(outcomes[0].error.is_none());
        assert_eq!(stats.transactions, 1);
        assert_eq!(stats.peak_batch_rows, expected_rows);
        assert_eq!(stats.peak_batch_payload_bytes, expected_bytes);
        assert!(store.contains_parsed_blob(oid, "python").unwrap());
        let hydrated = store
            .hydrate_file_state_with_source(
                oid,
                "python",
                GenerationId::BOOTSTRAP,
                &adapter,
                &file,
                &parsed.source,
            )
            .unwrap()
            .expect("publication must be readable from the store");
        assert_eq!(hydrated.declarations, parsed.declarations);
        assert_eq!(hydrated.type_identifiers, parsed.type_identifiers);
    }

    /// A Python workspace whose files each declare one distinctly named class,
    /// so every lookup below names a different identifier and cannot be
    /// answered from a name-keyed memo.
    fn workspace_scan_probe_project(file_count: usize) -> (tempfile::TempDir, Arc<dyn Project>) {
        brokk_bifrost_analysis::analyzer::test_support::python_package_project(
            (0..file_count).map(|index| format!("class Widget{index}:\n    pass\n")),
        )
    }

    /// One rust crate whose declarations live behind a module, so a scoped
    /// lookup expands into `::`-bearing spellings.
    fn rust_scoped_lookup_project() -> (tempfile::TempDir, Arc<dyn Project>) {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\n",
        )
        .expect("write manifest");
        std::fs::write(
            root.join("src/lib.rs"),
            "pub mod inner;\npub struct Outer;\n",
        )
        .expect("write lib");
        std::fs::write(
            root.join("src/inner.rs"),
            "pub struct Widget;\n\nimpl Widget {\n    pub fn make() -> Self {\n        Widget\n    }\n}\n",
        )
        .expect("write module");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        (temp, project)
    }

    /// #1748: `lookup_suffix_candidates` peels a rust lookup path on both `.`
    /// and `::`, so a `::`-spelled input mints spellings that carry `::` --
    /// and no rust `short_name` can contain one, because the FqName renderer
    /// emits `::` only between two C++ namespace segments. Every such spelling
    /// was still paying a pooled connection checkout, a generation check, a
    /// `prepare_cached` and an index probe to be told what the storage
    /// contract already says.
    ///
    /// Fails before the filter: all three spellings seek, so `row_reads` is 3
    /// and `dropped` is 0. After it, the two `::`-bearing spellings are
    /// dropped and only the one that can match seeks.
    #[brokk_bifrost_test_macros::hardwon(
        "#1748: Rust lookup generated unpersistable double-colon spellings during repo-scale usage scans"
    )]
    #[test]
    fn issue_1748_double_colon_spellings_do_not_seek_for_rust() {
        let (_temp, project) = rust_scoped_lookup_project();
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        analyzer.reset_definition_candidate_row_read_count_for_test();
        analyzer.reset_structural_miss_spelling_count_for_test();
        // Spellings: `probe::inner::Widget`, `inner::Widget`, `Widget`. Only
        // the last can match a stored rust short name.
        let scoped: Vec<CodeUnit> =
            CodeUnitIndex::definitions(&analyzer, "probe::inner::Widget").collect();
        let row_reads = analyzer.definition_candidate_row_read_count_for_test();
        let dropped = analyzer.structural_miss_spelling_count_for_test();

        assert_eq!(
            2, dropped,
            "both `::`-bearing spellings are structurally guaranteed misses"
        );
        assert_eq!(
            1, row_reads,
            "only the spelling the persisted vocabulary can hold may seek"
        );
        // The drop removes probes, never answers. Measured before the filter,
        // this lookup resolved to nothing too, and structurally it cannot
        // resolve to anything: `assemble_definition_candidates` keeps a row
        // only on an exact or normalized fq match against the *input*
        // spelling, rust's `normalize_full_name` is the identity, and no
        // stored rust fq name carries `::`. The three spellings were three
        // seeks for an answer the storage contract had already refused.
        assert!(
            scoped.is_empty(),
            "a `::`-spelled rust fq name resolved to {scoped:?} before the filter too"
        );
        // The declaration itself is reachable, by the dotted name it is
        // actually stored under -- see the sibling test. This is the
        // difference the filter must not blur.
    }

    /// #1748: the filter drops a spelling only when *both* declarations agree
    /// -- the renderer never emits the separator for this language, and the
    /// adapter's own lookup vocabulary treats it as a join. Scala satisfies the
    /// first and not the second: its cons class is named `::`, so `::` and
    /// `Foo.::` are ordinary scala short names and `List.:::` is an ordinary
    /// scala method.
    ///
    /// Caught by the parity run rather than by review:
    /// `scala_colon_infix_dispatch_uses_the_right_receiver` and
    /// `scala_infix_right_associative_and_postfix_calls_have_icfg_and_source_order`
    /// both broke on an earlier substring-only filter that used
    /// `absent_segment_separators` alone. Scala's declining to peel on `::` is
    /// the same fact stated once, which is why the two can no longer drift.
    #[brokk_bifrost_test_macros::hardwon(
        "#1748: Scala declarations containing colon text were dropped by generic separator normalization"
    )]
    #[test]
    fn issue_1748_scala_colon_named_declarations_are_never_dropped() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("create src");
        std::fs::write(
            root.join("src/Cons.scala"),
            "package coll\n\
             class ::[A](head: A, tail: List[A]) {\n\
             \x20 def :::(other: List[A]): List[A] = other\n\
             }\n",
        )
        .expect("write scala source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Scala));
        let analyzer = TreeSitterAnalyzer::new(project, ScalaAdapter);

        analyzer.reset_structural_miss_spelling_count_for_test();
        for name in ["coll.::", "::", "coll.::.:::", "::.head"] {
            let _ = CodeUnitIndex::definitions(&analyzer, name).count();
        }

        assert_eq!(
            0,
            analyzer.structural_miss_spelling_count_for_test(),
            "scala declares `::` as name text, not as a join, so nothing may be dropped"
        );
    }

    /// The other side of the filter: a dotted rust lookup carries no excluded
    /// separator, so nothing is dropped and every spelling still seeks. This is
    /// what keeps the cut from being a blanket reduction in probes.
    #[brokk_bifrost_test_macros::hardwon(
        "#1748: removing unpersistable spellings also dropped valid dotted Rust lookup names"
    )]
    #[test]
    fn issue_1748_dotted_rust_spellings_are_all_still_sought() {
        let (_temp, project) = rust_scoped_lookup_project();
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        analyzer.reset_definition_candidate_row_read_count_for_test();
        analyzer.reset_structural_miss_spelling_count_for_test();
        let dotted: Vec<CodeUnit> =
            CodeUnitIndex::definitions(&analyzer, "probe.inner.Widget").collect();

        assert_eq!(0, analyzer.structural_miss_spelling_count_for_test());
        assert_eq!(
            1,
            analyzer.definition_candidate_row_read_count_for_test(),
            "all seekable spellings belong to one arity-one request relation"
        );
        assert_eq!(
            vec!["probe.inner.Widget"],
            dotted
                .iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<String>>()
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "42f46e61f994: an empty mounted definition prefix could not be resolved from its rendered spelling"
    )]
    #[test]
    fn rendered_definition_lookup_reaches_an_empty_mounted_prefix() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "foo.rs");
        file.write(
            "pub struct Foo;\nimpl Foo {\n    pub fn target(&self) {}\n    pub fn other(&self) {}\n}\n",
        )
            .expect("write Rust fixture");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        let target = analyzer
            .declarations(&file)
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == "target")
            .expect("fixture declares Foo.target");

        assert_eq!(target.fq_name(), "Foo.target");
        assert_eq!(
            vec![target.clone()],
            CodeUnitIndex::definitions(&analyzer, "Foo.target").collect::<Vec<_>>(),
            "an anchored declaration at an empty package prefix must remain addressable"
        );

        let scope =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let scope_attribution = scope.enter();
        analyzer.begin_query(&scope);
        analyzer.prefetch_definitions(&["Foo.target".to_string(), "Foo.other".to_string()]);
        assert_eq!(
            vec![target],
            CodeUnitIndex::definitions(&analyzer, "Foo.target").collect::<Vec<_>>(),
            "batched lookup must retain the same empty-prefix declaration"
        );
        analyzer.end_query(&scope);
        drop(scope_attribution);
    }

    /// #1774: every caller of the non-persisted workspace declaration scan used
    /// to re-walk the whole live-path set, and the callers are per-name. One
    /// request that resolves several names therefore walked the workspace once
    /// per name. Fails at 3 (one per lookup) before the walk is memoized.
    #[brokk_bifrost_test_macros::hardwon(
        "#1774: each import lookup walked the workspace live-path set again within one request"
    )]
    #[test]
    fn issue_1774_one_request_walks_the_live_path_set_once_for_many_lookups() {
        let (_temp, project) = workspace_scan_probe_project(3);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());

        let scope =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let scope_attribution = scope.enter();
        analyzer.begin_query(&scope);
        analyzer.reset_workspace_path_scan_count_for_test();
        for index in 0..3 {
            let _ = CodeUnitIndex::lookup_candidates_by_identifier(
                &analyzer,
                &format!("Widget{index}"),
            );
        }
        let scans_in_one_request = analyzer.workspace_path_scan_count_for_test();
        analyzer.end_query(&scope);
        drop(scope_attribution);

        assert_eq!(
            1, scans_in_one_request,
            "a request must materialize the workspace live-path set at most once"
        );
    }

    /// The memo is request scoped, not analyzer scoped: a second request must
    /// see the workspace again rather than inherit the first request's walk.
    #[brokk_bifrost_test_macros::hardwon(
        "#1774: memoized live-path answers leaked into a later request after workspace mutation"
    )]
    #[test]
    fn issue_1774_a_later_request_walks_the_live_path_set_again() {
        let (_temp, project) = workspace_scan_probe_project(2);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());

        analyzer.reset_workspace_path_scan_count_for_test();
        for _ in 0..2 {
            let scope = Arc::new(
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default(),
            );
            let scope_attribution = scope.enter();
            analyzer.begin_query(&scope);
            let _ = CodeUnitIndex::lookup_candidates_by_identifier(&analyzer, "Widget0");
            analyzer.end_query(&scope);
            drop(scope_attribution);
        }

        assert_eq!(
            2,
            analyzer.workspace_path_scan_count_for_test(),
            "each request must re-read the workspace it was opened against"
        );
    }

    /// The `keep` predicate stays outside the memo, so the narrowed answer is
    /// the same whether the walk was just taken or served from the memo.
    #[brokk_bifrost_test_macros::hardwon(
        "#1774: a shared live-path scan reused one name's narrowed declarations for another name"
    )]
    #[test]
    fn issue_1774_memoized_walk_answers_each_name_with_its_own_narrowed_result() {
        let (_temp, project) = workspace_scan_probe_project(3);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());

        let unscoped: Vec<BTreeSet<CodeUnit>> = (0..3)
            .map(|index| {
                CodeUnitIndex::lookup_candidates_by_identifier(&analyzer, &format!("Widget{index}"))
            })
            .collect();

        let scope =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let scope_attribution = scope.enter();
        analyzer.begin_query(&scope);
        let scoped: Vec<BTreeSet<CodeUnit>> = (0..3)
            .map(|index| {
                CodeUnitIndex::lookup_candidates_by_identifier(&analyzer, &format!("Widget{index}"))
            })
            .collect();
        analyzer.end_query(&scope);
        drop(scope_attribution);

        assert_eq!(unscoped, scoped);
        for (index, matches) in scoped.iter().enumerate() {
            assert!(
                matches
                    .iter()
                    .any(|unit| unit.identifier() == format!("Widget{index}")),
                "lookup {index} must still find its own declaration: {matches:?}"
            );
        }
    }

    /// #1748: `definitions` is asked the same name many times inside one
    /// candidate-discovery pass. Fails at 2 before the request-scoped memo.
    #[test]
    fn issue_1748_repeated_definition_lookups_in_one_request_charge_one_store_read() {
        let (_temp, project) = workspace_scan_probe_project(1);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());

        let scope =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let scope_attribution = scope.enter();
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidates_query_count_for_test();
        let first: Vec<CodeUnit> =
            CodeUnitIndex::definitions(&analyzer, "pkg.mod_0.Widget0").collect();
        let second: Vec<CodeUnit> =
            CodeUnitIndex::definitions(&analyzer, "pkg.mod_0.Widget0").collect();
        let queries = analyzer.definition_candidates_query_count_for_test();
        analyzer.end_query(&scope);
        drop(scope_attribution);

        assert_eq!(first, second, "the memo must not change what is resolved");
        assert_eq!(
            1, queries,
            "a request must resolve one definition name with one store read"
        );
    }

    /// Parallel graph workers can reach one fq name before any worker has
    /// published its answer. The complete definition memo must single-flight
    /// that burst, not merely deduplicate its lower-level short-name row read.
    #[test]
    fn issue_1748_concurrent_definition_lookups_of_one_name_charge_one_query() {
        const WORKERS: usize = 8;

        let (_temp, project) = shared_short_name_project(64);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());
        let fq_name = "pkg.mod_0.Shared";
        let expected: Vec<CodeUnit> = CodeUnitIndex::definitions(&analyzer, fq_name).collect();

        let scope =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let scope_attribution = scope.enter();
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidates_query_count_for_test();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(WORKERS)
            .build()
            .expect("rayon pool");
        let start = std::sync::Barrier::new(WORKERS);
        let concurrent = pool.broadcast(|_| {
            start.wait();
            CodeUnitIndex::definitions(&analyzer, fq_name).collect::<Vec<CodeUnit>>()
        });
        let queries = analyzer.definition_candidates_query_count_for_test();
        analyzer.end_query(&scope);
        drop(scope_attribution);

        assert!(
            concurrent.iter().all(|answer| answer == &expected),
            "single flight must preserve the definition answer: {concurrent:#?}"
        );
        assert_eq!(
            1, queries,
            "concurrent callers of one fq name must build one complete answer"
        );
    }

    /// With no request open there is no memo, so the behaviour is exactly the
    /// unmemoized lookup. This is what keeps direct-analyzer callers honest.
    #[brokk_bifrost_test_macros::hardwon(
        "#1748: query memoization leaked beyond the request boundary and could stale later answers"
    )]
    #[test]
    fn issue_1748_definition_lookups_outside_a_request_are_not_memoized() {
        let (_temp, project) = workspace_scan_probe_project(1);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());

        analyzer.reset_definition_candidates_query_count_for_test();
        let _ = CodeUnitIndex::definitions(&analyzer, "pkg.mod_0.Widget0").count();
        let _ = CodeUnitIndex::definitions(&analyzer, "pkg.mod_0.Widget0").count();

        assert_eq!(2, analyzer.definition_candidates_query_count_for_test());
    }

    /// A workspace where one short name is shared by `count` distinct fq
    /// names -- the shape that defeated #1748's fq-keyed memo (#1839).
    fn shared_short_name_project(count: usize) -> (tempfile::TempDir, Arc<dyn Project>) {
        brokk_bifrost_analysis::analyzer::test_support::python_package_project(
            (0..count).map(|_| "class Shared:\n    pass\n".to_string()),
        )
    }

    /// #1839: distinct fq names that share one short name must not transport
    /// the shared candidate page for every spelling. Each logical point is one
    /// mounted request whose SQL result contains only selected identities.
    #[brokk_bifrost_test_macros::hardwon(
        "#1839: high-fan-out symbol resolution repeated definition-row reads for shared short names"
    )]
    #[test]
    fn issue_1839_distinct_fq_names_sharing_a_short_name_read_the_rows_once() {
        let (_temp, project) = shared_short_name_project(6);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());
        let names: Vec<String> = (0..6)
            .map(|index| format!("pkg.mod_{index}.Shared"))
            .collect();

        let point: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();

        let scope =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let scope_attribution = scope.enter();
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidates_query_count_for_test();
        analyzer.reset_definition_candidate_row_read_count_for_test();
        let memoized: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();
        let row_reads = analyzer.definition_candidate_row_read_count_for_test();
        let point_lookups = analyzer.definition_candidates_query_count_for_test();
        analyzer.end_query(&scope);
        drop(scope_attribution);

        assert_eq!(point, memoized, "the memo must not change any answer");
        assert_eq!(
            6, point_lookups,
            "each distinct fq name is still its own question"
        );
        assert_eq!(
            6, row_reads,
            "each distinct logical point is one mounted SQL request"
        );
    }

    /// #1748 D4: parallel exact lookups sharing a hot short name must stay
    /// bounded by the number of logical points, not multiply that number by
    /// every candidate spelling or transport the shared candidate page.
    #[test]
    fn issue_1748_concurrent_lookups_of_one_short_name_read_the_rows_once() {
        const WORKERS: usize = 8;

        let (_temp, project) = shared_short_name_project(WORKERS);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());
        let names: Vec<String> = (0..WORKERS)
            .map(|index| format!("pkg.mod_{index}.Shared"))
            .collect();

        let sequential: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();

        let scope =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let scope_attribution = scope.enter();
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidate_row_read_count_for_test();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(WORKERS)
            .build()
            .expect("rayon pool");
        // Every worker starts its lookup at the same instant: the fan-out
        // shape that originally multiplied each spelling's broad row read.
        let start = std::sync::Barrier::new(WORKERS);
        let concurrent = pool.broadcast(|context| {
            start.wait();
            CodeUnitIndex::definitions(&analyzer, &names[context.index()])
                .collect::<Vec<CodeUnit>>()
        });
        let row_reads = analyzer.definition_candidate_row_read_count_for_test();
        analyzer.end_query(&scope);
        drop(scope_attribution);

        assert_eq!(
            sequential, concurrent,
            "single flight must not change any answer"
        );
        assert_eq!(
            WORKERS, row_reads,
            "each concurrent logical point must issue one mounted request"
        );
    }

    /// The batched prefetch must fill the memo with the same answers the point
    /// lookups produce, in one store read for the whole key set.
    #[brokk_bifrost_test_macros::hardwon(
        "#1748: batched candidate discovery changed answers relative to point lookup behavior"
    )]
    #[test]
    fn issue_1748_prefetched_definitions_match_the_point_lookups_they_replace() {
        let (_temp, project) = workspace_scan_probe_project(4);
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());
        let names: Vec<String> = (0..4)
            .map(|index| format!("pkg.mod_{index}.Widget{index}"))
            .collect();

        let point: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();

        let scope =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let scope_attribution = scope.enter();
        analyzer.begin_query(&scope);
        analyzer.reset_definition_candidates_query_count_for_test();
        analyzer.reset_definition_prefetch_batch_count_for_test();
        analyzer.prefetch_definitions(&names);
        let batches = analyzer.definition_prefetch_batch_count_for_test();
        let prefetched: Vec<Vec<CodeUnit>> = names
            .iter()
            .map(|name| CodeUnitIndex::definitions(&analyzer, name).collect())
            .collect();
        let point_lookups = analyzer.definition_candidates_query_count_for_test();
        analyzer.end_query(&scope);
        drop(scope_attribution);

        assert_eq!(point, prefetched, "batched rows must resolve identically");
        assert_eq!(1, batches, "one batched read serves the whole key set");
        assert_eq!(
            0, point_lookups,
            "a prefetched name must not fall back to a point lookup"
        );
    }

    #[test]
    fn terminal_stale_dirty_state_remains_authoritative_without_retrying() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = "class Dirty:\n    pass\n";
        std::fs::write(root.join("dirty.py"), source).unwrap();
        let file = ProjectFile::new(root.clone(), "dirty.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let analyzer = TreeSitterAnalyzer::new(project, PythonAdapter::default());
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            analyzer.adapter.parser_language_for_file(&file),
        );
        let parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            analyzer.adapter.as_ref(),
            &file,
            source.to_string(),
        )
        .unwrap()
        .state;
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);
        let generation = analyzer.store_context.generations["python"];
        analyzer
            .store_context
            .store
            .ensure_language_epoch_value("python", "cutover-after-failure")
            .unwrap();
        analyzer.state.dirty_file_states.lock().unwrap().insert(
            key.clone(),
            TreeSitterAnalyzer::<PythonAdapter>::dirty_file_state(
                Arc::new(parsed),
                singleton_generation_map("python", generation),
                Vec::new(),
                STORE_WRITE_IMMEDIATE_RETRIES + 1,
                "stale generation".to_string(),
                DirtyFileStateStatus::TerminalStale,
            ),
        );
        let starts = analyzer
            .store_context
            .store
            .parsed_blob_transaction_starts_for_test();

        let state = analyzer.retry_dirty_file_state(&key, "python").unwrap();

        assert!(
            state
                .declarations
                .iter()
                .any(|unit| unit.short_name() == "Dirty")
        );
        assert_eq!(
            analyzer
                .store_context
                .store
                .parsed_blob_transaction_starts_for_test(),
            starts,
            "terminal stale state must not schedule another obsolete write"
        );
        assert!(
            analyzer
                .state
                .dirty_file_states
                .lock()
                .unwrap()
                .get(&key)
                .unwrap()
                .status
                == DirtyFileStateStatus::TerminalStale
        );
    }

    #[test]
    fn dirty_path_projection_is_authoritative_for_exact_module_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("pkg")).unwrap();
        let source = "def helper():\n    pass\n";
        std::fs::write(root.join("pkg/util.py"), source).unwrap();
        let file = ProjectFile::new(root.clone(), "pkg/util.py");
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let adapter = Arc::new(PythonAdapter::for_test_file(&file));
        let row = TreeSitterAnalyzer::<PythonAdapter>::path_symbol_row(&*adapter, &file, oid)
            .expect("python path projection");
        let mut dirty_path_symbol_rows = HashMap::default();
        dirty_path_symbol_rows.insert(file.clone(), ("python".to_string(), row.clone()));

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let live_paths = Arc::new(LivePathMap::default());
        live_paths.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let generation = store
            .ensure_language_epoch_value("python", "bounded-paths")
            .unwrap();
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            adapter.parser_language_for_file(&file),
        );
        let parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            &*adapter,
            &file,
            source.to_owned(),
        )
        .expect("Python fixture parses")
        .state;
        store
            .write_parsed_blob_at_generation(
                &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                oid,
                "python",
                generation,
                &*adapter,
                &parsed,
            )
            .unwrap();
        let workspace_id =
            brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(project.root());
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(
                project.root(),
            ),
            _projection_lease: None,
            gc: Arc::new(
                brokk_bifrost_analysis::analyzer::store::gc::AnalyzerGcCoordinator::default(),
            ),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths,
            generations: Arc::new(HashMap::from_iter([("python".to_string(), generation)])),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
            structural_facts: Arc::new(OnceLock::new()),
            cancellation: brokk_bifrost_core::cancellation::CancellationToken::default(),
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(
                HashMap::default(),
                HashMap::default(),
                dirty_path_symbol_rows,
                Vec::new(),
            ),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
                &store_context,
            )),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_index_cache(&config)),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_snapshot_caches(
                &config,
            )),
            TreeSitterAnalyzer::build_content_identity_base(&config, &PythonAdapter::default()),
            brokk_bifrost_analysis::analyzer::semantic::service::CompleteSemanticArtifactCache::default(),
            store_context,
            Arc::new(HashMap::default()),
        );

        assert_eq!(
            analyzer
                .get_definitions("pkg.util")
                .into_iter()
                .map(|unit| unit.fq_name())
                .collect::<Vec<_>>(),
            vec!["pkg.util".to_string()]
        );

        let selected = store
            .sync_workspace_snapshot_for_workspace(
                &workspace_id,
                "python",
                generation,
                &[brokk_bifrost_analysis::analyzer::store::WorkspaceFileRow {
                    rel_path: row.rel_path.clone(),
                    blob_oid: oid,
                }],
                std::slice::from_ref(&row),
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();
        analyzer
            .relational_workspace_snapshots
            .store(Arc::new(HashMap::from_iter([(
                "python".to_string(),
                selected,
            )])));

        // The same exact/normalized module is present in SQLite and the dirty
        // projection. Hydration must deduplicate the two admitted rows.
        let hit = analyzer.lookup_path_modules_by_fqn_limited("pkg.util", 8, || true);
        assert!(hit.complete);
        assert_eq!(hit.inspected, 2);
        assert_eq!(hit.rows.len(), 1);
        assert_eq!(hit.rows[0].fq_name(), "pkg.util");
        let absent = analyzer.lookup_path_modules_by_fqn_limited("pkg.absent", 8, || true);
        assert!(absent.complete);
        assert!(absent.rows.is_empty());

        for limit in [0, 1] {
            let capped = analyzer.lookup_path_modules_by_fqn_limited("pkg.util", limit, || true);
            assert!(!capped.complete);
            assert!(capped.rows.is_empty());
            assert!(capped.inspected <= limit);
        }
        let stopped = analyzer.lookup_path_modules_by_fqn_limited("pkg.util", 8, || false);
        assert!(!stopped.complete);
        assert!(stopped.rows.is_empty());
        assert_eq!(stopped.inspected, 0);
        let mut polls = 0;
        let interrupted = analyzer.lookup_path_modules_by_fqn_limited("pkg.util", 8, || {
            polls += 1;
            polls <= 3
        });
        assert!(!interrupted.complete);
        assert!(interrupted.rows.is_empty());
        assert_eq!(interrupted.inspected, 1);

        let replacement_source = "def replacement():\n    pass\n";
        let replacement_oid =
            Oid::hash_object(ObjectType::Blob, replacement_source.as_bytes()).unwrap();
        analyzer
            .store_context
            .live_paths
            .refresh([LivePathEntry::overlay(file.clone(), replacement_oid)]);
        let stale = analyzer.lookup_path_modules_by_fqn_limited("pkg.util", 8, || true);
        assert!(stale.complete);
        assert!(
            stale.rows.is_empty(),
            "neither stale persisted nor stale dirty OID is live"
        );
        let replacement = TreeSitterAnalyzer::<PythonAdapter>::path_symbol_row(
            &*analyzer.adapter,
            &file,
            replacement_oid,
        )
        .unwrap();
        analyzer
            .state
            .dirty_path_symbol_rows
            .lock()
            .unwrap()
            .insert(file, ("python".to_string(), replacement));
        let replaced = analyzer.lookup_path_modules_by_fqn_limited("pkg.util", 8, || true);
        assert!(replaced.complete);
        assert_eq!(replaced.rows.len(), 1);
        assert_eq!(replaced.rows[0].fq_name(), "pkg.util");

        let other = ProjectFile::new(analyzer.project.root().to_path_buf(), "pkg/other.py");
        std::fs::write(other.abs_path(), source).unwrap();
        let other_row =
            TreeSitterAnalyzer::<PythonAdapter>::path_symbol_row(&*analyzer.adapter, &other, oid)
                .unwrap();
        analyzer
            .store_context
            .live_paths
            .refresh([LivePathEntry::overlay(other.clone(), oid)]);
        analyzer
            .state
            .dirty_path_symbol_rows
            .lock()
            .unwrap()
            .insert(other, ("python".to_string(), other_row));
        let exhausted_dirty = analyzer.lookup_path_modules_by_fqn_limited("pkg.absent", 1, || true);
        assert!(
            !exhausted_dirty.complete,
            "SQL absence cannot bypass unvisited dirty rows"
        );
        assert_eq!(exhausted_dirty.inspected, 1);
        assert!(exhausted_dirty.rows.is_empty());
    }

    fn analyzer_with_retryable_dirty_python_file(
        relative_path: &str,
        source: &str,
    ) -> (
        tempfile::TempDir,
        ProjectFile,
        Oid,
        Arc<AnalyzerStore>,
        TreeSitterAnalyzer<PythonAdapter>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let file = ProjectFile::new(root.clone(), relative_path);
        std::fs::create_dir_all(file.abs_path().parent().unwrap()).unwrap();
        std::fs::write(file.abs_path(), source).unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Python));
        let adapter = Arc::new(PythonAdapter::for_test_file(&file));
        let mut parser = TreeSitterAnalyzer::<PythonAdapter>::build_parser(
            adapter.parser_language_for_file(&file),
        );
        let parsed = TreeSitterAnalyzer::<PythonAdapter>::analyze_source(
            &mut parser,
            &*adapter,
            &file,
            source.to_owned(),
        )
        .expect("python file parses")
        .state;
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);
        let mut dirty = HashMap::default();
        dirty.insert(
            key,
            TreeSitterAnalyzer::<PythonAdapter>::dirty_file_state(
                Arc::new(parsed),
                singleton_generation_map("python", GenerationId::BOOTSTRAP),
                Vec::new(),
                32,
                "forced test persistence failure".to_string(),
                DirtyFileStateStatus::Retryable,
            ),
        );
        let live_paths = Arc::new(LivePathMap::default());
        live_paths.refresh([LivePathEntry::overlay(file.clone(), oid)]);
        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(
                project.root(),
            ),
            _projection_lease: None,
            gc: Arc::new(
                brokk_bifrost_analysis::analyzer::store::gc::AnalyzerGcCoordinator::default(),
            ),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths,
            generations: Arc::new(HashMap::from_iter([(
                "python".to_string(),
                GenerationId::BOOTSTRAP,
            )])),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
            structural_facts: Arc::new(OnceLock::new()),
            cancellation: brokk_bifrost_core::cancellation::CancellationToken::default(),
        };
        let config = AnalyzerConfig::default();
        let analyzer = TreeSitterAnalyzer::from_state(
            project,
            adapter,
            config.clone(),
            AnalyzerRuntimeState::new(HashMap::default(), dirty, HashMap::default(), Vec::new()),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_cache(
                &config,
                &store_context,
            )),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_structural_index_cache(&config)),
            Arc::new(TreeSitterAnalyzer::<PythonAdapter>::build_snapshot_caches(
                &config,
            )),
            TreeSitterAnalyzer::build_content_identity_base(&config, &PythonAdapter::default()),
            brokk_bifrost_analysis::analyzer::semantic::service::CompleteSemanticArtifactCache::default(),
            store_context,
            Arc::new(HashMap::default()),
        );
        (temp, file, oid, store, analyzer)
    }

    #[test]
    fn dirty_file_state_is_authoritative_for_bulk_reads() {
        let (_temp, file, oid, store, analyzer) = analyzer_with_retryable_dirty_python_file(
            "pkg/dirty.py",
            "import os\nclass Dirty:\n    pass\n",
        );

        assert!(!store.contains_parsed_blob(oid, "python").unwrap());
        let states = analyzer.bulk_file_states([file.clone()], BulkFileStateSource::Omit);
        assert!(states.get(&file).is_some_and(|state| {
            state
                .declarations
                .iter()
                .any(|unit| unit.fq_name() == "pkg.dirty.Dirty")
        }));
        let imports = analyzer.bulk_import_infos([file.clone()]);
        assert_eq!(
            imports
                .get(&file)
                .and_then(|imports| imports.first())
                .and_then(|import| import.identifier.as_deref()),
            Some("os")
        );

        use brokk_bifrost_core::analyzer::{
            DefinitionLanguageScope, RelationalBatchOutcome, RelationalDefinitionLookup,
            RelationalDefinitionQuery, RelationalDefinitionRequest, RelationalDefinitionValue,
            RelationalName,
        };
        let rendered = brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path_fq(
            Language::Python,
            "pkg.dirty.Dirty",
            brokk_bifrost_core::analyzer::fq_name::segment_interner(),
        );
        let requests = [
            RelationalDefinitionRequest {
                ordinal: 1,
                language_scope: DefinitionLanguageScope::Language(Language::Python),
                name: RelationalName::stable(rendered.clone()),
                query: RelationalDefinitionQuery::ExactName,
            },
            RelationalDefinitionRequest {
                ordinal: 2,
                language_scope: DefinitionLanguageScope::Language(Language::Python),
                name: RelationalName::stable(rendered),
                query: RelationalDefinitionQuery::NormalizedName,
            },
        ];
        let RelationalBatchOutcome::Complete(results) =
            analyzer.batch(&requests, &CancellationToken::new())
        else {
            panic!("dirty rendered-name batch must complete")
        };
        for result in results {
            let RelationalDefinitionValue::Definitions(units) = result.value else {
                panic!("rendered-name lookup returned the wrong value shape")
            };
            assert_eq!(
                units.iter().map(CodeUnit::fq_name).collect::<Vec<_>>(),
                ["pkg.dirty.Dirty"],
                "rendered input must have the same kind-insensitive semantics in the dirty overlay"
            );
        }
    }

    #[test]
    fn storage_adapter_path_qualifiers_reconstruct_workspace_identity() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");

        let python_file = temp_file(&root, "pkg/service.py");
        python_file.write("class Service:\n    pass\n").unwrap();
        let python = PythonAdapter::for_test_file(&python_file);
        let python_unit = CodeUnit::new(
            python_file.clone(),
            CodeUnitType::Class,
            "pkg.service",
            "Service",
        );
        assert_eq!(python.storage_content_qualifier(&python_unit, ""), "");
        assert_eq!(python.storage_file_content_qualifier("pkg.service"), "");
        assert_eq!(
            python.hydrate_content_qualifier("", &python_file).unwrap(),
            "pkg.service"
        );

        let rust_file = temp_file(&root, "src/net/mod.rs");
        let rust = RustAdapter;
        let rust_unit = CodeUnit::new(rust_file.clone(), CodeUnitType::Class, "net", "Client");
        assert_eq!(rust.storage_content_qualifier(&rust_unit, ""), "");
        assert_eq!(
            rust.hydrate_content_qualifier("", &rust_file).unwrap(),
            "net"
        );
        let rust_impl_member = CodeUnit::with_signature(
            rust_file.clone(),
            CodeUnitType::Function,
            "model",
            "Writer.write",
            Some("impl Writer::fn write(&self) { ... }".to_string()),
            false,
        );
        // Rust names are persisted as an anchor plus a content-stable tail, so
        // no unit — however it is qualified — bakes package text into its row.
        assert_eq!(rust.storage_content_qualifier(&rust_impl_member, "net"), "");
        assert_eq!(
            rust.hydrate_content_qualifier("model", &rust_file).unwrap(),
            "model"
        );
        let file_package = rust
            .resolve_package_anchor(PackageAnchor::OwnModule { pop: 0 }, "", &rust_file)
            .expect("Rust resolves its own-module anchor");
        assert_eq!(
            file_package.display(brokk_bifrost_core::analyzer::fq_name::segment_interner()),
            "net"
        );
        assert_eq!(
            rust.resolve_package_anchor(PackageAnchor::OwnModule { pop: 1 }, "", &rust_file)
                .expect("Rust resolves a popped own-module anchor")
                .display(brokk_bifrost_core::analyzer::fq_name::segment_interner()),
            ""
        );
        // A crate mounted at the repository root has an empty crate-root
        // prefix; that is a resolved empty prefix, not an unresolvable anchor.
        assert_eq!(
            rust.resolve_package_anchor(PackageAnchor::CrateRoot, "", &rust_file)
                .expect("Rust resolves its crate-root anchor")
                .display(brokk_bifrost_core::analyzer::fq_name::segment_interner()),
            ""
        );

        std::fs::write(root.join("go.mod"), "module example.com/demo\n").unwrap();
        let go_file = temp_file(&root, "internal/service/service.go");
        go_file
            .write("package service\n\ntype Service struct{}\n")
            .unwrap();
        let go = GoAdapter;
        let go_unit = CodeUnit::new(
            go_file.clone(),
            CodeUnitType::Class,
            "example.com/demo/internal/service",
            "Service",
        );
        assert_eq!(go.storage_content_qualifier(&go_unit, "service"), "service");
        assert_eq!(
            go.hydrate_content_qualifier("", &go_file).unwrap(),
            "example.com/demo/internal/service"
        );
    }

    #[test]
    fn storage_adapter_path_units_and_tests_reconstruct_after_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let tsx_file = temp_file(&root, "src/widget.test.tsx");
        let source = "import { value } from './value';\ntest('value', () => value());\n";
        let adapter = TypescriptAdapter;

        assert_eq!(
            adapter.storage_language_key_for_file(&tsx_file),
            "typescript:tsx"
        );
        assert_eq!(
            adapter
                .storage_language_keys()
                .into_iter()
                .map(|(key, _)| key)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["typescript:ts".to_string(), "typescript:tsx".to_string()])
        );

        let mut state = empty_file_state(source, true);
        state.imports.push(ImportInfo {
            raw_snippet: "import { value } from './value';".to_string(),
            is_wildcard: false,
            is_global: false,
            identifier: Some("value".to_string()),
            alias: None,
            path: None,
            binder_span: None,
        });
        assert!(adapter.storage_contains_tests(&state));
        assert!(adapter.hydrate_contains_tests(false, &tsx_file, ""));

        adapter
            .synthesize_hydrated_units(&tsx_file, source, &mut state)
            .unwrap();
        let module = state
            .top_level_declarations
            .iter()
            .find(|unit| unit.is_module())
            .expect("synthetic TypeScript module");
        assert!(!adapter.should_persist_code_unit(module));
        assert!(state.declarations.contains(module));
        assert_eq!(state.ranges.get(module).map(Vec::len), Some(1));

        let js_file = temp_file(&root, "src/widget.spec.js");
        let javascript = JavascriptAdapter;
        assert!(javascript.hydrate_contains_tests(false, &js_file, ""));
        let mut js_state = empty_file_state(source, true);
        js_state.imports = state.imports.clone();
        javascript
            .synthesize_hydrated_units(&js_file, source, &mut js_state)
            .unwrap();
        let js_module = js_state
            .top_level_declarations
            .iter()
            .find(|unit| unit.is_module())
            .expect("synthetic JavaScript module");
        assert!(!javascript.should_persist_code_unit(js_module));
        assert!(js_state.declarations.contains(js_module));
        assert_eq!(js_state.ranges.get(js_module).map(Vec::len), Some(1));
    }

    fn cpp_alias_workspace_over_file_state_index_capacity() -> (tempfile::TempDir, Arc<dyn Project>)
    {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        for index in 0..=SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY {
            std::fs::write(
                root.join(format!("src/Alias{index}.cpp")),
                format!("using Alias{index} = int;\n"),
            )
            .expect("write alias source");
        }

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        (temp, project)
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[brokk_bifrost_test_macros::hardwon(
        "#1707: C++ navigation hydrated file states repeatedly and stalled for hours on Phalcon"
    )]
    #[test]
    fn type_alias_projection_avoids_full_file_hydration() {
        let (_temp, project) = cpp_alias_workspace_over_file_state_index_capacity();
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        let aliases = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.identifier().starts_with("Alias"))
            .collect::<Vec<_>>();
        assert_eq!(aliases.len(), SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1);

        analyzer.reset_full_hydration_count_for_test();
        assert!(aliases.iter().all(|alias| analyzer.is_type_alias(alias)));
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "persisted type-alias checks must not hydrate a FileState"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[brokk_bifrost_test_macros::hardwon(
        "#1707: C++ signature navigation triggered file-state hydration thrash on large workspaces"
    )]
    #[test]
    fn signature_projection_avoids_full_file_hydration() {
        let (_temp, project) = cpp_alias_workspace_over_file_state_index_capacity();
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        let aliases = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.identifier().starts_with("Alias"))
            .collect::<Vec<_>>();
        assert_eq!(aliases.len(), SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1);

        analyzer.reset_full_hydration_count_for_test();
        for alias in &aliases {
            assert!(
                analyzer
                    .signatures(alias)
                    .iter()
                    .any(|signature| signature.contains(alias.identifier())),
                "persisted signature must include {}",
                alias.identifier()
            );
        }
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "persisted signature reads must not hydrate a FileState"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[brokk_bifrost_test_macros::hardwon(
        "#1707: finding C++ method owners hydrated full file states across the large workspace"
    )]
    #[test]
    fn enclosing_declaration_projection_avoids_full_file_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        for index in 0..=SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY {
            std::fs::write(
                root.join(format!("src/Owner{index}.cpp")),
                format!(
                    "namespace demo {{ struct Owner{index} {{ int method{index}() {{ return {index}; }} }}; }}\n"
                ),
            )
            .expect("write C++ source");
        }

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        let methods = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.identifier().starts_with("method"))
            .collect::<Vec<_>>();
        assert_eq!(methods.len(), SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1);

        analyzer.reset_full_hydration_count_for_test();
        for method in methods {
            let file = method.source().clone();
            let source = std::fs::read_to_string(file.abs_path()).expect("C++ source");
            let start_byte = source.find("return").expect("return statement");
            let range = Range {
                start_byte,
                end_byte: start_byte + "return".len(),
                start_line: 0,
                end_line: 0,
            };
            assert_eq!(analyzer.enclosing_code_unit(&file, &range), Some(method));
        }
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "persisted owner lookup must not hydrate a FileState"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2642: exact-call queries spent seconds hydrating an analyzed file just to read its source"
    )]
    #[test]
    fn file_source_avoids_full_file_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let files: Vec<_> = (0..=SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY)
            .map(|index| {
                let file = temp_file(&root, &format!("src/file{index}.rs"));
                file.write(format!("pub fn declared{index}() {{}}\n"))
                    .expect("write Rust source");
                file
            })
            .collect();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        analyzer.get_all_declarations();
        let outside = files
            .iter()
            .find(|file| analyzer.source_snapshot_file_state(file).is_none())
            .cloned()
            .expect("analyzed file outside the source snapshot index");
        // A structural seed scan asks every analyzed file for its source, long
        // after the build's own file states have turned over. Drop them so the
        // read below has only the blob or a full hydration to answer from.
        analyzer
            .transient_file_states
            .lock()
            .expect("transient file-state cache mutex poisoned")
            .clear();
        analyzer.reset_full_hydration_count_for_test();

        let expected = std::fs::read_to_string(outside.abs_path()).expect("Rust source");
        assert_eq!(analyzer.file_source(&outside).as_deref(), Some(&*expected));
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "a source read must not hydrate a FileState (#2642)"
        );
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn batched_enclosing_projection_matches_single_range_queries() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let mut files: Vec<_> = (0..SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY)
            .map(|index| {
                let file = temp_file(&root, &format!("src/Owner{index}.cpp"));
                file.write(format!(
                    "namespace demo {{ struct Owner{index} {{ int first() {{ return 1; }} int second() {{ return 2; }} }}; }}\n"
                ))
                .expect("write C++ source");
                file
            })
            .collect();
        let target = temp_file(&root, "src/ZOwner.cpp");
        target
            .write(
                "namespace demo { struct ZOwner { int first() { return 1; } int second() { return 2; } }; }\n",
            )
            .expect("write C++ source");
        files.push(target);

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        analyzer.get_all_declarations();
        let file = files
            .iter()
            .find(|file| analyzer.source_snapshot_file_state(file).is_none())
            .expect("analyzed file outside the source snapshot index");
        assert!(analyzer.source_snapshot_file_state(file).is_none());
        let source = std::fs::read_to_string(file.abs_path()).expect("C++ source");
        let mut ranges = ["return 1", "return 2"]
            .into_iter()
            .map(|needle| {
                let start_byte = source.find(needle).expect("range needle");
                Range {
                    start_byte,
                    end_byte: start_byte + needle.len(),
                    start_line: 0,
                    end_line: 0,
                }
            })
            .collect::<Vec<_>>();
        ranges.push(Range {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            end_line: 0,
        });

        analyzer.reset_full_hydration_count_for_test();
        let expected = ranges
            .iter()
            .map(|range| analyzer.enclosing_code_unit(file, range))
            .collect::<Vec<_>>();
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        analyzer
            .enclosing_code_unit_store
            .lock()
            .expect("enclosing code-unit store mutex poisoned")
            .clear();
        assert_eq!(
            analyzer
                .enclosing_code_unit_store
                .lock()
                .expect("enclosing code-unit store mutex poisoned")
                .entry_count(),
            0,
            "batch must build the persisted projection index rather than reuse point-query state"
        );

        analyzer.reset_enclosing_parent_query_counts_for_test();
        let provider = analyzer
            .structural_fact_providers()
            .into_iter()
            .next()
            .expect("C++ structural provider");
        let actual = provider
            .structural_enclosing_code_units(file, &ranges)
            .expect("C++ batch enclosure capability");

        assert_eq!(actual, expected);
        assert_eq!(
            analyzer.enclosing_code_unit_query_count_for_test(),
            ranges.len(),
            "batch enclosure should retain one logical query per requested range"
        );
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        assert_eq!(
            analyzer
                .enclosing_code_unit_store
                .lock()
                .expect("enclosing code-unit store mutex poisoned")
                .entry_count(),
            1,
            "all ranges should reuse one persisted declaration index"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#1707: C++ enclosure queries repeatedly scanned persisted declarations in large files"
    )]
    #[test]
    fn enclosing_code_unit_interval_index_reuses_large_file_ranges() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let source = (0..=ENCLOSING_CODE_UNIT_INDEX_MIN_DECLARATIONS)
            .map(|index| format!("int method{index}() {{ return {index}; }}\n"))
            .collect::<String>();
        let file = temp_file(&root, "src/methods.cpp");
        file.write(&source).expect("write C++ source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Cpp));
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        let dirty = analyzer.state.dirty_snapshot();
        assert!(
            dirty.is_empty(),
            "interval-cache fixture requires a healthy C++ publication: {dirty:?}"
        );
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        assert!(
            analyzer
                .store_context
                .store
                .contains_parsed_blob(oid, "cpp")
                .unwrap(),
            "interval-cache fixture must have a complete persisted C++ blob"
        );
        let methods = analyzer
            .get_all_declarations()
            .into_iter()
            .filter(|unit| unit.identifier().starts_with("method"))
            .collect::<Vec<_>>();
        assert_eq!(
            methods.len(),
            ENCLOSING_CODE_UNIT_INDEX_MIN_DECLARATIONS + 1
        );

        analyzer.reset_full_hydration_count_for_test();
        for method in methods {
            let index = method
                .identifier()
                .strip_prefix("method")
                .expect("method declaration")
                .parse::<usize>()
                .expect("method index");
            let needle = format!("return {index}");
            let start_byte = source.find(&needle).expect("return statement");
            let range = Range {
                start_byte,
                end_byte: start_byte + needle.len(),
                start_line: 0,
                end_line: 0,
            };
            assert_eq!(analyzer.enclosing_code_unit(&file, &range), Some(method));
        }
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        assert_eq!(
            analyzer
                .enclosing_code_unit_store
                .lock()
                .expect("enclosing code-unit store mutex poisoned")
                .entry_count(),
            1,
            "all large-file owner lookups must reuse one interval index"
        );
    }

    #[test]
    fn stale_definition_query_records_failure_while_healthy_miss_does_not() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::write(root.join("Model.java"), "class Model {}\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        let healthy = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(&analyzer);
        assert!(analyzer.definitions("Missing").next().is_none());
        assert!(healthy.store_error().is_none());
        drop(healthy);

        analyzer
            .store_context
            .store
            .ensure_language_epoch_value("java", "cutover-before-definition-read")
            .unwrap();
        let stale = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(&analyzer);
        assert!(analyzer.definitions("Model").next().is_none());
        let error = stale
            .store_error()
            .expect("stale definition query should report its store error");
        assert!(error.to_string().contains("querying definition candidates"));
        assert!(error.to_string().contains("stale analyzer generation"));
        drop(stale);
    }

    #[test]
    fn bounded_regression_stale_candidate_queries_never_report_complete_misses() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::write(root.join("Model.java"), "class Model { void work() {} }\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        analyzer
            .store_context
            .store
            .ensure_language_epoch_value("java", "cutover-before-bounded-candidate-read")
            .unwrap();
        let context = brokk_bifrost_analysis::analyzer::AnalyzerQueryScope::new(&analyzer);

        let by_identifier =
            analyzer.lookup_declarations_by_identifier_limited("Model", 16, || true);
        let non_module =
            analyzer.lookup_non_module_declarations_by_identifier_limited("Model", 16, || true);
        let by_fqn =
            analyzer.lookup_declarations_by_persisted_fqn_limited("Model", false, 16, || true);
        let members = analyzer.lookup_members_for_owner_name_limited("Model", "work", 16, || true);

        for batch in [by_identifier, non_module, by_fqn, members] {
            assert!(
                !batch.complete,
                "a failed bounded store read must not become an authoritative miss"
            );
            assert!(batch.rows.is_empty());
        }
        assert!(
            context
                .store_error()
                .expect("stale bounded reads should record their store error")
                .to_string()
                .contains("stale analyzer generation")
        );
        drop(context);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#4510: repeated Rust candidate lookups issued one SQLite query per reference site"
    )]
    #[test]
    fn identifier_candidate_lookups_are_memoized_by_request_key() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file(
                "src/lib.rs",
                "pub struct Target;\npub fn use_target() { let _ = Target; }\n",
            )
            .build();
        let analyzer =
            TreeSitterAnalyzer::new(fixture.project_dyn() as Arc<dyn Project>, RustAdapter);
        let scope = AnalyzerQueryScope::for_identifier_candidate_memo(&analyzer);
        let run_lookup = |identifier, limit| {
            let _site_scope = AnalyzerQueryScope::new(&analyzer);
            assert!(
                analyzer
                    .active_query_cache_handle(|cache| &cache.definition_units)
                    .is_none(),
                "candidate-only scope must not retain general request memo tables"
            );
            analyzer.lookup_declarations_by_identifier_limited(identifier, limit, || true)
        };

        let cancelled = {
            let _site_scope = AnalyzerQueryScope::new(&analyzer);
            analyzer.lookup_declarations_by_identifier_limited("Target", 16, || false)
        };
        let first = run_lookup("Target", 16);
        let repeated = run_lookup("Target", 16);
        let other_limit = run_lookup("Target", 17);
        let missing = run_lookup("Missing", 16);
        let repeated_missing = run_lookup("Missing", 16);
        let executions = analyzer
            .query_read_cache_lock()
            .identifier_candidate_query_executions
            .load(Ordering::Relaxed);

        assert!(!cancelled.complete, "cancelled lookup must stay incomplete");
        assert!(
            first.complete,
            "the target query must be complete: {first:?}"
        );
        assert_eq!(first, repeated, "same key must return the identical rows");
        assert_eq!(
            first, other_limit,
            "the wider key must return the same rows"
        );
        assert!(
            missing.complete,
            "the miss query must be complete: {missing:?}"
        );
        assert_eq!(
            missing, repeated_missing,
            "same miss key must stay identical"
        );
        assert_eq!(first.rows.len(), 1);
        assert_eq!(first.rows[0].identifier(), "Target");
        assert!(missing.rows.is_empty());
        assert_eq!(
            executions, 3,
            "two repeated keys should collapse; a different limit remains a distinct key"
        );
        drop(scope);
    }

    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
    #[test]
    fn query_read_cache_keeps_broad_traversals_out_of_the_lru_eviction_loop() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let files: Vec<_> = (0..=SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY)
            .map(|index| {
                let file = temp_file(&root, &format!("src/Type{index}.java"));
                file.write(format!("package demo; class Type{index} {{}}\n"))
                    .expect("java source");
                file
            })
            .collect();

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let mut analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        // Construction seeds the source snapshot index with the first 1,024
        // file states. Clear it so every file goes through the query read
        // cache that this test is about.
        analyzer.clear_retained_file_states_for_test();
        analyzer.reset_full_hydration_count_for_test();

        let outer =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let inner =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let outer_attribution = outer.enter();
        analyzer.begin_query(&outer);
        for file in &files {
            assert!(analyzer.fetch_file_state(file).is_some());
        }
        let inner_attribution = inner.enter();
        analyzer.begin_query(&inner);
        for file in &files {
            assert!(analyzer.fetch_file_state(file).is_some());
        }
        analyzer.end_query(&inner);
        drop(inner_attribution);

        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1,
            "the nested query must reuse the outer query's file states"
        );

        analyzer.end_query(&outer);
        drop(outer_attribution);
        assert!(analyzer.fetch_file_state(&files[0]).is_some());
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            SOURCE_SNAPSHOT_FILE_STATE_INDEX_CAPACITY + 1,
            "the shared byte budget retains this small working set after the query ends"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "56c836ff5d88: live-file query results were not shared within the semantic-token request scope"
    )]
    #[test]
    fn query_read_cache_reuses_analyzed_live_files_until_the_outer_scope_ends() {
        let context =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let mut cache = QueryReadCache::default();
        let files = vec![ProjectFile::new(std::env::temp_dir(), "src/lib.rs")];

        let attribution = context.enter();
        cache.begin(&context);
        assert!(cache.analyzed_live_files().is_none());
        cache.retain_analyzed_live_files(files.clone());
        assert_eq!(cache.analyzed_live_files(), Some(files));

        cache.end(&context);
        drop(attribution);
        assert!(
            cache.analyzed_live_files().is_none(),
            "a later analyzer request must validate its own live-file snapshot"
        );
    }

    /// Direct analyzers keep a stable filesystem generation until callers
    /// explicitly report an edit with `update`.
    #[test]
    fn analyzed_live_files_refresh_only_after_explicit_update() {
        // Git-backed on purpose: `resolve_live_oids` only routes through
        // `LivePathValidation::Filesystem` (the `PathState.stat: Some(_)`
        // shape M3 memoizes) when `store_context.liveness` resolves a repo
        // for the project root; a non-git `TestProject` falls back to
        // treating every live path as an "overlay" with `stat: None`, which
        // never calls `fs::metadata` in the first place (unrelated to this
        // milestone) and so would not exercise the memoization at all.
        let temp = tempfile::TempDir::new().unwrap();
        let repo = brokk_bifrost_core::gitblob::test_repo::init_repo(temp.path());
        std::fs::write(temp.path().join("A.java"), "public class A {}\n").unwrap();
        brokk_bifrost_core::gitblob::test_repo::commit_all(&repo, "init");
        let root = temp.path().to_path_buf();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        let first =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let first_attribution = first.enter();
        analyzer.begin_query(&first);
        let files_first = analyzer.analyzed_live_files();
        assert_eq!(files_first.len(), 1, "files: {files_first:?}");
        let stats_after_listing =
            brokk_bifrost_analysis::analyzer::store::liveness::stat_call_count_for_test();
        let oid_first = analyzer
            .resolve_live_oid_for_file(&files_first[0])
            .expect("initial live oid");
        assert_eq!(
            brokk_bifrost_analysis::analyzer::store::liveness::stat_call_count_for_test(),
            stats_after_listing,
            "the analyzed-file pass should seed live OIDs for the rest of its query scope"
        );
        analyzer.end_query(&first);
        drop(first_attribution);

        // An out-of-band edit remains invisible until the caller reports it.
        std::fs::write(
            temp.path().join("A.java"),
            "public class A { void m() {} }\n",
        )
        .unwrap();
        brokk_bifrost_analysis::analyzer::store::liveness::reset_stat_call_count_for_test();
        let second =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let second_attribution = second.enter();
        analyzer.begin_query(&second);
        let files_second = analyzer.analyzed_live_files();
        let oid_before_update = analyzer
            .resolve_live_oid_for_file(&files_second[0])
            .expect("retained live oid");
        analyzer.end_query(&second);
        drop(second_attribution);
        assert_eq!(files_second, files_first);
        assert_eq!(oid_before_update, oid_first);
        assert_eq!(
            brokk_bifrost_analysis::analyzer::store::liveness::stat_call_count_for_test(),
            0,
            "an unrelated query must trust the analyzer's current filesystem generation"
        );

        // The explicit update bumps the generation and records the new state.
        let file = ProjectFile::new(temp.path().to_path_buf(), PathBuf::from("A.java"));
        let updated = analyzer.update(&BTreeSet::from([file]));

        // The updated analyzer exposes the new identity without another sweep.
        brokk_bifrost_analysis::analyzer::store::liveness::reset_stat_call_count_for_test();
        let third =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let third_attribution = third.enter();
        updated.begin_query(&third);
        let files_third = updated.analyzed_live_files();
        let oid_after_update = updated
            .resolve_live_oid_for_file(&files_third[0])
            .expect("updated live oid");
        updated.end_query(&third);
        drop(third_attribution);
        assert_eq!(files_third.len(), 1, "files: {files_third:?}");
        assert_ne!(oid_after_update, oid_first);
        assert_eq!(
            brokk_bifrost_analysis::analyzer::store::liveness::stat_call_count_for_test(),
            0,
            "the explicit update already established the new filesystem generation"
        );

        // Later query contexts continue reusing that generation.
        brokk_bifrost_analysis::analyzer::store::liveness::reset_stat_call_count_for_test();
        let fourth =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let fourth_attribution = fourth.enter();
        updated.begin_query(&fourth);
        let files_fourth = updated.analyzed_live_files();
        updated.end_query(&fourth);
        drop(fourth_attribution);
        assert_eq!(files_fourth, files_third);
        assert_eq!(
            brokk_bifrost_analysis::analyzer::store::liveness::stat_call_count_for_test(),
            0,
            "a later query must not re-stat the updated filesystem generation"
        );
    }

    #[test]
    fn canonical_bulk_import_facts_distinguish_empty_and_missing_without_reparse() {
        let source = "pub fn sample() {}\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/main.rs", source)
            .build();
        let file = fixture.file("src/main.rs");
        let project = Arc::new(CountingOverlayProject::new(fixture.root(), source));
        let db = fixture.root().join("bulk-imports.db");
        let store = AnalyzerStore::open_persistent(&db).expect("persistent store");
        let store_context = store_context_from_store(project.as_ref(), store, false);
        let mut analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project) as Arc<dyn Project>,
            RustAdapter,
            AnalyzerConfig::default(),
            store_context,
            None,
        )
        .expect("canonical analyzer");
        assert!(analyzer.state.dirty_snapshot().is_empty());
        analyzer.source_snapshot_file_states = Arc::new(HashMap::default());
        analyzer.query_file_state_snapshot.store(None);
        analyzer
            .transient_file_states
            .lock()
            .expect("transient cache")
            .clear();
        analyzer
            .query_read_cache_lock()
            .file_states
            .write()
            .expect("query cache")
            .clear();
        let scope = AnalyzerQueryScope::new(&analyzer);
        let oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("live overlay identity");
        let key = TreeSitterAnalyzer::<RustAdapter>::transient_cache_key(oid, &file);
        assert!(analyzer.retained_file_state(&file, &key).is_none());
        project.reset_reads();
        analyzer.reset_full_hydration_count_for_test();

        let empty = analyzer.bulk_file_dependency_facts([file.clone()]);
        let facts = empty.get(&file).expect("witnessed import-free file");
        assert!(facts.imports.is_empty());
        assert_eq!(facts.contains_tests, Some(false));
        assert_eq!(project.read_count(), 0, "bulk facts do not fetch source");
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);

        let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db)
            .expect("corruption connection");
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TRIGGER source_fact_manifests_no_direct_delete;
             DELETE FROM source_fact_manifests;",
        )
        .expect("remove the common publication witness");
        assert!(
            analyzer
                .bulk_file_dependency_facts([file.clone()])
                .is_empty(),
            "a missing canonical publication is not a known-empty import set"
        );
        assert_eq!(
            project.read_count(),
            0,
            "missing facts do not read or reparse source"
        );
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        assert!(
            analyzer.retained_file_state(&file, &key).is_none(),
            "missing bulk facts must not create a parsed transient state"
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM source_fact_manifests", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0,
            "bulk lookup must not repair the missing publication"
        );
        drop(scope);
    }

    #[test]
    fn coarse_graph_keeps_missing_canonical_publication_in_source_inventory() {
        use brokk_bifrost_analysis::analyzer::usages::file_usage_graph::WorkspaceFileUsageGraphBuildOutcome;

        use brokk_bifrost_analysis::analyzer::usages::file_usage_graph::build_workspace_file_usage_graph_with_cancellation;

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

        let source = "package example; class Factory {}";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("Factory.java", source)
            .build();
        let file = fixture.file("Factory.java");
        let mut counted = CountingOverlayProject::new(fixture.root(), source);
        counted.delegate = TestProject::new(fixture.root(), Language::Java);
        let project = Arc::new(counted);
        let db = fixture.root().join("coarse-inventory.db");
        let store = Arc::new(AnalyzerStore::open_persistent(&db).expect("persistent store"));
        let producer = JavaAnalyzer::new_with_config_store_context(
            Arc::clone(&project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
            store_context_from_shared_store(project.as_ref(), Arc::clone(&store), false),
            None,
        )
        .expect("primary publication");
        drop(producer);
        let analyzer = JavaAnalyzer::new_with_config_store_context(
            Arc::clone(&project) as Arc<dyn Project>,
            AnalyzerConfig::default(),
            store_context_from_shared_store(project.as_ref(), store, false),
            None,
        )
        .expect("reopened analyzer");
        assert!(analyzer.inner().source_snapshot_file_states.is_empty());
        let cancellation = CancellationToken::new();
        let selected = BTreeSet::from([UsageEcosystem::Jvm]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let oid = analyzer.inner().resolve_live_oid_for_file(&file).unwrap();
        let key = TreeSitterAnalyzer::<JavaAdapter>::transient_cache_key(oid, &file);
        assert!(analyzer.inner().retained_file_state(&file, &key).is_none());
        project.reset_reads();
        let empty = build_workspace_file_usage_graph_with_cancellation(
            &analyzer,
            scope.token(),
            &selected,
            &cancellation,
        );
        let WorkspaceFileUsageGraphBuildOutcome::Complete(empty) = empty else {
            panic!("a witnessed import-free Java file has a complete coarse graph");
        };
        assert_eq!(empty.nodes.len(), 1);
        assert_eq!(project.read_count(), 0);
        drop(scope);

        project.listing_failed.store(true, Ordering::Relaxed);
        let scope = AnalyzerQueryScope::new(&analyzer);
        analyzer.inner().resolve_live_oid_for_file(&file).unwrap();
        project.reset_reads();
        let unlisted = build_workspace_file_usage_graph_with_cancellation(
            &analyzer,
            scope.token(),
            &selected,
            &cancellation,
        );
        let WorkspaceFileUsageGraphBuildOutcome::Incomplete(unlisted) = unlisted else {
            panic!("listing failure cannot publish a complete coarse graph");
        };
        assert_eq!(
            unlisted.nodes.len(),
            1,
            "retain the selected live source identity"
        );
        assert_eq!(unlisted.nodes[0].primary_file, file);
        assert_eq!(project.read_count(), 0);
        drop(scope);
        project.listing_failed.store(false, Ordering::Relaxed);

        let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db).unwrap();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TRIGGER source_fact_manifests_no_direct_delete;
             DELETE FROM source_fact_manifests;",
        )
        .unwrap();
        let scope = AnalyzerQueryScope::new(&analyzer);
        assert!(
            analyzer.analyzed_files().is_empty(),
            "parse readiness hides the missing file"
        );
        assert!(analyzer.inner().retained_file_state(&file, &key).is_none());
        project.reset_reads();
        analyzer.inner().reset_full_hydration_count_for_test();
        let missing = build_workspace_file_usage_graph_with_cancellation(
            &analyzer,
            scope.token(),
            &selected,
            &cancellation,
        );
        let WorkspaceFileUsageGraphBuildOutcome::Incomplete(missing) = missing else {
            panic!("a missing publication remains visible as an incomplete coarse graph");
        };
        assert_eq!(missing.nodes.len(), 1);
        assert_eq!(missing.nodes[0].primary_file, file);
        assert!(missing.nodes[0].incomplete);
        assert_eq!(missing.nodes[0].contains_tests, None);
        assert_eq!(
            project.read_count(),
            0,
            "inventory and missing facts do not read source"
        );
        assert_eq!(analyzer.inner().full_hydration_count_for_test(), 0);
        assert!(analyzer.inner().retained_file_state(&file, &key).is_none());
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM source_fact_manifests", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
            0
        );
    }

    #[test]
    fn canonical_bulk_import_facts_reuse_updated_overlay_primary_state() {
        let initial = "use crate::OldThing;\npub fn sample() {}\n";
        let changed = "use crate::NewThing;\n#[test] fn sample() {}\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/main.rs", initial)
            .build();
        let file = fixture.file("src/main.rs");
        let project = Arc::new(CountingOverlayProject::new(fixture.root(), initial));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);
        project.set_source(changed);
        let updated = analyzer.update(&BTreeSet::from([file.clone()]));
        let scope = AnalyzerQueryScope::new(&updated);
        let oid = updated
            .resolve_live_oid_for_file(&file)
            .expect("updated overlay identity");
        let key = TreeSitterAnalyzer::<RustAdapter>::transient_cache_key(oid, &file);
        let retained = updated
            .retained_file_state(&file, &key)
            .expect("retained overlay primary state");
        assert!(retained.source_facts.is_some());
        assert_eq!(retained.source, changed);
        let expected_imports = retained.imports.clone();
        updated
            .store_context
            .store
            .mark_parsed_blob_incomplete_for_test(oid, "rust");
        project.reset_reads();
        updated.reset_full_hydration_count_for_test();

        let facts = updated.bulk_file_dependency_facts([file.clone()]);
        let facts = facts
            .get(&file)
            .expect("exact retained primary facts remain available");
        assert_eq!(facts.imports, expected_imports);
        assert_eq!(facts.contains_tests, Some(true));
        assert_eq!(project.read_count(), 0);
        assert_eq!(updated.full_hydration_count_for_test(), 0);
        drop(scope);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#5842: retained C++ declaration reads remounted a complete source arena per callable"
    )]
    fn cpp_retained_source_cache_preserves_mounts_reads_and_refusals() {
        let source = "struct Base {}; using Alias = Base; struct Derived : Alias {};";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
            .file("aliases.cpp", source)
            .file("copy.cpp", source)
            .file(
                "owner.h",
                "struct Outer { struct Inner { int value; } inner; };",
            )
            .build();
        let file = fixture.file("aliases.cpp");
        let copy = fixture.file("copy.cpp");
        let header = fixture.file("owner.h");
        let mut analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
        let cache = moka::sync::Cache::new(16);
        let retained = analyzer
            .canonical_cpp_source_facts(&file, "cpp", &cache)
            .expect("complete retained source mounts without a caller query scope");
        let repeated = analyzer
            .canonical_cpp_source_facts(&file, "cpp", &cache)
            .unwrap();
        assert!(
            Arc::ptr_eq(&retained, &repeated),
            "repeated retained reads must reuse the mounted source arena"
        );

        let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
        {
            let scope = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
            let warm = analyzer
                .canonical_cpp_source_facts(&file, "cpp", &cache)
                .unwrap();
            assert!(Arc::ptr_eq(&retained, &warm));
            assert!(scope.read_completion().is_ok());
        }
        let oid = analyzer.resolve_live_oid_for_file(&file).unwrap();
        assert!(ledger.keys().contains(&analyzer.file_read_key(&file, oid)));

        let other_mount = analyzer
            .canonical_cpp_source_facts(&copy, "cpp", &cache)
            .unwrap();
        assert!(!Arc::ptr_eq(&retained, &other_mount));
        assert!(!other_mount.declaration_units.is_empty());
        assert!(
            other_mount
                .declaration_units
                .values()
                .flatten()
                .all(|unit| unit.source() == &copy),
            "byte-identical files must keep their own declaration provenance"
        );
        let cpp_header = analyzer
            .canonical_cpp_source_facts(&header, "cpp", &cache)
            .unwrap();
        let c_header = analyzer
            .canonical_cpp_source_facts(&header, "cpp:c", &cache)
            .expect("the C header reading gives the nested tag file scope");
        assert!(!Arc::ptr_eq(&cpp_header, &c_header));
        assert!(
            cpp_header
                .declaration_units
                .values()
                .flatten()
                .any(|unit| unit.fq_name() == "Outer$Inner")
        );
        assert!(
            c_header
                .declaration_units
                .values()
                .flatten()
                .any(|unit| unit.fq_name() == "Inner")
        );
        assert!(Arc::ptr_eq(
            &c_header,
            &analyzer
                .canonical_cpp_source_facts(&header, "cpp:c", &cache)
                .unwrap()
        ));
        assert!(
            analyzer
                .canonical_cpp_source_facts(&file, "cpp:c", &cache)
                .is_none(),
            "a C++ translation unit has no retained alternate C projection"
        );

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        {
            let scope = AnalyzerQueryScope::with_cancellation(&analyzer, &cancelled);
            assert!(
                analyzer
                    .canonical_cpp_source_facts(&file, "cpp", &cache)
                    .is_none(),
                "a warm arena must not bypass the current admission stop"
            );
            assert!(matches!(
                scope.read_completion(),
                Err(QueryReadIncomplete::Cancelled)
            ));
        }

        // Compare a real, uncached store hydration with the retained mount;
        // serving the warm cache after eviction would not test equivalence.
        analyzer.clear_retained_file_states_for_test();
        let stored = analyzer
            .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(16))
            .expect("the complete persisted publication reconstructs the same facts");
        assert!(!Arc::ptr_eq(&retained, &stored));
        assert_eq!(retained.source, stored.source);
        assert_eq!(retained.facts, stored.facts);
        assert_eq!(retained.declaration_units, stored.declaration_units);

        file.write(format!("{source}\nstruct Added {{ int value; }};\n"))
            .unwrap();
        let updated = analyzer.update(&BTreeSet::from([file.clone()]));
        let changed = updated
            .canonical_cpp_source_facts(&file, "cpp", &cache)
            .unwrap();
        assert!(!Arc::ptr_eq(&retained, &changed));
        assert!(
            changed
                .declaration_units
                .values()
                .flatten()
                .any(|unit| unit.identifier() == "Added"),
            "a changed source must not reuse the old mounted facts"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4474: missing C++ source publication lost its store failure and retry boundary"
    )]
    fn cpp_missing_alias_publication_records_failure_and_retries_same_cache() {
        let source = "struct Base {}; using Alias = Base; struct Derived : Alias {};";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
            .file("aliases.cpp", source)
            .build();
        let file = fixture.file("aliases.cpp");
        let mut analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
        let mut parser =
            TreeSitterAnalyzer::<CppAdapter>::build_parser(CppAdapter.parser_language());
        let state = TreeSitterAnalyzer::<CppAdapter>::analyze_source(
            &mut parser,
            &CppAdapter,
            &file,
            source.to_owned(),
        )
        .expect("primary C++ publication fixture")
        .state;
        let oid = analyzer.resolve_live_oid_for_file(&file).unwrap();
        assert!(analyzer.state.dirty_snapshot().is_empty());
        analyzer.source_snapshot_file_states = Arc::new(HashMap::default());
        analyzer.query_file_state_snapshot.store(None);
        analyzer.transient_file_states.lock().unwrap().clear();
        analyzer
            .query_read_cache_lock()
            .file_states
            .write()
            .unwrap()
            .clear();
        analyzer
            .store_context
            .store
            .mark_parsed_blob_incomplete_for_test(oid, "cpp");
        let cache = moka::sync::Cache::new(1);
        analyzer.reset_full_hydration_count_for_test();
        {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            assert!(
                analyzer
                    .canonical_cpp_source_facts(&file, "cpp", &cache)
                    .is_none()
            );
            assert!(
                scope
                    .store_error()
                    .expect("missing publication must reach the query failure boundary")
                    .to_string()
                    .contains("required C/C++ source publication unavailable")
            );
            assert!(matches!(
                scope.read_completion(),
                Err(QueryReadIncomplete::StoreFailure(_))
            ));
        }
        analyzer
            .store_context
            .store
            .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
            .unwrap();
        {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            let facts = analyzer
                .canonical_cpp_source_facts(&file, "cpp", &cache)
                .expect("repair must retry through the same analyzer and canonical cache");
            assert!(facts.facts.declarations.iter().any(|fact| {
                fact.file_scope_alias
                    .as_ref()
                    .is_some_and(|alias| alias.name == "Alias" && alias.target == "Base")
            }));
            assert!(scope.store_error().is_none());
        }
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "failure and repair must not hydrate or reparse the donor file"
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#4474: bounded C++ parse was reported as missing store publication"
    )]
    fn cpp_forced_timeout_is_typed_incomplete_and_repairs_on_retry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = "struct Retry { int value; };\n";
        let file = ProjectFile::new(root.clone(), "src/Retry.cpp");
        file.write(source).expect("C++ retry fixture");

        let forced_path = file.abs_path().to_path_buf();
        FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned")
            .push(forced_path.clone());
        let project: Arc<dyn Project> = Arc::new(TestProject::new(&root, Language::Cpp));
        let analyzer = TreeSitterAnalyzer::new(project, CppAdapter);
        let mut forced_paths = FORCED_PARSE_TIMEOUT_PATHS
            .lock()
            .expect("forced parse timeout paths mutex poisoned");
        let forced_path_index = forced_paths
            .iter()
            .position(|path| path == &forced_path)
            .expect("test timeout path remains registered");
        forced_paths.remove(forced_path_index);
        drop(forced_paths);

        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
        let key = TreeSitterAnalyzer::<CppAdapter>::transient_cache_key(oid, &file);
        let retained = analyzer
            .retained_file_state(&file, &key)
            .expect("forced timeout retains the exact source state");
        assert_eq!(retained.source, source);
        assert!(!retained.parse_complete);
        assert!(
            !analyzer
                .store_context
                .store
                .contains_parsed_blob(oid, "cpp")
                .unwrap()
        );

        {
            let scope = AnalyzerQueryScope::new(&analyzer);
            assert!(
                analyzer
                    .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(1))
                    .is_none()
            );
            assert!(matches!(
                scope.read_completion(),
                Err(QueryReadIncomplete::SemanticEvidenceUnavailable(detail))
                    if detail.contains("retained C++ parse")
            ));
            assert!(scope.store_error().is_none());
        }

        let retried = analyzer.update(&BTreeSet::from([file.clone()]));
        let retried_state = retried
            .retained_file_state(&file, &key)
            .expect("retry retains repaired source state");
        assert!(retried_state.parse_complete);
        assert!(
            retried
                .store_context
                .store
                .contains_parsed_blob(oid, "cpp")
                .unwrap()
        );
        let scope = AnalyzerQueryScope::new(&retried);
        let facts = retried
            .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(1))
            .expect("repaired C++ publication supplies canonical facts");
        assert!(!facts.facts.declarations.is_empty());
        assert!(scope.read_completion().is_ok());
    }

    fn retain_source_facts_state_without_publication<A: LanguageAdapter>(
        analyzer: &TreeSitterAnalyzer<A>,
        adapter: &A,
        file: &ProjectFile,
        source: &str,
    ) -> Arc<FileState> {
        let mut parser =
            TreeSitterAnalyzer::<A>::build_parser(adapter.parser_language_for_file(file));
        let retained = Arc::new(
            TreeSitterAnalyzer::<A>::analyze_source(&mut parser, adapter, file, source.to_owned())
                .expect("source parses")
                .state,
        );
        let oid = analyzer
            .resolve_live_oid_for_file(file)
            .expect("fixture has a live blob");
        let key = TreeSitterAnalyzer::<A>::transient_cache_key(oid, file);
        analyzer
            .query_file_state_snapshot
            .store(Some(Arc::new(HashMap::from_iter([(
                key,
                Arc::clone(&retained),
            )]))));
        analyzer
            .store_context
            .store
            .mark_parsed_blob_incomplete_for_test(oid, adapter.storage_language_key_for_file(file));
        analyzer.reset_full_hydration_count_for_test();
        retained
    }

    #[test]
    fn java_source_facts_reuse_retained_primary_state_without_publication_retry() {
        let source = "class Factory { Factory make() { return this; } }";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("Factory.java", source)
            .build();
        let file = fixture.file("Factory.java");
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
        let retained =
            retain_source_facts_state_without_publication(&analyzer, &JavaAdapter, &file, source);
        let expected = retained
            .source_facts
            .as_ref()
            .unwrap()
            .java
            .clone()
            .unwrap();
        let facts = analyzer
            .canonical_java_source_facts(&file, &moka::sync::Cache::new(1))
            .unwrap();
        assert_eq!(facts.facts, expected);
        assert!(!facts.declaration_units.is_empty());
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
    }

    #[test]
    fn php_source_facts_require_publication_or_retained_primary_state() {
        use brokk_bifrost_php_analysis::analyzer::php::adapter::PhpAdapter;
        let source = "<?php class Owner { public string $value; }";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Php)
            .file("owner.php", source)
            .build();
        let file = fixture.file("owner.php");
        let mut analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), PhpAdapter);
        let mut parser =
            TreeSitterAnalyzer::<PhpAdapter>::build_parser(PhpAdapter.parser_language());
        let retained = TreeSitterAnalyzer::<PhpAdapter>::analyze_source(
            &mut parser,
            &PhpAdapter,
            &file,
            source.to_owned(),
        )
        .unwrap()
        .state;
        let expected = retained.source_facts.as_ref().unwrap().php.clone().unwrap();
        let cache = moka::sync::Cache::new(1);
        assert!(
            analyzer
                .canonical_php_source_facts(&file, &cache, &|| false)
                .is_none()
        );
        assert_eq!(cache.entry_count(), 0);
        let oid = analyzer.resolve_live_oid_for_file(&file).unwrap();
        analyzer
            .store_context
            .store
            .mark_parsed_blob_incomplete_for_test(oid, "php");
        analyzer.source_snapshot_file_states = Arc::new(HashMap::default());
        analyzer.transient_file_states.lock().unwrap().clear();
        analyzer.query_file_state_snapshot.store(None);
        let retained_key = TreeSitterAnalyzer::<PhpAdapter>::transient_cache_key(oid, &file);
        assert!(analyzer.retained_file_state(&file, &retained_key).is_none());
        analyzer.reset_full_hydration_count_for_test();
        assert!(
            analyzer
                .canonical_php_source_facts(&file, &cache, &|| true)
                .is_none()
        );
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        let key = TreeSitterAnalyzer::<PhpAdapter>::transient_cache_key(oid, &file);
        // The query file-state snapshot lives for one query; an analyzer read
        // that opens its own scope outside a query clears it on entry.
        let scope = AnalyzerQueryScope::new(&analyzer);
        analyzer
            .query_file_state_snapshot
            .store(Some(Arc::new(HashMap::from_iter([(
                key,
                Arc::new(retained),
            )]))));
        let facts = analyzer
            .canonical_php_source_facts(&file, &cache, &|| true)
            .unwrap();
        let admission = std::cell::Cell::new(0);
        assert!(
            analyzer
                .canonical_php_source_facts(&file, &cache, &|| {
                    let previous = admission.get();
                    admission.set(previous + 1);
                    previous == 0
                })
                .is_none()
        );
        drop(scope);
        assert!(analyzer.query_file_state_snapshot.load().is_none());
        cache.insert(
            (
                analyzer.language_generation("php").unwrap(),
                oid,
                file.clone(),
            ),
            Arc::clone(&facts),
        );
        admission.set(0);
        assert!(
            analyzer
                .canonical_php_source_facts(&file, &cache, &|| {
                    let previous = admission.get();
                    admission.set(previous + 1);
                    previous == 0
                })
                .is_none()
        );
        assert_eq!(facts.facts, expected);
        assert!(!facts.declaration_units.is_empty());
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
    }

    #[test]
    fn ruby_source_facts_reuse_retained_primary_state_without_publication_retry() {
        use brokk_bifrost_ruby_analysis::analyzer::ruby::adapter::RubyAdapter;
        let source = "autoload :Ready, \"ready\"\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Ruby)
            .file("main.rb", source)
            .build();
        let file = fixture.file("main.rb");
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), RubyAdapter);
        let _retained =
            retain_source_facts_state_without_publication(&analyzer, &RubyAdapter, &file, source);
        let oid = analyzer.resolve_live_oid_for_file(&file).unwrap();
        let facts = analyzer.canonical_ruby_source_facts(&file).unwrap();
        assert_eq!(
            facts.loads[0].autoload_constant.as_deref().unwrap(),
            ["Ready"]
        );
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        assert!(
            !analyzer
                .store_context
                .store
                .contains_parsed_blob(oid, "ruby")
                .unwrap()
        );
    }

    #[test]
    fn go_source_facts_reuse_retained_primary_state_without_publication_retry() {
        let source = "package demo\ntype Owner struct { Value int }\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file("owner.go", source)
            .build();
        let file = fixture.file("owner.go");
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), GoAdapter);
        let retained =
            retain_source_facts_state_without_publication(&analyzer, &GoAdapter, &file, source);
        let expected = retained.source_facts.as_ref().unwrap().go.clone().unwrap();
        let facts = analyzer
            .canonical_go_source_facts(
                &file,
                &brokk_bifrost_core::analyzer::memo_attribution::ReplayingMemo::new(
                    moka::sync::Cache::new(1),
                ),
            )
            .unwrap();
        assert_eq!(facts.facts, expected);
        assert!(!facts.declaration_units.is_empty());
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);
    }

    #[test]
    fn js_ts_source_facts_reuse_retained_primary_state_without_publication_retry() {
        fn check<A: LanguageAdapter + Clone>(adapter: A, path: &str) {
            let source = "export class Owner { run(value) { return value; } }";
            let fixture =
                crate::inline_project::InlineTestProject::with_language(adapter.language())
                    .file(path, source)
                    .build();
            let file = fixture.file(path);
            let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), adapter.clone());
            let retained =
                retain_source_facts_state_without_publication(&analyzer, &adapter, &file, source);
            let expected = retained
                .source_facts
                .as_ref()
                .unwrap()
                .js_ts
                .clone()
                .unwrap();
            let facts = analyzer
                .canonical_js_ts_source_facts(&file, &moka::sync::Cache::new(1))
                .unwrap();
            assert_eq!(facts.facts, expected);
            assert!(!facts.declaration_units.is_empty());
            assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        }
        check(JavascriptAdapter, "owner.js");
        check(TypescriptAdapter, "owner.ts");
    }

    #[test]
    fn js_ts_unparseable_source_is_a_structured_incomplete_read() {
        // A NUL inside a string is grammar-proven payload (#4479); one inside
        // an identifier is not, so the file stays refused as binary.
        let source = "const senti\0nel = 1;\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::JavaScript)
            .file("unsafe.js", source)
            .build();
        let file = fixture.file("unsafe.js");
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavascriptAdapter);
        let scope = AnalyzerQueryScope::new(&analyzer);

        assert!(
            analyzer
                .canonical_js_ts_source_facts(&file, &moka::sync::Cache::new(1))
                .is_none()
        );
        assert!(matches!(
            scope.read_completion(),
            Err(QueryReadIncomplete::StructureUnavailable(unavailable)) if unavailable == file
        ));
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn cpp_unparseable_source_is_a_structured_incomplete_read() {
        let source = format!(
            "// {}\n",
            "x".repeat(brokk_bifrost_core::analyzer::common::DEFAULT_MAX_LINE_LENGTH + 1)
        );
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
            .file("unsafe.cpp", &source)
            .build();
        let file = fixture.file("unsafe.cpp");
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
        let scope = AnalyzerQueryScope::new(&analyzer);

        assert!(
            analyzer
                .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(1))
                .is_none()
        );
        assert!(matches!(
            scope.read_completion(),
            Err(QueryReadIncomplete::StructureUnavailable(unavailable)) if unavailable == file
        ));
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn ruby_unparseable_source_is_a_structured_incomplete_read() {
        let source = format!(
            "#{}\n",
            "x".repeat(brokk_bifrost_core::analyzer::common::DEFAULT_MAX_LINE_LENGTH + 1)
        );
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Ruby)
            .file("unsafe.rb", &source)
            .build();
        let file = fixture.file("unsafe.rb");
        let analyzer = TreeSitterAnalyzer::new(
            fixture.project_dyn(),
            brokk_bifrost_ruby_analysis::analyzer::ruby::adapter::RubyAdapter,
        );
        let scope = AnalyzerQueryScope::new(&analyzer);

        assert!(analyzer.canonical_ruby_source_facts(&file).is_none());
        assert!(matches!(
            scope.read_completion(),
            Err(QueryReadIncomplete::StructureUnavailable(unavailable)) if unavailable == file
        ));
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn java_source_facts_refuse_kotlin_owned_files_as_structured_incomplete() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("src/main/kotlin/DeepThought.kt", "class DeepThought\n")
            .build();
        let file = fixture.file("src/main/kotlin/DeepThought.kt");
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
        let scope = AnalyzerQueryScope::new(&analyzer);

        assert!(
            analyzer
                .canonical_java_source_facts(&file, &moka::sync::Cache::new(1))
                .is_none()
        );
        assert!(matches!(
            scope.read_completion(),
            Err(QueryReadIncomplete::StructureUnavailable(unavailable)) if unavailable == file
        ));
        assert!(scope.store_error().is_none());
    }

    #[test]
    fn signature_metadata_cold_reader_uses_persisted_rows_without_file_hydration() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file(
                "Factory.java",
                "class Factory { public void make() {} private void make() {} }",
            )
            .build();
        let file = fixture.file("Factory.java");
        let mut analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), JavaAdapter);
        let state = analyzer.fetch_file_state(&file).expect("built Java state");
        let (unit, expected) = state
            .signature_metadata
            .iter()
            .find(|(unit, _)| unit.is_function() && unit.identifier() == "make")
            .map(|(unit, rows)| (unit.clone(), rows.clone()))
            .expect("two written metadata alternatives");
        assert_eq!(expected.len(), 2);
        let mut retained = (*state).clone();
        let retained_metadata = vec![SignatureMetadata::new("retained projection", Vec::new())];
        retained
            .signature_metadata
            .insert(unit.clone(), retained_metadata.clone());
        retained
            .signatures
            .insert(unit.clone(), vec![retained_metadata[0].label().to_owned()]);
        retained
            .signature_metadata_signature_ordinals
            .insert(unit.clone(), vec![0]);
        let retained = Arc::new(retained);
        drop(state);
        assert!(
            analyzer.state.dirty_snapshot().is_empty(),
            "fixture must be persisted"
        );
        analyzer.source_snapshot_file_states = Arc::new(HashMap::default());
        analyzer.query_file_state_snapshot.store(None);
        analyzer
            .transient_file_states
            .lock()
            .expect("transient cache lock")
            .clear();
        analyzer
            .query_read_cache_lock()
            .file_states
            .write()
            .expect("query cache lock")
            .clear();
        analyzer.reset_full_hydration_count_for_test();

        assert_eq!(analyzer.signature_metadata_vec_of(&unit), expected);
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "metadata must not fetch or hydrate the whole file on a cold cache"
        );

        let scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let oid = analyzer.resolve_live_oid_for_file(&file).unwrap();
        let key = TreeSitterAnalyzer::<JavaAdapter>::transient_cache_key(oid, &file);
        let assert_retained = || {
            assert_eq!(analyzer.signature_metadata_vec_of(&unit), retained_metadata);
            let bounded = analyzer.signature_metadata_limited(&unit, 8);
            assert!(bounded.complete);
            assert_eq!(bounded.rows, retained_metadata);
            assert_eq!(analyzer.full_hydration_count_for_test(), 0);
        };
        analyzer
            .transient_file_states
            .lock()
            .unwrap()
            .insert(key.clone(), Arc::clone(&retained));
        assert_retained();
        analyzer.transient_file_states.lock().unwrap().clear();

        let cache = analyzer
            .active_query_cache_handle(|cache| &cache.file_states)
            .unwrap();
        cache.write().unwrap().retain(key, Arc::clone(&retained));
        assert_retained();
        cache.write().unwrap().clear();

        analyzer.begin_streaming_file_read(&file);
        analyzer.retain_streaming_file_state_for_test(retained);
        assert_retained();
        analyzer.end_streaming_file_read(&file);
        drop(scope);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "e087290f89ff: concurrent C++ inverse batches contended by deep-copying file-state snapshots"
    )]
    #[test]
    fn bulk_file_state_snapshot_reuses_and_resets_across_query_scopes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let project = Arc::new(CountingOverlayProject::new(&root, "fn target() {}\n"));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);
        let file = ProjectFile::new(&root, "src/main.rs");

        let first =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let first_attribution = first.enter();
        analyzer.begin_query(&first);
        analyzer.reset_full_hydration_count_for_test();
        analyzer.bulk_file_states_for_query([file.clone()], BulkFileStateSource::Include);

        let oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("overlay OID");
        let key = TreeSitterAnalyzer::<RustAdapter>::transient_cache_key(oid, &file);
        let snapshot_guard = analyzer.query_file_state_snapshot.load();
        let snapshot = snapshot_guard
            .as_ref()
            .expect("bulk hydration should publish a file-state snapshot");
        let query_budget = {
            let cache = analyzer.query_read_cache_lock();
            cache
                .file_states
                .read()
                .expect("query file-state cache read lock poisoned")
                .max_bytes
        };
        let snapshot_bytes = snapshot
            .values()
            .map(|state| state.estimated_retained_bytes())
            .fold(0usize, usize::saturating_add);
        assert!(
            snapshot_bytes <= query_budget,
            "snapshot must stay within its request budget"
        );
        assert!(snapshot.contains_key(&key));

        // Remove the ordinary request and transient entries so a successful
        // fetch below proves it came from the immutable bulk snapshot.
        let file_states = {
            let cache = analyzer.query_read_cache_lock();
            Arc::clone(&cache.file_states)
        };
        file_states
            .write()
            .expect("query file-state cache write lock poisoned")
            .clear();
        {
            let mut transient = analyzer
                .transient_file_states
                .lock()
                .expect("transient file-state cache mutex poisoned");
            transient.clear();
        }

        let state = analyzer
            .fetch_file_state(&file)
            .expect("snapshot-backed file state");
        assert_eq!(state.source.as_str(), "fn target() {}\n");
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "fetch should reuse the immutable bulk snapshot"
        );
        let unit = state
            .top_level_declarations
            .first()
            .cloned()
            .expect("function declaration");
        assert!(
            !analyzer.ranges_limited(&unit, 8).rows.is_empty(),
            "ranges should also read the snapshot-backed state"
        );
        assert_eq!(analyzer.full_hydration_count_for_test(), 0);

        analyzer.end_query(&first);
        drop(first_attribution);
        assert!(
            analyzer.query_file_state_snapshot.load().as_ref().is_none(),
            "ending the outer query must clear the immutable snapshot"
        );

        project.set_source("fn changed() {}\n");
        let second =
            Arc::new(brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryContext::default());
        let second_attribution = second.enter();
        analyzer.begin_query(&second);
        analyzer.reset_full_hydration_count_for_test();
        let changed = analyzer
            .fetch_file_state(&file)
            .expect("changed overlay file state");
        assert_eq!(changed.source.as_str(), "fn changed() {}\n");
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            1,
            "a new query must hydrate the changed OID after snapshot reset"
        );
        analyzer.end_query(&second);
        drop(second_attribution);
    }

    /// #1450: the per-request cell above is dropped when the outer scope ends,
    /// so without a cross-request layer every later request re-parses. The
    /// retained tree is the *same* `Arc`, which is what makes the warm scan
    /// cost graph assembly rather than 662 parses.
    #[test]
    fn prepared_syntax_survives_across_outer_query_scopes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        let first = {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("first syntax")
        };
        let second = {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("retained syntax")
        };

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    /// The `ExactSource` flavor shares the mechanism, and it is a distinct
    /// cache entry from `Indexed`, so it is pinned separately.
    #[brokk_bifrost_test_macros::hardwon(
        "e976f7024fbb: prepared exact syntax was lost when a nested query scope ended"
    )]
    #[test]
    fn prepared_exact_syntax_survives_across_outer_query_scopes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        let exact = |label: &str| {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            match analyzer.prepared_syntax_limited(scope.token(), &file, 1 << 20) {
                Ok(Some((_, prepared))) => prepared,
                other => panic!("{label} exact syntax: {other:?}"),
            }
        };
        let first = exact("first");
        let second = exact("retained");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#3085: reusing parsed syntax across backing flavors mixed declaration indexes after the CI repair"
    )]
    #[test]
    fn prepared_syntax_flavors_reuse_the_parse_without_sharing_index_backing() {
        for order in [
            [
                PreparedSyntaxCacheFlavor::ExactSource,
                PreparedSyntaxCacheFlavor::Indexed,
            ],
            [
                PreparedSyntaxCacheFlavor::Indexed,
                PreparedSyntaxCacheFlavor::ExactSource,
            ],
        ] {
            let source = "fn target() {}\n";
            let project = crate::inline_project::InlineTestProject::with_language(Language::Rust)
                .file("src/main.rs", source)
                .build();
            let file = project.file("src/main.rs");
            let analyzer = TreeSitterAnalyzer::new(project.project_dyn(), RustAdapter);
            let target = analyzer
                .lookup_candidates_by_identifier("target")
                .into_iter()
                .next()
                .expect("indexed target");
            analyzer.reset_full_hydration_count_for_test();

            // Exercise both the active query cells and cross-request retention.
            for _ in 0..2 {
                let scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(
                    &analyzer,
                );
                for flavor in order {
                    let before = analyzer.full_hydration_count_for_test();
                    let prepared = match flavor {
                        PreparedSyntaxCacheFlavor::ExactSource => {
                            let (_, prepared) = analyzer
                                .prepared_syntax_limited(scope.token(), &file, source.len())
                                .expect("admitted source")
                                .expect("exact syntax");
                            assert!(matches!(prepared.backing(), PreparedSyntaxSource::Exact(_)));
                            assert!(prepared.declaration_node(&target).is_none());
                            assert_eq!(analyzer.full_hydration_count_for_test(), before);
                            prepared
                        }
                        PreparedSyntaxCacheFlavor::Indexed => {
                            let prepared = analyzer
                                .prepared_syntax(scope.token(), &file)
                                .expect("indexed syntax");
                            assert!(prepared.declaration_node(&target).is_some());
                            prepared
                        }
                    };
                    assert_eq!(prepared.source(), source);
                    assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
                }
            }
        }
    }

    /// The correctness claim behind retaining trees at all: entries are keyed
    /// by blob oid, so an out-of-band edit lands on a different key and the
    /// next request parses the new bytes. A path-keyed cache serves the stale
    /// tree here.
    #[brokk_bifrost_test_macros::hardwon(
        "#1450: retained Rust syntax survived a content change and served stale source facts"
    )]
    #[test]
    fn prepared_syntax_reparses_after_the_file_changes_between_query_scopes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\n").expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);

        let first = {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("first syntax")
        };
        assert_eq!(first.source(), "fn target() {}\n");

        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("edited rust source");
        let second = {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("edited syntax")
        };

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(
            second.source(),
            "fn target() {}\nfn consumer() { target(); }\n"
        );
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 2);

        // Restoring the original bytes restores the original key, and the
        // still-retained tree answers it without a third parse.
        file.write("fn target() {}\n")
            .expect("restored rust source");
        let restored = {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("restored syntax")
        };
        assert!(Arc::ptr_eq(&first, &restored));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 2);
    }

    /// The store is bounded by estimated retained bytes, not entry count, so a
    /// workspace larger than the budget evicts by recency instead of growing.
    #[brokk_bifrost_test_macros::hardwon(
        "#1450: retained prepared syntax exceeded its byte bound instead of evicting least-recent entries"
    )]
    #[test]
    fn prepared_syntax_store_evicts_the_least_recently_used_entry_past_its_bound() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\n").expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let prepared = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("syntax");

        let key = |seed: u8| PreparedSyntaxCacheKey {
            file_state: FileStateCacheKey {
                oid: Oid::hash_object(ObjectType::Blob, &[seed]).expect("blob oid"),
                rel_path: PathBuf::from("src/main.rs"),
                admission_policy: SourceAdmissionPolicy::current(),
            },
            origin: PreparedSourceOrigin::Disk,
            overlay_revision: None,
            flavor: PreparedSyntaxCacheFlavor::Indexed,
        };
        let entry_bytes = prepared
            .source()
            .len()
            .saturating_mul(PREPARED_SYNTAX_BYTES_PER_SOURCE_BYTE)
            .saturating_add(PREPARED_SYNTAX_STORE_ENTRY_OVERHEAD_BYTES);
        // Holds two entries and not three: the third insert overflows, and the
        // 7/8 watermark is still above two entries, so exactly one is evicted.
        let mut store = PreparedSyntaxStore::new(entry_bytes * 5 / 2);

        store.retain(key(1), Arc::clone(&prepared));
        store.retain(key(2), Arc::clone(&prepared));
        // Touching the first entry makes the second the least recent.
        assert!(store.get(&key(1)).is_some());
        store.retain(key(3), Arc::clone(&prepared));

        assert!(store.get(&key(1)).is_some(), "recently used entry evicted");
        assert!(store.get(&key(2)).is_none(), "least recent entry retained");
        assert!(store.get(&key(3)).is_some(), "newest entry evicted");
        assert!(store.retained_bytes <= store.max_bytes);

        // An evicted key is simply a miss: the caller reparses and re-retains.
        store.retain(key(2), Arc::clone(&prepared));
        assert!(store.get(&key(2)).is_some());
        assert!(store.retained_bytes <= store.max_bytes);
    }

    /// A single tree larger than the whole budget is never retained: holding it
    /// would evict everything else and then be dropped by the next insert.
    #[brokk_bifrost_test_macros::hardwon(
        "e976f7024fbb: prepared syntax cache retained a single entry larger than its byte cap"
    )]
    #[test]
    fn prepared_syntax_store_refuses_an_entry_larger_than_its_bound() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\n").expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let prepared = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("syntax");

        let mut store = PreparedSyntaxStore::new(PREPARED_SYNTAX_STORE_ENTRY_OVERHEAD_BYTES);
        let key = PreparedSyntaxCacheKey {
            file_state: FileStateCacheKey {
                oid: Oid::hash_object(ObjectType::Blob, b"oversized").expect("blob oid"),
                rel_path: PathBuf::from("src/main.rs"),
                admission_policy: SourceAdmissionPolicy::current(),
            },
            origin: PreparedSourceOrigin::Disk,
            overlay_revision: None,
            flavor: PreparedSyntaxCacheFlavor::Indexed,
        };
        store.retain(key.clone(), prepared);

        assert!(store.get(&key).is_none());
        assert_eq!(store.retained_bytes, 0);
    }

    fn import_infos(snippets: &[&str]) -> Arc<[ImportInfo]> {
        snippets
            .iter()
            .map(|snippet| ImportInfo {
                raw_snippet: (*snippet).to_string(),
                is_wildcard: false,
                is_global: false,
                identifier: None,
                alias: None,
                path: None,
                binder_span: None,
            })
            .collect()
    }

    fn import_key(seed: u8) -> FileStateCacheKey {
        FileStateCacheKey {
            oid: Oid::hash_object(ObjectType::Blob, &[seed]).expect("blob oid"),
            rel_path: PathBuf::from("src/main.rs"),
            admission_policy: SourceAdmissionPolicy::current(),
        }
    }

    /// The store is bounded by estimated retained bytes, not entry count, so a
    /// workspace larger than the budget evicts by recency instead of growing.
    #[brokk_bifrost_test_macros::hardwon(
        "#1451: retained import information exceeded its bound instead of evicting least-recent entries"
    )]
    #[test]
    fn import_info_store_evicts_the_least_recently_used_entry_past_its_bound() {
        let imports = import_infos(&["use crate::target::collect_it;"]);
        let entry_bytes = imports.estimated_bytes();
        // Holds two entries and not three: the third insert overflows, and the
        // 7/8 watermark is still above two entries, so exactly one is evicted.
        let mut store = ImportInfoStore::new(entry_bytes * 5 / 2);

        store.retain(
            import_key(1),
            RetainedImportInfos {
                imports: Arc::clone(&imports),
                canonical: false,
            },
        );
        store.retain(
            import_key(2),
            RetainedImportInfos {
                imports: Arc::clone(&imports),
                canonical: false,
            },
        );
        // Touching the first entry makes the second the least recent.
        assert!(store.get(&import_key(1)).is_some());
        store.retain(
            import_key(3),
            RetainedImportInfos {
                imports: Arc::clone(&imports),
                canonical: false,
            },
        );

        assert!(
            store.get(&import_key(1)).is_some(),
            "recently used entry evicted"
        );
        assert!(
            store.get(&import_key(2)).is_none(),
            "least recent entry retained"
        );
        assert!(store.get(&import_key(3)).is_some(), "newest entry evicted");
        assert!(store.retained_bytes <= store.max_bytes);

        // An evicted key is simply a miss: the caller rehydrates and re-retains.
        store.retain(
            import_key(2),
            RetainedImportInfos {
                imports,
                canonical: false,
            },
        );
        assert!(store.get(&import_key(2)).is_some());
        assert!(store.retained_bytes <= store.max_bytes);
    }

    /// A file whose imports alone exceed the whole budget is never retained:
    /// holding it would evict everything else and then be dropped by the next
    /// insert.
    #[brokk_bifrost_test_macros::hardwon(
        "15b5c2195090: import-info cache retained a single entry larger than its byte cap"
    )]
    #[test]
    fn import_info_store_refuses_an_entry_larger_than_its_bound() {
        let mut store = ImportInfoStore::new(IMPORT_INFO_STORE_ENTRY_OVERHEAD_BYTES);
        let key = import_key(1);
        store.retain(
            key.clone(),
            RetainedImportInfos {
                imports: import_infos(&["use crate::target::collect_it;"]),
                canonical: false,
            },
        );

        assert!(store.get(&key).is_none());
        assert_eq!(store.retained_bytes, 0);
    }

    #[test]
    fn checked_go_import_reader_ignores_legacy_cache_and_retention_cutoff() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Go)
            .file(
                "main.go",
                "package main\nimport \"fmt\"\nfunc main() { fmt.Println() }\n",
            )
            .build();
        let file = fixture.file("main.go");
        let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), GoAdapter);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let oid = analyzer.resolve_live_oid_for_file(&file).unwrap();
        let key = TreeSitterAnalyzer::<GoAdapter>::transient_cache_key(oid, &file);
        let expected = analyzer.fetch_file_state(&file).unwrap().imports.clone();
        assert!(!expected.is_empty());
        assert!(analyzer.state.dirty_snapshot().is_empty());
        analyzer.import_info_store_retain(key.clone(), Arc::from(Vec::<ImportInfo>::new()));
        assert_eq!(
            analyzer.import_info_of_checked(scope.token(), &file),
            Some(expected.clone()),
            "a legacy cached empty set cannot replace canonical imports"
        );

        *analyzer.import_info_store.lock().unwrap() = ImportInfoStore::new(1);
        analyzer.reset_full_hydration_count_for_test();
        for _ in 0..2 {
            assert_eq!(
                analyzer.import_info_of_checked(scope.token(), &file),
                Some(expected.clone())
            );
            assert!(
                analyzer.import_info_store_get_checked(&key).is_none(),
                "the tiny retained cache must reject the import payload"
            );
        }
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "canonical import reads must not hydrate or reparse the whole file"
        );
    }

    #[test]
    fn checked_import_cache_preserves_canonical_provenance() {
        let imports = import_infos(&["use crate::target::collect_it;"]);
        let key = import_key(1);
        let mut store = ImportInfoStore::new(IMPORT_INFO_STORE_MAX_BYTES);
        store.retain(
            key.clone(),
            RetainedImportInfos {
                imports: Arc::clone(&imports),
                canonical: false,
            },
        );
        assert!(!store.get(&key).unwrap().canonical);

        store.retain(
            key.clone(),
            RetainedImportInfos {
                imports,
                canonical: true,
            },
        );
        assert!(store.get(&key).unwrap().canonical);
    }

    /// The dirty overlay holds a parse the store has not accepted yet, so it
    /// outranks anything the cross-request store retained for the same key.
    #[test]
    fn dirty_imports_outrank_a_retained_import_info_entry() {
        let source = "import dirty_module\n".to_string();
        let (_temp, file, oid, _store, analyzer) =
            analyzer_with_retryable_dirty_python_file("dirty.py", &source);
        let key = TreeSitterAnalyzer::<PythonAdapter>::transient_cache_key(oid, &file);

        // Seed the cross-request store with a value the dirty state contradicts.
        analyzer.import_info_store_retain(key, import_infos(&["import stale_module"]));

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let imports = analyzer.import_info_of(token, &file);
        assert_eq!(
            vec!["dirty_module".to_string()],
            imports
                .iter()
                .filter_map(|import| import.identifier.clone())
                .collect::<Vec<_>>(),
            "dirty imports must outrank the retained entry; got {imports:#?}"
        );
        assert_eq!(analyzer.import_info_hydration_count_for_test(), 0);
    }

    #[test]
    fn prepared_syntax_initializes_once_for_concurrent_queries() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn target() {}\nfn consumer() { target(); }\n")
            .expect("rust source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let _scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let barrier = Arc::new(Barrier::new(8));

        let prepared: Vec<_> = std::thread::scope(|threads| {
            let analyzer = &analyzer;
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let file = file.clone();
                    threads.spawn(move || {
                        barrier.wait();
                        let scope =
                            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(
                                analyzer,
                            );
                        analyzer
                            .prepared_syntax(scope.token(), &file)
                            .expect("prepared syntax")
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("syntax worker"))
                .collect()
        });

        assert!(
            prepared
                .iter()
                .skip(1)
                .all(|syntax| Arc::ptr_eq(&prepared[0], syntax))
        );
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }

    #[test]
    fn rust_workspace_inputs_publish_atomically_and_keep_source_locality() {
        let manifest_v1 = "[package]\nname = \"sample\"\nedition = \"2021\"\n";
        let source_v1 = "pub fn sample() {}\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", manifest_v1)
            .file("src/lib.rs", source_v1)
            .build();
        let manifest = fixture.file("Cargo.toml");
        let source = fixture.file("src/lib.rs");
        let db = fixture.root().join("workspace-inputs.db");
        let store = AnalyzerStore::open_persistent(&db).expect("persistent store");
        let project = fixture.project_dyn();
        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            RustAdapter,
            AnalyzerConfig::default(),
            store_context_from_store(project.as_ref(), store, false),
            None,
        )
        .expect("Rust analyzer");

        let current_configuration = |analyzer: &TreeSitterAnalyzer<RustAdapter>| -> Vec<u8> {
            let snapshot = analyzer.selected_workspace_snapshots()["rust"].clone();
            let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db)
                .expect("workspace database");
            conn.query_row(
                "SELECT retained.source_bytes
                 FROM workspace_file_versions AS versions
                 JOIN workspace_input_sources AS retained
                   ON retained.content_oid = versions.blob_oid
                 WHERE versions.workspace_id = ?1 AND versions.lang = ?2
                   AND versions.generation = ?3 AND versions.input_kind = 'configuration'
                   AND versions.valid_from <= ?4
                   AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)",
                rusqlite::params![
                    analyzer.workspace_id().as_str(),
                    snapshot.lang.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision,
                ],
                |row| row.get(0),
            )
            .expect("current Cargo manifest bytes")
        };
        let current_source_oid = |analyzer: &TreeSitterAnalyzer<RustAdapter>| -> String {
            let snapshot = analyzer.selected_workspace_snapshots()["rust"].clone();
            let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db)
                .expect("workspace database");
            conn.query_row(
                "SELECT blob_oid
                 FROM workspace_file_versions
                 WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3
                   AND input_kind = 'source' AND rel_path = 'src/lib.rs'
                   AND valid_from <= ?4
                   AND (valid_until IS NULL OR ?4 < valid_until)",
                rusqlite::params![
                    analyzer.workspace_id().as_str(),
                    snapshot.lang.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision,
                ],
                |row| row.get(0),
            )
            .expect("current Rust source identity")
        };

        let first = analyzer.selected_workspace_snapshots()["rust"].revision;
        assert_eq!(first, 1, "source and configuration publish one revision");
        assert_eq!(current_configuration(&analyzer), manifest_v1.as_bytes());
        assert_eq!(
            current_source_oid(&analyzer),
            Oid::hash_object(ObjectType::Blob, source_v1.as_bytes())
                .expect("source identity")
                .to_string()
        );
        assert_eq!(
            analyzer
                .state
                .workspace_package_identity_input_digests
                .get(&manifest)
                .map(|digest| digest.content),
            Some(brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                manifest_v1.as_bytes()
            ))
        );

        let source_v2 = "pub fn changed() {}\n";
        source.write(source_v2).expect("updated Rust source");
        let updated = analyzer.update(&BTreeSet::from([source.clone()]));
        assert_eq!(updated.selected_workspace_snapshots()["rust"].revision, 2);
        assert_eq!(current_configuration(&updated), manifest_v1.as_bytes());
        assert_eq!(
            current_source_oid(&updated),
            Oid::hash_object(ObjectType::Blob, source_v2.as_bytes())
                .expect("updated source identity")
                .to_string()
        );

        let manifest_v2 = "[package]\nname = \"sample\"\nedition = \"2024\"\n";
        manifest.write(manifest_v2).expect("updated Cargo manifest");
        let updated_again = updated.update(&BTreeSet::from([manifest.clone()]));
        assert_eq!(
            updated_again.selected_workspace_snapshots()["rust"].revision,
            3
        );
        assert_eq!(
            current_configuration(&updated_again),
            manifest_v2.as_bytes()
        );
        assert_eq!(
            current_source_oid(&updated_again),
            Oid::hash_object(ObjectType::Blob, source_v2.as_bytes())
                .expect("source identity after configuration update")
                .to_string()
        );
        assert_eq!(
            updated_again
                .state
                .workspace_package_identity_input_digests
                .get(&manifest)
                .map(|digest| digest.content),
            Some(brokk_bifrost_core::analyzer::canonical_hash::sha256_bytes(
                manifest_v2.as_bytes()
            ))
        );

        let conn =
            brokk_bifrost_core::cache_db::open_unified_connection(&db).expect("workspace database");
        let source_history: i64 = conn
            .query_row(
                "SELECT count(*)
                 FROM workspace_file_versions
                 WHERE workspace_id = ?1 AND lang = 'rust'
                   AND input_kind = 'source' AND rel_path = 'src/lib.rs'",
                [analyzer.workspace_id().as_str()],
                |row| row.get(0),
            )
            .expect("source history");
        assert_eq!(
            source_history, 2,
            "configuration update preserves source locality"
        );
    }

    #[test]
    fn rust_untracked_crlf_manifest_reopens_with_isolated_selected_semantics() {
        let manifest_a_v1 = "[package]\r\n# untracked workspace A bytes\r\nname = \"alpha\"\r\nversion = \"0.1.0\"\r\nedition = \"2021\"\r\n";
        let manifest_a_v2 = "[package]\r\n# updated untracked workspace A bytes\r\nname = \"alpha\"\r\nversion = \"0.1.0\"\r\nedition = \"2024\"\r\n";
        let manifest_b = "[package]\r\n# untracked workspace B bytes\r\nname = \"beta\"\r\nversion = \"0.1.0\"\r\nedition = \"2021\"\r\n";
        let fixture_a = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", manifest_a_v1)
            .file("src/lib.rs", "pub mod alpha_part;\n")
            .file("src/alpha_part.rs", "pub fn target() {}\n")
            .build();
        let fixture_b = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", manifest_b)
            .file("src/lib.rs", "pub mod beta_part;\n")
            .file("src/beta_part.rs", "pub fn target() {}\n")
            .build();
        let cache = tempfile::tempdir().expect("shared cache directory");
        let db = cache.path().join("rust-workspaces.db");
        let open = |project: Arc<dyn Project>| {
            let store = AnalyzerStore::open_persistent(&db).expect("persistent store");
            let mut context = store_context_from_store(project.as_ref(), store, false);
            context.build_tier_access = Arc::new(AnalyzerBuildTierAccess::new_active());
            TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                Arc::clone(&project),
                RustAdapter,
                AnalyzerConfig::default(),
                context,
                None,
            )
            .expect("Rust analyzer")
        };
        let configuration_at =
            |snapshot: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId,
             revision: i64|
             -> Vec<u8> {
                let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db)
                    .expect("workspace database");
                conn.query_row(
                    "SELECT retained.source_bytes
                     FROM workspace_file_versions AS versions
                     JOIN workspace_input_sources AS retained
                       ON retained.content_oid = versions.blob_oid
                     WHERE versions.workspace_id = ?1 AND versions.lang = ?2
                       AND versions.generation = ?3 AND versions.input_kind = 'configuration'
                       AND versions.valid_from <= ?4
                       AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)",
                    rusqlite::params![
                        snapshot.workspace_id.as_str(),
                        snapshot.lang.as_str(),
                        snapshot.generation.get(),
                        revision,
                    ],
                    |row| row.get(0),
                )
                .expect("Cargo manifest bytes at retained revision")
            };
        let configuration_history =
            |snapshot: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId| -> Vec<Vec<u8>> {
                let conn =
                    brokk_bifrost_core::cache_db::open_unified_connection(&db).expect("workspace database");
                let mut statement = conn
                    .prepare(
                        "SELECT retained.source_bytes
                         FROM workspace_file_versions AS versions
                         JOIN workspace_input_sources AS retained
                           ON retained.content_oid = versions.blob_oid
                         WHERE versions.workspace_id = ?1 AND versions.lang = ?2
                           AND versions.generation = ?3 AND versions.input_kind = 'configuration'
                         ORDER BY versions.valid_from",
                    )
                    .expect("configuration history query");
                statement
                    .query_map(
                        rusqlite::params![
                            snapshot.workspace_id.as_str(),
                            snapshot.lang.as_str(),
                            snapshot.generation.get(),
                        ],
                        |row| row.get(0),
                    )
                    .expect("configuration history rows")
                    .collect::<std::result::Result<Vec<Vec<u8>>, _>>()
                    .expect("configuration history bytes")
            };
        let source_identity =
            |snapshot: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId| -> (i64, String, String) {
                let conn =
                    brokk_bifrost_core::cache_db::open_unified_connection(&db).expect("workspace database");
                conn.query_row(
                    "SELECT versions.file_version_id, versions.blob_oid,
                            versions.projection_digest
                     FROM workspace_file_versions AS versions
                     WHERE versions.workspace_id = ?1 AND versions.lang = ?2
                       AND versions.generation = ?3 AND versions.input_kind = 'source'
                       AND versions.rel_path = 'src/lib.rs'
                       AND versions.valid_from <= ?4
                       AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)",
                    rusqlite::params![
                        snapshot.workspace_id.as_str(),
                        snapshot.lang.as_str(),
                        snapshot.generation.get(),
                        snapshot.revision,
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .expect("current Rust source identity")
            };
        let assert_definition = |analyzer: &TreeSitterAnalyzer<RustAdapter>,
                                 name: &str,
                                 expected_file: &ProjectFile| {
            let definitions = analyzer.get_definitions(name);
            assert_eq!(definitions.len(), 1, "{definitions:?}");
            let definition = definitions.first().expect("one definition");
            assert_eq!(definition.source(), expected_file);
            assert_eq!(definition.fq_name_str(), name);
        };
        let route_names = |snapshot: &brokk_bifrost_analysis::analyzer::store::WorkspaceSnapshotId| -> Vec<String> {
            let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db).expect("workspace database");
            let mut statement = conn
                .prepare(
                    "SELECT declarations.module_name
                         FROM workspace_file_versions AS versions
                         JOIN blobs
                           ON blobs.lang = versions.lang
                          AND blobs.generation = versions.generation
                          AND blobs.blob_oid = versions.blob_oid
                         JOIN source_rust_module_routes AS routes
                           ON routes.blob_id = blobs.id
                         JOIN source_rust_module_declarations AS declarations
                           ON declarations.blob_id = routes.blob_id
                          AND declarations.declaration_id = routes.declaration_id
                         WHERE versions.workspace_id = ?1 AND versions.lang = ?2
                           AND versions.generation = ?3 AND versions.input_kind = 'source'
                           AND versions.rel_path = 'src/lib.rs'
                           AND versions.valid_from <= ?4
                           AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)
                         ORDER BY routes.ordinal",
                )
                .expect("selected Rust route query");
            statement
                .query_map(
                    rusqlite::params![
                        snapshot.workspace_id.as_str(),
                        snapshot.lang.as_str(),
                        snapshot.generation.get(),
                        snapshot.revision,
                    ],
                    |row| row.get(0),
                )
                .expect("selected Rust route rows")
                .collect::<std::result::Result<Vec<String>, _>>()
                .expect("selected Rust route names")
        };

        let project_a = fixture_a.project_dyn();
        let project_b = fixture_b.project_dyn();
        let manifest_a = fixture_a.file("Cargo.toml");
        let analyzer_a = open(Arc::clone(&project_a));
        let a_initial = analyzer_a.selected_workspace_snapshots()["rust"].clone();
        assert_eq!(a_initial.revision, 1);
        assert_eq!(
            configuration_at(&a_initial, a_initial.revision),
            manifest_a_v1.as_bytes()
        );
        assert_eq!(
            configuration_history(&a_initial),
            vec![manifest_a_v1.as_bytes()]
        );
        assert_definition(
            &analyzer_a,
            "alpha.alpha_part.target",
            &fixture_a.file("src/alpha_part.rs"),
        );
        assert_eq!(route_names(&a_initial), vec!["alpha_part".to_owned()]);
        let a_source_identity = source_identity(&a_initial);
        let cold_syntax_reads = analyzer_a
            .store_context
            .build_tier_access
            .tier_access_count(InformationTier::Syntax);
        assert_eq!(cold_syntax_reads, 2);
        let cold_publications = analyzer_a
            .store_context
            .store
            .parsed_blob_transaction_starts_for_test();

        manifest_a
            .write(manifest_a_v2)
            .expect("updated Cargo manifest");
        let updated_a = analyzer_a.update(&BTreeSet::from([manifest_a.clone()]));
        let a_updated = updated_a.selected_workspace_snapshots()["rust"].clone();
        assert_eq!(a_updated.revision, a_initial.revision + 1);
        assert_eq!(
            configuration_at(&a_updated, a_initial.revision),
            manifest_a_v1.as_bytes()
        );
        assert_eq!(
            configuration_at(&a_updated, a_updated.revision),
            manifest_a_v2.as_bytes()
        );
        assert_eq!(
            configuration_history(&a_updated),
            vec![manifest_a_v1.as_bytes(), manifest_a_v2.as_bytes()]
        );
        assert_definition(
            &updated_a,
            "alpha.alpha_part.target",
            &fixture_a.file("src/alpha_part.rs"),
        );
        assert_eq!(route_names(&a_updated), vec!["alpha_part".to_owned()]);
        assert_eq!(source_identity(&a_updated), a_source_identity);
        assert_eq!(
            updated_a
                .store_context
                .build_tier_access
                .tier_access_count(InformationTier::Syntax),
            cold_syntax_reads
        );
        assert_eq!(
            updated_a
                .store_context
                .store
                .parsed_blob_transaction_starts_for_test(),
            cold_publications
        );
        assert_eq!(
            updated_a.state.persistence_stats,
            PersistBatchStats::default()
        );
        drop(updated_a);
        drop(analyzer_a);

        let analyzer_b = open(Arc::clone(&project_b));
        let b_snapshot = analyzer_b.selected_workspace_snapshots()["rust"].clone();
        assert_ne!(a_updated.workspace_id, b_snapshot.workspace_id);
        assert_eq!(b_snapshot.revision, 1);
        assert_eq!(
            configuration_at(&b_snapshot, b_snapshot.revision),
            manifest_b.as_bytes()
        );
        assert_definition(
            &analyzer_b,
            "beta.beta_part.target",
            &fixture_b.file("src/beta_part.rs"),
        );
        assert_eq!(route_names(&b_snapshot), vec!["beta_part".to_owned()]);
        assert!(
            analyzer_b
                .get_definitions("alpha.alpha_part.target")
                .is_empty()
        );
        assert_ne!(source_identity(&b_snapshot).1, a_source_identity.1);
        drop(analyzer_b);

        let reopened_a = open(project_a);
        let a_reopened = reopened_a.selected_workspace_snapshots()["rust"].clone();
        assert_eq!(a_reopened, a_updated);
        assert_eq!(
            configuration_at(&a_reopened, a_initial.revision),
            manifest_a_v1.as_bytes()
        );
        assert_eq!(
            configuration_at(&a_reopened, a_reopened.revision),
            manifest_a_v2.as_bytes()
        );
        assert_definition(
            &reopened_a,
            "alpha.alpha_part.target",
            &fixture_a.file("src/alpha_part.rs"),
        );
        assert_eq!(route_names(&a_reopened), vec!["alpha_part".to_owned()]);
        assert_eq!(source_identity(&a_reopened), a_source_identity);
        assert!(
            reopened_a
                .get_definitions("beta.beta_part.target")
                .is_empty()
        );
        assert_eq!(
            reopened_a
                .store_context
                .build_tier_access
                .tier_access_count(InformationTier::Syntax),
            0
        );
        assert_eq!(
            reopened_a.state.persistence_stats,
            PersistBatchStats::default()
        );
        assert_eq!(
            configuration_at(&b_snapshot, b_snapshot.revision),
            manifest_b.as_bytes()
        );
    }

    #[test]
    fn rust_configuration_capture_failure_keeps_old_head_and_recovers() {
        let manifest_v1 = "[package]\nname = \"sample\"\nedition = \"2021\"\n";
        let manifest_v2 = "[package]\nname = \"sample\"\nedition = \"2024\"\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", manifest_v1)
            .file("src/lib.rs", "pub fn sample() {}\n")
            .build();
        let manifest = fixture.file("Cargo.toml");
        let project = Arc::new(ConfigurationCaptureFailureProject::new(
            fixture.project().clone(),
            manifest.clone(),
        ));
        let project_dyn: Arc<dyn Project> = Arc::clone(&project) as Arc<dyn Project>;
        let db = fixture.root().join("workspace-inputs-failure.db");
        let store = AnalyzerStore::open_persistent(&db).expect("workspace store");
        let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project_dyn),
            RustAdapter,
            AnalyzerConfig::default(),
            store_context_from_store(project_dyn.as_ref(), store, false),
            None,
        )
        .expect("initial Rust analyzer");
        assert!(analyzer.workspace_package_inventory_complete());

        let current_configuration = |analyzer: &TreeSitterAnalyzer<RustAdapter>| -> Vec<u8> {
            let snapshot = analyzer.selected_workspace_snapshots()["rust"].clone();
            let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db)
                .expect("workspace database");
            conn.query_row(
                "SELECT retained.source_bytes
                 FROM workspace_file_versions AS versions
                 JOIN workspace_input_sources AS retained
                   ON retained.content_oid = versions.blob_oid
                 WHERE versions.workspace_id = ?1 AND versions.lang = ?2
                   AND versions.generation = ?3 AND versions.input_kind = 'configuration'
                   AND versions.valid_from <= ?4
                   AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)",
                rusqlite::params![
                    analyzer.workspace_id().as_str(),
                    snapshot.lang.as_str(),
                    snapshot.generation.get(),
                    snapshot.revision,
                ],
                |row| row.get(0),
            )
            .expect("current Cargo manifest bytes")
        };
        let configuration_history = |analyzer: &TreeSitterAnalyzer<RustAdapter>| -> i64 {
            let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db)
                .expect("workspace database");
            conn.query_row(
                "SELECT count(*)
                 FROM workspace_file_versions
                 WHERE workspace_id = ?1 AND lang = 'rust'
                   AND input_kind = 'configuration'",
                [analyzer.workspace_id().as_str()],
                |row| row.get(0),
            )
            .expect("configuration history")
        };

        let old_revision = analyzer.selected_workspace_snapshots()["rust"].revision;
        assert_eq!(current_configuration(&analyzer), manifest_v1.as_bytes());
        assert_eq!(configuration_history(&analyzer), 1);

        manifest.write(manifest_v2).expect("updated manifest");
        project.fail_next_capture();
        let failed = analyzer.update(&BTreeSet::from([manifest.clone()]));
        // The failed update removed the file only after the immutable listing
        // was captured, so restore it before opening the next generation.
        manifest
            .write(manifest_v2)
            .expect("restore updated manifest");

        assert!(!failed.workspace_package_inventory_complete());
        assert_eq!(
            failed.selected_workspace_snapshots()["rust"].revision,
            old_revision,
            "an incomplete configuration capture must retain the old head"
        );
        assert_eq!(current_configuration(&failed), manifest_v1.as_bytes());
        assert_eq!(
            configuration_history(&failed),
            1,
            "the failed generation must not publish a configuration revision"
        );
        let scope = AnalyzerQueryScope::new(&failed);
        let error = scope
            .store_error()
            .expect("the build failure must reach the query boundary");
        assert!(
            error.to_string().contains("Cargo.toml"),
            "capture failure must name the missing manifest: {error}"
        );
        drop(scope);

        let recovered = failed.update(&BTreeSet::from([manifest]));
        assert!(recovered.workspace_package_inventory_complete());
        assert_eq!(
            recovered.selected_workspace_snapshots()["rust"].revision,
            old_revision + 1
        );
        assert_eq!(current_configuration(&recovered), manifest_v2.as_bytes());
        assert_eq!(configuration_history(&recovered), 2);
        let scope = AnalyzerQueryScope::new(&recovered);
        assert!(
            scope.store_error().is_none(),
            "a successful rebuild clears the retained construction error"
        );
    }

    fn native_configuration_lifecycle<A: LanguageAdapter + Clone>(
        adapter: A,
        source_path: &str,
        source: &str,
        config_path: &str,
    ) {
        let fixture = crate::inline_project::InlineTestProject::with_language(adapter.language())
            .file(source_path, source)
            .file(config_path, "first\r\n")
            .file(".gitignore", ".bifrost/\nvendor/\n")
            .build();
        let project = fixture.project_dyn();
        let db = fixture.root().join("selected-config.db");
        let open = || {
            TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                Arc::clone(&project),
                adapter.clone(),
                AnalyzerConfig::default(),
                store_context_from_store(
                    project.as_ref(),
                    AnalyzerStore::open_persistent(&db).unwrap(),
                    false,
                ),
                None,
            )
            .unwrap()
        };
        let first = open();
        let initial = first
            .selected_workspace_snapshots()
            .values()
            .next()
            .unwrap()
            .clone();
        let first_key = first.language_content_identity();
        let config = fixture.file(config_path);
        config.write("second\n").unwrap();
        let second = first.update(&BTreeSet::from([config.clone()]));
        let next = second
            .selected_workspace_snapshots()
            .values()
            .next()
            .unwrap()
            .clone();
        assert_eq!(next.revision, initial.revision + 1);
        assert_ne!(second.language_content_identity(), first_key);
        let reopened = open();
        assert_eq!(
            second.language_content_identity(),
            reopened.language_content_identity()
        );
        assert_eq!(
            reopened
                .selected_workspace_snapshots()
                .values()
                .next()
                .unwrap(),
            &next
        );
        let conn = brokk_bifrost_core::cache_db::open_unified_connection(&db).unwrap();
        let source_versions: i64 = conn.query_row(
            "SELECT count(*) FROM workspace_file_versions WHERE workspace_id = ?1 AND lang = ?2 AND input_kind = 'source'",
            rusqlite::params![initial.workspace_id.as_str(), initial.lang], |row| row.get(0),
        ).unwrap();
        assert_eq!(
            source_versions, 1,
            "configuration edits must not republish source"
        );
        for (revision, expected) in [(initial.revision, "first\r\n"), (next.revision, "second\n")] {
            let bytes: Vec<u8> = conn.query_row(
                "SELECT retained.source_bytes FROM workspace_file_versions AS versions
                 JOIN workspace_input_sources AS retained ON retained.content_oid = versions.blob_oid
                 WHERE versions.workspace_id = ?1 AND versions.lang = ?2 AND versions.rel_path = ?3
                   AND versions.input_kind = 'configuration' AND versions.valid_from <= ?4
                   AND (versions.valid_until IS NULL OR ?4 < versions.valid_until)",
                rusqlite::params![initial.workspace_id.as_str(), initial.lang, config_path, revision], |row| row.get(0),
            ).unwrap();
            assert_eq!(bytes, expected.as_bytes());
        }
        let overlay = Arc::new(OverlayProject::new(Arc::clone(&project)));
        assert!(overlay.set(config.abs_path(), "second\n".into()));
        let unchanged = second.clone_with_project(Arc::new(overlay.snapshot()));
        assert_eq!(
            unchanged
                .store_context
                .store
                .native_configuration_overlay_mismatch(
                    unchanged.project.as_ref(),
                    &unchanged.selected_workspace_snapshots(),
                    &initial.lang,
                    adapter.language(),
                    &brokk_bifrost_core::cancellation::CancellationToken::new()
                )
                .unwrap(),
            brokk_bifrost_analysis::analyzer::store::workspace_inputs::NativeConfigurationOverlayAuthority::Current
        );
        assert!(overlay.set(config.abs_path(), "unsaved\n".into()));
        let request = second.clone_with_project(Arc::new(overlay.snapshot()));
        assert_eq!(
            request
                .store_context
                .store
                .native_configuration_overlay_mismatch(
                    request.project.as_ref(),
                    &request.selected_workspace_snapshots(),
                    &initial.lang,
                    adapter.language(),
                    &brokk_bifrost_core::cancellation::CancellationToken::new()
                )
                .unwrap(),
            brokk_bifrost_analysis::analyzer::store::workspace_inputs::NativeConfigurationOverlayAuthority::Mismatch(
                config_path.into()
            )
        );
        assert_ne!(
            request.language_content_identity(),
            second.language_content_identity()
        );
        let captured = TreeSitterAnalyzer::<A>::workspace_configuration_inputs(
            overlay.as_ref(),
            &adapter,
            None,
        )
        .unwrap();
        assert_eq!(
            captured
                .iter()
                .find(|input| input.relative_path() == config_path)
                .unwrap()
                .source_bytes(),
            b"second\n"
        );
        let extra = fixture.file(if adapter.language() == Language::Go {
            "extra/go.sum"
        } else {
            "extra/gradle.properties"
        });
        assert!(overlay.set(extra.abs_path(), "only in editor\n".into()));
        let captured = TreeSitterAnalyzer::<A>::workspace_configuration_inputs(
            overlay.as_ref(),
            &adapter,
            None,
        )
        .unwrap();
        assert_eq!(captured.len(), 1);
        let overlay_only = Arc::new(OverlayProject::new(Arc::clone(&project)));
        assert!(overlay_only.set(extra.abs_path(), "only in editor\n".into()));
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        assert_eq!(
            second
                .store_context
                .store
                .native_configuration_overlay_mismatch(
                    overlay_only.as_ref(),
                    &second.selected_workspace_snapshots(),
                    &initial.lang,
                    adapter.language(),
                    &cancellation,
                )
                .unwrap(),
            brokk_bifrost_analysis::analyzer::store::workspace_inputs::NativeConfigurationOverlayAuthority::Mismatch(
                brokk_bifrost_core::path_utils::rel_path_string(&extra)
            )
        );
        cancellation.cancel();
        assert_eq!(
            second
                .store_context
                .store
                .native_configuration_overlay_mismatch(
                    overlay_only.as_ref(),
                    &second.selected_workspace_snapshots(),
                    &initial.lang,
                    adapter.language(),
                    &cancellation,
                )
                .unwrap(),
            brokk_bifrost_analysis::analyzer::store::workspace_inputs::NativeConfigurationOverlayAuthority::Cancelled
        );
        let source_file = fixture.file(source_path);
        source_file.write(format!("{source}\n")).unwrap();
        let source_updated = second.update(&BTreeSet::from([source_file]));
        assert_eq!(
            source_updated
                .selected_workspace_snapshots()
                .values()
                .next()
                .unwrap()
                .revision,
            next.revision + 1
        );
        assert_ne!(
            source_updated.language_content_identity(),
            second.language_content_identity()
        );
    }

    #[test]
    fn java_native_configuration_lifecycle() {
        native_configuration_lifecycle(
            JavaAdapter,
            "Sample.java",
            "class Sample {}",
            "gradle.properties",
        );
    }

    #[test]
    fn jvm_toolchain_native_configuration_lifecycle() {
        native_configuration_lifecycle(
            JavaAdapter,
            "Sample.java",
            "class Sample {}",
            ".bifrost/jvm-toolchains.json",
        );
    }

    #[test]
    fn go_native_configuration_lifecycle() {
        native_configuration_lifecycle(
            GoAdapter,
            "sample.go",
            "package sample\ntype Item struct{}",
            "go.sum",
        );
    }

    #[test]
    fn rust_workspace_configuration_capture_uses_disk_and_keeps_overlay_only_paths_transient() {
        let disk_manifest = "[package]\nname = \"sample\"\nedition = \"2021\"\n";
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("Cargo.toml", disk_manifest)
            .file("src/lib.rs", "pub fn sample() {}\n")
            .build();
        let base = fixture.project_dyn();
        let overlay = Arc::new(OverlayProject::new(base));
        let manifest = fixture.file("Cargo.toml");
        assert!(overlay.set(
            manifest.abs_path(),
            "[package]\nname = \"overlay\"\nedition = \"2024\"\n".to_owned()
        ));

        let snapshot = WorkspaceBuildSnapshot::capture(overlay.as_ref(), None, &[Language::Rust])
            .expect("workspace snapshot");
        let captured = TreeSitterAnalyzer::<RustAdapter>::workspace_configuration_inputs(
            overlay.as_ref(),
            &RustAdapter,
            Some(snapshot.as_ref()),
        )
        .expect("disk configuration capture");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].relative_path(), "Cargo.toml");
        assert_eq!(captured[0].source_bytes(), disk_manifest.as_bytes());

        let overlay_only = fixture.file("generated/Cargo.toml");
        assert!(overlay.set(
            overlay_only.abs_path(),
            "[package]\nname = \"generated\"\n".to_owned()
        ));
        let snapshot = WorkspaceBuildSnapshot::capture(overlay.as_ref(), None, &[Language::Rust])
            .expect("workspace snapshot with overlay-only path");
        let captured = TreeSitterAnalyzer::<RustAdapter>::workspace_configuration_inputs(
            overlay.as_ref(),
            &RustAdapter,
            Some(snapshot.as_ref()),
        )
        .expect("overlay-only configuration is transient");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].relative_path(), "Cargo.toml");
        assert_eq!(captured[0].source_bytes(), disk_manifest.as_bytes());
    }

    #[test]
    fn prepared_syntax_refreshes_after_outer_scope_and_overlay_change() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        file.write("fn disk() {}\n").expect("rust source");
        let project = Arc::new(CountingOverlayProject::new(&root, "fn first() {}\n"));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);

        let first = {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            let prepared = analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("first syntax");
            assert_eq!(prepared.source(), "fn first() {}\n");
            assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
            prepared
        };

        project.set_source("fn second() { first(); }\n");
        let scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let second = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("updated syntax");

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.source(), "fn second() { first(); }\n");
        // Two revisions, one parse each: the counter totals every parse of the
        // file rather than bucketing by source identity, so "no revision was
        // parsed twice" reads as one parse per revision.
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 2);
        assert_ne!(
            first.tree().root_node().to_sexp(),
            second.tree().root_node().to_sexp()
        );
    }

    #[test]
    fn cancelled_cold_overlay_syntax_does_not_hydrate_or_initialize_cache() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn disk() {}\n").expect("rust source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&overlay) as Arc<dyn Project>, RustAdapter);
        let source = (0..20_000)
            .map(|index| format!("fn target_{index}() {{}}\n"))
            .collect::<String>();
        assert!(overlay.set(file.abs_path(), source.clone()));
        analyzer.reset_full_hydration_count_for_test();
        let scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let cancellation = CancellationToken::cancel_after_checks_for_test(6);

        assert!(matches!(
            analyzer.prepared_syntax_limited_cancellable(
                scope.token(),
                &file,
                source.len(),
                Some(&cancellation)
            ),
            PreparedSyntaxLimitedOutcome::Cancelled
        ));
        assert_eq!(
            analyzer.prepared_syntax_parse_count_for_test(&file),
            1,
            "the cancellation should interrupt an admitted parse attempt"
        );
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "bounded cancellation must not hydrate or analyze the cold overlay revision"
        );

        let prepared =
            analyzer.prepared_syntax_limited_cancellable(scope.token(), &file, source.len(), None);
        let PreparedSyntaxLimitedOutcome::Available(_, prepared) = prepared else {
            panic!("a later uncancelled request must retry instead of reading cached failure");
        };
        assert_eq!(prepared.source(), source);
        assert_eq!(prepared.origin(), PreparedSourceOrigin::Overlay);
        assert!(prepared.overlay_revision().is_some());
        assert!(matches!(prepared.backing(), PreparedSyntaxSource::Exact(_)));
        assert_eq!(
            analyzer.prepared_syntax_parse_count_for_test(&file),
            2,
            "cancelled preparation must not initialize the syntax cache"
        );
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            0,
            "successful bounded preparation must remain syntax-only"
        );

        let indexed = analyzer
            .prepared_syntax(scope.token(), &file)
            .expect("ordinary preparation should remain indexed");
        assert_eq!(indexed.source(), source);
        assert_eq!(indexed.origin(), prepared.origin());
        assert_eq!(indexed.overlay_revision(), prepared.overlay_revision());
        assert!(matches!(
            indexed.backing(),
            PreparedSyntaxSource::Indexed(_)
        ));
        assert_eq!(
            analyzer.full_hydration_count_for_test(),
            1,
            "ordinary preparation must still hydrate indexed declarations"
        );
        assert_eq!(
            analyzer.prepared_syntax_parse_count_for_test(&file),
            2,
            "indexed preparation must reuse the successful syntax-only parse"
        );
    }

    #[test]
    fn prepared_syntax_cache_identity_distinguishes_repeated_overlay_content() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        file.write("fn disk() {}\n").expect("rust source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let overlay = Arc::new(OverlayProject::new(base));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&overlay) as Arc<dyn Project>, RustAdapter);
        let repeated_source = "fn repeated() {}\n";

        assert!(overlay.set(file.abs_path(), repeated_source.to_owned()));
        let first = {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("first overlay")
        };
        assert!(overlay.set(file.abs_path(), "fn middle() {}\n".to_owned()));
        let middle = {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("middle overlay")
        };
        assert!(overlay.set(file.abs_path(), repeated_source.to_owned()));
        let repeated = {
            let scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            analyzer
                .prepared_syntax(scope.token(), &file)
                .expect("repeated overlay")
        };

        assert_eq!(first.source(), repeated.source());
        assert_eq!(first.origin(), PreparedSourceOrigin::Overlay);
        assert_eq!(middle.origin(), PreparedSourceOrigin::Overlay);
        assert_eq!(repeated.origin(), PreparedSourceOrigin::Overlay);
        let first_revision = first.overlay_revision().expect("first overlay revision");
        let middle_revision = middle.overlay_revision().expect("middle overlay revision");
        let repeated_revision = repeated
            .overlay_revision()
            .expect("repeated overlay revision");
        assert!(first_revision < middle_revision);
        assert!(middle_revision < repeated_revision);
        assert_ne!(first_revision, repeated_revision);
        assert!(!Arc::ptr_eq(&first, &repeated));
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#746: repeated overlay queries rehashed the same source and failed to refresh after the outer request"
    )]
    #[test]
    fn query_read_cache_hashes_overlay_once_and_refreshes_after_outer_scope() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        let source = "pub struct Example;\nimpl Example { pub fn value(&self) -> usize { 1 } }\n";
        file.write(source).expect("rust source");
        let project = Arc::new(CountingOverlayProject::new(root, source));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);
        project.reset_reads();

        let outer_scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let first_oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("first overlay oid");
        assert_eq!(
            project.read_count(),
            1,
            "the first OID lookup reads the overlay"
        );
        assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(first_oid));
        assert_eq!(
            project.read_count(),
            1,
            "repeated OID lookup must use the query cache"
        );

        let declarations = analyzer.declarations(&file);
        let reads_after_hydration = project.read_count();
        for declaration in declarations {
            assert!(!analyzer.ranges(&declaration).is_empty());
        }
        assert_eq!(
            project.read_count(),
            reads_after_hydration,
            "range traversal must not reread the overlay"
        );

        {
            let _inner_scope =
                brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
            assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(first_oid));
            assert_eq!(
                project.read_count(),
                reads_after_hydration,
                "nested scopes must reuse the outer cache"
            );
        }
        assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(first_oid));
        assert_eq!(
            project.read_count(),
            reads_after_hydration,
            "dropping the inner scope must retain the cache"
        );
        drop(outer_scope);

        project.set_source(format!("{source}\n"));
        let _next_scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let next_oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("updated overlay oid");
        assert_ne!(
            next_oid, first_oid,
            "the next query must observe changed overlay text"
        );
        assert_eq!(
            project.read_count(),
            reads_after_hydration + 1,
            "the next query should read the overlay once"
        );
    }

    #[test]
    fn legacy_source_identity_survives_primary_publication_and_reopen() {
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("Legacy.java", "class Legacy {}\n")
            .build();
        let file = fixture.file("Legacy.java");
        let raw = b"// legacy \x97 comment\nclass Legacy {}\n";
        std::fs::write(file.abs_path(), raw).expect("legacy source bytes");
        let oid = Oid::hash_object(ObjectType::Blob, raw).expect("raw source identity");
        let decoded = brokk_bifrost_core::analyzer::project::decode_source_bytes(raw.to_vec())
            .expect("decoded parser source");
        assert_ne!(
            Oid::hash_object(ObjectType::Blob, decoded.as_bytes()).unwrap(),
            oid
        );
        let db = fixture.root().join("legacy-source.db");
        for _ in 0..2 {
            let project: Arc<dyn Project> =
                Arc::new(TestProject::new(fixture.root(), Language::Java));
            let store = AnalyzerStore::open_persistent(&db).expect("persistent store");
            let context = store_context_from_store(project.as_ref(), store, false);
            let analyzer = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                project,
                JavaAdapter,
                AnalyzerConfig::default(),
                context,
                None,
            )
            .expect("legacy primary publication");
            assert!(
                analyzer
                    .get_all_declarations()
                    .iter()
                    .any(|unit| unit.short_name() == "Legacy")
            );
            assert_eq!(analyzer.resolve_live_oid_for_file(&file), Some(oid));
            assert_eq!(
                analyzer.source_for_oid(&file, oid).as_deref(),
                Some(decoded.as_str())
            );
            assert!(analyzer.indexed_source_matches(&file, &decoded));
            assert_eq!(
                analyzer
                    .structural_snapshot_key(&file, &decoded)
                    .unwrap()
                    .oid,
                oid
            );
            let (prepared_oid, snapshot) = analyzer
                .source_snapshot_limited(&file, usize::MAX)
                .expect("prepared source")
                .expect("source snapshot");
            assert_eq!(prepared_oid, oid);
            assert_eq!(snapshot.source(), decoded);
            assert!(
                analyzer
                    .store_context
                    .store
                    .contains_blob(oid, "java")
                    .expect("published blob")
            );
        }
    }

    #[test]
    fn content_oid_memo_does_not_alias_distinct_raw_snapshots_with_same_decoded_text() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/Legacy.java");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        let raw_first = b"class Legacy { /* invalid byte: \x80 */ }\n";
        let raw_second = b"class Legacy { /* invalid byte: \x81 */ }\n";
        std::fs::write(file.abs_path(), raw_first).expect("first raw source");
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        let decoded_first =
            brokk_bifrost_core::analyzer::project::decode_source_bytes(raw_first.to_vec())
                .expect("first decoded source");
        let decoded_second =
            brokk_bifrost_core::analyzer::project::decode_source_bytes(raw_second.to_vec())
                .expect("second decoded source");
        assert_eq!(decoded_first, decoded_second);
        let first_oid = Oid::hash_object(ObjectType::Blob, raw_first).expect("first raw oid");
        let second_oid = Oid::hash_object(ObjectType::Blob, raw_second).expect("second raw oid");
        assert_ne!(first_oid, second_oid);

        analyzer.reset_blob_hash_count_for_test();
        assert_eq!(
            analyzer.content_oid_of(&file, &decoded_first),
            Some(first_oid)
        );
        std::fs::write(file.abs_path(), raw_second).expect("second raw source");
        assert_eq!(
            analyzer.content_oid_of(&file, &decoded_second),
            Some(second_oid)
        );
        assert_eq!(
            analyzer.blob_hash_count_for_test(),
            1,
            "the shared memo hashes the decoded text once while raw identity is selected per snapshot"
        );
    }

    #[test]
    fn live_blob_persistence_rejects_source_changed_between_identity_and_parse() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        let old_source = "pub fn old_name() { old_name(); }\n";
        let new_source = "pub fn new_name() { new_name(); }\n";
        file.write(old_source).expect("Rust source");

        let project = Arc::new(CountingOverlayProject::new(&root, old_source));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);
        let store = Arc::clone(&analyzer.store_context.store);
        let old_oid =
            Oid::hash_object(ObjectType::Blob, old_source.as_bytes()).expect("old source OID");
        let generation = analyzer.store_context.generations["rust"];
        let initial = store
            .rust_usage_facts(old_oid, "rust")
            .expect("initial Rust usage facts");
        assert!(
            initial
                .identifier_occurrences
                .iter()
                .any(|occurrence| occurrence.identifier == "old_name"),
            "the old publication must contain the old identifier"
        );

        project.arm_source_swap(new_source);
        analyzer.persist_live_blobs(std::slice::from_ref(&file));

        let after_changed_parse = store
            .rust_usage_facts(old_oid, "rust")
            .expect("old Rust usage facts remain readable");
        assert_eq!(
            after_changed_parse, initial,
            "a changed parse must not replace the old OID's publication"
        );
        assert!(
            !after_changed_parse
                .identifier_occurrences
                .iter()
                .any(|occurrence| occurrence.identifier == "new_name")
        );

        store.delete_rust_facts_for_test("rust");
        project.arm_source_swap(new_source);
        analyzer.persist_live_blobs(std::slice::from_ref(&file));
        assert!(
            store
                .blobs_with_rust_facts("rust", generation, &[old_oid])
                .expect("probe missing old publication")
                .is_empty(),
            "a changed parse must not manufacture a missing old publication"
        );
    }

    #[test]
    fn live_blob_persistence_accepts_a_current_mount_added_after_indexing() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let indexed_file = temp_file(&root, "src/main.rs");
        let source = "pub fn live_declaration() { live_declaration(); }\n";
        indexed_file.write(source).expect("indexed Rust source");

        let project = Arc::new(CountingOverlayProject::new(&root, source));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&project) as Arc<dyn Project>, RustAdapter);
        let store = Arc::clone(&analyzer.store_context.store);
        let generation = analyzer.store_context.generations["rust"];
        let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("source OID");
        let late_file = ProjectFile::new(root, "src/late.rs");
        analyzer
            .store_context
            .live_paths
            .refresh([LivePathEntry::overlay(late_file.clone(), oid)]);

        assert!(
            analyzer
                .indexed_live_snapshot
                .oid_for_path(&late_file)
                .is_none()
        );
        assert_eq!(analyzer.live_snapshot().oid_for_path(&late_file), Some(oid));
        store.delete_rust_facts_for_test("rust");
        assert!(
            store
                .blobs_with_rust_facts("rust", generation, &[oid])
                .expect("probe removed publication")
                .is_empty()
        );

        analyzer.persist_live_blobs(std::slice::from_ref(&late_file));

        assert!(
            store
                .blobs_with_rust_facts("rust", generation, &[oid])
                .expect("probe restored publication")
                .contains(&oid)
        );
    }

    #[test]
    fn warm_rebuild_uses_bulk_presence_without_redundant_point_contains_queries() {
        const UNIQUE_FILES: usize = 10;
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        for index in 0..UNIQUE_FILES {
            let file = ProjectFile::new(root.clone(), format!("pkg{index}/type{index}.py"));
            file.write(format!("class Type{index}:\n    pass\n"))
                .unwrap();
        }
        let shared_source = "class Shared:\n    pass\n";
        for path in ["dup_a/shared.py", "dup_b/shared.py"] {
            ProjectFile::new(root.clone(), path)
                .write(shared_source)
                .unwrap();
        }
        for path in ["broken_a/binary.py", "broken_b/binary.py"] {
            ProjectFile::new(root.clone(), path)
                .write("\0not parseable source")
                .unwrap();
        }
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Python));
        let store = Arc::new(
            AnalyzerStore::open_persistent(&temp.path().join("analyzer.db"))
                .expect("persistent analyzer store"),
        );
        let store_context = AnalyzerStoreContext {
            store: Arc::clone(&store),
            workspace_id: brokk_bifrost_analysis::analyzer::store::WorkspaceId::for_root(
                project.root(),
            ),
            _projection_lease: None,
            gc: Arc::new(
                brokk_bifrost_analysis::analyzer::store::gc::AnalyzerGcCoordinator::default(),
            ),
            liveness: None,
            workspace_snapshot: None,
            workspace_listing_complete: true,
            revision_blobs: None,
            live_paths: Arc::new(LivePathMap::default()),
            generations: Arc::new(HashMap::default()),
            build_abort: Arc::new(BuildAbort::default()),
            build_tier_access: Arc::new(AnalyzerBuildTierAccess::default()),
            structural_facts: Arc::new(OnceLock::new()),
            cancellation: brokk_bifrost_core::cancellation::CancellationToken::default(),
        };
        let config = AnalyzerConfig::default();

        let _cold = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            PythonAdapter::default(),
            config.clone(),
            store_context.clone(),
            None,
        )
        .expect("analyzer epochs should initialize");
        store.reset_parsed_blob_point_contains_queries_for_test();
        let warm_parse_count = Arc::new(AtomicUsize::new(0));
        let warm_progress_count = Arc::clone(&warm_parse_count);
        let warm = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            Arc::clone(&project),
            PythonAdapter::default(),
            config.clone(),
            store_context.clone(),
            Some(Arc::new(move |event| {
                if event.phase == BuildProgressPhase::Parse {
                    warm_progress_count.fetch_add(1, Ordering::Relaxed);
                }
            })),
        )
        .expect("analyzer epochs should initialize");
        let warm_point_queries = store.parsed_blob_point_contains_queries_for_test();
        assert_eq!(warm.get_definitions("dup_a.shared.Shared").len(), 1);
        assert_eq!(warm.get_definitions("dup_b.shared.Shared").len(), 1);

        let shared_oid = Oid::hash_object(ObjectType::Blob, shared_source.as_bytes()).unwrap();
        store.mark_parsed_blob_incomplete_for_test(shared_oid, "python");
        store.reset_parsed_blob_point_contains_queries_for_test();
        let parse_count = Arc::new(AtomicUsize::new(0));
        let progress_count = Arc::clone(&parse_count);
        let recovered = TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
            project,
            PythonAdapter::default(),
            config,
            store_context,
            Some(Arc::new(move |event| {
                if event.phase == BuildProgressPhase::Parse {
                    progress_count.fetch_add(1, Ordering::Relaxed);
                }
            })),
        )
        .expect("analyzer epochs should initialize");
        let recovery_point_queries = store.parsed_blob_point_contains_queries_for_test();

        assert_eq!(
            warm_parse_count.load(Ordering::Relaxed),
            1,
            "one unparseable representative should cover both duplicate paths"
        );
        assert_eq!(
            parse_count.load(Ordering::Relaxed),
            2,
            "rebuild should parse one corrupt representative and retry the unparseable key once"
        );
        assert_eq!(recovered.get_definitions("dup_a.shared.Shared").len(), 1);
        assert_eq!(recovered.get_definitions("dup_b.shared.Shared").len(), 1);
        assert_eq!(
            (warm_point_queries, recovery_point_queries),
            (0, 0),
            "the authoritative bulk missing set should avoid per-file contains checks on warm and one-corrupt-key rebuilds"
        );
    }

    /// #2917: the memoized blob identity is the answer `git hash-object` gives
    /// for the bytes in hand -- for the indexed disk source, for a dirty
    /// rewrite of the same file, and for an unsaved overlay -- and a repeat
    /// question about unchanged bytes does not run SHA-1 again.
    /// A location lookup asks for a file's current state once per declaration.
    /// Within one request the file's text is read, copied and hashed once, not
    /// once per declaration: on tract's 850 KB generated file the per-ask copy
    /// and hash cost about 0.2 s per point, and about 1.3 s more when the
    /// allocator returned each copy's pages to the kernel.
    #[brokk_bifrost_test_macros::hardwon(
        "#2917: one request reread and rehashed the same file content"
    )]
    #[test]
    fn a_request_reads_and_hashes_a_files_current_text_once() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/lib.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        let source = (0..20)
            .map(|index| format!("pub fn f{index}() {{}}\n"))
            .collect::<String>();
        file.write(&source).expect("source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(Arc::clone(&base), RustAdapter);
        let units = analyzer.location_declarations(&file);
        assert_eq!(units.len(), 20, "{units:?}");

        let scope = AnalyzerQueryScope::new(&analyzer);
        analyzer.blob_oids.text_hashes.store(0, Ordering::Relaxed);
        for unit in &units {
            assert!(!analyzer.location_ranges(unit).is_empty(), "{unit:?}");
        }
        assert_eq!(analyzer.blob_oids.text_hashes.load(Ordering::Relaxed), 1);
        drop(scope);
    }

    #[test]
    fn content_oid_of_matches_git_hash_object_and_hashes_each_source_once() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        let disk_source = "fn disk() {}\n";
        file.write(disk_source).expect("disk source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(Arc::clone(&base), RustAdapter);
        let expected =
            |source: &str| Oid::hash_object(ObjectType::Blob, source.as_bytes()).expect("blob oid");

        analyzer.reset_blob_hash_count_for_test();
        assert_eq!(
            analyzer.content_oid_of(&file, disk_source),
            Some(expected(disk_source))
        );
        assert_eq!(analyzer.blob_hash_count_for_test(), 1);
        let reread = base.read_source(&file).expect("disk read");
        assert_eq!(
            analyzer.content_oid_of(&file, &reread),
            Some(expected(disk_source))
        );
        assert_eq!(
            analyzer.blob_hash_count_for_test(),
            1,
            "the same bytes from a fresh read must be recognized without SHA-1"
        );

        let dirty_source = "fn disk() {}\nfn dirty() {}\n";
        file.write(dirty_source).expect("dirty source");
        assert_eq!(
            analyzer.content_oid_of(&file, dirty_source),
            Some(expected(dirty_source))
        );
        assert_eq!(
            analyzer.blob_hash_count_for_test(),
            2,
            "a dirty rewrite must miss the memo and get its own identity"
        );
        assert_eq!(
            analyzer.content_oid_of(&file, dirty_source),
            Some(expected(dirty_source))
        );
        assert_eq!(analyzer.blob_hash_count_for_test(), 2);

        let overlay_source = "fn unsaved() {}\n";
        let overlay = Arc::new(OverlayProject::new(Arc::clone(&base)));
        assert!(overlay.set(file.abs_path(), overlay_source.to_owned()));
        let frozen: Arc<dyn Project> = Arc::new(overlay.snapshot());
        let request = analyzer.clone_with_project(frozen);
        assert_eq!(
            request.resolve_live_oid_for_file(&file),
            Some(expected(overlay_source)),
            "an overlay's live identity is the hash of its unsaved bytes"
        );
        assert_eq!(
            request.content_oid_of(&file, overlay_source),
            Some(expected(overlay_source))
        );
        assert_eq!(
            analyzer.blob_hash_count_for_test(),
            3,
            "the overlay is hashed once, through the memo the request clone shares"
        );
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#746: a cloned analyzer with a new project reused the sibling project's cached source identity"
    )]
    #[test]
    fn clone_with_project_has_an_independent_query_read_cache() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        file.write("fn disk() {}\n").expect("rust source");

        let live_project = Arc::new(CountingOverlayProject::new(&root, "fn live() {}\n"));
        let analyzer =
            TreeSitterAnalyzer::new(Arc::clone(&live_project) as Arc<dyn Project>, RustAdapter);
        live_project.reset_reads();
        let _live_scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&analyzer);
        let live_oid = analyzer
            .resolve_live_oid_for_file(&file)
            .expect("live overlay oid");

        let snapshot_project = Arc::new(CountingOverlayProject::new(
            &root,
            "fn frozen_snapshot() {}\n",
        ));
        let snapshot =
            analyzer.clone_with_project(Arc::clone(&snapshot_project) as Arc<dyn Project>);
        snapshot_project.reset_reads();
        let _snapshot_scope =
            brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::new(&snapshot);
        let snapshot_oid = snapshot
            .resolve_live_oid_for_file(&file)
            .expect("snapshot overlay oid");

        assert_ne!(
            snapshot_oid, live_oid,
            "project snapshots must not share live OIDs"
        );
        assert_eq!(
            snapshot_project.read_count(),
            1,
            "snapshot should read its own overlay"
        );
    }

    #[test]
    fn clone_with_project_isolates_transient_live_paths_from_disk_and_siblings() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = temp_file(&root, "src/main.rs");
        std::fs::create_dir_all(file.abs_path().parent().expect("source parent"))
            .expect("source directory");
        let disk_source = "fn disk() {}\n";
        let overlay_source = "fn unsaved() { disk(); }\n";
        file.write(disk_source).expect("disk source");
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Rust));
        let disk = TreeSitterAnalyzer::new(Arc::clone(&base), RustAdapter);
        let sibling = disk.clone_with_project(Arc::clone(&base));
        let disk_oid = Oid::hash_object(ObjectType::Blob, disk_source.as_bytes()).unwrap();
        let overlay_oid = Oid::hash_object(ObjectType::Blob, overlay_source.as_bytes()).unwrap();

        let live_overlay = Arc::new(OverlayProject::new(Arc::clone(&base)));
        assert!(live_overlay.set(file.abs_path(), overlay_source.to_owned()));
        let frozen_overlay: Arc<dyn Project> = Arc::new(live_overlay.snapshot());
        let request = disk.clone_with_project(frozen_overlay);
        let state = request
            .fetch_file_state(&file)
            .expect("parse the transient overlay revision");
        assert_eq!(state.source, overlay_source);
        assert_eq!(request.resolve_live_oid_for_file(&file), Some(overlay_oid));

        assert_eq!(disk.resolve_live_oid_for_file(&file), Some(disk_oid));
        assert_eq!(sibling.resolve_live_oid_for_file(&file), Some(disk_oid));
        assert_eq!(disk.file_source(&file).as_deref(), Some(disk_source));
        assert_eq!(sibling.file_source(&file).as_deref(), Some(disk_source));

        assert!(live_overlay.clear(&file.abs_path()));
        let cleared_project: Arc<dyn Project> = Arc::new(live_overlay.snapshot());
        let cleared = disk.clone_with_project(cleared_project);
        assert_eq!(cleared.resolve_live_oid_for_file(&file), Some(disk_oid));
        assert_eq!(cleared.file_source(&file).as_deref(), Some(disk_source));
        assert_eq!(request.file_source(&file).as_deref(), Some(overlay_source));
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#2913: file summaries bypassed the persisted projection and hydrated full declarations"
    )]
    #[test]
    fn file_summary_uses_persisted_projection_without_full_hydration() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/demo/Example.java");
        file.write(
            "package demo; public class Example { public String name; public void run() {} }\n",
        )
        .expect("java source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = JavaAnalyzer::new(project);
        analyzer.inner().reset_full_hydration_count_for_test();

        let first_projection = analyzer
            .summary_file_projection(&file)
            .expect("persisted summary projection");
        let second_projection = analyzer
            .summary_file_projection(&file)
            .expect("cached summary projection");
        assert!(Arc::ptr_eq(&first_projection, &second_projection));

        let result = crate::searchtools::summarize_files(&analyzer, vec![file]);

        assert_eq!(result.summaries.len(), 1);
        assert!(
            result.summaries[0]
                .elements
                .iter()
                .any(|element| element.symbol.contains("Example.run")),
            "persisted projection should render method summaries"
        );
        assert_eq!(analyzer.inner().full_hydration_count_for_test(), 0);
    }

    #[brokk_bifrost_test_macros::hardwon(
        "c9dec2d64a1e: requesting a Java summary for a Rust-owned file panicked on a missing projection"
    )]
    #[test]
    fn file_summary_refuses_files_owned_by_another_language_analyzer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let foreign_file = ProjectFile::new(root.clone(), "src/lib.rs");
        foreign_file
            .write("pub fn foreign() {}\n")
            .expect("rust source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = JavaAnalyzer::new(project);

        assert!(analyzer.summary_file_projection(&foreign_file).is_none());
    }

    /// #2913: the import tier obeys the same refusal every other per-file store
    /// read here does. `ImportAnalysisProvider` fan-outs legitimately ask every
    /// provider about an arbitrary file, and a foreign file's storage key has
    /// no entry in this analyzer's own generation map, so hydrating it recorded
    /// `missing captured analyzer generation for <lang>` on the request context
    /// -- which ends the whole tool call, after the work it was asked for
    /// already succeeded.
    #[brokk_bifrost_test_macros::hardwon(
        "#2913: a mixed C++ scan tried to hydrate Java imports without the captured Java generation"
    )]
    #[test]
    fn import_hydration_refuses_files_owned_by_another_language_analyzer() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        std::fs::write(
            root.join("Demo.java"),
            "package demo;\n\nimport java.util.List;\n\nclass Demo {}\n",
        )
        .unwrap();
        std::fs::write(root.join("demo.rs"), "use std::fmt;\n\npub fn work() {}\n").unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);
        let own_file = ProjectFile::new(root.clone(), "Demo.java");
        let foreign_file = ProjectFile::new(root, "demo.rs");

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();

        assert!(
            analyzer.resolve_live_oid_for_file(&foreign_file).is_some(),
            "the shared live-path map must reach the foreign file, or the read \
             this pins would never be attempted and the test would pass vacuously"
        );
        assert_eq!(
            1,
            analyzer.import_info_of(token, &own_file).len(),
            "the analyzer must still answer for a file it owns"
        );
        assert!(
            analyzer.import_info_of(token, &foreign_file).is_empty(),
            "a file this analyzer never analyzed has no imports here"
        );
        assert!(
            scope.store_error().is_none(),
            "refusing a foreign file must not record a store failure: {:?}",
            scope.store_error()
        );
    }

    #[test]
    fn literal_symbol_search_keeps_members_of_matching_java_types() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/demo/Gson.java");
        file.write(
            "package demo; public class Gson { public void fromJson() {} } class Other { void unrelated() {} }\n",
        )
        .expect("java source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let analyzer = TreeSitterAnalyzer::new(project, JavaAdapter);

        let matches = analyzer.search_definitions("Gson", false);
        let patterns = SearchSymbolPatternBatch::compile(vec!["Gson".to_string()], false, None);
        let candidates = analyzer.search_symbol_candidates(&patterns, None).rows;

        assert!(matches.iter().any(|unit| unit.fq_name() == "demo.Gson"));
        assert!(
            matches
                .iter()
                .any(|unit| unit.fq_name() == "demo.Gson.fromJson")
        );
        assert!(!matches.iter().any(|unit| unit.short_name() == "unrelated"));
        assert!(candidates.iter().any(|candidate| {
            candidate.code_unit.fq_name() == "demo.Gson.fromJson"
                && candidate.primary_range.is_some()
                && !candidate.in_test_region
        }));
    }

    #[brokk_bifrost_test_macros::hardwon(
        "#1209: broad symbol search ignored cancellation after partially scanning candidates"
    )]
    #[test]
    fn issue_1199_symbol_candidate_scan_honors_midstream_cancellation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "src/lib.rs");
        file.write(
            (0..32)
                .map(|index| format!("pub fn diagnostic_{index}() {{}}\n"))
                .collect::<String>(),
        )
        .expect("rust source");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Rust));
        let analyzer = TreeSitterAnalyzer::new(project, RustAdapter);
        let cancellation = CancellationToken::cancel_after_checks_for_test(6);
        let patterns =
            SearchSymbolPatternBatch::compile(vec!["diagnostic_.*".to_string()], false, None);

        let candidates = analyzer.search_symbol_candidates(&patterns, Some(&cancellation));

        assert!(!candidates.complete, "{candidates:#?}");
        assert!(candidates.inspected > 0, "{candidates:#?}");
        assert!(cancellation.is_cancelled());
    }
}
