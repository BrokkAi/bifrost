#[cfg(test)]
mod cpp_extraction_tests {
    mod definition_lookup {
        use brokk_bifrost_analysis::IAnalyzer;
        use brokk_bifrost_core::analyzer::definition_lookup::BoundedDefinitionLookup;

        use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;

        use std::sync::Arc;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::model::ProjectFile;
        use brokk_bifrost_test_macros::hardwon;
        #[test]
        #[hardwon(
            "#3140: empty language delegates multiplied definition lookups and masked later source updates"
        )]
        fn workspace_lookup_skips_empty_delegates_and_observes_their_first_source() {
            use brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate;

            use brokk_bifrost_cpp_analysis::CppAnalyzer;

            use brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer;

            use brokk_bifrost_jvm_analysis::analyzer::scala::ScalaAnalyzer;
            use std::collections::{BTreeMap, BTreeSet};

            let fixture = crate::inline_project::InlineTestProject::new()
                .file("widget.cpp", "class Widget {};\n")
                .build();
            let analyzer = MultiAnalyzer::new(BTreeMap::from([
                (
                    Language::Cpp,
                    AnalyzerDelegate::new(CppAnalyzer::from_project(fixture.project().clone())),
                ),
                (
                    Language::Scala,
                    AnalyzerDelegate::new(ScalaAnalyzer::from_project(fixture.project().clone())),
                ),
            ]));
            let scala_batches = |analyzer: &MultiAnalyzer| {
                analyzer.delegates()[&Language::Scala]
                    .analyzer()
                    .test_hooks()
                    .relational_definition_batch_call_count_for_test()
            };
            let before = scala_batches(&analyzer);
            {
                let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::None);
                assert_eq!(lookup.fqn("Widget").len(), 1);
                assert!(lookup.fqn("Absent").is_empty());
                assert_eq!(lookup.identifier("Widget").len(), 1);
                assert_eq!(lookup.by_normalized_fqn("Widget").len(), 1);
                assert!(!lookup.package_exists_in_any_language("absent"));
                lookup.prefetch_fqns(&["AlsoAbsent".to_string()]);
                assert!(lookup.fqn("AlsoAbsent").is_empty());
            }
            assert_eq!(
                scala_batches(&analyzer) - before,
                0,
                "empty Scala must do no relational work for C++ workspace lookups"
            );
            // Reusing a lookup under a newly attached ledger must restore negative
            // reads for empty languages, even after its pruned list was cached.
            let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::None);
            assert!(lookup.identifier("Missing").is_empty());
            {
                let ledger =
                    Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
                let _scope = brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope::with_read_ledger(
                &analyzer,
                Arc::clone(&ledger),
            );
                assert!(lookup.identifier("LedgerMissing").is_empty());
                assert!(scala_batches(&analyzer) > before);
                assert!(!ledger.keys().is_empty());
            }
            drop(lookup);

            // A scoped resolver must still see an exact target in another language.
            let lookup = AnalyzerDefinitionLookup::new(&analyzer, Language::Scala);
            assert_eq!(lookup.fqn_in_any_language("Widget").len(), 1);
            assert!(lookup.fqn("Widget").is_empty());
            drop(lookup);

            let file = ProjectFile::new(fixture.root().to_path_buf(), "Added.scala");
            file.write("package added\nclass Added\n").unwrap();
            let updated = analyzer.update(&BTreeSet::from([file]));
            let lookup = AnalyzerDefinitionLookup::new(&updated, Language::Cpp);
            assert_eq!(lookup.fqn_in_any_language("added.Added").len(), 1);
            assert!(lookup.package_exists_in_any_language("added"));
            assert!(lookup.fqn("added.Added").is_empty());
        }
    }

    mod fact_reference_edges {

        use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeCatalog;

        use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeSelectedFragment;

        use brokk_bifrost_cpp_analysis::CppAnalyzer;

        use crate::inline_project::InlineTestProject;

        use brokk_bifrost_core::analyzer::{CodeUnitIndex, Language};

        #[test]
        fn include_claimed_extensionless_cpp_uses_declaration_language_authority() {
            const HEADER: &str = "struct Item {};\n";

            let project = InlineTestProject::with_language(Language::Cpp)
                .file("main.cc", "#include \"claimed_header\"\nItem item;\n")
                .file("claimed_header", HEADER)
                .build();
            let file = project.file("claimed_header");
            assert_eq!(file.language(), Language::None);
            assert_eq!(file.declaration_language(), Language::Cpp);
            let analyzer = CppAnalyzer::from_project(project.project().clone());
            assert!(
                analyzer.analyzed_files().contains(&file),
                "the include target must be adopted by the C++ analyzer"
            );
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_cpp::LANGUAGE.into())
                .expect("C++ grammar must match the shared tree-sitter runtime");
            let tree = parser
                .parse(HEADER, None)
                .expect("extensionless C++ law source must parse");
            let facts =
                brokk_bifrost_cpp::adapter::parse_cpp_file(&file, HEADER, &tree).resolution_facts;
            let fragment = BindingFragmentId::for_test(b"include-claimed-cpp-edge-law");
            let lexical =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    fragment,
                    Language::Cpp,
                    &facts,
                )
                .lexical()
                .clone();
            let typed =
                brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                    fragment,
                    Language::Cpp,
                    &facts,
                )
                .typed()
                .clone();

            let catalog = FactReferenceEdgeCatalog::from_selected_fragments(
                &analyzer,
                [FactReferenceEdgeSelectedFragment::new(
                    file,
                    HEADER,
                    &facts,
                    &lexical,
                    &typed,
                    brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(
                    ),
                )],
                &CancellationToken::new(),
            )
            .expect("declaration-owned C++ facts must not be rejected by the path extension")
            .expect("a live extensionless C++ catalog must publish");
            assert_eq!(catalog.selected_fragment_files().count(), 1);
        }
    }

    mod source_admission {
        use brokk_bifrost_analysis::CancellationToken;
        use brokk_bifrost_analysis::analyzer::source_admission::SourceAdmissionPolicy;
        use brokk_bifrost_analysis::analyzer::source_admission::SourceAdmissionRefusal;
        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::parse_admitted_source_with_policy;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::*;
        use brokk_bifrost_analysis::analyzer::{QueryReadIncomplete, QueryScope};
        use brokk_bifrost_cpp_analysis::analyzer::cpp::source_storage::CanonicalCppSourceFacts;
        use git2::ObjectType;
        use std::{collections::BTreeSet, sync::Arc, time::Instant};
        use tree_sitter::Parser;

        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::source_admission_test_support::*;

        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;

        use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

        use brokk_bifrost_core::analyzer::model::Language;

        use git2::Oid;

        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::TreeSitterAnalyzer;

        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

        use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;

        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_test_macros::hardwon;

        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::source_admission_test_support::parse;

        #[test]
        #[hardwon("#5408: cached data admission must not authorize a changed source blob")]
        fn numeric_data_admission_cache_follows_the_exact_blob() {
            let source = table();
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("data.h", &source)
                .build();
            let file = fixture.file("data.h");
            let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
            let cache = moka::sync::Cache::new(4);
            assert!(
                analyzer
                    .canonical_cpp_source_facts(&file, "cpp", &cache)
                    .is_some()
            );
            file.write(format!(
                "int data[] = {{{}unknown}};\n",
                "0x0123456789abcdef,".repeat(1400)
            ))
            .unwrap();
            let changed: TreeSitterAnalyzer<CppAdapter> =
                IAnalyzer::update(&analyzer, &BTreeSet::from([file.clone()]));
            {
                let scope = AnalyzerQueryScope::new(&changed);
                assert!(
                    changed
                        .canonical_cpp_source_facts(&file, "cpp", &cache)
                        .is_none()
                );
                assert!(
                    matches!(scope.read_completion(), Err(QueryReadIncomplete::StructureUnavailable(unavailable)) if unavailable == file)
                );
                assert!(scope.store_error().is_none());
            }
            file.write(&source).unwrap();
            let repaired: TreeSitterAnalyzer<CppAdapter> =
                IAnalyzer::update(&changed, &BTreeSet::from([file.clone()]));
            let scope = AnalyzerQueryScope::new(&repaired);
            assert!(
                repaired
                    .canonical_cpp_source_facts(&file, "cpp", &cache)
                    .is_some()
            );
            assert!(scope.read_completion().is_ok());
        }
        #[test]
        #[hardwon(
            "#5408: successful generated-header admission must survive canonical reads, warm reuse and reopen"
        )]
        fn numeric_data_admission_cold_warm_reopen_retains_exact_source_and_siblings() {
            let source = table();
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("data.h", &source)
                .build();
            let file = fixture.file("data.h");
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            let project = fixture.project_dyn();
            let db = fixture.root().join("admission.db");
            let build = |context| {
                TreeSitterAnalyzer::new_with_config_storage_context_and_progress(
                    Arc::clone(&project),
                    CppAdapter,
                    AnalyzerConfig::default(),
                    context,
                    None,
                )
                .unwrap()
            };
            let context = store_context_from_store(
                project.as_ref(),
                AnalyzerStore::open_persistent(&db).unwrap(),
                false,
            );
            let cold = build(context.clone());
            let warm = build(context);
            let analyzers: [&TreeSitterAnalyzer<CppAdapter>; 2] = [&cold, &warm];
            for analyzer in analyzers {
                let scope = AnalyzerQueryScope::new(analyzer);
                let facts = analyzer
                    .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(1))
                    .expect("published canonical table facts");
                assert!(
                    facts
                        .declaration_units
                        .values()
                        .flatten()
                        .any(|unit| unit.short_name() == "sibling")
                );
                assert!(
                    facts
                        .declaration_units
                        .values()
                        .flatten()
                        .any(|unit| unit.short_name() == "target")
                );
                assert!(
                    analyzer
                        .store_context
                        .store
                        .contains_parsed_blob(oid, "cpp")
                        .unwrap()
                );
                assert_eq!(analyzer.fetch_file_state(&file).unwrap().source, source);
                assert!(
                    scope.read_completion().is_ok(),
                    "{:?}",
                    scope.read_completion()
                );
            }
            drop(warm);
            drop(cold);
            let reopened = build(store_context_from_store(
                project.as_ref(),
                AnalyzerStore::open_persistent(&db).unwrap(),
                false,
            ));
            let scope = AnalyzerQueryScope::new(&reopened);
            assert!(
                reopened
                    .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(1))
                    .is_some()
            );
            assert!(scope.read_completion().is_ok());
            assert_eq!(reopened.fetch_file_state(&file).unwrap().source, source);
        }
        #[test]
        #[hardwon("#5408: interrupted bounded data proofs must not poison exact syntax reuse")]
        fn numeric_data_admission_interruption_is_transient() {
            let source = table();
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("data.h", &source)
                .build();
            let file = fixture.file("data.h");
            let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
            let scope = AnalyzerQueryScope::new(&analyzer);
            let cancellation = CancellationToken::cancel_after_checks_for_test(12);
            assert!(matches!(
                analyzer.prepared_syntax_limited_cancellable(
                    scope.token(),
                    &file,
                    source.len(),
                    Some(&cancellation)
                ),
                PreparedSyntaxLimitedOutcome::Cancelled
            ));
            let PreparedSyntaxLimitedOutcome::Available(_, syntax) = analyzer
                .prepared_syntax_limited_cancellable(scope.token(), &file, source.len(), None)
            else {
                panic!("an interrupted proof must be retried");
            };
            assert_eq!(syntax.source(), source);
            let mut parser = Parser::new();
            parser.set_language(&CppAdapter.parser_language()).unwrap();
            assert!(matches!(
                parse_admitted_source_with_policy(
                    &mut parser,
                    &CppAdapter,
                    &source,
                    None,
                    Instant::now(),
                    SourceAdmissionPolicy::from_setting(None)
                ),
                BoundedParse::TimedOut
            ));
            assert!(matches!(
                parse(&CppAdapter, &source, None),
                BoundedParse::Complete(_)
            ));
        }

        #[test]
        #[hardwon(
            "#5408: admission budget refusal was indistinguishable from a missing store publication"
        )]
        fn numeric_data_admission_refusal_is_incomplete_and_not_a_store_error() {
            let source = format!("int data[] = {{{}}};\n", "0x0123456789abcdef,".repeat(4200));
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("data.h", &source)
                .build();
            let file = fixture.file("data.h");
            let analyzer = TreeSitterAnalyzer::new(fixture.project_dyn(), CppAdapter);
            for _ in 0..2 {
                let scope = AnalyzerQueryScope::new(&analyzer);
                assert!(
                    analyzer
                        .canonical_cpp_source_facts(&file, "cpp", &moka::sync::Cache::new(1))
                        .is_none()
                );
                assert!(
                    matches!(scope.read_completion(), Err(QueryReadIncomplete::SemanticEvidenceUnavailable(reason)) if reason.contains("ExcludedNodes") && reason.contains("8192"))
                );
                assert!(scope.store_error().is_none());
            }
            let oid = Oid::hash_object(ObjectType::Blob, source.as_bytes()).unwrap();
            assert!(
                !analyzer
                    .store_context
                    .store
                    .contains_parsed_blob(oid, "cpp")
                    .unwrap()
            );
        }
        #[test]
        #[hardwon(
            "#5408: AST data exemption must not hide executable, recovered or structurally overlong source"
        )]
        fn numeric_data_admission_refuses_nonliteral_and_over_budget_trees() {
            for operand in [
                "f()",
                "identifier",
                "-f()",
                "+x",
                "!1",
                "1_tag",
                ".x=1",
                "[f()]=1",
                "[](){return 1;}()",
            ] {
                let source = format!(
                    "int data[] = {{{}{operand}}};\n",
                    "0x0123456789abcdef,".repeat(1000)
                );
                assert!(
                    matches!(
                        parse(&CppAdapter, &source, None),
                        BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
                    ),
                    "nonliteral control {operand} was admitted"
                );
            }
            let source = format!(
                "int data[] = {{{}}}; {}\n",
                "0x0123456789abcdef,".repeat(1000),
                "int code;".repeat(2000)
            );
            assert!(matches!(
                parse(&CppAdapter, &source, None),
                BoundedParse::Refused(SourceAdmissionRefusal::StructuralLine { .. })
            ));
            let source = format!("int data[] = {{{}}};\n", "0x0123456789abcdef,".repeat(4200));
            assert!(matches!(
        parse(&CppAdapter, &source, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: brokk_bifrost_analysis::analyzer::semantic::source_admission::AdmissionDimension::ExcludedNodes,
            limit: 8192,
            ..
        })
    ));
            let many_nodes = format!("int data[] = {{{}}};\n", "1,".repeat(33_000));
            assert!(matches!(
        parse(&CppAdapter, &many_nodes, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: brokk_bifrost_analysis::analyzer::semantic::source_admission::AdmissionDimension::Nodes,
            limit: 65_536,
            ..
        })
    ));
            let overlapping = format!(
                "int data[] = {{{}}};\n",
                "{".repeat(110) + &"0x0123456789abcdef,".repeat(4200) + &"}".repeat(110)
            );
            assert!(matches!(
        parse(&CppAdapter, &overlapping, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: brokk_bifrost_analysis::analyzer::semantic::source_admission::AdmissionDimension::SpanBytes,
            limit: 8_388_608,
            ..
        })
    ));
            let source = format!("int data[] = {{{}}};\n", "1,".repeat(600_000));
            assert!(matches!(
        parse(&CppAdapter, &source, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: brokk_bifrost_analysis::analyzer::semantic::source_admission::AdmissionDimension::SourceBytes,
            limit: 1_048_576,
            ..
        })
    ));
            let source = format!(
                "int data[] = {{{}}};\n",
                "{".repeat(130) + "1" + &"}".repeat(130) + &",0x0123456789abcdef".repeat(1000)
            );
            assert!(matches!(
        parse(&CppAdapter, &source, None),
        BoundedParse::Refused(SourceAdmissionRefusal::Budget {
            dimension: brokk_bifrost_analysis::analyzer::semantic::source_admission::AdmissionDimension::Depth,
            ..
        })
    ));
        }
    }

    mod class_template_storage {
        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;

        use brokk_bifrost_analysis::analyzer::store::test_support::assert_direct_prepared_parity;

        use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

        use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        use brokk_bifrost_core::analyzer::model::CodeUnit;

        use rusqlite::Connection;

        use brokk_bifrost_core::hash::HashMap;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::model::ProjectFile;

        use brokk_bifrost_analysis::analyzer::store::ensure_revisioned_workspace_views;

        use brokk_bifrost_core::analyzer::CodeUnitIndex;
        use brokk_bifrost_core::analyzer::model::{CppTemplateMetadata, CppTemplateTerm};
        use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;
        /// Declares, in order: a primary class template with a defaulted parameter, a
        /// non-type parameter and a variadic parameter; its partial specialization,
        /// which carries specialization arguments; an alias template whose target is a
        /// qualified name with arguments; and an alias template whose target has no
        /// argument list at all.
        const TEMPLATE_SOURCE: &str = concat!(
            "namespace demo {\n",
            "class Holder {};\n",
            "template <typename T, typename U = T*, unsigned N = 4, typename... Rest>\n",
            "class Bundle {};\n",
            "template <typename T, typename... Rest>\n",
            "class Bundle<T, T*, 0, Rest...> {};\n",
            "template <typename T> using Handle = ::demo::Bundle<T, T*>;\n",
            "template <typename T> using Plain = Holder;\n",
            "}\n",
        );
        /// The persisted schema of a store that has done production work is the
        /// baseline and nothing else. The analyzer's own workspace projections are
        /// TEMP objects on each connection; a projection that lost its `TEMP` would
        /// land in `main` and survive the process, which is what this pins.
        #[test]
        fn a_worked_store_holds_exactly_the_baseline_schema() {
            let baseline_temp = tempfile::TempDir::new().unwrap();
            let baseline_path = baseline_temp
                .path()
                .join(brokk_bifrost_core::cache_db::cache_db_file_name());
            let baseline =
                brokk_bifrost_core::cache_db::open_unified_connection(&baseline_path).unwrap();
            let baseline_objects = persisted_schema_objects(&baseline);
            let baseline_tables = || {
                baseline_objects
                    .iter()
                    .filter(|(kind, _)| kind == "table")
                    .map(|(_, name)| name.as_str())
                    .collect::<Vec<_>>()
            };
            for family in [
                "unit_cpp_class_templates",
                "unit_cpp_class_template_parameters",
                "unit_cpp_class_template_alias_components",
                "unit_cpp_class_template_expressions",
                "unit_cpp_class_template_terms",
            ] {
                assert!(
                    baseline_tables().contains(&family),
                    "the baseline must still declare {family}: {:?}",
                    baseline_tables()
                );
            }

            let temp = tempfile::TempDir::new().unwrap();
            let db_path = temp.path().join("worked.db");
            let file = template_fixture(temp.path());
            let source = file.read_to_string().unwrap();
            let oid = oid_for(source.as_bytes());
            let parsed = parse_state(&CppAdapter, &file);
            {
                let store = AnalyzerStore::open_persistent(&db_path).unwrap();
                store
                    .write_parsed_blob(oid, "cpp", &CppAdapter, &parsed)
                    .unwrap();
                assert!(
                    store
                        .hydrate_file_state(oid, "cpp", &CppAdapter, &file)
                        .unwrap()
                        .is_some()
                );
                let conn = store.read_conn().unwrap();
                ensure_revisioned_workspace_views(&conn).unwrap();
            }

            let worked = Connection::open(&db_path).unwrap();
            assert_eq!(
                persisted_schema_objects(&worked),
                baseline_objects,
                "a worked store must persist the baseline schema and nothing else"
            );
        }
        /// Fails with the whole parsed map when the fixture stops producing one of the
        /// shapes this suite exists to cover, rather than passing vacuously.
        fn assert_fixture_covers_every_shape(metadata: &HashMap<CodeUnit, CppTemplateMetadata>) {
            let values = || metadata.values();
            assert!(
                values().any(|value| value
                    .parameters
                    .iter()
                    .any(|parameter| parameter.default.is_some())),
                "no parameter default in {metadata:#?}"
            );
            assert!(
                values().any(|value| value.parameters.iter().any(|parameter| parameter.variadic)),
                "no variadic parameter in {metadata:#?}"
            );
            assert!(
                values().any(|value| !value.specialization_arguments.is_empty()),
                "no specialization arguments in {metadata:#?}"
            );
            assert!(
                values().any(
                    |value| value.alias_target.as_ref().is_some_and(|alias| alias
                        .arguments
                        .as_ref()
                        .is_some_and(|args| !args.is_empty()))
                ),
                "no alias target with arguments in {metadata:#?}"
            );
            assert!(
                values().any(|value| value
                    .alias_target
                    .as_ref()
                    .is_some_and(|alias| alias.arguments.is_none())),
                "no alias target without an argument list in {metadata:#?}"
            );
            assert!(
                values()
                    .flat_map(|value| value
                        .parameters
                        .iter()
                        .filter_map(|parameter| parameter.default.as_ref())
                        .chain(value.specialization_arguments.iter())
                        .chain(
                            value
                                .alias_target
                                .iter()
                                .flat_map(|alias| alias.arguments.iter().flatten())
                        ))
                    .any(|expression| matches!(
                        &expression.term,
                        CppTemplateTerm::Node { children, .. } if !children.is_empty()
                    )),
                "no compound expression term in {metadata:#?}"
            );
        }
        fn persist_and_hydrate_template_metadata(
            file: &ProjectFile,
            parsed: &brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState,
        ) -> brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState {
            let oid = oid_for(file.read_to_string().unwrap().as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, parsed)
                .unwrap();
            store
                .hydrate_file_state(oid, "cpp", &CppAdapter, file)
                .unwrap()
                .unwrap()
        }
        #[test]
        fn persisted_cpp_class_templates_preserve_every_metadata_shape() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = template_fixture(temp.path());
            let parsed = parse_state(&CppAdapter, &file);
            assert_fixture_covers_every_shape(&parsed.cpp_template_metadata);
            let hydrated = persist_and_hydrate_template_metadata(&file, &parsed);

            assert_eq!(
                hydrated.cpp_template_metadata, parsed.cpp_template_metadata,
                "persisted class-template metadata must hydrate unchanged"
            );
            // The same fixture through the prepared batch path and bulk hydration,
            // over the whole FileState rather than this one map.
            assert_direct_prepared_parity(&CppAdapter, "cpp", &file);
        }
        fn persisted_schema_objects(conn: &Connection) -> Vec<(String, String)> {
            conn.prepare(
                "SELECT type, name FROM main.sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<(String, String)>>>()
            .unwrap()
        }
        fn template_fixture(root: &std::path::Path) -> ProjectFile {
            let file = ProjectFile::new(root.to_path_buf(), "include/bundle.h");
            file.write(TEMPLATE_SOURCE).unwrap();
            file
        }
        /// What `CppAnalyzer::template_metadata` answers after a build is what the
        /// relational families hold. The comparison runs against the metadata read
        /// back out of a store rather than against the parse alone, so this is the
        /// warm-versus-persisted parity the opaque payload used to get from
        /// `assert_file_state_equivalent`, unit by unit and in both directions.
        #[test]
        fn warm_analyzer_class_template_metadata_matches_the_persisted_metadata() {
            let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
                .file("include/bundle.h", TEMPLATE_SOURCE)
                .build();
            let file = fixture.file("include/bundle.h");
            let parsed = parse_state(&CppAdapter, &file);
            assert_fixture_covers_every_shape(&parsed.cpp_template_metadata);

            let store = AnalyzerStore::open_ephemeral().unwrap();
            let oid = oid_for(file.read_to_string().unwrap().as_bytes());
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, &parsed)
                .unwrap();
            let persisted = store
                .hydrate_file_state(oid, "cpp", &CppAdapter, &file)
                .unwrap()
                .unwrap()
                .cpp_template_metadata;
            assert_eq!(persisted, parsed.cpp_template_metadata);

            let analyzer = brokk_bifrost_cpp_analysis::analyzer::cpp::CppAnalyzer::from_project(
                fixture.project().clone(),
            );
            for (unit, metadata) in &persisted {
                assert_eq!(
                    analyzer.template_metadata(unit).as_ref(),
                    Some(metadata),
                    "warm metadata differs for {unit:?}"
                );
            }
            // And no other declaration acquires metadata of its own.
            for unit in &analyzer.get_all_declarations() {
                assert_eq!(
                    analyzer.template_metadata(unit),
                    persisted.get(unit).cloned(),
                    "warm metadata differs for {unit:?}"
                );
            }
        }
    }

    mod store {
        use brokk_bifrost_analysis::analyzer::store::StoreLanguageAdapter;
        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
        use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::LanguageAdapter;

        pub(super) use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        pub(super) use std::sync::Arc;

        pub(super) use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::FileState;

        pub(super) use brokk_bifrost_core::hash::HashMap;

        pub(super) use brokk_bifrost_core::analyzer::model::Language;

        pub(super) use brokk_bifrost_analysis::analyzer::store::epoch;

        pub(super) use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

        pub(super) use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

        use brokk_bifrost_core::test_support::write_file;

        use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;

        use brokk_bifrost_analysis::analyzer::store::test_support::assert_prior_parsed_blob_invalidated;

        use brokk_bifrost_analysis::analyzer::store::test_support::persisted_short_names;

        /// #3501: a genuinely unclosed translation unit is persisted and hydrated
        /// as partial, with every recovered declaration kept. ABI 15 now reads the
        /// original one- and two-header linkage witnesses as complete positives.
        #[test]
        fn a_parse_left_inside_an_unclosed_construct_persists_as_partial() {
            let one = format!(
                "#include <stdarg.h>\n{}int sqlite3_open(void) {{ return 0; }}\n",
                amalgamated_c_header("SQLITE3_H", "sqlite3_file")
            );
            let temp = tempfile::TempDir::new().unwrap();
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let generation = store
                .ensure_language_epoch_value("cpp:c", "parse-completeness-v1")
                .unwrap();
            for (name, source, expected) in [
                (
                    "one.c",
                    one,
                    brokk_bifrost_core::analyzer::model::ParseCompleteness::Complete,
                ),
                (
                    "two.c",
                    two_amalgamated_c_headers(),
                    brokk_bifrost_core::analyzer::model::ParseCompleteness::Complete,
                ),
                (
                    "unclosed.c",
                    format!("{}\n{}", "{".repeat(32), two_amalgamated_c_headers()),
                    brokk_bifrost_core::analyzer::model::ParseCompleteness::Partial,
                ),
            ] {
                let file = write_file(temp.path(), name, &source);
                assert_eq!(CppAdapter.storage_language_key_for_file(&file), "cpp:c");
                let oid = oid_for(source.as_bytes());
                let state = parse_state(&CppAdapter, &file);
                assert_eq!(state.completeness, expected, "{name}");
                store
                    .write_parsed_blob_at_generation(
                        &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                        oid,
                        "cpp:c",
                        generation,
                        &CppAdapter,
                        &state,
                    )
                    .unwrap();

                let persisted: String = store
                    .read_conn()
                    .unwrap()
                    .query_row(
                        "SELECT meta.parse_completeness
                     FROM blob_meta AS meta
                     JOIN blobs ON blobs.id = meta.blob_id
                     WHERE blobs.blob_oid = ?1 AND blobs.lang = 'cpp:c'",
                        [oid.to_string()],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(persisted, expected.label(), "{name}");

                let hydrated = store
                    .hydrate_file_state_with_source(
                        oid,
                        "cpp:c",
                        generation,
                        &CppAdapter,
                        &file,
                        &source,
                    )
                    .unwrap()
                    .expect("hydration should succeed");
                assert_eq!(hydrated.completeness, expected, "{name}");
                assert_eq!(hydrated.declarations, state.declarations, "{name}");
                assert!(
                    hydrated
                        .declarations
                        .iter()
                        .any(|unit| unit.fq_name() == "sqlite3_open"),
                    "{name}: recovery keeps its declarations: {:?}",
                    hydrated.declarations
                );
            }
        }
        /// One header of the SQLite amalgamation's shape: an include guard around
        /// an `extern "C"` block that `#if 0` opens and a second `#if 0` closes.
        fn amalgamated_c_header(guard: &str, aggregate: &str) -> String {
            format!(
                "#ifndef {guard}\n#define {guard}\n#if 0\nextern \"C\" {{\n#endif\n\
             struct {aggregate} {{ int value; }};\n\
             #if 0\n}}  /* End of the 'extern \"C\"' block */\n#endif\n#endif\n"
            )
        }
        /// A `.c` blob and a byte-identical `.cpp` blob are two different
        /// extractions of one content hash, so they must live under different cache
        /// `lang` keys or the second one analyzed would read the first one's rows.
        #[test]
        fn c_and_cpp_projections_of_one_blob_use_distinct_storage_language_keys() {
            let temp = tempfile::TempDir::new().unwrap();
            let source = "struct outer {\n\
             struct inner { int value; } item;\n\
             };\n";
            let c_file = write_file(temp.path(), "tags.c", source);
            let cpp_file = write_file(temp.path(), "tags.cpp", source);
            let header_file = write_file(temp.path(), "tags.h", source);

            assert_eq!(CppAdapter.storage_language_key_for_file(&c_file), "cpp:c");
            assert_eq!(CppAdapter.storage_language_key_for_file(&cpp_file), "cpp");
            assert_eq!(
                CppAdapter.storage_language_key_for_file(&header_file),
                "cpp"
            );
            assert_eq!(
                CppAdapter
                    .storage_language_keys()
                    .into_iter()
                    .map(|(key, _)| key)
                    .collect::<Vec<_>>(),
                vec!["cpp".to_string(), "cpp:c".to_string()]
            );

            let state = Arc::new(parse_state(&CppAdapter, &c_file));
            let oid = oid_for(state.source.as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let epochs = CppAdapter
                .storage_language_keys()
                .into_iter()
                .map(|(key, ts_language)| {
                    (
                        key,
                        epoch::epoch_for(Language::Cpp, &ts_language).to_string(),
                    )
                })
                .collect::<Vec<_>>();
            let generations = store.ensure_language_epoch_values(&epochs).unwrap();
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    oid,
                    "cpp:c",
                    generations["cpp:c"],
                    &CppAdapter,
                    state.as_ref(),
                )
                .unwrap();

            assert!(store.contains_parsed_blob(oid, "cpp:c").unwrap());
            assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
        }
        #[test]
        fn cpp_abstract_reference_declarator_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "refs.h",
                "struct Sink {\n\
             void accept(const int&);\n\
             };\n\
             auto ref_of(int& value) -> int&;\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "abstract-reference-declarator-identity-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        /// A cache written before headers gained a stored C reading (#1970) holds
        /// `cpp` rows for a header with no `cpp:c` companion, which the loader
        /// would read as "the two readings agree". The salt bump is what stops
        /// that from being believed.
        #[test]
        fn cpp_c_header_projection_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "tags.h",
                "struct outer {\n\
             struct inner { int value; } item;\n\
             };\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "c-header-projection-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_c_tag_scope_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "tags.c",
                "struct outer {\n\
             struct inner { int value; } item;\n\
             };\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch =
                epoch::epoch_before_bump(epoch::TestEpochLanguage::Cpp, "c-tag-scope-2026-08");
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        /// #3493: the C and C++ walk now records callable modifier metadata, and
        /// it recorded none before. A blob persisted under the prior epoch
        /// deserializes as "nobody read the modifiers", which is indistinguishable
        /// from an adapter that honestly declares none, so `receiver_contract_of`
        /// reports no contract and every C or C++ procedure summary stays inert.
        /// The salt is the only thing that retires those rows.
        #[brokk_bifrost_test_macros::hardwon(
            "#3493: persisted C and C++ callables lacked modifier metadata for receiver contracts"
        )]
        #[test]
        fn cpp_callable_modifier_metadata_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "client.cpp",
                "namespace shop {\n\
             class Client { public: void send(int order); static int count(); };\n\
             void Client::send(int order) { (void)order; }\n\
             int total(int order) { return order; }\n\
             }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "cpp-callable-modifier-metadata-2026-09",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_complete_sentinel_class_tail_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "raw_hash_set.h",
                "namespace absl { namespace container_internal {\n\
             template <class T> class raw_hash_set { using hasher = T; };\n\
             }}\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "complete-sentinel-class-tail-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_conditional_alias_physical_ranges_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "mathlib.h",
                "class MathLib {\n\
             public:\n\
             #if defined(HAVE_BOOST) && defined(HAVE_BOOST_INT128)\n\
               using bigint = boost::multiprecision::int128_t;\n\
               using biguint = boost::multiprecision::uint128_t;\n\
             #else\n\
               using bigint = long long;\n\
               using biguint = unsigned long long;\n\
             #endif\n\
             };\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "conditional-alias-physical-ranges-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[brokk_bifrost_test_macros::hardwon(
            "9d8e13727de8: C++ explicit-object parameters were counted as ordinary callable arity"
        )]
        #[test]
        fn cpp_explicit_object_arity_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "visitor.h",
                "struct Visitor {\n\
             void fail(this auto const& self) {}\n\
             };\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "explicit-object-callable-arity-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_fragmented_export_sibling_class_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "token.h",
                "#define SIMPLECPP_LIB\n\
             namespace simplecpp {\n\
             using TokenString = std::string;\n\
             struct Location {};\n\
             class SIMPLECPP_LIB Token {\n\
             public:\n\
               Token(const TokenString &s, const Location &loc) :\n\
                   location(loc), string(s) {\n\
               }\n\
               TokenString string;\n\
               Location location;\n\
             };\n\
             }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "fragmented-export-sibling-class-parent-scope-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_macro_argument_typedef_declarator_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "internal/cgen/base/token-public.h",
                "#define WUFFS_BASE__SLICE(T) struct { T* ptr; size_t len; }\n\
             typedef struct wuffs_base__token__struct {\n\
               unsigned long long repr;\n\
             } wuffs_base__token;\n\
             typedef WUFFS_BASE__SLICE(wuffs_base__token) wuffs_base__slice_token;\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "macro-argument-typedef-declarator-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        /// C++ materialization provenance (issue #1476): a `#define` is a
        /// generation site producing its macro unit, a preprocessor conditional
        /// is a recorded configuration gate, and an export-macro class the parser
        /// broke is recorded as a recovered declaration.
        #[brokk_bifrost_test_macros::hardwon(
            "#2552: export-macro recovery lost the displaced C++ class constructor and its provenance"
        )]
        #[test]
        fn cpp_macro_config_and_recovery_records() {
            use brokk_bifrost_core::analyzer::structural::materialization::GenerationKind;

            use brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord;

            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "config.h",
                concat!(
                    "#define WIDGET_MAX 8\n",
                    "#ifdef USE_FAST\n",
                    "int fast_path();\n",
                    "#else\n",
                    "int slow_path();\n",
                    "#endif\n",
                ),
            );
            let state = parse_state(&CppAdapter, &file);
            let records = &state.materialization_records;
            let generated: Vec<_> = records
                .iter()
                .filter_map(|record| match record {
                    MaterializationRecord::GeneratedDeclaration { kind, unit, .. } => {
                        Some((*kind, unit.fq_name().to_string()))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                generated,
                vec![(
                    GenerationKind::PreprocessorDefinition,
                    "WIDGET_MAX".to_string()
                )],
                "records: {records:?}"
            );
            let gates: Vec<_> = records
                .iter()
                .filter_map(|record| match record {
                    MaterializationRecord::ConfigurationConditional { range } => Some(*range),
                    _ => None,
                })
                .collect();
            assert_eq!(gates.len(), 1, "records: {records:?}");
            let source = file.read_to_string().unwrap();
            let ifdef_start = source.find("#ifdef").unwrap();
            assert_eq!(gates[0].start_byte, ifdef_start);
            assert!(
                gates[0].end_byte >= source.find("slow_path").unwrap(),
                "the gate interval must cover the else branch: {:?}",
                gates[0]
            );

            // The f7a2bb5 shape: an export-annotation macro on a single-base class
            // makes tree-sitter parse the class as a bogus function definition;
            // recovery re-derives the class and must say it did so.
            let recovered_file = write_file(
                temp.path(),
                "exported.h",
                concat!(
                    "class CORE_EXPORT QgsPoint : public QgsAbstractGeometry\n",
                    "{\n",
                    "  public:\n",
                    "    QgsPoint( double x, double y );\n",
                    "};\n",
                ),
            );
            let state = parse_state(&CppAdapter, &recovered_file);
            let recovered: Vec<_> = state
                .materialization_records
                .iter()
                .filter_map(|record| match record {
                    MaterializationRecord::RecoveredDeclaration { unit, .. } => {
                        Some(unit.fq_name().to_string())
                    }
                    _ => None,
                })
                .collect();
            // The class, and the constructor its access label swallowed: the
            // reparsed body reads `QgsPoint( double x, double y );` as a call
            // statement under `public:`, and recovery reparses the declarator from
            // that call (#2552).
            assert_eq!(
                recovered,
                vec!["QgsPoint".to_string(), "QgsPoint.QgsPoint".to_string()],
                "records: {:?}",
                state.materialization_records
            );
        }
        #[test]
        fn cpp_macro_decorated_template_class_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "span.h",
                "namespace absl {\n\
             ABSL_NAMESPACE_BEGIN\n\
             template <typename T>\n\
             class ABSL_ATTRIBUTE_VIEW Span {\n\
             public:\n\
               int begin() const;\n\
               int back() const;\n\
             };\n\
             int begin();\n\
             int back();\n\
             }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "macro-decorated-template-class-scope-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_macro_displaced_callable_name_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "real_box.h",
                "class RealBox {\n\
             public:\n\
             [[nodiscard]] AMREX_GPU_HOST_DEVICE\n\
             Real hi(int dir) const noexcept { return dir; }\n\
             };\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "macro-displaced-scalar-return-callable-name-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_macro_template_return_owner_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "ops-inl.h",
                "template <class T> struct Vec128 {};\n\
             template <class T> using Vec64 = Vec128<T>;\n\
             HWY_API Vec64<unsigned> LowerHalf(Vec128<unsigned> value) { return {}; }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch =
                epoch::cpp_epoch_before_macro_template_return_free_function_ownership();
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        #[brokk_bifrost_test_macros::hardwon(
            "#3633+#5868: namespace recovery producer changes must invalidate unchanged source blobs"
        )]
        fn cpp_namespace_recovery_ancestry_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "recovered_namespace.cpp",
                "#define APP_IF_ACTIVE if (active) {\n\
             namespace app { namespace detail {\n\
             bool check(bool active) { APP_IF_ACTIVE return true; }\n\
             class Tail {}; } }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "namespace-recovery-ancestry-authority-2026-09",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
            // Generation invalidation needs unchanged source, not a private corpus
            // shape. Keep this independently authored contract available publicly.
            let file = write_file(
                temp.path(),
                "literal_namespace.cpp",
                "OPAQUE_PREFIX\nnamespace recovered\n{\nint member;\n}\nint member;\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "cpp-recovered-literal-namespace-head-5868-2026-10",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "cpp-canonical-lexical-owner-5868-2026-10",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_namespaced_plain_fragment_boundary_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "types.h",
                "#define DEPRECATED(message)\n\
             namespace demo {\n\
             struct Base {\n\
             int legacy() const DEPRECATED(\"use replacement\") { return 1; }\n\
             int replacement() const;\n\
             };\n\
             struct Derived : Base {};\n\
             }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "namespaced-plain-fragment-boundary-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_nested_include_claim_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "dense.h",
                "class Dense {\npublic:\n#include \"dense_plugin.h\"\n};\n",
            );
            let mut state = parse_state(&CppAdapter, &file);
            assert!(
                state
                    .imports
                    .iter()
                    .any(|import| import.raw_snippet.contains("dense_plugin.h")),
                "the current walk records the include written inside the class body: {:?}",
                state.imports
            );
            // Before this epoch includes were collected by the declaration walk,
            // which descends only through declaration scopes, so a directive inside
            // a class body was never recorded as an include claim.
            state
                .imports
                .retain(|import| !import.raw_snippet.contains("dense_plugin.h"));
            let source_facts = state
                .source_facts
                .as_mut()
                .expect("canonical C++ source facts");
            source_facts.imports.clear();
            source_facts.generic_imports.clear();
            source_facts
                .cpp
                .as_mut()
                .expect("C++ properties")
                .includes
                .clear();
            let state = Arc::new(state);
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "nested-include-claims-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_partial_parse_completeness_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            // Enough unmatched braces keep recovery at an ERROR root rather than
            // letting the parser synthesize local closing tokens. Preserve the
            // partial-blob epoch contract with genuinely malformed source.
            let source = format!("{}\n{}", "{".repeat(32), two_amalgamated_c_headers());
            let file = write_file(temp.path(), "sqlite3.h", &source);
            let state = parse_state(&CppAdapter, &file);
            assert_eq!(
                state.completeness,
                brokk_bifrost_core::analyzer::model::ParseCompleteness::Partial
            );
            let prior_epoch = epoch::cpp_epoch_before_partial_parse_completeness();
            assert_prior_parsed_blob_invalidated(&CppAdapter, &state, &prior_epoch);
        }
        #[test]
        fn cpp_plain_fragmented_class_sibling_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "analyzer.h",
                "struct Analyzer {\n\
             struct Action {};\n\
             template<class T> void analyze(T value) { Action action; }\n\
             };\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "plain-fragmented-class-sibling-ownership-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_raw_quoted_include_header_epoch_invalidates_prior_parsed_blobs() {
            let fixture = crate::inline_project::InlineTestProject::with_language(Language::Cpp)
                .file(
                    "main.cpp",
                    "#include \"C:\\Users\\ADMINI~1\\include\\helper.h\"\nint main() {}\n",
                )
                .build();
            let file = fixture.file("main.cpp");
            let state = parse_state(&CppAdapter, &file);
            let oid = oid_for(state.source.as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let prior = epoch::cpp_epoch_before_raw_quoted_include_header_paths();
            let prior_generation = store.ensure_language_epoch_value("cpp", &prior).unwrap();
            store
                .write_parsed_blob_at_generation(
                    &brokk_bifrost_analysis::analyzer::store::test_blob_file(),
                    oid,
                    "cpp",
                    prior_generation,
                    &CppAdapter,
                    &state,
                )
                .unwrap();
            assert!(store.contains_parsed_blob(oid, "cpp").unwrap());

            let current = store
                .ensure_language_epoch(Language::Cpp, &tree_sitter_cpp::LANGUAGE.into())
                .unwrap();
            assert_ne!(current, prior_generation);
            assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
            assert_eq!(
                store
                    .missing_parsed_blob_keys(&[(oid, "cpp".to_owned())])
                    .unwrap(),
                vec![(oid, "cpp".to_owned())]
            );
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
                .unwrap();
            assert!(store.contains_parsed_blob(oid, "cpp").unwrap());
            let imports = store
                .hydrate_import_infos(&[(file.clone(), oid)], "cpp", &CppAdapter)
                .unwrap();
            assert_eq!(imports.get(&file), Some(&state.imports));
            assert_eq!(
                state.imports[0].raw_snippet,
                "#include \"C:\\Users\\ADMINI~1\\include\\helper.h\""
            );
        }
        #[brokk_bifrost_test_macros::hardwon(
            "#1208: recovered C++ typedef bases changed without invalidating stored declarations"
        )]
        #[test]
        fn cpp_recovered_typedef_base_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "levelrangefilter.h",
                "class LOG4CXX_EXPORT LevelRangeFilter : public spi::Filter {\n\
             typedef spi::Filter BASE_CLASS;\n\
             };\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            // Recompute the immediately preceding C++ epoch for this target from
            // the complete pre-#1208 language salt, rather than passing an
            // arbitrary old label through the store's generic epoch API. The live
            // grammar fingerprint is target-specific, so the durable contract is
            // the generation cutover below, not one target's full epoch digest.
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "recovered-typedef-base-alias-identity-2026-07",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        /// C++ recovered-origin provenance for the remaining recovery shapes
        /// (issue #1657): a sentinel-macro region reparse records every unit the
        /// reparse walk mints, and a fragmented multiple-base export declaration
        /// records its recovered class. The formerly fragmented macro-constrained
        /// partial specialization now parses cleanly under the macro-declaration
        /// grammar and stays pinned as recovery-free.
        #[brokk_bifrost_test_macros::hardwon(
            "#1657+5554beb0001d: remaining C++ recovery shapes must retain Recovered source provenance"
        )]
        #[test]
        fn cpp_remaining_recovery_shapes_record_recovered_origin() {
            use brokk_bifrost_core::analyzer::model::Range;
            use brokk_bifrost_core::analyzer::structural::materialization::MaterializationRecord;

            fn recovered_units(state: &FileState) -> Vec<(String, Range)> {
                state
                    .materialization_records
                    .iter()
                    .filter_map(|record| match record {
                        MaterializationRecord::RecoveredDeclaration { recovery, unit } => {
                            Some((unit.fq_name().to_string(), *recovery))
                        }
                        _ => None,
                    })
                    .collect()
            }

            let temp = tempfile::TempDir::new().unwrap();

            // Issue #941: file-scope macro sentinels make tree-sitter swallow the
            // wrapped namespace/struct region as one bogus function definition.
            // The region reparse mints the namespace, struct, and method directly
            // (there is no single recovered envelope unit), so every minted unit
            // carries the reparse window; the sibling outside the region stays
            // parsed.
            let sentinel = write_file(
                temp.path(),
                "sentinel.cpp",
                concat!(
                    "BEGIN_NS\n",
                    "namespace demo { struct Widget { void doWork(); }; }\n",
                    "END_NS\n",
                    "void callWidget() {\n",
                    "    demo::Widget w;\n",
                    "    w.doWork();\n",
                    "}\n",
                ),
            );
            let state = parse_state(&CppAdapter, &sentinel);
            let recovered = recovered_units(&state);
            let names: Vec<&str> = recovered.iter().map(|(name, _)| name.as_str()).collect();
            assert_eq!(
                names,
                ["demo", "demo.Widget", "demo.Widget.doWork"],
                "records: {:?}",
                state.materialization_records
            );
            let source = sentinel.read_to_string().unwrap();
            let widget_start = source.find("struct Widget").unwrap();
            for (name, recovery) in &recovered {
                assert!(
                    recovery.start_byte <= widget_start && widget_start < recovery.end_byte,
                    "the reparse window must cover the recovered struct for {name}: {recovery:?}"
                );
            }

            // Issue #938: a multiple-base export-macro class parses as a broken
            // `declaration` whose members tree-sitter scatters; the recovery
            // records the recovered class over its full class range.
            let fragmented = write_file(
                temp.path(),
                "two_base.h",
                concat!(
                    "#define VIEWS_EXPORT\n",
                    "namespace views {\n",
                    "class VIEWS_EXPORT TwoBase : public internal::NativeWidgetDelegate,\n",
                    "                             public ui::EventSource {\n",
                    "public:\n",
                    "    TwoBase();\n",
                    "};\n",
                    "}\n",
                ),
            );
            let state = parse_state(&CppAdapter, &fragmented);
            let recovered = recovered_units(&state);
            assert_eq!(
                recovered.len(),
                1,
                "records: {:?}",
                state.materialization_records
            );
            let (name, recovery) = &recovered[0];
            assert_eq!(
                name, "views.TwoBase",
                "records: {:?}",
                state.materialization_records
            );
            let source = fragmented.read_to_string().unwrap();
            let class_start = source.find("class VIEWS_EXPORT").unwrap();
            assert_eq!(recovery.start_byte, class_start, "recovery: {recovery:?}");
            assert!(
                recovery.end_byte > source.find("TwoBase();").unwrap(),
                "the recovery window must span to the displaced closing brace: {recovery:?}"
            );

            // A macro-constrained template parameter used to fragment this
            // partial specialization; under the macro-declaration grammar the
            // constraint macros parse as `macro_modifier`s, so this fixture now
            // pins that the shape stays clean.
            let specialization = write_file(
                temp.path(),
                "expected.hpp",
                concat!(
                    "namespace lib {\n",
                    "#if USE_STANDARD\n",
                    "using std::expected;\n",
                    "#else\n",
                    "template<typename T, typename E> class expected;\n",
                    "\n",
                    "template<typename E>\n",
                    "class expected<void, E> {\n",
                    "public:\n",
                    "    constexpr expected() noexcept\n",
                    "        : contained(true)\n",
                    "    {}\n",
                    "\n",
                    "    constexpr explicit expected(in_place_t(void))\n",
                    "        : contained(true)\n",
                    "    {}\n",
                    "\n",
                    "    template<typename G = E\n",
                    "        nsel_REQUIRES_T(\n",
                    "            !std::is_convertible<G const&, E>::value\n",
                    "        )\n",
                    "    >\n",
                    "    nsel_constexpr14 explicit expected(G const& error)\n",
                    "        : contained(false)\n",
                    "    {\n",
                    "        contained.construct_error(E{error.error()});\n",
                    "    }\n",
                    "\n",
                    "    template<typename G = E\n",
                    "        nsel_REQUIRES_T(\n",
                    "            std::is_convertible<G const&, E>::value\n",
                    "        )\n",
                    "    >\n",
                    "    nsel_constexpr14 expected(G const& error)\n",
                    "        : contained(false)\n",
                    "    {\n",
                    "        contained.construct_error(error.error());\n",
                    "    }\n",
                    "\n",
                    "    bool has_value() const { return contained.has_value(); }\n",
                    "\n",
                    "private:\n",
                    "    bool contained;\n",
                    "};\n",
                    "\n",
                    "void after_specialization() {}\n",
                    "#endif\n",
                    "}\n",
                ),
            );
            let state = parse_state(&CppAdapter, &specialization);
            let recovered = recovered_units(&state);
            // The macro-declaration grammar admits the constraint macros as
            // `macro_modifier`s, so this fixture no longer recovers; keep it as a
            // pin that the shape stays clean rather than silently re-breaking.
            assert_eq!(
                recovered.len(),
                0,
                "the macro-constrained specialization must parse without recovery: {:?}",
                state.materialization_records
            );
        }
        #[test]
        fn cpp_sentinel_class_before_member_callable_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "distribution.h",
                "namespace absl { ABSL_NAMESPACE_BEGIN\n\
             template <class T> class distribution { using result_type = T;\n\
             result_type operator()() { return result_type{}; } }; }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "sentinel-class-before-member-callable-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        /// The contract is per language, not global. C++ renders `::` between
        /// namespace segments, so nothing may be dropped for it -- and its
        /// persisted vocabulary is free to carry `::`.
        #[test]
        fn cpp_short_name_vocabulary_is_not_narrowed_by_the_filter() {
            assert!(
                brokk_bifrost_core::analyzer::fq_name::absent_segment_separators(Language::Cpp)
                    .is_empty(),
                "cpp renders every separator the lookup vocabulary can carry"
            );

            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "sample.cpp",
                "namespace ns1 { namespace ns2 { struct Outer { void method(); }; } }\n\
             void ns1::ns2::Outer::method() {}\n",
            );
            let names = persisted_short_names(&CppAdapter, "cpp", &file);
            assert!(
                names.iter().any(|name| name.contains("Outer")),
                "cpp fixture should persist the nested type: {names:?}"
            );
        }
        #[test]
        fn cpp_source_member_prototype_units_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "client.h",
                "namespace shop {\n\
             class Client { public: void send(int order); static int count(); };\n\
             }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "cpp-source-member-prototype-units-2026-09",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_structured_parameter_types_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "overloads.h",
                "template <typename T, ENABLE(T)>\n\
             T choose(T value) { return value; }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "structured-callable-parameter-types-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn cpp_templated_plain_fragment_ownership_epoch_invalidates_prior_parsed_blobs() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "particle_tile.h",
                "namespace demo {\n\
             template <class T> struct ParticleTile {\n\
             using Alias = T;\n\
             Alias get() const;\n\
             };\n\
             }\n",
            );
            let state = Arc::new(parse_state(&CppAdapter, &file));
            let prior_epoch = epoch::epoch_before_bump(
                epoch::TestEpochLanguage::Cpp,
                "templated-plain-fragment-prefix-and-sibling-ownership-2026-08",
            );
            assert_prior_parsed_blob_invalidated(&CppAdapter, state.as_ref(), &prior_epoch);
        }
        #[test]
        fn missing_optional_fact_manifest_row_is_treated_as_incomplete() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "include/missing.h",
                "template <typename T, typename U = T*> class Missing {};\n",
            );
            let source = file.read_to_string().unwrap();
            let oid = oid_for(source.as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, &parse_state(&CppAdapter, &file))
                .unwrap();

            {
                let conn = store.conn.lock().unwrap();
                // Two schema-117 defences stand between this store and the
                // damaged one the test needs: the seal keeps a published
                // C++ class-template manifest row immutable, and the family's
                // foreign key cascades the header rows away with it. Drop the
                // seal and suspend foreign keys so the manifest row alone
                // disappears, which is what a store damaged outside SQLite looks
                // like.
                conn.execute_batch(
                "DROP TRIGGER blob_optional_fact_manifest_cpp_class_templates_no_delete_after_seal;
                 PRAGMA foreign_keys = OFF;",
            )
            .unwrap();
                let deleted = conn
                .execute(
                    "DELETE FROM blob_optional_fact_manifest
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'cpp') AND fact_kind = 1",
                    [oid.to_string()],
                )
                .unwrap();
                assert_eq!(deleted, 1);
                conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
                let surviving: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM unit_cpp_class_templates
                     WHERE blob_id = (SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'cpp')",
                        [oid.to_string()],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(surviving > 0, "the orphaned fact rows must survive");
            }

            assert!(!store.contains_parsed_blob(oid, "cpp").unwrap());
            assert!(
                store
                    .hydrate_file_state(oid, "cpp", &CppAdapter, &file)
                    .unwrap()
                    .is_none()
            );
            let hydrated = store
                .hydrate_file_states(
                    &[(file.clone(), oid)],
                    "cpp",
                    &CppAdapter,
                    &HashMap::from_iter([(file.clone(), source)]),
                )
                .unwrap();
            assert!(!hydrated.contains_key(&file));
        }
        #[test]
        fn search_candidate_projection_proves_repeated_callable_definitions() {
            let temp = tempfile::TempDir::new().unwrap();
            let file = write_file(
                temp.path(),
                "src/conditional.cpp",
                "#if FIRST\nint selected() { return 1; }\n#else\nlong selected() { return 2; }\n#endif\n",
            );
            let oid = oid_for(file.read_to_string().unwrap().as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, &parse_state(&CppAdapter, &file))
                .unwrap();

            let candidates = store.search_candidate_rows_by_lang("cpp").unwrap();
            let selected = candidates
                .iter()
                .find(|row| row.candidate.short_name == "selected")
                .expect("repeated conditional definition");

            assert!(selected.has_multiple_ranges, "{selected:#?}");
            assert!(selected.all_ranges_are_definitions, "{selected:#?}");
            assert_eq!(
                selected.primary_range.map(|range| range.start_line),
                Some(2)
            );
        }
        /// Two amalgamated headers and a definition: tree-sitter returns an ERROR
        /// root with the first include guard left open, and every declaration
        /// lies inside it (#3501).
        fn two_amalgamated_c_headers() -> String {
            format!(
                "#include <stdarg.h>\n{}{}int sqlite3_open(void) {{ return 0; }}\n",
                amalgamated_c_header("SQLITE3_H", "sqlite3_file"),
                amalgamated_c_header("_SQLITE3RTREE_H_", "sqlite3_rtree_geometry")
            )
        }
    }

    mod resolution_producer {}

    mod source_facts {
        use brokk_bifrost_analysis::analyzer::store_bridge::AnalyzerStoreEngineExt;
        use brokk_bifrost_cpp_analysis::analyzer::cpp::source_storage::CppSourceStorage;

        use brokk_bifrost_cpp_analysis::analyzer::cpp::adapter::CppAdapter;

        use brokk_bifrost_cpp_analysis::analyzer::cpp::CppAnalyzer;

        use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;

        use brokk_bifrost_analysis::analyzer::store::test_blob_oid as oid_for;

        use brokk_bifrost_analysis::analyzer::store::test_support::parse_state;

        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

        use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::project::OverlayProject;

        use brokk_bifrost_core::analyzer::project::Project;

        use crate::inline_project::InlineTestProject;
        use brokk_bifrost_core::analyzer::query_token::QueryScope;
        use brokk_bifrost_cpp::graph_support::CppSource;
        use std::collections::BTreeSet;
        use std::sync::Arc;
        const SOURCE: &str = r#"#include <vector>
namespace ns {
struct Base {};
template<class T = Base> struct Box {};
using RootAlias = Box<Base>;
struct Value : virtual Base {
  int value, *pointer;
  Box<Base> box;
  Box<> default_box;
  using Default = Box<>;
  using Alias = Box<Base>;
#if defined(USE_FAST_VALUE)
  using Conditional = Box<>;
#else
  using Conditional = Box<Base>;
#endif
  int run(const Base *value) const;
  void empty();
};
int Value::run(const Base *value) const { namespace local = ns; return 1; }
namespace root = ::ns;
#if defined(USE_FAST_VALUE)
namespace fast = ns::detail;
#endif
}
"#;
        #[test]
        fn cpp_dirty_overlay_source_facts_replace_stale_generation() {
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("types.cpp", "struct Original {};")
                .build();
            let file = fixture.file("types.cpp");
            let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
            let analyzer = CppAnalyzer::from_project(fixture.project().clone())
                .clone_with_project(overlay.clone() as Arc<dyn Project>);

            let original_unit = {
                let scope = AnalyzerQueryScope::new(&analyzer);
                let source = CppSource::declaration_source_facts(&analyzer, scope.token(), &file)
                    .expect("original C++ source facts");
                let unit = source
                    .declaration_units
                    .values()
                    .flatten()
                    .find(|unit| unit.identifier() == "Original")
                    .cloned()
                    .expect("original declaration unit");
                assert!(
                    CppSource::declaration_source_properties(&analyzer, scope.token(), &unit)
                        .is_some_and(|properties| !properties.is_empty()),
                    "original declaration properties must come from canonical facts"
                );
                unit
            };

            assert!(overlay.set(file.abs_path(), "struct Updated {};".to_owned(),));
            let updated =
                analyzer.clone_with_project(Arc::new(overlay.snapshot()) as Arc<dyn Project>);
            assert!(overlay.clear(&file.abs_path()));

            let updated_units = updated.declarations(&file);
            let updated_unit = updated_units
                .iter()
                .find(|unit| unit.identifier() == "Updated")
                .cloned()
                .expect("updated declaration unit from the dirty overlay");
            assert!(
                updated_units
                    .iter()
                    .all(|unit| unit.identifier() != "Original"),
                "updated generation must retire stale declaration units: {updated_units:?}"
            );
            {
                let scope = AnalyzerQueryScope::new(&updated);
                let source = CppSource::declaration_source_facts(&updated, scope.token(), &file)
                    .expect("updated C++ source facts must stay in memory after clearing overlay");
                let names: BTreeSet<_> = source
                    .declaration_units
                    .values()
                    .flatten()
                    .map(|unit| unit.identifier().to_owned())
                    .collect();
                assert!(names.contains("Updated"), "updated source names: {names:?}");
                assert!(!names.contains("Original"), "stale source names: {names:?}");
                assert!(
                    CppSource::declaration_source_properties(
                        &updated,
                        scope.token(),
                        &updated_unit
                    )
                    .is_some_and(|properties| !properties.is_empty()),
                    "updated declaration properties must use the in-memory canonical source"
                );
            }

            let scope = AnalyzerQueryScope::new(&analyzer);
            let original_source =
                CppSource::declaration_source_facts(&analyzer, scope.token(), &file)
                    .expect("pre-update analyzer source facts");
            let names: BTreeSet<_> = original_source
                .declaration_units
                .values()
                .flatten()
                .map(|unit| unit.identifier().to_owned())
                .collect();
            assert!(
                names.contains("Original"),
                "pre-update source names: {names:?}"
            );
            assert!(
                !names.contains("Updated"),
                "stale overlay leaked into old generation: {names:?}"
            );
            assert!(
                CppSource::declaration_source_properties(&analyzer, scope.token(), &original_unit)
                    .is_some_and(|properties| !properties.is_empty()),
                "pre-update declaration properties must retain their own generation"
            );
        }
        #[test]
        fn cpp_source_facts_reopen_without_source_and_mount_exact_bridges() {
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("first/types.cpp", SOURCE)
                .file("second/types.cpp", SOURCE)
                .build();
            let file = fixture.file("first/types.cpp");
            let second = fixture.file("second/types.cpp");
            let state = parse_state(&CppAdapter, &file);
            let expected = state.source_facts.as_ref().unwrap().cpp.as_ref().unwrap();
            assert!(
                expected
                    .declarations
                    .iter()
                    .any(|fact| fact.callable_comparable_shapes == Some(Vec::new()))
            );
            let oid = oid_for(SOURCE.as_bytes());
            let path = fixture.root().join("cpp-source.db");
            {
                let store = AnalyzerStore::open_persistent(&path).unwrap();
                store
                    .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
                    .unwrap();
            }
            std::fs::remove_file(file.abs_path()).unwrap();
            let store = AnalyzerStore::open_persistent(&path).unwrap();
            let generation = store.current_generation("cpp").unwrap();
            let (first, mounted) = brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_facts_match_across_mounts(
                &store,
                generation,
                &file,
                &second,
                |store, generation, file, cancellation| {
                    store.cpp_source_facts(oid, generation, "cpp", &CppAdapter, file, cancellation)
                },
                |read| &read.facts,
            );
            // Expression and statement rows are query-lifetime projections. The
            // canonical declaration rows, includes, and using directives are the
            // persisted source-facts contract exercised by this cold reopen.
            assert_eq!(first.facts.includes, expected.includes);
            assert_eq!(first.facts.declarations, expected.declarations);
            assert_eq!(first.facts.using_namespaces, expected.using_namespaces);
            // Block scope, a global target, a nested target and guards each
            // cross the relational and JSON columns of the alias rows.
            let aliases = &expected.namespace_aliases;
            assert_eq!(
                aliases
                    .iter()
                    .map(|alias| (
                        alias.name.as_str(),
                        alias.target.clone(),
                        alias.target_global,
                        alias.namespace.clone(),
                        alias.block.is_some(),
                        alias.guards.as_ref().map(|guards| guards.is_empty()),
                    ))
                    .collect::<Vec<_>>(),
                [
                    (
                        "local",
                        Some(vec!["ns".into()]),
                        false,
                        vec!["ns".into()],
                        true,
                        Some(true)
                    ),
                    (
                        "root",
                        Some(vec!["ns".into()]),
                        true,
                        vec!["ns".into()],
                        false,
                        Some(true)
                    ),
                    (
                        "fast",
                        Some(vec!["ns".into(), "detail".into()]),
                        false,
                        vec!["ns".into()],
                        false,
                        Some(false),
                    ),
                ],
                "{aliases:?}"
            );
            assert_eq!(first.facts.namespace_aliases, expected.namespace_aliases);
            assert!(first.facts.expressions.is_empty());
            assert_eq!(first.facts.statement_facts, Default::default());
            assert_eq!(
                first.source,
                state.source_facts.as_ref().unwrap().occurrences
            );
            assert!(
                first
                    .declaration_units
                    .values()
                    .flatten()
                    .all(|unit| unit.source() == &file)
            );
            assert!(
                mounted
                    .declaration_units
                    .values()
                    .flatten()
                    .all(|unit| unit.source() == &second)
            );
            assert!(
                store
                    .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| false)
                    .unwrap()
                    .is_none()
            );
            store
                .conn
                .execute(|conn| {
                    assert!(
                        conn.execute(
                            "UPDATE source_cpp_declarations SET trailing_qualifiers='broken'",
                            []
                        )
                        .is_err()
                    );
                    assert!(
                        conn.execute("UPDATE blob_meta SET cpp_source_version=NULL", [])
                            .is_err()
                    );
                    conn.execute("DELETE FROM blobs", [])?;
                    for table in [
                        "source_cpp_manifests",
                        "source_cpp_declarations",
                        "source_cpp_comparable_parameters",
                        "source_cpp_comparable_nodes",
                        "source_cpp_comparable_node_names",
                        "source_cpp_comparable_node_arguments",
                        "source_cpp_template_expressions",
                        "source_cpp_template_terms",
                        "source_cpp_includes",
                        "source_cpp_declaration_contexts",
                        "source_cpp_flattened_namespaces",
                        "source_cpp_guard_sets",
                        "source_cpp_guard_nodes",
                        "source_cpp_guard_edges",
                        "source_cpp_guard_roots",
                    ] {
                        let count: i64 =
                            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                                row.get(0)
                            })?;
                        assert_eq!(count, 0, "{table} must cascade with its owning blob");
                    }
                    Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
                })
                .unwrap();
        }
        #[test]
        fn cpp_source_lookup_seeks_populated_publications_before_and_after_statistics() {
            use rusqlite::params;

            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("types.cpp", SOURCE)
                .build();
            let file = fixture.file("types.cpp");
            let state = parse_state(&CppAdapter, &file);
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let generation = store.current_generation("cpp").unwrap();
            let oid = oid_for(SOURCE.as_bytes());
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
                .unwrap();
            for index in 0..32 {
                let other = oid_for(format!("planner publication {index}").as_bytes());
                store
                    .write_parsed_blob(other, "cpp", &CppAdapter, &state)
                    .unwrap();
            }
            brokk_bifrost_analysis::analyzer::store::source_facts::assert_source_lookup_plan(
                &store,
                |conn| {
                    conn.prepare(&format!(
                "EXPLAIN QUERY PLAN {}",
                brokk_bifrost_cpp_analysis::analyzer::cpp::source_storage::CPP_SOURCE_HEADER_SQL
            ))
                    .unwrap()
                    .query_map(
                        params![
                            oid.to_string(),
                            "cpp",
                            generation.get(),
                            brokk_bifrost_core::analyzer::cpp_facts::CPP_SOURCE_FACTS_VERSION,
                            brokk_bifrost_analysis::analyzer::store::source_facts::SOURCE_FACTS_VERSION,
                        ],
                        |row| row.get::<_, String>(3),
                    )
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap()
                },
                || {
                    store
                        .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
                        .unwrap()
                        .is_some()
                },
            );
            store
                .conn
                .execute(|conn| {
                    conn.execute("DELETE FROM blobs", [])?;
                    let count: i64 =
                        conn.query_row("SELECT COUNT(*) FROM source_cpp_manifests", [], |row| {
                            row.get(0)
                        })?;
                    assert_eq!(
                        count, 0,
                        "blob deletion must cascade sealed source publications"
                    );
                    Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
                })
                .unwrap();
        }
        #[test]
        fn cpp_source_publication_distinguishes_empty_missing_and_repaired() {
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("empty.cpp", "\n")
                .build();
            let file = fixture.file("empty.cpp");
            let mut state = parse_state(&CppAdapter, &file);
            let oid = oid_for(state.source.as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let generation = store.current_generation("cpp").unwrap();
            let facts = state.source_facts.as_mut().unwrap().cpp.take().unwrap();
            assert!(
                store
                    .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
                    .is_err()
            );
            state.source_facts.as_mut().unwrap().cpp = Some(facts);
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
                .unwrap();
            let read = store
                .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
                .unwrap()
                .unwrap();
            assert!(read.facts.declarations.is_empty());
            assert!(read.facts.includes.is_empty());
            store
                .conn
                .execute(|conn| {
                    assert!(
                        conn.execute(
                            "UPDATE source_cpp_manifests SET payload_bytes = payload_bytes",
                            []
                        )
                        .is_err()
                    );
                    conn.execute("UPDATE blob_meta SET is_complete = 0", [])?;
                    assert!(
                        conn.execute("UPDATE blob_meta SET cpp_source_version = NULL", [])
                            .is_err()
                    );
                    conn.execute("UPDATE blob_meta SET is_complete = 1", [])?;
                    conn.execute_batch(
                        "DROP TRIGGER source_cpp_manifests_no_delete_after_seal;
                 DELETE FROM source_cpp_manifests;",
                    )?;
                    Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
                })
                .unwrap();
            assert!(
                store
                    .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
                    .unwrap()
                    .is_none()
            );
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
                .unwrap();
            assert!(
                store
                    .cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true)
                    .unwrap()
                    .is_some()
            );
        }
        #[test]
        fn cpp_source_reader_rejects_corrupt_cpp_accounting() {
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("types.cpp", SOURCE)
                .build();
            let file = fixture.file("types.cpp");
            let state = parse_state(&CppAdapter, &file);
            let oid = oid_for(SOURCE.as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let generation = store.current_generation("cpp").unwrap();
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
                .unwrap();
            brokk_bifrost_analysis::analyzer::store::source_facts::assert_reader_rejects_tampering(
                || {
                    store.conn.execute(|conn| {
                        assert!(
                            conn.execute(
                                "UPDATE source_cpp_manifests SET payload_bytes = payload_bytes",
                                []
                            )
                            .is_err()
                        );
                        conn.execute_batch(
                            "DROP TRIGGER source_cpp_manifests_no_update_after_seal;
                     UPDATE source_cpp_manifests
                     SET payload_bytes = payload_bytes + 1;",
                        )?;
                        Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
                    })
                },
                || store.cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true),
            );
        }
        #[test]
        fn cpp_source_reader_rejects_corrupt_global_accounting() {
            let fixture = InlineTestProject::with_language(Language::Cpp)
                .file("types.cpp", SOURCE)
                .build();
            let file = fixture.file("types.cpp");
            let state = parse_state(&CppAdapter, &file);
            let oid = oid_for(SOURCE.as_bytes());
            let store = AnalyzerStore::open_ephemeral().unwrap();
            let generation = store.current_generation("cpp").unwrap();
            store
                .write_parsed_blob(oid, "cpp", &CppAdapter, &state)
                .unwrap();
            brokk_bifrost_analysis::analyzer::store::source_facts::assert_reader_rejects_tampering(
                || {
                    store.conn.execute(|conn| {
                assert!(
                    conn.execute(
                        "UPDATE source_fact_manifests SET declaration_unit_count = declaration_unit_count",
                        []
                    )
                    .is_err()
                );
                conn.execute_batch(
                    "DROP TRIGGER source_fact_manifests_declared_fields_are_immutable;
                     UPDATE source_fact_manifests
                     SET declaration_unit_count = declaration_unit_count + 1;",
                )?;
                Ok::<_, brokk_bifrost_analysis::analyzer::store::StoreError>(())
            })
                },
                || store.cpp_source_facts(oid, generation, "cpp", &CppAdapter, &file, &|| true),
            );
        }
    }

    mod file_usage_graph {

        use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

        use brokk_bifrost_analysis::analyzer::usages::file_usage_graph::WorkspaceFileUsageGraphBuildOutcome;

        use brokk_bifrost_analysis::analyzer::usages::file_usage_graph::build_workspace_file_usage_graph_with_cancellation;

        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

        use brokk_bifrost_cpp_analysis::CppAnalyzer;

        use brokk_bifrost_core::analyzer::model::Language;

        use brokk_bifrost_core::analyzer::query_token::QueryScope;

        use brokk_bifrost_core::cancellation::CancellationToken;

        use crate::inline_project::InlineTestProject;

        use brokk_bifrost_analysis::analyzer::usages::file_usage_graph::assert_edge;
        #[test]
        fn cpp_inventory_keeps_adopted_inc_edges_and_excludes_unowned_files() {
            let built = InlineTestProject::with_language(Language::Cpp)
        .file(
            "main.cpp",
            "#include \"adopted.inc\"\n#include \"reference_only.vue\"\nint main() { return 0; }\n",
        )
        .file("adopted.inc", "struct Adopted { int value; };\n")
        .file("unadopted.inc", "struct Orphan { int value; };\n")
        .file(
            "reference_only.vue",
            "<template><p>reference only</p></template>\n",
        )
        .file("inactive.py", "class Inactive: pass\n")
        .build();
            let analyzer = CppAnalyzer::from_project(built.project().clone());
            let main = built.file("main.cpp");
            let adopted = built.file("adopted.inc");
            let unadopted = built.file("unadopted.inc");
            let inactive = built.file("inactive.py");
            let reference_only = built.file("reference_only.vue");
            let cancellation = CancellationToken::new();
            let scope = AnalyzerQueryScope::new(&analyzer);
            let outcome = build_workspace_file_usage_graph_with_cancellation(
                &analyzer,
                scope.token(),
                &[UsageEcosystem::Cpp].into_iter().collect(),
                &cancellation,
            );

            let graph = match outcome {
                WorkspaceFileUsageGraphBuildOutcome::Complete(graph)
                | WorkspaceFileUsageGraphBuildOutcome::Incomplete(graph) => graph,
                WorkspaceFileUsageGraphBuildOutcome::Cancelled => panic!("unexpected cancellation"),
            };
            assert!(graph.nodes.iter().any(|node| node.primary_file == main));
            assert!(graph.nodes.iter().any(|node| node.primary_file == adopted));
            assert!(
                !graph
                    .nodes
                    .iter()
                    .any(|node| node.primary_file == unadopted)
            );
            assert!(!graph.nodes.iter().any(|node| node.primary_file == inactive));
            assert!(
                !graph
                    .nodes
                    .iter()
                    .any(|node| node.primary_file == reference_only)
            );
            assert_edge(&graph, &main, &adopted);
        }
    }
}
